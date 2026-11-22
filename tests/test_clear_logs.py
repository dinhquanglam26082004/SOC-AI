import asyncio
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import threading
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient

from api.app import ai_worker, create_app
from common.event_store import EventStore
from common.runtime_store import RuntimeStore
from wazuh_integration.mapper import map_wazuh_alert


def sample_alert(event_id='alert-1', seconds=-60):
    return {
        'id': event_id,
        'timestamp': (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat(),
        'agent': {'id': '001', 'name': 'test-agent', 'ip': '192.0.2.1'},
        'manager': {'name': 'test-manager'},
        'rule': {'id': '2502', 'level': 10, 'description': 'Authentication failure',
                 'groups': ['authentication_failed']},
        'data': {'srcip': '192.0.2.2', 'dstuser': 'analyst'},
        'location': 'journald',
    }


def sample_zeek():
    return {
        'id': 'dns-1',
        'timestamp': (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
        'agent': {'id': '001', 'name': 'test-agent'},
        'manager': {'name': 'test-manager'},
        'rule': {'id': '100121', 'level': 3, 'description': 'Zeek DNS',
                 'groups': ['zeek_telemetry']},
        'location': '/opt/zeek/logs/current/dns.log',
        'data': {'query': 'example.test', 'qtype_name': 'A'},
    }


def test_reset_clears_events_and_blocks_old_deliveries_but_keeps_cases(tmp_path):
    path = tmp_path / 'runtime.sqlite3'
    store = EventStore(path)
    source = sample_alert()
    alert, _ = store.accept(map_wazuh_alert(source), True)
    store.accept(map_wazuh_alert(sample_zeek()), False)
    store.save_case({'id': 'case-1', 'note': 'keep case'})
    RuntimeStore(path).save({'alerts': {alert['id']: alert}, 'cases': {'case-1': {'id': 'case-1'}},
                             'responses': [{'action': 'keep response'}]})
    assert store.log_stats()['total'] == 2
    assert store.queue_stats() == {'queued': 1}

    request_id = str(uuid4())
    result = store.clear_logs_and_alerts(request_id)
    assert result['deleted']['alerts'] == 1
    assert result['deleted']['logs'] == 2
    assert result['deleted']['queued_jobs'] == 1
    assert store.list_events() == []
    assert store.list_logs()['logs'] == []
    assert store.queue_stats() == {}
    assert store.list_cases() == [{'id': 'case-1', 'note': 'keep case'}]
    snapshot = RuntimeStore(path).load()
    assert 'alerts' not in snapshot and 'cases' in snapshot and snapshot['responses']
    with store.connect() as db:
        for table in ('events', 'zeek_logs', 'log_index', 'investigation_event_index',
                      'authentication_facts', 'ai_jobs'):
            assert db.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0] == 0

    ignored, _ = store.accept(map_wazuh_alert(source), True)
    assert ignored['_ignored_before_reset'] is True
    assert store.list_logs()['logs'] == []
    new_alert, _ = store.accept(map_wazuh_alert(sample_alert('new-alert', 5)), True)
    # Retrying the same request cannot erase events that arrived after the reset.
    assert store.clear_logs_and_alerts(request_id) == result
    assert store.get(new_alert['id']) is not None


def test_old_ai_job_cannot_update_new_job_with_same_event_id(tmp_path):
    store = EventStore(tmp_path / 'runtime.sqlite3')
    source = sample_alert()
    old_alert, _ = store.accept(map_wazuh_alert(source), True)
    old_job = store.claim()
    store.clear_logs_and_alerts(str(uuid4()))

    later_source = deepcopy(source)
    later_source['timestamp'] = (datetime.now(timezone.utc) + timedelta(seconds=5)).isoformat()
    store.accept(map_wazuh_alert(later_source), True)
    new_job = store.claim()
    assert old_job['id'] == new_job['id'] == old_alert['id']
    assert not store.progress(old_job, 'outdated', 1, 'model')
    assert not store.finish(old_job)
    assert not store.skip(old_job, 'outdated')
    assert store.get(new_job['id'])['ai_status'] == 'running'
    assert store.finish(new_job)
    assert store.get(new_job['id'])['ai_status'] == 'completed'


def test_clear_api_requires_explicit_local_confirmation(tmp_path, monkeypatch):
    monkeypatch.setenv('WAZUH_ENABLED', 'false')
    monkeypatch.setenv('TELEGRAM_BOT_TOKEN', '')
    monkeypatch.setenv('TELEGRAM_CHAT_ID', '')
    app = create_app(tmp_path / 'runtime.sqlite3', workers=False)
    with TestClient(app, base_url='http://localhost:8100') as client:
        app.state.store.accept(map_wazuh_alert(sample_alert()), True)
        audit = app.state.investigation_store
        investigation = audit.create('alert-1', {})
        report = {'verdict': 'inconclusive', 'reasoning': 'Needs analyst review.'}
        audit.update(investigation['id'], {'review_status': 'pending', 'needs_analyst': True},
                     'completed', report)
        assert len(audit.pending_reviews()['items']) == 1
        request_id = str(uuid4())
        headers = {'Origin': 'http://localhost:8100', 'X-SOC-Action': 'clear-logs'}
        body = {'confirm': True, 'request_id': request_id}
        assert client.post('/api/logs/clear', json=body).status_code == 403
        assert client.post('/api/logs/clear', json=body,
                           headers={**headers, 'Origin': 'http://example.com'}).status_code == 403
        assert client.post('/api/logs/clear', json={**body, 'confirm': False}, headers=headers).status_code == 400
        assert client.post('/api/logs/clear', json={**body, 'confirm': 'true'}, headers=headers).status_code == 422
        assert client.get('/api/alerts').json()['metrics']['total'] == 1
        response = client.post('/api/logs/clear', json=body, headers=headers)
        assert response.status_code == 200
        assert response.json()['deleted']['alerts'] == 1
        assert client.get('/api/alerts').json()['metrics']['total'] == 0
        assert audit.pending_reviews()['items'] == []
        saved = audit.current('alert-1')
        assert saved['summary']['review_status'] == 'cleared'
        assert saved['report'] == report
        later = audit.create('new-alert', {})
        audit.update(later['id'], {'review_status': 'pending', 'needs_analyst': True},
                     'completed', report)
        retried = client.post('/api/logs/clear', json=body, headers=headers)
        assert retried.status_code == 200
        assert [item['alert_id'] for item in audit.pending_reviews()['items']] == ['new-alert']


def test_cleared_running_job_does_not_send_a_telegram_notification(tmp_path):
    async def run():
        store = EventStore(tmp_path / 'runtime.sqlite3')
        store.accept(map_wazuh_alert(sample_alert()), True)
        app = SimpleNamespace(state=SimpleNamespace(store=store, ai_slots=asyncio.Semaphore(1)))
        started, release = threading.Event(), threading.Event()

        def slow_analyze(*args):
            started.set()
            if not release.wait(5):
                raise TimeoutError('Test job was not released')
            return {'verdict': 'inconclusive'}, {'status': 'not_requested'}

        with patch('api.app.analyze', side_effect=slow_analyze), \
                patch('api.app.send_investigation_alert') as notify:
            task = asyncio.create_task(ai_worker(app))
            try:
                assert await asyncio.to_thread(started.wait, 3)
                store.clear_logs_and_alerts(str(uuid4()))
                release.set()
                await asyncio.sleep(.2)
                assert store.list_events() == []
                notify.assert_not_called()
            finally:
                release.set()
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    asyncio.run(run())
