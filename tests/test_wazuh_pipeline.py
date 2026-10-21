import asyncio
from copy import deepcopy
import json
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from api.app import create_app, ai_worker
from common.event_store import EventStore, QueueFull
from common.runtime_store import RuntimeStore
from wazuh_integration.mapper import map_wazuh_alert, ai_eligible
from wazuh_integration.spool import Spool, integration
from wazuh_integration.forwarder import deliver, write_status


@pytest.fixture
def event():
    # Synthetic Wazuh fixtures are test-only; they are never presented as live traffic.
    return {'id': '1725000.123', 'timestamp': '2026-10-20T08:00:00+07:00',
            'agent': {'id': '007', 'name': 'win-agent', 'ip': '192.0.2.7'},
            'manager': {'name': 'soc-manager'},
            'rule': {'id': '550', 'level': 3, 'description': 'File changed', 'groups': ['syscheck']},
            'syscheck': {'path': 'C:\\SOC-Lab\\watched\\hello.txt', 'event': 'modified'}}


@pytest.fixture(autouse=True)
def settings(monkeypatch):
    monkeypatch.setenv('WAZUH_WEBHOOK_TOKEN', 'test-only-token')
    monkeypatch.setenv('WAZUH_ENABLED', 'true')
    monkeypatch.setenv('WAZUH_AI_MIN_LEVEL', '7')
    monkeypatch.setenv('WAZUH_AI_GROUP_ALLOWLIST', 'syscheck')
    monkeypatch.setenv('WAZUH_AI_RULE_ALLOWLIST', '')
    monkeypatch.setenv('AI_MAX_CONCURRENCY', '1')


def test_fim_mapping_and_no_attacker_inference(event):
    r = map_wazuh_alert(event)
    assert r['source'] == 'wazuh' and r['src_ip'] is None and r['dst_ip'] is None
    assert r['timestamp'] == '2026-10-20T01:00:00Z'
    assert r['raw_event'] == event and r['file_event'] == 'modified'
    assert ai_eligible(r)
    event['syscheck']['path'] = '/tmp/soc-lab/hello.txt'
    assert map_wazuh_alert(event)['file_path'].startswith('/tmp/')


def test_windows_evidence_and_optional_fields(event):
    event.pop('syscheck')
    event['data'] = {'win': {'system': {'eventID': '4625'}, 'eventdata': {'targetUserName': 'soc-lab-user', 'ipAddress': '198.51.100.8'}}}
    r = map_wazuh_alert(event)
    assert r['src_ip'] == '198.51.100.8' and r['username'] == 'soc-lab-user'
    assert r['event_id'] == '4625' and r['file_path'] is None
    event.pop('data')
    assert map_wazuh_alert(event)['process'] is None


@pytest.mark.parametrize('change', [{'rule': {}}, {'agent': None}, {'timestamp': 'nonsense'}, {'rule': {'id': '1', 'description': 'x', 'level': 99}}])
def test_mapper_rejects_malformed(event, change):
    event.update(change)
    with pytest.raises((ValueError, TypeError)):
        map_wazuh_alert(event)


def test_filters_are_independent(event, monkeypatch):
    event['rule']['groups'] = ['authentication_failed']
    assert not ai_eligible(map_wazuh_alert(event))
    monkeypatch.setenv('WAZUH_AI_RULE_ALLOWLIST', '550')
    assert ai_eligible(map_wazuh_alert(event))


def test_webhook_auth_durable_async_and_restart_dedup(tmp_path, event):
    path = tmp_path / 'runtime.db'
    headers = {'X-Webhook-Token': 'test-only-token'}
    app = create_app(path, workers=False)
    with TestClient(app) as c, patch('api.app.analyze', side_effect=AssertionError('must not wait for LLM')):
        assert c.post('/wazuh', json=event).status_code == 401
        assert c.post('/wazuh', json=event, headers={'X-Webhook-Token': 'wrong'}).status_code == 401
        response = c.post('/wazuh', json=event, headers=headers)
        assert response.status_code == 202 and response.json()['durable']
        assert len(EventStore(path).list_events()) == 1  # independent DB reader before client receives another request
        assert c.post('/wazuh', json=event, headers=headers).json()['duplicate']
        assert app.state.store.queue_stats() == {'queued': 1}
        assert c.get('/api/alerts').json()['metrics']['total'] == 1
        assert c.post('/api/response/execute').status_code == 501
        for old in ('/zeek', '/webhook', '/api/demo/stream-5min/start'):
            assert c.post(old, json=event).status_code == 404
    with TestClient(create_app(path, workers=False)) as c:
        assert c.post('/wazuh', json=event, headers=headers).json()['duplicate']
        assert c.get('/api/cases').json()['cases'] == []
        assert c.app.state.store.queue_stats() == {'queued': 1}


def test_payload_and_queue_backpressure(tmp_path, event, monkeypatch):
    monkeypatch.setenv('WAZUH_MAX_PAYLOAD_BYTES', '20')
    with TestClient(create_app(tmp_path / 'a.db', workers=False)) as c:
        assert c.post('/wazuh', json=event, headers={'X-Webhook-Token': 'test-only-token'}).status_code == 413
    s = EventStore(tmp_path / 'b.db', max_jobs=0)
    with pytest.raises(QueueFull):
        s.accept(map_wazuh_alert(event), True)
    assert s.list_events() == []
    r, _ = s.accept(map_wazuh_alert(event), False)
    assert r['ai_status'] == 'skipped'


def test_migration_retains_source_cases_and_responses(tmp_path):
    path = tmp_path / 'old.db'
    original = {'alerts': {'old': {'id': 'old', 'source': 'legacy-source'}}, 'cases': {'C1': {'id': 'C1', 'notes': 'retained'}}, 'responses': [{'action': 'old record'}]}
    RuntimeStore(path).save(original)
    s = EventStore(path)
    assert s.get('old')['source'] == 'legacy-source'
    assert s.list_cases() == list(original['cases'].values())
    assert RuntimeStore(path).load() == original
    assert len(EventStore(path).list_events()) == 1


def test_failed_ai_survives_recovery_no_fake_report(tmp_path, event):
    s = EventStore(tmp_path / 'a.db')
    r, _ = s.accept(map_wazuh_alert(event), True)
    running = s.claim()
    assert running['ai_status'] == 'running'
    s.recover()
    assert s.get(r['id'])['ai_status'] == 'queued'
    s.finish(s.claim(), 'Ollama/RAG unavailable')
    result = s.get(r['id'])
    assert result['ai_status'] == 'failed' and result['raw_event'] == event
    assert 'investigation_report' not in result
    with s.connect() as db:
        db.execute('UPDATE ai_jobs SET updated=0')
    assert s.retry(r['id']) and not s.retry(r['id'])


def test_worker_service_failure(tmp_path, event):
    async def run():
        from types import SimpleNamespace
        s = EventStore(tmp_path / 'worker.db')
        r, _ = s.accept(map_wazuh_alert(event), True)
        app = SimpleNamespace(state=SimpleNamespace(store=s, ai_slots=asyncio.Semaphore(1)))
        with patch('api.app.analyze', side_effect=RuntimeError('RAG unavailable')):
            task = asyncio.create_task(ai_worker(app))
            for _ in range(100):
                await asyncio.sleep(.01)
                if s.get(r['id'])['ai_status'] == 'failed':
                    break
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        assert s.get(r['id'])['ai_status'] == 'failed'
        assert 'investigation_report' not in s.get(r['id'])
    asyncio.run(run())


def test_spool_restart_http_retry_and_deadletter(tmp_path, event):
    path = tmp_path / 'spool.db'
    s = Spool(path)
    s.put(event)
    # unavailable backend: the durable payload remains after process restart
    deliver(s, 'http://127.0.0.1:1/wazuh', 'test', timeout=.1)
    s = Spool(path)
    assert s.stats()['pending'] == 1
    class Handler(BaseHTTPRequestHandler):
        code = 202
        def do_POST(self):
            self.rfile.read(int(self.headers['Content-Length']))
            self.send_response(self.code)
            self.end_headers()
            self.wfile.write(b'{"durable":true}')
        def log_message(self, *args):
            pass
    server = HTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with s.connect() as db:
            db.execute('UPDATE queue SET next_try=0')
        target = f'http://127.0.0.1:{server.server_port}/wazuh'
        deliver(s, target, 'test')
        assert s.stats()['pending'] == 0 and s.stats()['sent'] == 1
        s.put(event)
        Handler.code = 401
        deliver(s, target, 'test')
        assert s.stats()['dead_letter'] == 1
        with s.connect() as db:
            job_id = db.execute('SELECT id FROM queue').fetchone()[0]
        s.replay(job_id)
        Handler.code = 202
        deliver(s, target, 'test')
        assert s.stats()['sent'] == 2
    finally:
        server.shutdown()
        server.server_close()


def test_spool_capacity_and_integration_ack(tmp_path, event, monkeypatch):
    path = tmp_path / 'queue.db'
    monkeypatch.setenv('WAZUH_SPOOL_PATH', str(path))
    alert = tmp_path / 'alert.json'
    alert.write_text(json.dumps(event))
    integration(alert)
    assert Spool(path).stats()['pending'] == 1
    with pytest.raises(RuntimeError):
        Spool(path, max_bytes=1).put(event)
    assert Spool(path).stats()['pending'] == 1


def test_missing_token_fails_startup(tmp_path, monkeypatch):
    monkeypatch.setenv('WAZUH_WEBHOOK_TOKEN', '')
    with pytest.raises(RuntimeError, match='WAZUH_WEBHOOK_TOKEN'):
        with TestClient(create_app(tmp_path / 'missing.db', workers=False)):
            pass


def test_invalid_payload_and_store_failure_not_acknowledged(tmp_path, event):
    with TestClient(create_app(tmp_path / 'http.db', workers=False)) as c:
        headers = {'X-Webhook-Token': 'test-only-token'}
        assert c.post('/wazuh', json={}, headers=headers).status_code == 422
        with patch.object(c.app.state.store, 'accept', side_effect=OSError('disk unavailable')):
            assert c.post('/wazuh', json=event, headers=headers).status_code == 503
        assert c.get('/api/alerts').json()['metrics']['total'] == 0


def test_concurrent_duplicate_is_single_job(tmp_path, event):
    from concurrent.futures import ThreadPoolExecutor
    s = EventStore(tmp_path / 'concurrent.db')
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: s.accept(map_wazuh_alert(deepcopy(event)), True), range(12)))
    assert sum(not duplicate for _, duplicate in results) == 1
    assert len(s.list_events()) == 1 and s.queue_stats() == {'queued': 1}


def test_context_cites_only_visible_documents(monkeypatch):
    from common.knowledge_context import bounded_context
    monkeypatch.setenv('AI_CONTEXT_CHARS', '100')
    context, citations = bounded_context([{'text': 'x' * 150, 'metadata': {'source': 'one'}}, {'text': 'y' * 100, 'metadata': {'source': 'two'}}])
    assert len(context) <= 100 and citations == [{'source': 'one'}]
