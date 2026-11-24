from datetime import datetime, timezone

from fastapi.testclient import TestClient

from api.app import create_app
from common.event_store import EventStore
from wazuh_integration.mapper import map_wazuh_alert


def alert(event_id):
    return map_wazuh_alert({
        'id': event_id, 'timestamp': datetime.now(timezone.utc).isoformat(),
        'agent': {'id': '001', 'name': 'victim'}, 'manager': {'name': 'manager'},
        'rule': {'id': '2502', 'level': 10, 'description': 'Authentication failure',
                 'groups': ['authentication_failed']},
        'data': {'srcip': '192.0.2.1', 'dstuser': event_id},
        'location': 'journald',
    })


def test_pause_keeps_existing_queue_and_running_job_and_stores_new_alert(tmp_path):
    path = tmp_path / 'runtime.sqlite3'
    store = EventStore(path, max_jobs=2)
    running, _ = store.accept(alert('first'), True)
    running = store.claim()
    queued, _ = store.accept(alert('second'), True)

    store.set_ai_paused(True)
    assert EventStore(path).ai_paused() is True
    assert store.claim() is None
    # A full queue must not reject newly collected alerts while paused.
    incoming, duplicate = store.accept(alert('third'), True)
    assert not duplicate and incoming['ai_status'] == 'skipped'
    assert incoming['ai_allowed'] and 'tạm dừng' in incoming['ai_skip_reason']
    assert store.get(incoming['id'])['event_kind'] == 'alert'
    assert store.queue_stats() == {'queued': 1, 'running': 1}
    assert store.finish(running)
    assert store.get(running['id'])['ai_status'] == 'completed'
    assert store.claim() is None

    # Manual investigation can be requested while paused; it waits for resume.
    assert store.retry(incoming['id'])
    assert store.claim() is None
    store.set_ai_paused(False)
    assert EventStore(path).ai_paused() is False
    assert store.claim()['id'] in {queued['id'], incoming['id']}


def test_pause_api_requires_local_origin_and_boolean(tmp_path, monkeypatch):
    monkeypatch.setenv('WAZUH_ENABLED', 'false')
    monkeypatch.setenv('TELEGRAM_BOT_TOKEN', '')
    monkeypatch.setenv('TELEGRAM_CHAT_ID', '')
    app = create_app(tmp_path / 'runtime.sqlite3', workers=False)
    headers = {'Origin': 'http://localhost:8100', 'X-SOC-Action': 'ai-control'}
    with TestClient(app, base_url='http://localhost:8100') as client:
        assert client.get('/api/sources/status').json()['ai_paused'] is False
        assert client.post('/api/ai-control', json={'paused': True}).status_code == 403
        assert client.post('/api/ai-control', json={'paused': True},
                           headers={**headers, 'Origin': 'http://example.com'}).status_code == 403
        assert client.post('/api/ai-control', json={'paused': 'true'}, headers=headers).status_code == 422
        assert client.post('/api/ai-control', json={'paused': True}, headers=headers).json() == {'paused': True}
        assert client.get('/api/sources/status').json()['ai_paused'] is True
        assert client.post('/api/ai-control', json={'paused': False}, headers=headers).json() == {'paused': False}
