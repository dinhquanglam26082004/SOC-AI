"""Alert chat reads the retained history without handing the model a database dump."""

import json

from fastapi.testclient import TestClient

from agents.analyst_chat_tools import execute
from api.app import create_app
from common.event_store import EventStore


def add_alerts(store, count=14):
    with store.connect() as db:
        for index in range(count):
            record = {
                'id': f'WAZUH-test-{index}', 'event_kind': 'alert',
                'timestamp': f'2026-11-18T11:{index:02}:00Z',
                'received_at': f'2026-11-18T11:{index:02}:01Z',
                'agent': {'id': '001', 'name': 'ubuntu-agent', 'ip': '192.0.2.10'},
                'rule': {'id': '777' if index == 0 else '100181', 'level': 7,
                         'description': 'DNS bat thuong' if index else 'Canh bao cu', 'groups': ['zeek_detection']},
                'severity': 'HIGH' if index % 2 else 'MEDIUM',
                'ai_status': 'completed', 'source_product': 'zeek', 'log_type': 'dns',
                'src_ip': '192.0.2.20' if index == 0 else '192.0.2.21',
                'dst_ip': '192.0.2.53', 'dst_port': 53,
                'investigation_report': {'verdict': 'inconclusive', 'reasoning': 'Chua du bang chung.'},
            }
            db.execute('INSERT INTO events VALUES(?,?)', (record['id'], json.dumps(record)))
        db.execute('INSERT INTO events VALUES(?,?)', ('telemetry', json.dumps({'event_kind': 'telemetry'})))


def test_search_counts_all_history_and_pages_without_telemetry(tmp_path):
    store = EventStore(tmp_path / 'runtime.db')
    add_alerts(store)
    first = execute(store, 'search_alerts', {'page_size': 8})
    second = execute(store, 'search_alerts', {'page_size': 8, 'page': 2})
    assert first['ok'] and first['total'] == 14 and first['returned'] == 8
    assert first['next_page'] == 2 and first['has_more']
    assert second['total'] == 14 and second['returned'] == 6 and not second['has_more']
    assert not {a['id'] for a in first['alerts']} & {a['id'] for a in second['alerts']}
    assert 'WAZUH-test-0' in {a['id'] for a in second['alerts']}
    assert first['severity_counts'] == {'HIGH': 7, 'MEDIUM': 7}


def test_following_page_keeps_initial_range_when_new_alert_arrives(tmp_path):
    store = EventStore(tmp_path / 'runtime.db')
    add_alerts(store)
    first = execute(store, 'search_alerts', {'page_size': 8})
    with store.connect() as db:
        newest = json.loads(db.execute("SELECT payload FROM events WHERE id='WAZUH-test-13'").fetchone()[0])
        newest['id'] = 'WAZUH-new'
        db.execute('INSERT INTO events VALUES(?,?)', (newest['id'], json.dumps(newest)))
    second = execute(store, 'search_alerts', {**first['scope'], 'page': 2})
    assert second['total'] == 14
    assert 'WAZUH-new' not in {item['id'] for item in first['alerts'] + second['alerts']}
    assert len({item['id'] for item in first['alerts'] + second['alerts']}) == 14
    assert execute(store, 'search_alerts', {})['total'] == 15
    with store.connect() as db:
        db.execute("INSERT INTO runtime_control VALUES('reset_generation','1')")
    expired = execute(store, 'search_alerts', {**first['scope'], 'page': 2})
    assert not expired['ok'] and 'lam moi' in expired['error']


def test_old_alert_is_findable_by_rule_ip_and_id(tmp_path):
    store = EventStore(tmp_path / 'runtime.db')
    add_alerts(store)
    by_rule = execute(store, 'search_alerts', {'rule_id': 777, 'agent': 'ubuntu-agent'})
    by_ip = execute(store, 'search_alerts', {'ip': '192.0.2.20'})
    detail = execute(store, 'get_alert_details', {'alert_id': 'WAZUH-test-0'})
    assert by_rule['total'] == by_ip['total'] == 1
    assert by_rule['alerts'][0]['id'] == by_ip['alerts'][0]['id'] == 'WAZUH-test-0'
    assert detail['found'] and detail['alert']['investigation']['verdict'] == 'inconclusive'
    assert not execute(store, 'get_alert_details', {'alert_id': 'telemetry'})['found']


def test_search_scope_validation_and_parameterization(tmp_path):
    store = EventStore(tmp_path / 'runtime.db')
    add_alerts(store)
    window = execute(store, 'search_alerts', {'since': '2026-11-18T11:02:00Z',
                                               'until': '2026-11-18T11:04:00Z'})
    assert window['ok'] and window['total'] == 3
    assert not execute(store, 'search_alerts', {'since': '2026-11-18'})['ok']
    assert not execute(store, 'search_alerts', {'ip': 'not-an-ip'})['ok']
    assert not execute(store, 'search_alerts', {'page': 0})['ok']
    assert not execute(store, 'run_shell', {'command': 'anything'})['ok']
    injected = execute(store, 'search_alerts', {'keyword': "x' OR 1=1 --"})
    assert injected['ok'] and injected['total'] == 0
    assert execute(store, 'search_alerts', {})['total'] == 14


def test_chat_routes_older_alert_to_model_with_visible_query_scope(tmp_path, monkeypatch):
    monkeypatch.setenv('WAZUH_ENABLED', 'false')
    monkeypatch.delenv('TELEGRAM_BOT_TOKEN', raising=False)
    monkeypatch.delenv('TELEGRAM_CHAT_ID', raising=False)
    calls = []

    def model(messages, **kwargs):
        calls.append((messages, kwargs))
        if kwargs.get('tools'):
            return {'message': {'content': '', 'tool_calls': [
                {'function': {'name': 'search_alerts', 'arguments': {'rule_id': '777'}}}]}}
        return {'message': {'content': 'Có một cảnh báo rule 777.'}, 'done_reason': 'stop'}

    monkeypatch.setattr('common.ollama_client.chat_messages', model)
    with TestClient(create_app(db_path=tmp_path / 'runtime.db', workers=False)) as client:
        add_alerts(client.app.state.store)
        response = client.post('/api/analyst-chat', json={'messages': [
            {'role': 'user', 'content': 'Tìm cảnh báo rule 777'}]})
    assert response.status_code == 200
    assert response.json()['lookups'][0]['total'] == 1
    assert response.json()['lookups'][0]['scope']['rule_id'] == '777'
    final_context = json.loads(calls[1][0][1]['content'].split(': ', 1)[1])
    assert final_context['alert_queries'][0]['alerts'][0]['id'] == 'WAZUH-test-0'
    assert final_context['alert_metrics']['total'] == 14


def test_stream_provides_scope_and_does_not_confuse_a_page_with_all_alerts(tmp_path, monkeypatch):
    monkeypatch.setenv('WAZUH_ENABLED', 'false')
    monkeypatch.delenv('TELEGRAM_BOT_TOKEN', raising=False)
    monkeypatch.delenv('TELEGRAM_CHAT_ID', raising=False)
    monkeypatch.setattr('common.ollama_client.chat_messages', lambda *args, **kwargs:
                        {'message': {'content': '', 'tool_calls': [
                            {'function': {'name': 'search_alerts', 'arguments': {'page_size': 5}}}]}})
    sent = []

    class Response:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        def raise_for_status(self): pass
        async def aiter_lines(self):
            yield json.dumps({'message': {'content': 'Có 14 cảnh báo.'}, 'done': False})
            yield json.dumps({'message': {'content': ''}, 'done': True, 'done_reason': 'stop'})

    class Client:
        def __init__(self, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        def stream(self, method, url, json):
            sent.append(json)
            return Response()

    monkeypatch.setattr('api.app.httpx.AsyncClient', Client)
    with TestClient(create_app(db_path=tmp_path / 'runtime.db', workers=False)) as client:
        add_alerts(client.app.state.store)
        response = client.post('/api/analyst-chat/stream', json={'messages': [
            {'role': 'user', 'content': 'Tổng hợp tất cả cảnh báo'}]})
    events = [json.loads(line) for line in response.text.splitlines()]
    lookup = next(event for event in events if event['type'] == 'lookup')
    assert (lookup['total'], lookup['returned'], lookup['has_more'], lookup['next_page']) == (14, 5, True, 2)
    final_context = json.loads(sent[0]['messages'][1]['content'].split(': ', 1)[1])
    assert final_context['alert_queries'][0]['total'] == 14
    assert len(final_context['alert_queries'][0]['alerts']) == 5
    assert events[-1]['type'] == 'done'


def test_requested_next_page_uses_same_snapshot_without_another_planning_call(tmp_path, monkeypatch):
    monkeypatch.setenv('WAZUH_ENABLED', 'false')
    monkeypatch.delenv('TELEGRAM_BOT_TOKEN', raising=False)
    monkeypatch.delenv('TELEGRAM_CHAT_ID', raising=False)
    calls = []

    def model(messages, **kwargs):
        calls.append(kwargs)
        assert not kwargs.get('tools')
        return {'message': {'content': 'Trang tiếp theo.'}, 'done_reason': 'stop'}

    monkeypatch.setattr('common.ollama_client.chat_messages', model)
    with TestClient(create_app(db_path=tmp_path / 'runtime.db', workers=False)) as client:
        add_alerts(client.app.state.store)
        first = execute(client.app.state.store, 'search_alerts', {'page_size': 8})
        response = client.post('/api/analyst-chat', json={
            'messages': [{'role': 'user', 'content': 'Xem trang tiếp theo'}],
            'alert_search': {**first['scope'], 'page': 2},
        })
    assert response.status_code == 200
    lookup = response.json()['lookups'][0]
    assert lookup['total'] == 14 and lookup['returned'] == 6 and lookup['scope']['page'] == 2
    assert len(calls) == 1
