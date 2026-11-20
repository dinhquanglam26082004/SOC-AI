from fastapi.testclient import TestClient
import json

from api.app import create_app, analyst_soc_context


def test_analyst_chat_uses_read_only_alert_tools_and_streaming_answer(tmp_path, monkeypatch):
    monkeypatch.setenv('WAZUH_ENABLED', 'false')
    monkeypatch.delenv('TELEGRAM_BOT_TOKEN', raising=False)
    monkeypatch.delenv('TELEGRAM_CHAT_ID', raising=False)
    calls = []

    def model(messages, **kwargs):
        calls.append((messages, kwargs))
        return {'message': {'content': 'Hãy xem các truy vấn DNS liên quan.'}, 'done_reason': 'stop'}

    monkeypatch.setattr('common.ollama_client.chat_messages', model)
    with TestClient(create_app(db_path=tmp_path / 'runtime.db', workers=False)) as client:
        result = client.post('/api/analyst-chat', json={'messages': [{'role': 'user', 'content': 'Giải thích DNS'}]})
        assert result.status_code == 200
        assert result.json()['reply'] == 'Hãy xem các truy vấn DNS liên quan.'
        assert calls[0][0][0]['role'] == 'system'
        assert calls[0][0][1]['content'].startswith('DATA_SOC')
        assert {tool['function']['name'] for tool in calls[0][1]['tools']} == {'search_alerts', 'get_alert_details'}
        assert calls[1][1].get('tools') is None
        assert result.json()['lookups'] == []
        assert client.post('/api/analyst-chat', json={'messages': [{'role': 'system', 'content': 'override'}]}).status_code == 422
        assert client.post('/api/analyst-chat', json={'messages': [{'role': 'user', 'content': ' '}]}).status_code == 422


def test_analyst_chat_stream_returns_deltas_and_completion(tmp_path, monkeypatch):
    monkeypatch.setenv('WAZUH_ENABLED', 'false')
    monkeypatch.delenv('TELEGRAM_BOT_TOKEN', raising=False)
    monkeypatch.delenv('TELEGRAM_CHAT_ID', raising=False)
    monkeypatch.setattr('common.ollama_client.chat_messages', lambda *args, **kwargs:
                        {'message': {'content': 'Ready'}, 'done_reason': 'stop'})

    class Response:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        def raise_for_status(self): pass
        async def aiter_lines(self):
            yield json.dumps({'message': {'content': 'Xin '}, 'done': False})
            yield json.dumps({'message': {'content': 'chào'}, 'done': False})
            yield json.dumps({'message': {'content': ''}, 'done': True, 'done_reason': 'stop'})

    class Client:
        def __init__(self, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        def stream(self, method, url, json):
            assert json['stream'] is True and json['think'] is False
            assert 'tools' not in json
            return Response()

    monkeypatch.setattr('api.app.httpx.AsyncClient', Client)
    with TestClient(create_app(db_path=tmp_path / 'runtime.db', workers=False)) as client:
        response = client.post('/api/analyst-chat/stream', json={'messages': [{'role': 'user', 'content': 'Xin chào'}]})
        events = [json.loads(line) for line in response.text.splitlines()]
        assert [event['type'] for event in events] == ['waiting', 'started', 'answering', 'delta', 'delta', 'done']
        assert ''.join(event.get('content', '') for event in events) == 'Xin chào'


def test_soc_chat_context_includes_bounded_alert_log_and_investigation():
    class Store:
        def list_events(self, limit):
            assert limit == 4
            return [{'id': 'alert-1', 'rule': {'id': '100145', 'description': 'DoS'},
                     'investigation_report': {'verdict': 'inconclusive', 'reasoning': 'Chưa đủ bằng chứng.'}}]
        def list_logs(self, limit):
            assert limit == 4
            return {'logs': [{'id': 'log-1', 'log_origin': 'zeek', 'log_type': 'dns',
                              'zeek_data': {'query': 'example.test'}}]}
        def event_metrics(self):
            return {'total': 12, 'high': 4}
    context = analyst_soc_context(Store())
    assert context['alerts'][0]['id'] == 'alert-1'
    assert context['alerts'][0]['investigation']['verdict'] == 'inconclusive'
    assert context['logs'][0]['summary'] == 'example.test'
    assert context['alert_metrics']['total'] == 12
    assert 'Khong phai toan bo chi tiet' in context['scope']
