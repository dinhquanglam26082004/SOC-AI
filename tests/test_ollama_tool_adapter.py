from common.ollama_client import _normalize_tool_call


TOOLS = [{'function': {'name': 'get_alert'}}]


def test_normalizes_only_registered_strict_tool_calls():
    message = {'role': 'assistant', 'content': 'Response: {"name":"get_alert","parameters":{"alert_id":"A"}}'}
    result = _normalize_tool_call(message, TOOLS)
    assert result['tool_calls'][0]['function'] == {'name': 'get_alert', 'arguments': {'alert_id': 'A'}}
    assert result['content'] == ''
    fenced = {'role': 'assistant', 'content': '```json\n{"name":"get_alert","parameters":{"alert_id":"A"}}\n```'}
    assert _normalize_tool_call(fenced, TOOLS)['tool_calls'] == result['tool_calls']


def test_does_not_convert_unknown_or_ambiguous_output():
    for content in ('{"name":"shell","parameters":{}}',
                    '{"name":[],"parameters":{}}',
                    'Run this: {"name":"get_alert","parameters":{}}',
                    '{"name":"get_alert","parameters":{},"extra":true}'):
        message = {'role': 'assistant', 'content': content}
        assert _normalize_tool_call(message, TOOLS) == message
    message = {'role': 'assistant', 'content': '{"name":"get_alert","parameters":{}}'}
    assert _normalize_tool_call(message, None) == message
