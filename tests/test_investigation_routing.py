"""The model receives available tools without alert-specific recommendations."""
from agents.investigation_graph import InvestigationGraph, SYSTEM
from agents.investigation_tools import DESCRIPTIONS, MODELS, definitions


def test_model_context_has_no_recommended_tools():
    class Audit:
        def evidence(self, incident):
            return []
    class Tools:
        def envelope(self, status):
            return {"scope": {}}
    graph = InvestigationGraph(None, Audit(), checkpoint_path="unused")
    graph.limits = graph.default_limits
    graph.id = "test"
    graph.alert = {"id": "alert", "timestamp": "2026-01-01T00:00:00Z", "rule": {}}
    graph.tools = Tools()
    context = graph.context({})
    assert "recommended_tools" not in context
    assert "recommended_tools" not in SYSTEM
    names = {tool["function"]["name"] for tool in definitions()}
    assert {"summarize_dns_activity", "compare_dns_baseline", "search_auth_events",
            "summarize_zeek_flows"} <= names


def test_published_tool_descriptions_and_scope_schemas():
    published = {item['function']['name']: item['function'] for item in definitions()}
    assert set(DESCRIPTIONS) == set(MODELS)
    assert set(published) == set(MODELS) - {'get_alert'}
    for name, tool in published.items():
        assert tool['description'] == DESCRIPTIONS[name]
        assert set(tool['parameters'].get('required', [])) == set(MODELS[name].model_json_schema().get('required', []))
        assert {'_verification_question', '_selection_reason'} <= set(tool['parameters']['properties'])

    dns = published['summarize_dns_activity']['parameters']
    assert set(dns['required']) == {'domain', 'since', 'until'}
    flow = published['summarize_zeek_flows']['parameters']
    assert set(flow['required']) == {'src_ip', 'dst_ip', 'dst_port', 'since', 'until'}
    auth = published['search_auth_events']['parameters']['properties']
    # Published schemas stay compact; limits are enforced by Pydantic at dispatch.
    assert auth['limit']['default'] == 20 and auth['limit']['type'] == 'integer'
    assert auth['ip']['type'] == 'string'
    assert 'source IP only' in auth['ip']['description']
    privilege = published['search_privilege_events']['parameters']['properties']
    assert 'IP-less local sudo/su' in privilege['ip']['description']
    rootkit = published['search_rootkit_evidence']['parameters']['properties']
    assert rootkit['ip']['type'] == 'string' and 'does not filter results' in rootkit['ip']['description']
    fim = published['search_file_changes']['parameters']['properties']
    assert fim['file_path']['type'] == 'string' and '/proc/PID' in fim['file_path']['description']
    from agents.investigation_tools import MODELS as M
    import pytest
    with pytest.raises(Exception):
        M['search_auth_events'].model_validate({'limit': 101})
    assert 'exactly' in published['search_zeek_dns']['description']
    assert 'cannot total all sources' in published['summarize_zeek_flows']['description']
    assert 'within incident scope' in published['compare_dns_baseline']['description']
