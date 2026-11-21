"""Alert-type tool routing and deterministic DNS-tunneling evidence (regression for the
19/11/2026 demo: noisy PTR/NTP lookups hid the tunnel queries from the model)."""
import json

import pytest

from agents.investigation_graph import InvestigationGraph
from agents.investigation_profiles import (baseline_calls, classify, parent_domain, tools_for)
from agents.investigation_store import InvestigationStore
from agents.investigation_tools import MODELS, definitions
from common.event_store import EventStore
from wazuh_integration.mapper import map_wazuh_alert

GATEWAY = '192.168.19.2'
TUNNEL_SERVER = '192.168.19.130'
VICTIM = '192.168.19.129'


@pytest.fixture
def tunnel_lab(tmp_path, monkeypatch):
    monkeypatch.setenv('AI_GRAPH_PROGRESS_MODE', 'true')
    monkeypatch.delenv('AI_TOOL_ROUTING', raising=False)
    store = EventStore(tmp_path / 'events.db')
    audit = InvestigationStore(tmp_path / 'audit.db')
    seq = [0]

    def dns(minute, second, query, qtype, resp=TUNNEL_SERVER, rule=None):
        seq[0] += 1
        raw = {'id': str(seq[0]), 'timestamp': f'2026-11-19T09:{minute:02}:{second:02}Z',
               'agent': {'id': '001', 'name': 'ubuntu-agent', 'ip': VICTIM}, 'manager': {'name': 'soc-manager'},
               'rule': rule or {'id': '100121', 'level': 3, 'description': 'Zeek DNS', 'groups': ['zeek', 'zeek_telemetry']},
               'location': '/opt/zeek/logs/current/dns.log', '_soc_stream': 'archives',
               'data': {'uid': f'C{seq[0]}', 'id': {'orig_h': VICTIM, 'orig_p': '5000', 'resp_h': resp, 'resp_p': '53'},
                        'proto': 'udp', 'query': query, 'qtype_name': qtype, 'rcode_name': 'NOERROR'}}
        record = map_wazuh_alert(raw)
        store.accept(record, False)
        return record

    # Noise first (older): reverse lookups and NTP to the gateway, like the real demo.
    for i in range(12):
        dns(25, i, f'{i}.19.168.192.in-addr.arpa', 'PTR', resp=GATEWAY)
        dns(26, i, 'ntp.ubuntu.com', 'A', resp=GATEWAY)
    # Tunnel traffic: many distinct random labels under one parent domain.
    for i in range(40):
        dns(32, i, f'yrb{i:03x}q.tunnel.lab.local', 'NULL')
        dns(32, i + 1, f'ytb{i:03x}z.tunnel.lab.local', 'TXT')
    trigger = dns(33, 5, 'vaaaakaswii.tunnel.lab.local', 'NULL', rule={
        'id': '100181', 'level': 7, 'description': 'Zeek DNS: nhieu query NULL',
        'groups': ['zeek', 'network', 'zeek_detection', 'zeek_dns_anomaly'],
        'mitre': {'id': ['T1071.004'], 'tactic': ['Command and Control'], 'technique': ['DNS']}})
    return store, audit, trigger


def test_classify_and_route_dns_tunneling(tunnel_lab):
    *_, trigger = tunnel_lab
    assert classify(trigger) == 'dns_tunneling'
    routed = tools_for(trigger, list(MODELS))
    assert {'summarize_dns_activity', 'compare_dns_baseline', 'search_zeek_dns'} <= set(routed)
    assert not {'search_auth_events', 'search_file_changes', 'search_rootkit_evidence',
                'search_zeek_http', 'summarize_zeek_flows'} & set(routed)
    # Routed schemas must leave room for evidence in a 4096-token context.
    assert len(json.dumps(definitions(routed))) < 0.6 * len(json.dumps(definitions()))


def test_routing_can_be_disabled(tunnel_lab, monkeypatch):
    *_, trigger = tunnel_lab
    monkeypatch.setenv('AI_TOOL_ROUTING', 'false')
    assert set(tools_for(trigger, list(MODELS))) == set(MODELS) - {'get_alert'}
    assert baseline_calls(trigger, '2026-11-19T09:18:05Z', '2026-11-19T09:48:05Z') == []


def test_unknown_alert_keeps_full_tool_set():
    alert = {'rule': {'id': '99999', 'groups': ['custom']}}
    assert classify(alert) is None
    assert set(tools_for(alert, list(MODELS))) == set(MODELS) - {'get_alert'}


@pytest.mark.parametrize('query,expected', [
    ('vaaaakaswii.tunnel.lab.local', 'tunnel.lab.local'),
    ('abc.example.com.', 'example.com'),
    ('example.com', 'example.com'),
    ('1.19.168.192.in-addr.arpa', None),
    ('localhost', None), (None, None)])
def test_parent_domain(query, expected):
    assert parent_domain(query) == expected


def test_dns_suffix_and_qtype_filters_exclude_gateway_noise(tunnel_lab):
    store, audit, trigger = tunnel_lab
    from agents.investigation_tools import LocalTools
    incident = audit.create(trigger['id'], {})['id']
    tools = LocalTools(store, audit, incident, trigger)
    unfiltered = tools.execute('search_zeek_dns', {'ip': VICTIM, 'limit': 20})
    assert all('in-addr.arpa' in i['dns']['query'] or 'ntp' in i['dns']['query'] for i in unfiltered['items'])
    filtered = tools.execute('search_zeek_dns', {'ip': VICTIM, 'domain_suffix': 'tunnel.lab.local', 'limit': 100})
    assert filtered['total_matched'] == 81
    assert all(i['dns']['query'].endswith('.tunnel.lab.local') for i in filtered['items'])
    nulls = tools.execute('search_zeek_dns', {'domain_suffix': 'tunnel.lab.local', 'qtype_name': 'null'})
    assert nulls['total_matched'] == 41
    # Suffix is label-boundary safe and not a LIKE pattern.
    assert tools.execute('search_zeek_dns', {'domain_suffix': 'lab.local_'})['status'] == 'empty'
    assert tools.execute('search_zeek_dns', {'domain_suffix': 'nnel.lab.local'})['status'] == 'empty'


def test_graph_collects_tunnel_evidence_before_model_plans(tunnel_lab):
    store, audit, trigger = tunnel_lab
    seen = {}

    def client(messages, **kwargs):
        incident = audit.current(trigger['id'])['id']
        if kwargs.get('schema'):
            refs = [e['evidence_id'] for e in audit.evidence(incident) if e['evidence_type'] == 'aggregate']
            return {'message': {'content': json.dumps({
                'incident_type': 'DNS tunneling', 'verdict': 'inconclusive', 'confidence': .5,
                'reasoning': 'Có nhiều subdomain khác nhau dưới tunnel.lab.local cần xác minh.',
                'findings': [{'statement': 'Có nhiều subdomain duy nhất dưới tunnel.lab.local.', 'evidence_ids': refs[:1]}],
                'hypotheses': [], 'unknowns': ['Chưa xác định tiến trình tạo query.'],
                'recommendations': ['Kiểm tra tiến trình trên máy nguồn.']})}, 'done_reason': 'stop'}
        seen.setdefault('tools', [t['function']['name'] for t in kwargs.get('tools') or []])
        seen.setdefault('context', json.loads(messages[1]['content']))
        return {'message': {'content': json.dumps({'hypotheses': [], 'need_more': False, 'question': ''})}}

    report = InvestigationGraph(store, audit, client=client).run_alert(trigger)

    automatic = [o for o in report['tool_outcomes'] if o.get('automatic')]
    assert [o['tool'] for o in automatic] == ['summarize_dns_activity', 'search_zeek_dns', 'compare_dns_baseline']
    summary = automatic[0]['dns_summary']
    assert summary['scope']['domain'] == 'tunnel.lab.local'
    assert summary['unique_subdomains'] == 81
    assert summary['query_types'] == {'NULL': 41, 'TXT': 40}
    # The model saw the profile and the tunnel evidence, not gateway noise.
    context = seen['context']
    assert context['alert_profile']['category'] == 'dns_tunneling'
    queries = [e['data'].get('dns', {}).get('query', '') for e in context['evidence']]
    assert queries and not any('in-addr.arpa' in q or 'ntp.ubuntu.com' in q for q in queries)
    assert any(e['kind'] == 'aggregate' for e in context['evidence'])
    # Collected tools remain available for a narrower or different scoped query.
    assert 'summarize_dns_activity' in seen['tools'] and 'search_auth_events' not in seen['tools']
    assert 'search_process_events' in seen['tools']
