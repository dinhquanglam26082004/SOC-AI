"""AI response planning: fixed catalog, evidence grounding, policy gate, approval and simulated execution.
Mocked model and temporary databases only; nothing touches a host."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from agents.response_planner import gate, plan_response, playbook_response_section, prepare_guidance, CATALOG
from agents.investigation_store import InvestigationStore
from api.app import create_app
from common.runtime_store import RuntimeStore
from wazuh_integration.mapper import map_wazuh_alert

AGENT = {'id': '001', 'name': 'ubuntu-agent', 'ip': '192.168.19.129'}


def dns_alert():
    raw = {'id': '1795080785.760073', 'timestamp': '2026-11-19T09:33:05Z', 'agent': AGENT,
           'manager': {'name': 'soc-manager'},
           'rule': {'id': '100181', 'level': 7, 'description': 'Zeek DNS: nhieu query NULL',
                    'groups': ['zeek', 'zeek_detection', 'zeek_dns_anomaly'],
                    'mitre': {'id': ['T1071.004']}},
           'location': '/opt/zeek/logs/current/dns.log', '_soc_stream': 'archives',
           'data': {'uid': 'C1', 'id': {'orig_h': '192.168.19.129', 'orig_p': '5000',
                                        'resp_h': '192.168.19.130', 'resp_p': '53'},
                    'query': 'vaaaakaswii.tunnel.lab.local', 'qtype_name': 'NULL'}}
    return map_wazuh_alert(raw)


def evidence_items():
    return [
        {'evidence_id': 'EV-agg', 'evidence_type': 'aggregate', 'tool': 'summarize_dns_activity',
         'source_record_id': 'aggregate-1', 'event_time': '2026-11-19T09:40:00Z',
         'data': {'dns_summary': {'scope': {'domain': 'tunnel.lab.local'}, 'unique_subdomains': 180,
                                  'query_types': {'NULL': 41, 'TXT': 27}}}},
        {'evidence_id': 'EV-fim', 'evidence_type': 'observed', 'tool': 'search_file_changes',
         'source_record_id': 'r2', 'event_time': '2026-11-19T09:30:00Z',
         'data': {'file_path': '/etc/systemd/system/net-helper.service', 'file_change': {'event': 'added'}}},
        {'evidence_id': 'EV-guide', 'evidence_type': 'guidance', 'tool': 'search_runbook',
         'source_record_id': 'kb', 'event_time': None, 'data': {'text': 'block evil.example'}},
    ]


def draft(action, target, refs=('EV-agg',), reason='Lý do kiểm thử.', guidance=('G1',)):
    return {'action': action, 'target': target, 'reason': reason, 'evidence_ids': list(refs), 'guidance_ids': list(guidance)}


def playbook():
    return {'status':'matched', 'playbook_id':'PB-TEST', 'playbook_name':'DNS tunneling response', 'playbook_source':'test.txt',
            'playbook_text':'PLAYBOOK ID: PB-TEST\nDNS tunneling\n\nRESPONSE:\n1. Preserve evidence.\n2. Filter the domain.\n3. Disable the service.\n4. Stop the process.\n\nESCALATION:\nReview.\n'}


def by_target(actions):
    return {(a['action'], a['target']): a for a in actions}


def test_catalog_fills_risk_command_and_rollback_not_the_model():
    out = gate([draft('block_domain', 'tunnel.lab.local')], verdict='malicious',
               evidence=evidence_items(), alert=dns_alert())
    a = out[0]
    assert a['status'] == 'proposed' and a['impact'] == 'low' and a['mitigation'] == 'M1037'
    assert 'tunnel.lab.local' in a['command'] and 'tunnel.lab.local' in a['rollback']
    assert a['requires_approval'] is True


def test_policy_rejects_ungrounded_targets_unknown_evidence_and_guidance_citations():
    alert = dns_alert()
    out = by_target(gate([
        draft('block_domain', 'evil.example', refs=['EV-guide']),         # only guidance cites it
        draft('block_ip', '203.0.113.9'),                                   # appears nowhere
        draft('block_domain', 'tunnel.lab.local', refs=['EV-fabricated']),  # invented evidence id
        draft('disable_service', '/etc/systemd/system/net-helper.service', refs=['EV-fim']),
    ], verdict='malicious', evidence=evidence_items(), alert=alert))
    assert out[('block_domain', 'evil.example')]['status'] == 'rejected'
    assert out[('block_ip', '203.0.113.9')]['status'] == 'rejected'
    fabricated = out[('block_domain', 'tunnel.lab.local')]
    assert fabricated['status'] == 'rejected' and any('evidence_id' in r for r in fabricated['policy_reasons'])
    assert out[('disable_service', '/etc/systemd/system/net-helper.service')]['status'] == 'proposed'


def test_disruptive_actions_need_malicious_verdict_low_impact_allowed():
    actions = [draft('block_domain', 'tunnel.lab.local'), draft('isolate_host', '001'),
               draft('collect_forensics', 'ubuntu-agent', refs=[])]
    out = by_target(gate(actions, verdict='inconclusive', evidence=evidence_items(), alert=dns_alert()))
    assert out[('block_domain', 'tunnel.lab.local')]['status'] == 'proposed'
    assert out[('collect_forensics', 'ubuntu-agent')]['status'] == 'proposed'
    assert out[('isolate_host', '001')]['status'] == 'rejected'
    out = by_target(gate(actions, verdict='malicious', evidence=evidence_items(), alert=dns_alert()))
    assert out[('isolate_host', '001')]['status'] == 'proposed'


def test_host_must_be_the_alert_agent_and_protected_targets_are_refused(monkeypatch):
    monkeypatch.setenv('RESPONSE_PROTECTED_TARGETS', '192.168.19.130')
    out = by_target(gate([draft('isolate_host', 'other-host'), draft('block_ip', '192.168.19.130'),
                          draft('block_ip', '127.0.0.1'), draft('isolate_host', '192.168.19.129')],
                         verdict='malicious', evidence=evidence_items(), alert=dns_alert()))
    assert out[('isolate_host', 'other-host')]['status'] == 'rejected'
    assert out[('block_ip', '192.168.19.130')]['status'] == 'rejected'
    assert out[('block_ip', '127.0.0.1')]['status'] == 'rejected'
    assert out[('isolate_host', '192.168.19.129')]['status'] == 'proposed'


def test_duplicates_removed_and_order_follows_ir_phases():
    out = gate([draft('isolate_host', '001'), draft('block_domain', 'tunnel.lab.local'),
                draft('block_domain', 'TUNNEL.lab.local'), draft('collect_forensics', '001', refs=[]),
                draft('disable_service', '/etc/systemd/system/net-helper.service', refs=['EV-fim'])],
               verdict='malicious', evidence=evidence_items(), alert=dns_alert())
    assert [a['phase'] for a in out] == ['preservation', 'containment', 'containment', 'eradication']
    assert sum(a['action'] == 'block_domain' for a in out) == 1


def test_playbook_response_section_is_extracted():
    text = 'PLAYBOOK ID: X\n\nNAME:\nN\n\nRESPONSE:\n1. Block the domain.\n\nESCALATION:\nCall lead.\n'
    assert playbook_response_section(text) == '1. Block the domain.'
    assert playbook_response_section(None) == ''


def test_missing_or_invalid_playbook_does_not_call_model():
    client=fake_client(good_plan())
    with pytest.raises(ValueError,match='playbook'):
        plan_response(alert=dns_alert(),report={},verdict='malicious',evidence=evidence_items(),client=client)
    assert not client.calls
    with pytest.raises(ValueError,match='RESPONSE'):
        prepare_guidance({**playbook(),'playbook_text':'Only investigation guidance.'})


def test_actual_dns_playbook_keeps_response_and_escalation_provenance():
    text=(Path(__file__).resolve().parents[1]/'rag/documents/playbooks/PB-EXT-DNS-TUNNELING.txt').read_text(encoding='utf-8')
    source={**playbook(),'playbook_id':'PB-EXT-DNS-TUNNELING',
            'playbook_source':'PB-EXT-DNS-TUNNELING.txt','playbook_text':text}
    guidance=prepare_guidance(source)
    assert guidance['playbook_id']=='PB-EXT-DNS-TUNNELING' and len(guidance['sha256'])==64
    assert any(p['section']=='RESPONSE' and 'M1037' in p['text'] for p in guidance['passages'])
    assert any(p['section']=='ESCALATION' and 'Preserve' in p['text'] for p in guidance['passages'])


def test_unknown_or_missing_guidance_is_rejected_even_with_valid_evidence():
    payload=json.dumps({'summary':'Kiểm tra.', 'actions':[
        draft('block_domain','tunnel.lab.local',guidance=[]),
        draft('disable_service','/etc/systemd/system/net-helper.service',refs=['EV-fim'],guidance=['fake'])]})
    plan=plan_response(alert=dns_alert(),report={},verdict='malicious',evidence=evidence_items(),
                       playbook=playbook(),client=fake_client(payload))
    assert all(a['status']=='rejected' and 'playbook' in a['policy_reasons'][-1] for a in plan['actions'])
    assert all(not a['guidance_ids'] for a in plan['actions'])


def test_unrelated_but_existing_guidance_is_not_accepted_for_action():
    payload=json.dumps({'summary':'Kiểm tra.', 'actions':[
        draft('collect_forensics','001',refs=[],guidance=['G2']),
        draft('block_domain','tunnel.lab.local',guidance=['G2'])]})
    plan=plan_response(alert=dns_alert(),report={},verdict='malicious',evidence=evidence_items(),
                       playbook=playbook(),client=fake_client(payload))
    actions=by_target(plan['actions'])
    assert actions[('collect_forensics','001')]['status']=='rejected'
    assert 'chưa thể hiện rõ loại hành động' in actions[('collect_forensics','001')]['policy_reasons'][-1]
    assert actions[('block_domain','tunnel.lab.local')]['status']=='proposed'


def test_model_gets_one_repair_for_unrelated_guidance():
    wrong=json.dumps({'summary':'Kiểm tra.', 'actions':[draft('collect_forensics','001',refs=[],guidance=['G2'])]})
    fixed=json.dumps({'summary':'Kiểm tra.', 'actions':[draft('collect_forensics','001',refs=[],guidance=['G1'])]})
    client=fake_client(wrong,fixed)
    plan=plan_response(alert=dns_alert(),report={},verdict='inconclusive',evidence=evidence_items(),
                       playbook=playbook(),client=client)
    assert len(client.calls)==2 and plan['actions'][0]['status']=='proposed'
    assert plan['actions'][0]['guidance_ids']==['G1']
    assert 'chưa thể hiện rõ loại hành động' in client.calls[1][0][-1]['content']


def fake_client(*payloads):
    calls = []

    def client(messages, **kwargs):
        calls.append((messages, kwargs))
        return {'message': {'content': payloads[min(len(calls) - 1, len(payloads) - 1)]}, 'done_reason': 'stop'}
    client.calls = calls
    return client


def good_plan():
    return json.dumps({'summary': 'Chặn domain tunnel và gỡ persistence.', 'actions': [
        draft('collect_forensics', '001', refs=[]),
        draft('block_domain', 'tunnel.lab.local',guidance=['G2']),
        draft('disable_service', '/etc/systemd/system/net-helper.service', refs=['EV-fim'],guidance=['G3']),
        draft('kill_process', 'iodine',guidance=['G4']),  # not in evidence -> rejected by the gate
    ]})


def test_plan_response_uses_schema_catalog_and_repairs_invalid_json_once():
    bad = json.dumps({'summary': 'x', 'actions': [draft('analyze_dns_query_patterns', 'x')]})  # hallucinated tool
    client = fake_client(bad, good_plan())
    plan = plan_response(alert=dns_alert(), report={'verdict': 'malicious', 'findings': []}, verdict='malicious',
                         evidence=evidence_items(), playbook=playbook(), client=client)
    assert len(client.calls) == 2
    context = json.loads(client.calls[0][0][1]['content'])
    assert {a['action'] for a in context['allowed_actions']} == set(CATALOG)
    assert context['knowledge_guidance']['playbook_id'] == 'PB-TEST'
    assert context['knowledge_guidance']['passages'][0]['text'] == '1. Preserve evidence.'
    assert plan['knowledge_guidance']['source'] == 'test.txt'
    assert {a['action']:a['guidance_ids'] for a in plan['actions']} == {
        'collect_forensics':['G1'],'block_domain':['G2'],'disable_service':['G3'],'kill_process':['G4']}
    assert client.calls[0][1]['schema']['properties']['actions']
    statuses = {a['action']: a['status'] for a in plan['actions']}
    assert statuses == {'collect_forensics': 'proposed', 'block_domain': 'proposed',
                        'disable_service': 'proposed', 'kill_process': 'rejected'}


def test_plan_response_fails_closed_after_repair():
    bad = json.dumps({'summary': 'x', 'actions': [draft('rm_rf_everything', '/')]})
    with pytest.raises(ValueError):
        plan_response(alert=dns_alert(), report={}, verdict='malicious', evidence=evidence_items(),
                      playbook=playbook(), client=fake_client(bad, bad))


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv('WAZUH_WEBHOOK_TOKEN', 'test-only')
    monkeypatch.delenv('RESPONSE_EXECUTION_MODE', raising=False)
    app = create_app(str(tmp_path / 'runtime.sqlite3'), workers=False)
    with TestClient(app) as client:
        alert = dns_alert()
        app.state.store.accept(alert, False)
        audit = app.state.investigation_store
        incident = audit.create(alert['id'], {})['id']
        for item in evidence_items():
            audit.add_evidence(incident, item['source_record_id'], item['evidence_type'], item['data'], item['tool'], {})
        ids = [e['evidence_id'] for e in audit.evidence(incident)]
        agg = next(e['evidence_id'] for e in audit.evidence(incident) if e['evidence_type'] == 'aggregate')
        fim = next(e['evidence_id'] for e in audit.evidence(incident) if e['tool'] == 'search_file_changes')
        report = {'verdict': 'malicious', 'incident_type': 'DNS Tunneling', 'reasoning': 'r', 'findings': []}
        audit.update(incident, {'node': 'completed', 'verdict': 'malicious'}, 'completed', report)
        saved = app.state.store.get(alert['id'])
        saved['investigation_report'] = {**report, 'incident_id': incident}
        saved['playbook_proposal'] = playbook()
        with app.state.store.connect() as db:
            db.execute('UPDATE events SET payload=? WHERE id=?', (json.dumps(saved), alert['id']))
        plan = json.dumps({'summary': 'Kế hoạch.', 'actions': [
            draft('block_domain', 'tunnel.lab.local', refs=[agg],guidance=['G2']),
            draft('disable_service', '/etc/systemd/system/net-helper.service', refs=[fim],guidance=['G3']),
            draft('kill_process', 'iodine', refs=[agg],guidance=['G4'])]})
        app.state.response_client = fake_client(plan)
        yield client, app, alert, incident, ids


def test_api_plan_approve_and_simulated_execution(api):
    client, app, alert, incident, _ = api
    origin = {'Origin': 'http://localhost:8100'}
    response = client.post(f"/api/alerts/{alert['id']}/response/plan", headers=origin)
    assert response.status_code == 201, response.text
    plan = response.json()
    assert plan['incident_id'] == incident and plan['status'] == 'proposed'
    status = {a['action']: (a['id'], a['status']) for a in plan['actions']}
    assert status['kill_process'][1] == 'rejected'
    assert client.get(f"/api/alerts/{alert['id']}/response/plan").json()['id'] == plan['id']
    # Nothing approved yet -> nothing executes.
    assert client.post('/api/response/execute', json={'plan_id': plan['id']}, headers=origin).status_code == 409
    # A policy-rejected action cannot be approved.
    bad = client.post(f"/api/response/plans/{plan['id']}/decision", headers=origin,
                      json={'approve': [status['kill_process'][0]]})
    assert bad.status_code == 409
    ok = client.post(f"/api/response/plans/{plan['id']}/decision", headers=origin,
                     json={'approve': [status['block_domain'][0]], 'decline': [status['disable_service'][0]]})
    assert ok.status_code == 200 and ok.json()['status'] == 'reviewed'
    executed = client.post('/api/response/execute', json={'plan_id': plan['id']}, headers=origin).json()
    assert [r['action'] for r in executed['executed']] == ['block_domain']
    assert executed['executed'][0]['status'] == 'simulated' and executed['executed'][0]['mode'] == 'simulate'
    after = {a['action']: a['status'] for a in executed['plan']['actions']}
    assert after == {'block_domain': 'simulated', 'disable_service': 'declined', 'kill_process': 'rejected'}
    history = client.get('/api/response/history').json()['history']
    assert [h['target'] for h in history] == ['tunnel.lab.local']
    assert history[0]['knowledge_guidance']['playbook_id']=='PB-TEST'
    assert history[0]['guidance_ids']==['G2'] and history[0]['knowledge_guidance']['passages'][0]['id']=='G2'
    assert RuntimeStore(app.state.store.path).load()['responses'][0]['approved_by'] == 'local-analyst'
    # A plan executes once.
    assert client.post('/api/response/execute', json={'plan_id': plan['id']}, headers=origin).status_code == 409


def test_api_refuses_live_mode_benign_verdict_and_missing_investigation(api, monkeypatch):
    client, app, alert, incident, ids = api
    origin = {'Origin': 'http://localhost:8100'}
    plan = client.post(f"/api/alerts/{alert['id']}/response/plan", headers=origin).json()
    first = next(a['id'] for a in plan['actions'] if a['status'] == 'proposed')
    client.post(f"/api/response/plans/{plan['id']}/decision", headers=origin, json={'approve': [first]})
    monkeypatch.setenv('RESPONSE_EXECUTION_MODE', 'live')
    assert client.post('/api/response/execute', json={'plan_id': plan['id']}, headers=origin).status_code == 501
    assert client.get('/api/response/history').json()['history'] == []
    # Analyst review overrides the model verdict: benign -> no plan.
    app.state.investigation_store.review(incident, 'benign', 'Hoạt động đã được xác nhận là kiểm thử nội bộ.', ids[:1])
    assert client.post(f"/api/alerts/{alert['id']}/response/plan", headers=origin).status_code == 409
    assert client.post('/api/alerts/WAZUH-unknown/response/plan', headers=origin).status_code == 404


def test_old_plan_without_guidance_cannot_be_approved_or_executed(api):
    client, app, alert, incident, _ = api
    origin={'Origin':'http://localhost:8100'}
    old=app.state.response_store.create(alert['id'],incident,{'actions':[
        {'id':'A1','action':'block_ip','target':'192.0.2.7','status':'approved'}]})
    decision=client.post(f"/api/response/plans/{old['id']}/decision",headers=origin,json={'approve':['A1']})
    assert decision.status_code==409 and 'playbook' in decision.text
    execution=client.post('/api/response/execute',headers=origin,json={'plan_id':old['id']})
    assert execution.status_code==409 and 'playbook' in execution.text


def test_plan_refuses_mismatched_investigation_source(api):
    client, app, alert, _, _ = api
    saved=app.state.store.get(alert['id'])
    saved['investigation_report']['incident_id']='INV-other'
    with app.state.store.connect() as db:
        db.execute('UPDATE events SET payload=? WHERE id=?', (json.dumps(saved), alert['id']))
    response=client.post(f"/api/alerts/{alert['id']}/response/plan",headers={'Origin':'http://localhost:8100'})
    assert response.status_code==409 and 'lượt điều tra hiện tại' in response.text
    assert not app.state.response_client.calls


def test_response_retrieves_relevant_playbook_when_existing_match_is_unrelated(api):
    client, app, alert, _, _ = api
    saved=app.state.store.get(alert['id'])
    saved['playbook_proposal']={**playbook(),'playbook_name':'SSH brute force','playbook_text':'SSH brute force\nRESPONSE:\n1. Review SSH.'}
    with app.state.store.connect() as db:
        db.execute('UPDATE events SET payload=? WHERE id=?', (json.dumps(saved), alert['id']))
    with patch('agents.playbook_agent.propose_playbook',return_value=playbook()) as retrieve:
        response=client.post(f"/api/alerts/{alert['id']}/response/plan",headers={'Origin':'http://localhost:8100'})
    assert response.status_code==201, response.text
    assert response.json()['knowledge_guidance']['title']=='DNS tunneling response'
    assert retrieve.call_args.kwargs['allow_inconclusive'] is True


def test_response_reports_unavailable_knowledge_without_calling_model(api):
    client, app, alert, _, _ = api
    saved=app.state.store.get(alert['id']);saved['playbook_proposal']={'status':'not_found'}
    with app.state.store.connect() as db:
        db.execute('UPDATE events SET payload=? WHERE id=?', (json.dumps(saved), alert['id']))
    with patch('agents.playbook_agent.propose_playbook',return_value={'status':'not_found'}):
        response=client.post(f"/api/alerts/{alert['id']}/response/plan",headers={'Origin':'http://localhost:8100'})
    assert response.status_code==409 and 'playbook' in response.text.lower()
    assert not app.state.response_client.calls
