"""Mocked model, synthetic events, temporary DBs only; no production ingestion/model calls."""
from copy import deepcopy
import json
import sqlite3
import time
from unittest.mock import Mock, patch

import pytest
from fastapi.testclient import TestClient
from agents.investigation_graph import InvestigationGraph, report_language_errors
from agents.investigation_schema import Limits, WorkflowError
from agents.investigation_store import InvestigationStore
from agents.investigation_tools import LocalTools, MODELS
from api.app import create_app, analyze
from common.event_store import EventStore
from wazuh_integration.mapper import map_wazuh_alert


def test_activity_includes_only_compact_cited_evidence_for_that_investigation(tmp_path):
    audit = InvestigationStore(tmp_path / 'audit.sqlite3')
    run = audit.create('alert-1', {})['id']
    other = audit.create('alert-2', {})['id']
    payload = {'event_time': '2026-11-17T01:00:00Z', 'src_ip': '192.0.2.1',
               'dns': {'query': 'example.test'}, 'full_log': 'do-not-copy-full-log'}
    ref = audit.add_evidence(run, 'event-1', 'observed', payload, 'search_zeek_dns', {})
    ignored = audit.add_evidence(run, 'event-2', 'observed', payload, 'search_zeek_dns', {})
    foreign = audit.add_evidence(other, 'event-3', 'observed', payload, 'search_zeek_dns', {})
    audit.update(run, {}, status='completed', report={'findings': [
        {'statement': 'DNS observation', 'evidence_ids': [ref, foreign]}]})
    result = audit.detail(run, 'activity', limit=1)
    assert result['evidence_total'] == 2
    assert [item['evidence_id'] for item in result['finding_evidence']] == [ref]
    assert result['finding_evidence'][0]['data']['dns']['query'] == 'example.test'
    assert 'full_log' not in result['finding_evidence'][0]['data']
    assert ignored not in json.dumps(result['finding_evidence'])


@pytest.fixture
def lab(tmp_path,monkeypatch):
    monkeypatch.setenv('WAZUH_WEBHOOK_TOKEN','test-only')
    monkeypatch.setenv('AI_WORKFLOW','langgraph')
    monkeypatch.setenv('AI_GRAPH_PROGRESS_MODE','false')
    store=EventStore(tmp_path/'logs.db')
    audit=InvestigationStore(tmp_path/'soc_investigations.sqlite3')
    def event(number,groups=None,agent='007',minute='00'):
        raw={'id':str(number),'timestamp':f'2026-10-25T01:{minute}:00Z',
            'agent':{'id':agent,'name':'test-agent','ip':'192.0.2.7'},'manager':{'name':'lab'},
            'rule':{'id':'5710','level':8,'description':'Authentication failed','groups':groups or ['authentication_failed']},
            'data':{'srcip':'198.51.100.8','srcuser':'lab-user'}}
        record=map_wazuh_alert(raw)
        store.accept(record,False)
        return record
    trigger=event(1)
    event(2,['authentication_success'])
    event(3,agent='other')
    event(4,minute='30')
    return store,audit,trigger,event


def report(audit,incident,verdict='inconclusive',bad=False):
    refs=[e['evidence_id'] for e in audit.evidence(incident)]
    return {'incident_type':'Authentication anomaly','verdict':verdict,'confidence':.5,
        'reasoning':'Sự kiện xác thực cần được chuyên viên xác minh.',
        'findings':[{'statement':'Đã ghi nhận một sự kiện xác thực.','evidence_ids':['EV-fabricated'] if bad else refs}],
        'hypotheses':[],'unknowns':['Chưa xác minh quyền truy cập và mục đích.'],
        'recommendations':['Xác minh quyền truy cập với người quản lý tài sản.']}


def client_for(audit,trigger,tools=True,verdict='inconclusive'):
    def client(messages,**kwargs):
        incident=audit.current(trigger['id'])['id']
        if kwargs.get('schema'):
            return {'message':{'content':json.dumps(report(audit,incident,verdict))},'done_reason':'stop'}
        return {'message':{'content':'Check both success and failure.', 'tool_calls':[
            {'function':{'name':'search_auth_events','arguments':{}}}]} if tools else {'content':'Insufficient evidence.'}}
    return client


def test_tools_scope_success_failure_empty_and_limit(lab):
    store,audit,trigger,_=lab
    incident=audit.create(trigger['id'],Limits().model_dump())['id']
    tools=LocalTools(store,audit,incident,trigger)
    result=tools.execute('search_auth_events',{})
    assert result['status']=='ok' and len(result['items'])==2
    assert {r['rule']['groups'][0] for r in result['items']}=={'authentication_failed','authentication_success'}
    for args in ({'agent_id':'other'},{'ip':'203.0.113.9'},{'since':'2026-10-24T00:00:00Z'},
                 {'limit':101},{'limit':'50'},{'sql':'DELETE FROM events'}):
        assert tools.execute('search_auth_events',args)['status']=='error'
    assert tools.execute('shell',{'command':'whoami'})['status']=='error'
    assert tools.execute('get_alert',{'alert_id':'other'})['status']=='error'
    assert tools.execute('search_zeek_connections',{})['status']=='empty'
    assert tools.execute('search_auth_events',{'limit':1})['status']=='truncated'
    evidence=audit.evidence(incident)
    assert len([e for e in evidence if e['evidence_type']!='aggregate'])==2
    aggregates=[e for e in evidence if e['evidence_type']=='aggregate' and 'authentication_summary' in e['data']]
    assert len(aggregates)==1  # A different page limit does not create a second aggregate.
    assert aggregates[0]['data']['authentication_summary']['scope']['agent_id']==trigger['agent']['id']


def test_runbook_is_guidance_unavailable_and_timeout(lab):
    store,audit,trigger,_=lab
    incident=audit.create(trigger['id'],Limits().model_dump())['id']
    tools=LocalTools(store,audit,incident,trigger,retrieve=lambda q:{'documents':['Check authorization'],
        'ids':['runbook-1'],'metadatas':[{'source':'local-playbook'}]})
    assert tools.execute('search_runbook',{'query':'SSH'})['guidance_only']
    assert audit.evidence(incident)[0]['evidence_type']=='guidance'
    tools.retrieve=lambda q:{'error':'offline'}
    assert tools.execute('search_runbook',{'query':'SSH'})['status']=='unavailable'
    tools.retrieve=lambda q:time.sleep(.05) or {'documents':[]}
    assert tools.execute('search_runbook',{'query':'SSH'},timeout=.001)['error']=='retrieval_timeout'
    time.sleep(.06)


def test_graph_bounded_persisted_and_cached(lab):
    store,audit,trigger,_=lab
    client=Mock(side_effect=client_for(audit,trigger))
    graph=InvestigationGraph(store,audit,client=client)
    result=graph.run_alert(trigger)
    run=audit.current(trigger['id'])
    assert result['workflow']=='langgraph' and result['verdict']=='inconclusive'
    assert audit.counts(run['id'])=={'model':3,'tool':2}
    assert len(audit.evidence(run['id']))==3  # Two source records and one derived aggregate.
    assert run['status']=='completed'
    assert all(call.kwargs['timeout']<=900 for call in client.call_args_list)
    assert any(m['role']=='tool' for m in client.call_args_list[1].args[0])
    before=client.call_count
    assert graph.run_alert(trigger)==result and client.call_count==before
    detail=audit.detail(run['id'],limit=1)
    assert len(detail['items'])==1 and detail['next_offset']==1 and detail['total']==3
    with sqlite3.connect(graph.checkpoint_path) as db:
        assert db.execute('SELECT COUNT(*) FROM checkpoints').fetchone()[0]>0


def test_manual_reinvestigation_of_completed_alert_keeps_prior_dossier(lab):
    store,audit,trigger,_=lab
    first=InvestigationGraph(store,audit,client=client_for(audit,trigger,False)).run_alert(trigger)
    old_id=first['incident_id']
    old_evidence=audit.evidence(old_id)
    assert store.retry(trigger['id'])
    running=store.claim()
    running['investigation_report']=first
    assert store.finish(running)
    assert store.get(trigger['id'])['ai_status']=='completed'
    assert store.retry(trigger['id'])
    assert not store.retry(trigger['id'])
    rerun=store.claim()
    assert rerun['ai_manual_request'] and rerun['ai_status']=='running'
    second=InvestigationGraph(store,audit,client=client_for(audit,trigger,False)).run_alert(
        rerun,force_new=True)
    assert second['incident_id']!=old_id
    assert audit.current(trigger['id'])['id']==second['incident_id']
    assert audit.detail(old_id)['id']==old_id
    assert audit.evidence(old_id)==old_evidence
    assert {e['evidence_id'] for e in audit.evidence(old_id)}=={
        e['evidence_id'] for e in audit.evidence(second['incident_id'])}
    rerun['investigation_report']=second
    assert store.finish(rerun)


def test_model_selects_tools_without_static_recommendations(lab, monkeypatch):
    # Mechanics test for the unrouted tool set; routing is covered in test_investigation_profiles.py.
    monkeypatch.setenv("AI_TOOL_ROUTING", "false")
    store,audit,trigger,_=lab
    trigger['source_product']='zeek'
    trigger['rule']['groups']=['zeek_detection']
    available=[]
    first_context={}

    def client(messages,**kwargs):
        if kwargs.get('schema'):
            return {'message':{'content':json.dumps(report(audit,audit.current(trigger['id'])['id']))}}
        if not first_context:
            first_context.update(json.loads(messages[1]['content']))
        available.extend(tool['function']['name'] for tool in kwargs['tools'])
        return {'message':{'content':'','tool_calls':[
            {'function':{'name':'search_zeek_connections','arguments':{}}}]}}

    result=InvestigationGraph(store,audit,client=client).run_alert(trigger)
    assert set(available)==set(MODELS)-{'get_alert'}
    assert 'recommended_tools' not in first_context
    tool_calls=audit.detail(result['incident_id'],'tools',limit=20)['items']
    selected=[call for call in tool_calls if call['name']=='search_zeek_connections']
    assert selected and selected[0]['result'].get('error') != 'tool_not_allowed'


def test_tool_plan_executes_batch_before_model_reviews_results(lab):
    store,audit,trigger,_=lab
    planner_messages=[]

    def client(messages,**kwargs):
        if kwargs.get('schema'):
            return {'message':{'content':json.dumps(report(audit,audit.current(trigger['id'])['id']))}}
        planner_messages.append(deepcopy(messages))
        if len(planner_messages)==1:
            return {'message':{'content':'','tool_calls':[
                {'function':{'name':'search_auth_events','arguments':{}}},
                {'function':{'name':'not_a_tool','arguments':{}}},
                {'function':{'name':'search_related_alerts','arguments':{}}},
            ]}}
        return {'message':{'content':'No further tools are needed.'}}

    result=InvestigationGraph(store,audit,client=client).run_alert(trigger)
    assert result['workflow']=='langgraph'
    assert len(planner_messages)==2
    returned=[m for m in planner_messages[1] if m['role']=='tool']
    assert [m['tool_name'] for m in returned]==['search_auth_events','not_a_tool','search_related_alerts']
    assert json.loads(returned[1]['content'])['status']=='error'
    assert json.loads(returned[2]['content'])['status'] in {'ok','empty','truncated'}


def test_tool_can_run_again_with_new_arguments(lab, monkeypatch):
    # Mechanics test for the unrouted tool set; routing is covered in test_investigation_profiles.py.
    monkeypatch.setenv("AI_TOOL_ROUTING", "false")
    store,audit,trigger,event=lab
    plans=[]

    def client(messages,**kwargs):
        incident=audit.current(trigger['id'])['id']
        if kwargs.get('schema'):
            return {'message':{'content':json.dumps(report(audit,incident))}}
        plans.append((deepcopy(messages),{tool['function']['name'] for tool in kwargs['tools']}))
        if len(plans)==1:
            calls=[('search_auth_events',{'limit':1}),('search_auth_events',{'limit':2}),
                   ('search_related_alerts',{})]
        elif len(plans)==2:
            calls=[('search_auth_events',{'limit':10}),('search_zeek_dns',{})]
        else:
            calls=[]
        return {'message':{'content':'','tool_calls':[{'function':{'name':name,'arguments':args}} for name,args in calls]}}

    result=InvestigationGraph(store,audit,client=client,limits=Limits(progress_mode=True)).run_alert(trigger)
    calls=audit.detail(result['incident_id'],'tools',limit=100)['items']
    assert [c['name'] for c in calls].count('search_auth_events')==3
    assert [c['name'] for c in calls].count('search_related_alerts')==1
    assert [c['name'] for c in calls].count('search_zeek_dns')==1
    assert 'search_auth_events' in plans[0][1]
    assert 'search_auth_events' in plans[1][1]
    assert 'search_related_alerts' in plans[1][1]
    assert 'search_zeek_dns' in plans[1][1]
    skipped=[o for o in result['tool_outcomes'] if o.get('call_disposition')=='blocked']
    assert not skipped
    first_results=[json.loads(m['content']) for m in plans[1][0] if m['role']=='tool']
    assert all(item['call_disposition']=='executed' for item in first_results)

    other=event(5)
    result2=InvestigationGraph(store,audit,client=client_for(audit,other),
                               limits=Limits(rounds=1,model_calls=3)).run_alert(other)
    other_calls=audit.detail(result2['incident_id'],'tools',limit=20)['items']
    assert [c['name'] for c in other_calls].count('search_auth_events')==1


def test_equivalent_defaults_reuse_query_without_duplicate_evidence(lab):
    store,audit,trigger,_=lab
    plans=[]
    def client(messages,**kwargs):
        incident=audit.current(trigger['id'])['id']
        if kwargs.get('schema'):
            return {'message':{'content':json.dumps(report(audit,incident))}}
        plans.append(messages)
        if len(plans)==1:
            calls=[{}, {'limit':20,'agent_id':trigger['agent']['id'],
                        'since':'2026-10-25T00:45:00+00:00','until':'2026-10-25T01:15:00Z'}]
            return {'message':{'content':'','tool_calls':[{'function':{'name':'search_auth_events','arguments':a}} for a in calls]}}
        return {'message':{'content':'{"hypotheses":[],"need_more":false,"question":""}'}}
    result=InvestigationGraph(store,audit,client=client,limits=Limits(progress_mode=True)).run_alert(trigger)
    calls=[c for c in audit.detail(result['incident_id'],'tools',limit=100)['items'] if c['name']=='search_auth_events']
    assert len(calls)==1
    outcomes=[o for o in result['tool_outcomes'] if o['tool']=='search_auth_events']
    assert [o['call_disposition'] for o in outcomes]==['executed','cached']
    assert outcomes[1]['call_reason']=='equivalent_query'
    assert len([e for e in audit.evidence(result['incident_id']) if e['evidence_type']=='observed'])==1


def test_event_details_accepts_multiple_evidence_ids(lab):
    store,audit,trigger,event=lab
    event(6,minute='01')
    calls=[]
    def client(messages,**kwargs):
        incident=audit.current(trigger['id'])['id']
        if kwargs.get('schema'):
            return {'message':{'content':json.dumps(report(audit,incident))}}
        calls.append(1)
        if len(calls)==1:
            return {'message':{'content':'','tool_calls':[{'function':{'name':'search_auth_events','arguments':{}}}]}}
        if len(calls)==2:
            ids=[e['evidence_id'] for e in audit.evidence(incident) if e['evidence_type']=='observed']
            return {'message':{'content':'','tool_calls':[{'function':{'name':'get_event_details','arguments':{'evidence_id':i}}} for i in ids]}}
        return {'message':{'content':'{"hypotheses":[],"need_more":false,"question":""}'}}
    result=InvestigationGraph(store,audit,client=client,limits=Limits(progress_mode=True)).run_alert(trigger)
    details=[c for c in audit.detail(result['incident_id'],'tools',limit=100)['items'] if c['name']=='get_event_details']
    assert len(details)==2
    assert len({c['args']['evidence_id'] for c in details})==2
    assert all(c['result']['call_disposition']=='executed' for c in details)


def test_failed_tool_attempt_can_be_corrected(lab):
    store,audit,trigger,_=lab
    available=[]
    def client(messages,**kwargs):
        incident=audit.current(trigger['id'])['id']
        if kwargs.get('schema'):
            return {'message':{'content':json.dumps(report(audit,incident))}}
        available.append({tool['function']['name'] for tool in kwargs['tools']})
        args={'agent_id':'wrong-agent'} if len(available)==1 else {}
        return {'message':{'content':'','tool_calls':[{'function':{'name':'search_auth_events','arguments':args}}]}}
    result=InvestigationGraph(store,audit,client=client,limits=Limits(progress_mode=True)).run_alert(trigger)
    calls=audit.detail(result['incident_id'],'tools',limit=20)['items']
    auth=[c for c in calls if c['name']=='search_auth_events']
    assert len(auth)==2 and auth[0]['result']['error']=='invalid_scope_or_arguments'
    assert 'search_auth_events' in available[0] and 'search_auth_events' in available[1]
    assert any(o.get('call_disposition')=='executed' for o in result['tool_outcomes'] if o['tool']=='search_auth_events')


def test_system_called_dos_tool_remains_available_for_a_new_scope(lab):
    store,audit,trigger,_=lab
    trigger=deepcopy(trigger)
    trigger['rule']={'id':'100142','level':10,'description':'DoS traffic','groups':['zeek_detection']}
    trigger.update(source_product='zeek',event_kind='alert',src_ip='198.51.100.8',
                   dst_ip='192.0.2.7',dst_port='80')
    available=[]
    def client(messages,**kwargs):
        incident=audit.current(trigger['id'])['id']
        if kwargs.get('schema'):
            return {'message':{'content':json.dumps(report(audit,incident))}}
        available.append({tool['function']['name'] for tool in kwargs['tools']})
        calls=[{'function':{'name':'summarize_zeek_flows','arguments':{}}}] if len(available)==1 else []
        return {'message':{'content':'','tool_calls':calls}}
    result=InvestigationGraph(store,audit,client=client,limits=Limits(progress_mode=True)).run_alert(trigger)
    calls=audit.detail(result['incident_id'],'tools',limit=20)['items']
    assert [c['name'] for c in calls].count('summarize_zeek_flows')==2
    assert 'summarize_zeek_flows' in available[0]
    assert any(o['tool']=='summarize_zeek_flows' and o.get('error')=='invalid_scope_or_arguments'
               for o in result['tool_outcomes'])


def test_model_tool_explanation_is_recorded_but_not_sent_to_tool(lab):
    store,audit,trigger,_=lab
    requests=[]
    def client(messages,**kwargs):
        if kwargs.get('schema'):
            return {'message':{'content':json.dumps(report(audit,audit.current(trigger['id'])['id']))}}
        requests.append(messages)
        if len(requests)==1:
            return {'message':{'content':'','tool_calls':[{'function':{'name':'search_auth_events',
                'arguments':{'limit':10,'_verification_question':'Có đăng nhập thất bại không?',
                             '_selection_reason':'Cảnh báo liên quan xác thực.'}}}]}}
        return {'message':{'content':'No further tools.'}}
    result=InvestigationGraph(store,audit,client=client).run_alert(trigger)
    activity=audit.detail(result['incident_id'],'activity',limit=100)['items']
    tool=next(item for item in activity if item['kind']=='tool' and item['name']=='search_auth_events')
    assert tool['query']['limit']==10 and tool['query']['agent_id']==trigger['agent']['id']
    assert tool['outcome']=='ok'
    assert tool['model_explanation']=={'question':'Có đăng nhập thất bại không?', 'reason':'Cảnh báo liên quan xác thực.'}
    assert 'evidence_ids' in tool


@pytest.mark.parametrize('verdict',['malicious','benign'])
def test_trigger_alone_preserves_model_verdict_with_warning(lab,verdict):
    store,audit,trigger,_=lab
    result=InvestigationGraph(store,audit,client=client_for(audit,trigger,False,verdict)).run_alert(trigger)
    assert result['verdict']==verdict and result['confidence']==0.5
    assert result['policy_adjustments'] and result['needs_analyst']


def test_schema_repair_and_bad_ids_fail_with_diagnostics(lab):
    store,audit,trigger,_=lab
    calls=[]
    def client(messages,**kwargs):
        calls.append(kwargs)
        if not kwargs.get('schema'): return {'message':{'content':'Conclude.'}}
        incident=audit.current(trigger['id'])['id']
        return {'message':{'content':json.dumps(report(audit,incident,bad=True))}}
    with pytest.raises(WorkflowError,match='invalid_report'):
        InvestigationGraph(store,audit,client=client).run_alert(trigger)
    run=audit.current(trigger['id'])
    assert run['status']=='failed' and run['report'] is None
    assert len(calls)==3  # planner + final + one repair
    assert 'EV-fabricated' in json.dumps(audit.detail(run['id'],'models'))
    old_id=run['id']
    InvestigationGraph(store,audit,client=client_for(audit,trigger,False)).run_alert(trigger)
    assert audit.current(trigger['id'])['id']!=old_id


def test_single_repair_can_succeed(lab):
    store,audit,trigger,_=lab
    count=0
    def client(messages,**kwargs):
        nonlocal count
        if not kwargs.get('schema'): return {'message':{'content':'Conclude.'}}
        count+=1
        return {'message':{'content':'invalid' if count==1 else json.dumps(report(audit,audit.current(trigger['id'])['id']))}}
    assert InvestigationGraph(store,audit,client=client).run_alert(trigger)['verdict']=='inconclusive'
    assert count==2


def test_english_report_is_retried_without_changing_verdict_or_evidence(lab):
    store,audit,trigger,_=lab
    calls=[]
    def client(messages,**kwargs):
        if not kwargs.get('schema'):
            return {'message':{'content':'No tools.'}}
        calls.append(messages)
        result=report(audit,audit.current(trigger['id'])['id'],'malicious')
        if len(calls)==1:
            result['reasoning']='The alert indicates a suspected attack from multiple sources.'
        return {'message':{'content':json.dumps(result,ensure_ascii=False)}}
    result=InvestigationGraph(store,audit,client=client).run_alert(trigger)
    assert len(calls)==2 and 'tiếng Việt' in calls[1][-1]['content']
    assert 'mỗi mục trình bày một phát hiện' in calls[0][0]['content']
    assert 'không điền số liệu hoặc kết luận khi dữ liệu không có' in calls[0][0]['content']
    assert result['verdict']=='malicious'
    assert result['reasoning']=='Sự kiện xác thực cần được chuyên viên xác minh.'
    assert result['findings'][0]['evidence_ids']


def test_report_language_validation_allows_technical_names_but_flags_english():
    item={'reasoning':'Nghi ngờ DNS tunneling từ 192.0.2.1.',
          'findings':[{'statement':'Đã ghi nhận SSH brute force.', 'evidence_ids':[]}],
          'hypotheses':[], 'unknowns':[], 'recommendations':['Kiểm tra DNS.']}
    assert report_language_errors(item)==[]
    item['recommendations']=['Investigate the source and verify the account.']
    assert report_language_errors(item)==['recommendations[0]']


def test_repeated_english_report_fails_instead_of_silently_displaying(lab):
    store,audit,trigger,_=lab
    def client(messages,**kwargs):
        if not kwargs.get('schema'):
            return {'message':{'content':'No tools.'}}
        result=report(audit,audit.current(trigger['id'])['id'])
        result['reasoning']='The alert indicates a suspected attack from multiple sources.'
        return {'message':{'content':json.dumps(result,ensure_ascii=False)}}
    with pytest.raises(WorkflowError,match='tiếng Anh'):
        InvestigationGraph(store,audit,client=client).run_alert(trigger)


def test_language_retry_rejects_changed_verdict(lab):
    store,audit,trigger,_=lab
    count=0
    def client(messages,**kwargs):
        nonlocal count
        if not kwargs.get('schema'):
            return {'message':{'content':'No tools.'}}
        count+=1
        result=report(audit,audit.current(trigger['id'])['id'], 'malicious' if count==1 else 'benign')
        if count==1:
            result['reasoning']='The alert indicates a suspected attack from multiple sources.'
        return {'message':{'content':json.dumps(result,ensure_ascii=False)}}
    with pytest.raises(WorkflowError,match='thay đổi verdict'):
        InvestigationGraph(store,audit,client=client).run_alert(trigger)


def test_time_and_tool_budget(lab):
    store,audit,trigger,_=lab
    run=audit.create(trigger['id'],Limits(seconds=1).model_dump())
    with audit.connect() as db:
        db.execute('UPDATE investigations SET started=? WHERE id=?',(time.time()-10,run['id']))
    client=Mock(side_effect=AssertionError('expired budget cannot call model'))
    result=InvestigationGraph(store,audit,client=client).run_alert(trigger)
    assert result['stop_reason']=='time_budget' and result['verdict']=='inconclusive'
    assert result['generated_by']=='workflow_budget_stop' and not client.called


def test_one_tool_budget_and_one_model_budget(lab):
    store,audit,trigger,_=lab
    client=Mock(side_effect=client_for(audit,trigger))
    result=InvestigationGraph(store,audit,client=client,limits=Limits(tool_calls=1,model_calls=1)).run_alert(trigger)
    assert result['verdict']=='inconclusive'
    assert audit.counts(result['incident_id'])=={'model':1,'tool':1}


def test_resume_after_process_death_uses_same_run_and_completed_call(lab):
    store,audit,trigger,_=lab
    class ProcessDeath(BaseException): pass
    graph=InvestigationGraph(store,audit,client=client_for(audit,trigger))
    original=graph.use_tools
    def crash(state):
        original(state)
        raise ProcessDeath()
    graph.use_tools=crash
    with pytest.raises(ProcessDeath): graph.run_alert(trigger)
    before=audit.current(trigger['id'])
    assert before['status']=='running'
    result=InvestigationGraph(store,audit,client=client_for(audit,trigger)).run_alert(trigger)
    assert result['incident_id']==before['id']
    assert audit.counts(before['id'])=={'model':3,'tool':2}
    assert len(audit.evidence(before['id']))==3  # Resume must not duplicate the derived aggregate.


def test_interrupted_model_requires_explicit_new_run(lab):
    store,audit,trigger,_=lab
    class ProcessDeath(BaseException): pass
    with pytest.raises(ProcessDeath):
        InvestigationGraph(store,audit,client=Mock(side_effect=ProcessDeath())).run_alert(trigger)
    with pytest.raises(WorkflowError,match='interrupted_call'):
        InvestigationGraph(store,audit,client=Mock(side_effect=AssertionError('must not redispatch'))).run_alert(trigger)
    assert audit.current(trigger['id'])['status']=='failed'


def test_logs_cannot_launch_graph(lab):
    store,audit,trigger,_=lab
    trigger['event_kind']='telemetry'
    with pytest.raises(WorkflowError,match='not_security_alert'):
        InvestigationGraph(store,audit,client=Mock()).run_alert(trigger)
    assert audit.current(trigger['id']) is None


def test_api_detail_limits_and_no_raw_model_prompts(lab):
    store,audit,trigger,_=lab
    result=InvestigationGraph(store,audit,client=client_for(audit,trigger)).run_alert(trigger)
    with TestClient(create_app(store.path,workers=False)) as c:
        assert c.get('/api/alerts/'+trigger['id']+'/investigation').status_code==200
        url='/api/investigations/'+result['incident_id']
        assert c.get(url+'?limit=101').status_code==422
        assert c.get(url+'?section=unknown').status_code==422
        data=c.get(url+'?section=models').json()
        assert all('args' not in item and 'result' not in item for item in data['items'])
        assert c.get(url+'?limit=1').json()['next_offset']==1


def test_playbook_failure_keeps_completed_investigation(lab,monkeypatch):
    store,audit,trigger,_=lab
    monkeypatch.setenv('AI_PLAYBOOK_ENABLED','true')
    expected=InvestigationGraph(store,audit,client=client_for(audit,trigger)).run_alert(trigger)
    with patch('agents.playbook_agent.propose_playbook',side_effect=RuntimeError('offline')):
        result,proposal=analyze(trigger,store=store,audit=audit)
    expected={k:v for k,v in expected.items() if k not in {'timeline','verification_checks'}}
    expected['tool_outcomes']=[{k:v for k,v in item.items() if k!='authentication_summary'} for item in expected.get('tool_outcomes',[])]
    assert result==expected and proposal['status']=='failed'
    assert audit.current(trigger['id'])['status']=='completed'
    assert trigger['grounded_response']['status']=='no_source'


def test_analyze_creates_audited_source_backed_response_preview(lab,monkeypatch):
    store,audit,trigger,_=lab
    monkeypatch.setenv('AI_PLAYBOOK_ENABLED','true')
    original=InvestigationGraph(store,audit,client=client_for(audit,trigger)).run_alert(trigger)
    source={'status':'matched','playbook_id':'PB-SSH','playbook_name':'SSH authentication',
        'playbook_source':'ssh.txt','playbook_text':'SSH brute force\nRESPONSE:\n1. Preserve authentication evidence.\n'}
    model_response={'message':{'content':json.dumps({'summary':'Bảo toàn chứng cứ.', 'actions':[
        {'action':'collect_forensics','target':'007','reason':'Giữ log xác thực.',
         'evidence_ids':[],'guidance_ids':['G1']}]})},'done_reason':'stop'}
    progress=[]
    with patch('agents.playbook_agent.propose_playbook',return_value=source) as retrieve, \
         patch('common.ollama_client.chat_messages',return_value=model_response) as model:
        result,proposal=analyze(trigger,on_progress=lambda stage,step:progress.append(stage),store=store,audit=audit)
    preview=trigger['grounded_response']
    assert result['recommendations']==original['recommendations']  # The original model report is preserved.
    assert preview['status']=='available' and preview['incident_id']==original['incident_id']
    assert preview['knowledge_guidance']['playbook_id']=='PB-SSH'
    assert preview['actions'][0]['guidance_ids']==['G1'] and preview['actions'][0]['status']=='proposed'
    assert trigger['_automatic_response_plan']['actions'] == preview['actions']
    assert trigger['_automatic_response_plan']['verdict_source'] == 'model_report'
    assert retrieve.call_args.kwargs['allow_inconclusive'] is True
    assert 'grounding_response' in progress and model.call_count==1
    assert trigger['investigation']['response_model_calls']==1
    activity=audit.detail(original['incident_id'],'activity',limit=100)
    assert any(i['kind']=='model' and i['name']=='response_recommendation' for i in activity['items'])


def test_invalid_source_backed_preview_does_not_reuse_unverified_suggestions(lab,monkeypatch):
    store,audit,trigger,_=lab
    monkeypatch.setenv('AI_PLAYBOOK_ENABLED','true')
    InvestigationGraph(store,audit,client=client_for(audit,trigger)).run_alert(trigger)
    source={'status':'matched','playbook_id':'PB-SSH','playbook_name':'SSH authentication',
        'playbook_source':'ssh.txt','playbook_text':'SSH brute force\nRESPONSE:\n1. Preserve authentication evidence.\n'}
    with patch('agents.playbook_agent.propose_playbook',return_value=source), \
         patch('common.ollama_client.chat_messages',side_effect=RuntimeError('model offline')):
        result,_=analyze(trigger,store=store,audit=audit)
    assert result['recommendations']  # Kept in the audit record, not shown as sourced suggestions.
    assert trigger['grounded_response']['status']=='error'


def test_metadata_backfill_idempotent_and_backup(lab):
    store,audit,trigger,_=lab
    with store.connect() as db:
        before=db.execute('SELECT COUNT(*) FROM investigation_event_index').fetchone()[0]
        db.execute("DELETE FROM migrations WHERE name='investigation_index_v1'")
        db.execute('DELETE FROM investigation_event_index')
    EventStore(store.path)
    EventStore(store.path)
    with store.connect() as db:
        assert db.execute('SELECT COUNT(*) FROM investigation_event_index').fetchone()[0]==before
        assert db.execute('PRAGMA synchronous').fetchone()[0]==2
    assert list(__import__('pathlib').Path(store.path).parent.glob('backups/*.sqlite3'))


def test_native_ollama_payload_and_timeout():
    from common.ollama_client import chat_messages
    response=Mock()
    response.json.return_value={'message':{'content':'','tool_calls':[{'function':{'name':'get_alert','arguments':{'alert_id':'x'}}}]},'done_reason':'stop'}
    messages=[{'role':'system','content':'Test'}, {'role':'user','content':'Read alert'},
              {'role':'assistant','content':'','tool_calls':[]},
              {'role':'tool','tool_name':'get_alert','content':'{}'}]
    with patch('common.ollama_client.requests.post',return_value=response) as post:
        result=chat_messages(messages,tools=[{'type':'function'}],schema={'type':'object'},timeout=2)
    payload=post.call_args.kwargs['json']
    assert payload['messages']==messages and payload['format']=={'type':'object'}
    assert payload['tools'] and payload['think'] is False
    assert post.call_args.kwargs['timeout']==2 and result['message']['tool_calls']


def test_transport_schema_avoids_ollama_repetition_limit():
    from agents.investigation_schema import ollama_report_schema,InvestigationReport
    transport=json.dumps(ollama_report_schema())
    assert 'maxLength' not in transport and 'minLength' not in transport
    assert 'maxLength' in json.dumps(InvestigationReport.model_json_schema())
    assert 'additionalProperties' in transport and '$defs' in transport and 'inconclusive' in transport


def test_tool_error_warns_without_changing_verdict_and_lease_blocks_parallel_run(lab):
    store,audit,trigger,_=lab
    def client(messages,**kwargs):
        if kwargs.get('schema'):
            return {'message':{'content':json.dumps(report(audit,audit.current(trigger['id'])['id'],'benign'))}}
        return {'message':{'content':'Check scope.','tool_calls':[
            {'function':{'name':'search_auth_events','arguments':{}}},
            {'function':{'name':'search_zeek_dns','arguments':{'agent_id':'other'}}}]}}
    with audit.lease(trigger['id'],30),pytest.raises(WorkflowError,match='investigation_busy'):
        InvestigationGraph(store,audit,client=client).run_alert(trigger)
    result=InvestigationGraph(store,audit,client=client).run_alert(trigger)
    assert result['verdict']=='benign' and result['needs_analyst']
    assert any(o['status']=='error' for o in result['tool_outcomes'])


def test_dos_failed_flows_not_proven_impact(lab):
    store,audit,trigger,_=lab
    trigger['rule']['description']='Zeek suspected DoS: failed TCP flows; service impact unconfirmed'
    result=InvestigationGraph(store,audit,client=client_for(audit,trigger,True,'malicious')).run_alert(trigger)
    assert result['verdict']=='malicious' and result['needs_analyst']
    assert any('Service impact' in u for u in result['policy_adjustments'])


def test_runtime_rag_missing_database_is_read_only(tmp_path,monkeypatch):
    from rag import query
    monkeypatch.setattr(query,'_collection',None)
    monkeypatch.setattr(query,'CHROMA_PATH',str(tmp_path/'missing-knowledge'))
    with patch('rag.query.chromadb.PersistentClient') as client:
        with pytest.raises(RuntimeError,match='not initialized'):
            query._get_collection()
    assert not client.called and not (tmp_path/'missing-knowledge').exists()


def test_zeek_connections_are_historical_observations_without_process_inference(lab):
    store,audit,trigger,_=lab
    conn=map_wazuh_alert({'id':'conn-only','timestamp':trigger['timestamp'],
        'agent':trigger['agent'],'manager':{'name':'lab'},'location':'/opt/zeek/logs/current/conn.log',
        'rule':{'id':'100120','level':3,'description':'Zeek connection','groups':['zeek_telemetry']},
        'data':{'uid':'C-test-only','id.orig_h':'198.51.100.8','id.resp_h':'192.0.2.7',
                'id.resp_p':22,'proto':'tcp','conn_state':'S0','orig_bytes':0,'resp_bytes':0}})
    store.accept(conn,False)
    incident=audit.create(trigger['id'],Limits().model_dump())['id']
    result=LocalTools(store,audit,incident,trigger).execute('search_zeek_connections',{})
    assert result['status']=='ok' and len(result['items'])==1
    item=result['items'][0]
    assert item['zeek_connection']['conn_state']=='S0'
    assert item['process'] is None and item['event_time']!=item['received_at']
    assert store.queue_stats()=={}


def test_connection_search_recovers_from_ungrounded_model_ip_with_audited_scope(lab, monkeypatch):
    monkeypatch.setenv('AI_TOOL_ROUTING','false')
    store,audit,trigger,_=lab
    conn=map_wazuh_alert({'id':'conn-fallback','timestamp':trigger['timestamp'],
        'agent':trigger['agent'],'manager':{'name':'lab'},'location':'/opt/zeek/logs/current/conn.log',
        'rule':{'id':'100120','level':3,'description':'Zeek connection','groups':['zeek_telemetry']},
        'data':{'uid':'C-fallback','id.orig_h':'198.51.100.8','id.resp_h':'192.0.2.7',
                'id.resp_p':22,'proto':'tcp','conn_state':'S0'}})
    store.accept(conn,False)
    messages=[]
    def client(history,**kwargs):
        incident=audit.current(trigger['id'])['id']
        if kwargs.get('schema'):
            return {'message':{'content':json.dumps(report(audit,incident))}}
        messages.append(deepcopy(history))
        if len(messages)==1:
            return {'message':{'content':'','tool_calls':[{'function':{'name':'search_zeek_connections',
                'arguments':{'ip':'10.10.10.10','agent_id':'007'}}}]}}
        return {'message':{'content':'Không cần thêm công cụ.'}}
    result=InvestigationGraph(store,audit,client=client,limits=Limits(progress_mode=True)).run_alert(trigger)
    item=next(o for o in result['tool_outcomes'] if o['tool']=='search_zeek_connections')
    assert item['status']=='ok' and item['query']['ip']=='198.51.100.8'
    assert item['scope_adjustment']=={'requested_ip':'10.10.10.10','effective_ip':'198.51.100.8',
                                     'source':'alert.src_ip','reason':'requested_ip_not_in_incident_evidence'}
    audit_item=next(i for i in audit.detail(result['incident_id'],'activity',limit=100)['items']
                    if i.get('name')=='search_zeek_connections')
    assert audit_item['query']['ip']=='198.51.100.8' and audit_item['scope_adjustment']==item['scope_adjustment']
    response=next(json.loads(m['content']) for m in messages[1] if m.get('tool_name')=='search_zeek_connections')
    assert response['scope_adjustment']==item['scope_adjustment']
    # The lower-level API continues rejecting an IP without incident evidence.
    direct=LocalTools(store,audit,result['incident_id'],trigger)
    assert direct.execute('search_zeek_connections',{'ip':'10.10.10.10'})['error']=='invalid_scope_or_arguments'


def test_connection_search_does_not_invent_scope_if_alert_has_no_ip(lab, monkeypatch):
    monkeypatch.setenv('AI_TOOL_ROUTING','false')
    store,audit,trigger,_=lab
    trigger=deepcopy(trigger)
    trigger.update(src_ip=None,dst_ip=None,agent={'id':'007','name':'test-agent'})
    def client(history,**kwargs):
        incident=audit.current(trigger['id'])['id']
        if kwargs.get('schema'):
            return {'message':{'content':json.dumps(report(audit,incident))}}
        if any(m.get('role')=='tool' for m in history):
            return {'message':{'content':'Không đủ thông tin.'}}
        return {'message':{'content':'','tool_calls':[{'function':{'name':'search_zeek_connections',
            'arguments':{'ip':'10.10.10.10'}}}]}}
    result=InvestigationGraph(store,audit,client=client,limits=Limits(progress_mode=True)).run_alert(trigger)
    item=next(o for o in result['tool_outcomes'] if o['tool']=='search_zeek_connections')
    assert item['error']=='invalid_scope_or_arguments' and 'scope_adjustment' not in item


def test_graph_failure_never_silently_calls_legacy(lab):
    store,audit,trigger,_=lab
    with patch('agents.investigation_graph.InvestigationGraph.run_alert',side_effect=WorkflowError('invalid_report','test')), \
         patch('agents.investigation_agent.investigate') as legacy:
        with pytest.raises(WorkflowError,match='invalid_report'):
            analyze(trigger,store=store,audit=audit)
    assert not legacy.called


def test_explicit_legacy_rollback_and_playbook_isolation(lab,monkeypatch):
    store,audit,trigger,_=lab
    monkeypatch.setenv('AI_WORKFLOW','legacy')
    report={'incident_type':'Legacy test report'}
    with patch('agents.investigation_agent.investigate',return_value=report), \
         patch('agents.playbook_agent.propose_playbook',side_effect=RuntimeError('unavailable')):
        saved,proposal=analyze(trigger,store=store,audit=audit)
    assert saved==report and trigger['investigation_report']==report
    assert proposal['status']=='failed' and audit.current(trigger['id']) is None
