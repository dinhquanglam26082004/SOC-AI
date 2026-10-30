"""Mocked model, synthetic events, temporary DBs only; no production ingestion/model calls."""
from copy import deepcopy
import json
import sqlite3
import time
from unittest.mock import Mock, patch

import pytest
from fastapi.testclient import TestClient
from agents.investigation_graph import InvestigationGraph
from agents.investigation_schema import Limits, WorkflowError
from agents.investigation_store import InvestigationStore
from agents.investigation_tools import LocalTools
from api.app import create_app, analyze
from common.event_store import EventStore
from wazuh_integration.mapper import map_wazuh_alert


@pytest.fixture
def lab(tmp_path,monkeypatch):
    monkeypatch.setenv('WAZUH_WEBHOOK_TOKEN','test-only')
    monkeypatch.setenv('AI_WORKFLOW','langgraph')
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
        'reasoning':'Observed authentication events require analyst validation.',
        'findings':[{'statement':'An authentication event was observed.','evidence_ids':['EV-fabricated'] if bad else refs}],
        'hypotheses':[],'unknowns':['Authorization and intent are not established.'],
        'recommendations':['Verify source access with the asset owner.']}


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
    assert len(audit.evidence(incident))==2  # deduplicated across repeated searches


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
    assert len(audit.evidence(run['id']))==2
    assert run['status']=='completed'
    assert all(call.kwargs['timeout']<=900 for call in client.call_args_list)
    assert any(m['role']=='tool' for m in client.call_args_list[1].args[0])
    before=client.call_count
    assert graph.run_alert(trigger)==result and client.call_count==before
    detail=audit.detail(run['id'],limit=1)
    assert len(detail['items'])==1 and detail['next_offset']==1 and detail['total']==2
    with sqlite3.connect(graph.checkpoint_path) as db:
        assert db.execute('SELECT COUNT(*) FROM checkpoints').fetchone()[0]>0


def test_model_tools_are_routed_and_enforced(lab):
    store,audit,trigger,_=lab
    trigger['source_product']='zeek'
    trigger['rule']['groups']=['zeek_detection']
    available=[]

    def client(messages,**kwargs):
        if kwargs.get('schema'):
            return {'message':{'content':json.dumps(report(audit,audit.current(trigger['id'])['id']))}}
        available.extend(tool['function']['name'] for tool in kwargs['tools'])
        return {'message':{'content':'','tool_calls':[
            {'function':{'name':'search_auth_events','arguments':{}}}]}}

    result=InvestigationGraph(store,audit,client=client).run_alert(trigger)
    assert set(available)=={'search_zeek_connections','search_related_alerts'}
    assert all(name in {'search_zeek_connections','search_related_alerts'} for name in available)
    tool_calls=audit.detail(result['incident_id'],'tools',limit=20)['items']
    rejected=[call for call in tool_calls if call['name']=='search_auth_events']
    assert rejected and rejected[0]['result']['error']=='tool_not_allowed'


@pytest.mark.parametrize('verdict',['malicious','benign'])
def test_trigger_alone_cannot_support_definitive_verdict(lab,verdict):
    store,audit,trigger,_=lab
    result=InvestigationGraph(store,audit,client=client_for(audit,trigger,False,verdict)).run_alert(trigger)
    assert result['verdict']=='inconclusive' and result['confidence'] is None


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
    assert len(audit.evidence(before['id']))==2


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


def test_tool_error_blocks_benign_and_lease_blocks_parallel_run(lab):
    store,audit,trigger,_=lab
    def client(messages,**kwargs):
        if kwargs.get('schema'):
            return {'message':{'content':json.dumps(report(audit,audit.current(trigger['id'])['id'],'benign'))}}
        return {'message':{'content':'Check scope.','tool_calls':[
            {'function':{'name':'search_auth_events','arguments':{}}},
            {'function':{'name':'search_auth_events','arguments':{'agent_id':'other'}}}]}}
    with audit.lease(trigger['id'],30),pytest.raises(WorkflowError,match='investigation_busy'):
        InvestigationGraph(store,audit,client=client).run_alert(trigger)
    result=InvestigationGraph(store,audit,client=client).run_alert(trigger)
    assert result['verdict']=='inconclusive'
    assert any(o['status']=='error' for o in result['tool_outcomes'])


def test_dos_failed_flows_not_proven_impact(lab):
    store,audit,trigger,_=lab
    trigger['rule']['description']='Zeek suspected DoS: failed TCP flows; service impact unconfirmed'
    result=InvestigationGraph(store,audit,client=client_for(audit,trigger,True,'malicious')).run_alert(trigger)
    assert result['verdict']=='inconclusive'
    assert any('Service impact' in u for u in result['unknowns'])


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
