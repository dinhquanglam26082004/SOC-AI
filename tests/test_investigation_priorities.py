"""High-priority evidence/review behavior, using isolated DBs and mock models."""
import json
from unittest.mock import Mock
import pytest
from fastapi.testclient import TestClient
from agents.investigation_graph import InvestigationGraph
from agents.investigation_store import InvestigationStore
from agents.investigation_tools import LocalTools
from agents.investigation_schema import Limits
from agents.investigation_policy import hypotheses
from common.event_store import EventStore
from evaluation.investigation_cases import raw,cases
from evaluation.run_investigation import run_case,summarize
from api.app import create_app
from wazuh_integration.mapper import map_wazuh_alert


@pytest.fixture
def lab(tmp_path,monkeypatch):
    monkeypatch.setenv('WAZUH_WEBHOOK_TOKEN','test-only')
    store=EventStore(tmp_path/'logs.sqlite3');audit=InvestigationStore(tmp_path/'soc_investigations.sqlite3')
    def add(number,**kwargs):
        record=map_wazuh_alert(raw(number,**kwargs));store.accept(record,False);return record
    alert=add(1)
    return store,audit,alert,add


def tool(lab):
    store,audit,alert,_=lab
    run=audit.create(alert['id'],Limits().model_dump())
    return LocalTools(store,audit,run['id'],alert),run


def test_auth_aggregate_exact_beyond_returned_page(lab):
    store,audit,alert,add=lab
    for number in range(2,12):add(number)
    add(12,kind='success',minute=1)
    tools,run=tool(lab);result=tools.execute('search_auth_events',{'limit':1})
    group=result['authentication_summary']['groups'][0]
    assert result['status']=='truncated' and len(result['items'])==1
    assert group['failure_count']==11 and group['success_count']==1 and group['failure_before_success']
    assert len(audit.evidence(run['id']))==1  # aggregate counts are not fabricated event evidence


@pytest.mark.parametrize('kwargs',[{'user':'other'},{'ip':'203.0.113.9'},{'minute':0}])
def test_auth_does_not_merge_users_ips_or_same_time(lab,kwargs):
    *_,add=lab;add(2,kind='success',**kwargs)
    tools,_=tool(lab)
    groups=tools.execute('search_auth_events',{})['authentication_summary']['groups']
    assert not any(g['failure_before_success'] for g in groups)


def test_auth_user_and_source_filter(lab):
    *_,add=lab;add(2,user='other',kind='success',minute=1)
    tools,_=tool(lab)
    result=tools.execute('search_auth_events',{'username':'lab-user','ip':'198.51.100.8'})
    assert len(result['items'])==1
    assert result['authentication_summary']['groups'][0]['success_count']==0


def test_hypothesis_positive_and_negative_refs(lab):
    tools,run=tool(lab);items=tools.execute('search_auth_events',{})['items']
    eid=items[0]['evidence_id'];evidence={e['evidence_id']:e for e in lab[1].evidence(run['id'])}
    h=hypotheses([{'statement':'An event occurred','status':'supported','supporting':[eid]}],evidence)[0]
    assert h['id']=='H-001' and h['supporting']==[eid]
    with pytest.raises(ValueError,match='both support and refute'):
        hypotheses([{**h,'refuting':[eid]}],evidence)
    with pytest.raises(ValueError,match='Unknown'):
        hypotheses([{**h,'supporting':['made-up']}],evidence)
    with pytest.raises(ValueError,match='needs supporting'):
        hypotheses([{'statement':'Attack succeeded','status':'supported'}],evidence)


def make_client(audit,alert,verdict='benign',request_more=False):
    def client(messages,**kwargs):
        run=audit.current(alert['id'])
        if kwargs.get('schema'):
            refs=[e['evidence_id'] for e in audit.evidence(run['id'])]
            return {'message':{'content':json.dumps({'incident_type':'Authentication','verdict':verdict,
                'reasoning':'Source authorization has not been verified.','findings':[{'statement':'Authentication records exist.','evidence_ids':refs}],
                'hypotheses':[],'unknowns':[],'recommendations':['Verify authorization.']})}}
        if request_more:
            return {'message':{'content':json.dumps({'hypotheses':[],'need_more':True,'question':'Confirm account authorization.'})}}
        return {'message':{'content':'','tool_calls':[{'function':{'name':'search_auth_events','arguments':{}}}]}}
    return client


def test_review_before_conclude_and_benign_requires_positive_authorization(lab):
    store,audit,alert,add=lab;add(2,kind='success',minute=1)
    report=InvestigationGraph(store,audit,client=make_client(audit,alert)).run_alert(alert)
    assert report['verdict']=='inconclusive' and report['needs_analyst']
    assert report['review_status']=='pending' and report['analyst_tasks']
    assert report['hypotheses'][0]['id']=='H-001'
    with audit.connect() as db:
        stages=[r[0] for r in db.execute('SELECT node FROM workflow_steps WHERE incident_id=? ORDER BY id',(report['incident_id'],))]
    assert stages.index('reviewing')<stages.index('concluding')
    assert report['verification_checks']


def test_review_question_loops_within_original_budget(lab):
    store,audit,alert,_=lab
    client=Mock(side_effect=make_client(audit,alert,'inconclusive',True))
    report=InvestigationGraph(store,audit,client=client).run_alert(alert)
    assert len(report['verification_checks'])==2
    assert report['verification_checks'][0]['need_more'] is True
    assert report['verification_checks'][1]['need_more'] is False
    assert audit.counts(report['incident_id'])['model']==3


def test_analyst_queue_and_review_do_not_replace_ai_report(lab):
    store,audit,alert,_=lab
    report=InvestigationGraph(store,audit,client=make_client(audit,alert)).run_alert(alert)
    eid=audit.evidence(report['incident_id'])[0]['evidence_id']
    with TestClient(create_app(store.path,workers=False)) as client:
        assert len(client.get('/api/investigations').json()['items'])==1
        url='/api/investigations/'+report['incident_id']+'/review'
        body={'decision':'benign','notes':'Asset owner confirmed scheduled maintenance and the authorized account.','evidence_ids':['wrong']}
        assert client.post(url,json=body).status_code==409
        body['evidence_ids']=[eid]
        assert client.post(url,json=body).status_code==201
        assert client.get('/api/investigations').json()['items']==[]
        detail=client.get('/api/investigations/'+report['incident_id']).json()
        assert detail['summary']['analyst_review']['decision']=='benign'
        assert detail['report']['verdict']=='inconclusive'
        assert detail['summary']['review_status']=='reviewed'


def test_contract_suite_does_not_claim_model_accuracy():
    item=run_case(cases()[0],'contract')
    assert item['completed'] and item['verdict']=='inconclusive'
    assert summarize([item],'contract')['quality_metrics'] is None


def test_historical_handoff_is_idempotent_and_preserves_report(lab):
    store,audit,alert,_=lab
    run=audit.create(alert['id'],Limits().model_dump())
    report={'verdict':'inconclusive','reasoning':'Historical report.'}
    audit.update(run['id'],{'node':'completed'},'completed',report)
    with audit.connect() as db:
        db.execute("DELETE FROM audit_migrations WHERE name='analyst_handoff_v1'")
    reopened=InvestigationStore(audit.path)
    assert len(reopened.pending_reviews()['items'])==1
    assert reopened.current(alert['id'])['report']==report
    assert len(InvestigationStore(audit.path).pending_reviews()['items'])==1


def test_pending_queue_prefers_latest_run(lab):
    _,audit,alert,_=lab
    old=audit.create(alert['id'],Limits().model_dump())
    audit.update(old['id'],{'review_status':'pending'},'failed')
    new=audit.create(alert['id'],Limits().model_dump())
    assert audit.pending_reviews()['items']==[]
    audit.update(new['id'],{'review_status':'pending'},'completed',{'verdict':'inconclusive'})
    assert [row['id'] for row in audit.pending_reviews()['items']]==[new['id']]


def test_guidance_cannot_resolve_hypothesis(lab):
    _,audit,alert,_=lab;_,run=tool(lab)
    eid=audit.add_evidence(run['id'],'guide','guidance',{'source':'local-guide'},'search_runbook',{})
    evidence={e['evidence_id']:e for e in audit.evidence(run['id'])}
    with pytest.raises(ValueError,match='Guidance'):
        hypotheses([{'statement':'Incident is confirmed','status':'supported','supporting':[eid]}],evidence)


@pytest.mark.parametrize('case',cases(),ids=lambda case:case['id'])
def test_recommended_tools_follow_incident_type(case):
    from agents.investigation_policy import recommended_tools
    alert=map_wazuh_alert(case['events'][0])
    assert recommended_tools(alert)[0]==case['expected_tool']
