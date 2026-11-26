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
from agents.investigation_policy import assess_verdict
from wazuh_integration.mapper import map_wazuh_alert


@pytest.fixture
def lab(tmp_path,monkeypatch):
    monkeypatch.setenv('WAZUH_WEBHOOK_TOKEN','test-only')
    monkeypatch.setenv('AI_GRAPH_PROGRESS_MODE','false')
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
    assert group['failure_count']==0 and group['success_count']==0
    assert group['failure_record_count']==11 and group['success_record_count']==1
    assert group['failure_before_success'] is False
    evidence=audit.evidence(run['id'])
    aggregate=next(e for e in evidence if e['evidence_id']==result['aggregate_evidence_id'])
    assert aggregate['evidence_type']=='aggregate' and aggregate['data']['source']=='derived-soc-sqlite'
    assert aggregate['data']['authentication_summary']['scope']['agent_id']==alert['agent']['id']
    aggregate_group=aggregate['data']['authentication_summary']['groups'][0]
    assert aggregate_group['failure_count']==0 and aggregate_group['failure_record_count']==11
    assert len([e for e in evidence if e['evidence_type']!='aggregate'])==1


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
                'reasoning':'Chưa xác minh quyền truy cập của nguồn.','findings':[{'statement':'Đã ghi nhận các sự kiện xác thực.','evidence_ids':refs}],
                'hypotheses':[],'unknowns':[],'recommendations':['Xác minh quyền truy cập.']})}}
        if request_more:
            return {'message':{'content':json.dumps({'hypotheses':[],'need_more':True,'question':'Confirm account authorization.'})}}
        return {'message':{'content':'','tool_calls':[{'function':{'name':'search_auth_events','arguments':{}}}]}}
    return client


def test_review_before_conclude_and_benign_requires_positive_authorization(lab):
    store,audit,alert,add=lab;add(2,kind='success',minute=1)
    report=InvestigationGraph(store,audit,client=make_client(audit,alert)).run_alert(alert)
    assert report['verdict']=='benign' and report['needs_analyst']
    assert report['review_status']=='pending'
    assert not report['analyst_tasks']
    assert not report['hypotheses']
    assert report['recommendations']==['Xác minh quyền truy cập.']
    with audit.connect() as db:
        stages=[r[0] for r in db.execute('SELECT node FROM workflow_steps WHERE incident_id=? ORDER BY id',(report['incident_id'],))]
    assert stages.index('reviewing')<stages.index('concluding')
    assert report['verification_checks']


def test_linux_account_change_always_requires_analyst_review():
    evidence=[{'evidence_id':'EV-1','evidence_type':'trigger','data':{'rule':{
        'id':'5901','description':'New group added to the system.','groups':['syslog']}}}]
    report={'verdict':'malicious','reasoning':'Account change observed.',
            'findings':[{'evidence_ids':['EV-1']}],'hypotheses':[],
            'unknowns':[],'recommendations':[],'policy_adjustments':[]}
    result=assess_verdict(report,evidence,[])
    assert result['needs_analyst'] is True
    assert result['review_status']=='pending'
    assert any('authorization' in reason.lower() for reason in result['policy_adjustments'])


def test_historical_linux_account_incident_is_migrated_to_pending(tmp_path):
    audit=InvestigationStore(tmp_path/'soc_investigations.sqlite3')
    run=audit.create('alert-5901',Limits().model_dump())
    audit.add_evidence(run['id'],'source-5901','trigger',{
        'event_time':'2026-11-23T08:54:51Z',
        'rule':{'id':'5901','description':'New group added','groups':['syslog']}},
        'get_alert',{})
    report={'verdict':'malicious','reasoning':'Old report.',
            'findings':[],'hypotheses':[],'unknowns':[],'recommendations':[]}
    audit.update(run['id'],{'needs_analyst':False,'review_status':'not_required'},
                'completed',report)
    with audit.connect() as db:
        db.execute("DELETE FROM audit_migrations WHERE name='linux_account_review_v2'")
    reopened=InvestigationStore(audit.path)
    summary=reopened.current('alert-5901')['summary']
    saved_report=reopened.current('alert-5901')['report']
    assert summary['needs_analyst'] is True
    assert summary['review_status']=='pending'
    assert saved_report['needs_analyst'] is True
    assert saved_report['review_status']=='pending'


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
        body={'decision':'malicious','notes':'Analyst reviewed the observed activity and marked it malicious.','evidence_ids':['wrong']}
        assert client.post(url,json=body).status_code==409
        body['evidence_ids']=[eid]
        assert client.post(url,json=body).status_code==201
        assert client.get('/api/investigations').json()['items']==[]
        detail=client.get('/api/investigations/'+report['incident_id']).json()
        assert detail['summary']['analyst_review']['decision']=='malicious'
        assert detail['report']['verdict']=='benign'
        assert detail['summary']['review_status']=='reviewed'


def test_grouped_alert_investigation_endpoint_resolves_representative(lab):
    store,audit,alert,_=lab
    report=InvestigationGraph(store,audit,client=make_client(audit,alert)).run_alert(alert)
    grouped={**store.get(alert['id']),
             'id':'grouped-alert',
             'ai_status':'skipped',
             'ai_group':{'representative_alert_id':alert['id'],'policy':'active_similarity'}}
    with store.connect() as db:
        db.execute('INSERT INTO events VALUES(?,?)',
                   (grouped['id'],json.dumps(grouped)))
    with TestClient(create_app(store.path,workers=False)) as client:
        response=client.get('/api/alerts/grouped-alert/investigation')
        assert response.status_code==200
        assert response.json()['id']==report['incident_id']
        assert response.json()['summary']['alert_id']==alert['id']


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
