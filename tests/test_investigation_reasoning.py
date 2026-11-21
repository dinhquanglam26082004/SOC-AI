"""Goal-driven planning and content checks; isolated stores, no model/network calls."""
from copy import deepcopy
import json
from unittest.mock import Mock, patch

import pytest
from fastapi.testclient import TestClient

from agents.investigation_evidence import field_value, independent_ids, pending_recommendations, verify_findings
from agents.investigation_graph import InvestigationGraph
from agents.investigation_policy import assess_verdict, tool_options, hypotheses
from agents.investigation_schema import InvestigationReport, Limits
from agents.investigation_store import InvestigationStore
from agents.investigation_tools import LocalTools, definitions
from api.app import create_app
from common.event_store import EventStore
from evaluation.investigation_cases import raw
from wazuh_integration.mapper import map_wazuh_alert


@pytest.fixture
def lab(tmp_path,monkeypatch):
    monkeypatch.setenv('WAZUH_WEBHOOK_TOKEN','test-only')
    store=EventStore(tmp_path/'logs.db')
    audit=InvestigationStore(tmp_path/'soc_investigations.sqlite3')
    alert=map_wazuh_alert(raw(1));store.accept(alert,False)
    second=map_wazuh_alert(raw(2,kind='success',minute=1));store.accept(second,False)
    return store,audit,alert


def ready(lab):
    store,audit,alert=lab
    graph=InvestigationGraph(store,audit,limits=Limits(progress_mode=True))
    graph.run=audit.current(alert['id']) or audit.create(alert['id'],graph.default_limits.model_dump())
    graph.id=graph.run['id'];graph.alert=alert;graph.limits=graph.default_limits
    graph.tools=LocalTools(store,audit,graph.id,alert)
    return graph


def final_message():
    return {'message':{'content':json.dumps({'incident_type':'Test','verdict':'inconclusive',
        'reasoning':'Authorization remains unverified.','findings':[],
        'unknowns':['Authorization'],'recommendations':[]})}}


def plan(name=None,args=None,**review):
    content={'need_more':True,'question':'Which observations address the hypothesis?',
             'missing_evidence':'Corroborating source records.','assessment':'Available records do not establish authorization.',**review}
    message={'content':json.dumps(content)}
    if name:message['tool_calls']=[{'function':{'name':name,'arguments':args or {}}}]
    return {'message':message}


def test_tool_menu_depends_on_capability_not_rule_id(lab):
    alert=deepcopy(lab[2]);initial=tool_options(alert)
    assert 'search_auth_events' in initial and 'search_file_changes' not in initial
    alert['rule']['id']='521'
    assert tool_options(alert)==initial
    assert 'search_privilege_events' not in initial  # "success" is not "su"
    assert 'search_zeek_dns' in tool_options(alert,requested=['search_zeek_dns'])
    assert 'shell' not in tool_options(alert,requested=['shell'])
    assert 'search_file_changes' in tool_options(alert,[{'evidence_type':'observed','data':{'file_change':{'path':'/test'}}}])
    direct=definitions(['search_auth_events'])[0]['function']['parameters']
    planned=definitions(['search_auth_events'],planning=True)[0]['function']['parameters']
    assert 'question' not in direct['properties'] and 'question' in planned['required']


def test_equivalent_query_replays_after_reopen_without_spending_budget(lab):
    graph=ready(lab)
    result=graph.tool('search_auth_events',{})
    graph=ready(lab)  # New Python graph object, same durable run.
    graph.tools.execute=Mock(side_effect=AssertionError('equivalent query must not execute'))
    explicit={'agent_id':graph.tools.agent,'since':graph.tools.since.replace('Z','+00:00'),
              'until':graph.tools.until,'limit':20,'username':'','ip':None}
    again=graph.tool('search_auth_events',explicit)
    assert again['items']==result['items'] and again['reused']
    assert graph.audit.counts(graph.id)=={'tool':1}
    assert not graph.tools.execute.called


def test_canonicalization_respects_filter_semantics(lab):
    graph=ready(lab);normalize=graph.tools.normalize_arguments
    assert normalize('search_zeek_dns',{'query':'LAB.TEST'})==normalize('search_zeek_dns',{'query':'lab.test'})
    assert normalize('search_auth_events',{'username':'Alice'})!=normalize('search_auth_events',{'username':'alice'})
    assert normalize('search_auth_events',{'limit':1})!=normalize('search_auth_events',{'limit':2})
    with pytest.raises(ValueError):normalize('search_auth_events',{'agent_id':'other'})
    with pytest.raises(ValueError):normalize('search_auth_events',{'limit':True})


def test_old_raw_audit_arguments_are_normalized_on_replay(lab):
    graph=ready(lab)
    old=graph.audit.call(graph.id,'historical-call','tool','search_auth_events',{},10,
                        lambda:graph.tools.execute('search_auth_events',{}))
    result=graph.tool('search_auth_events',{'limit':20})
    assert result['reused_call_id']=='historical-call' and result['items']==old['items']


def test_missing_goal_prevents_dispatch_and_does_not_spin(lab):
    store,audit,alert=lab
    client=Mock(side_effect=lambda messages,**kw:final_message() if kw.get('schema') else
        {'message':{'content':'','tool_calls':[{'function':{'name':'search_auth_events','arguments':{}}}]}})
    result=InvestigationGraph(store,audit,client=client,limits=Limits(progress_mode=True)).run_alert(alert)
    assert audit.counts(result['incident_id'])=={'model':3,'tool':1}
    assert result['stop_reason']=='no_new_evidence'
    assert any(c['validation_error'] for c in result['verification_checks'])


def test_planner_expands_menu_then_reviews_result_and_stops(lab):
    store,audit,alert=lab;contexts=[];menus=[]
    plans=iter([plan(tools=['search_zeek_dns']),plan('search_zeek_dns',{'query':'lab.test'}),
                plan(need_more=False,question='No retained DNS matches; authorization needs an analyst.')])
    def client(messages,**kw):
        if kw.get('schema'):return final_message()
        contexts.append(json.loads(messages[1]['content']))
        menus.append([t['function']['name'] for t in kw['tools']])
        return next(plans)
    result=InvestigationGraph(store,audit,client=client,limits=Limits(progress_mode=True)).run_alert(alert)
    assert 'search_zeek_dns' not in menus[0] and 'search_zeek_dns' in menus[1]
    assert contexts[-1]['query_history'][-1]['status']=='empty'
    assert len(result['tool_outcomes'])==2
    assert result['tool_outcomes'][-1]['question'] and result['needs_analyst']


def test_only_one_tool_executes_before_reassessment(lab):
    store,audit,alert=lab
    first=plan('search_auth_events')
    first['message']['tool_calls'].append({'function':{'name':'search_related_alerts','arguments':{}}})
    replies=iter([first,plan(need_more=False)])
    def client(messages,**kw):return final_message() if kw.get('schema') else next(replies)
    result=InvestigationGraph(store,audit,client=client,limits=Limits(progress_mode=True)).run_alert(alert)
    assert [o['tool'] for o in result['tool_outcomes']]==['get_alert','search_auth_events']


def test_next_query_requires_structured_review(lab):
    store,audit,alert=lab
    replies=iter([plan('search_auth_events'),{'message':{'content':'More tools!',
        'tool_calls':[{'function':{'name':'search_related_alerts','arguments':{
            'question':'Any alerts?','missing_evidence':'Other alerts','hypothesis_id':'H-001'}}}]}},plan(need_more=False)])
    def client(messages,**kw):return final_message() if kw.get('schema') else next(replies)
    result=InvestigationGraph(store,audit,client=client,limits=Limits(progress_mode=True)).run_alert(alert)
    assert len(result['tool_outcomes'])==2
    assert any(c['validation_error']=='Missing structured result review.' for c in result['verification_checks'])


def evidence(eid='EV-1',kind='observed',source='source-1',**data):
    return {'evidence_id':eid,'evidence_type':kind,'source_record_id':source,'data':data}


def finding(**changes):
    return {'statement':'This proves remote execution.','evidence_ids':['EV-1'],'claim_type':'recorded_fact',
            'assertions':[{'evidence_id':'EV-1','field':'/http/status_code','value':200}],**changes}


def test_valid_field_cannot_launder_unrelated_model_statement():
    checked=verify_findings([finding()],[evidence(http={'status_code':200})])[0]
    assert checked['statement']=='Recorded: /http/status_code = 200'
    assert checked['model_statement']=='This proves remote execution.'
    assert checked['verification']['status']=='recorded_fact'


@pytest.mark.parametrize('data',[{'http':{'status_code':403}}, {'http':{}}, {'http':{'status_code':True}}])
def test_existing_id_does_not_verify_incorrect_content(data):
    checked=verify_findings([finding()],[evidence(**data)])[0]
    assert checked['verification']['status']=='unverified'
    assert checked['verification']['issues']


def test_boolean_is_not_integer_and_unasserted_citations_are_not_verified():
    f=finding(assertions=[{'evidence_id':'EV-1','field':'/flag','value':1}])
    assert verify_findings([f],[evidence(flag=True)])[0]['verification']['status']=='unverified'
    f=finding(evidence_ids=['EV-1','EV-2'])
    assert verify_findings([f],[evidence(http={'status_code':200}),evidence('EV-2')])[0]['verification']['status']=='unverified'


def test_supported_premises_do_not_confirm_an_inference():
    checked=verify_findings([finding(claim_type='inference')],[evidence(http={'status_code':200})])[0]
    assert checked['verification']['status']=='supported_inference'
    assert 'not entailment' in checked['verification']['scope']


def test_repeated_alerts_same_source_and_same_log_are_not_independent():
    items=[evidence('trigger','trigger','a',rule={'id':'10'},agent={'id':'1'},full_log='same'),
           evidence('repeat',source='b',rule={'id':'10'},agent={'id':'1'}),
           evidence('same-source',source='a',rule={'id':'20'},agent={'id':'1'}),
           evidence('same-log',source='c',rule={'id':'30'},agent={'id':'1'},full_log='same'),
           evidence('independent',source='d',rule={'id':'40'},agent={'id':'1'})]
    assert independent_ids(items)=={'independent'}


def test_matched_fields_alone_cannot_validate_malicious_verdict():
    items=[evidence(http={'status_code':200})]
    report=InvestigationReport.model_validate({'incident_type':'HTTP','verdict':'malicious','reasoning':'Execution happened.',
        'findings':[finding()],'unknowns':[],'recommendations':[]}).model_dump()
    report['findings']=verify_findings(report['findings'],items)
    result=assess_verdict(report,items,[])
    assert result['verdict']=='inconclusive' and result['needs_analyst']
    assert any('causal claim' in gap for gap in result['unknowns'])


def test_unsupplied_evidence_is_rejected_even_if_persisted(lab):
    graph=ready(lab);graph.tool('get_alert',{'alert_id':lab[2]['id']})
    eid=graph.audit.evidence(graph.id)[0]['evidence_id']
    report=json.loads(final_message()['message']['content'])
    report['findings']=[{'statement':'Event','evidence_ids':[eid]}]
    with pytest.raises(ValueError,match='unsupplied'):graph.validate(json.dumps(report),supplied=[])


def test_recommendations_preserve_manual_review_and_new_scopes():
    steps=['Run search_auth_events again.','Review search_auth_events results.',
           'Run search_auth_events for a wider time window.','Contact asset owner.','Contact asset owner.']
    remaining,omitted=pending_recommendations(steps,[{'tool':'search_auth_events','status':'ok'}],['search_auth_events'])
    assert remaining==steps[1:4] and len(omitted)==1
    assert pending_recommendations(steps[:1],[{'tool':'search_auth_events','status':'error'}],['search_auth_events'])[0]


def test_exact_evidence_api_is_run_scoped_and_handles_missing_sources(lab):
    store,audit,alert=lab;graph=ready(lab)
    graph.tool('get_alert',{'alert_id':alert['id']})
    graph.tool('search_auth_events',{})
    item=next(e for e in audit.evidence(graph.id) if e['evidence_type']=='observed')
    guidance=audit.add_evidence(graph.id,'guide','guidance',{},'search_runbook',{})
    other=audit.create(alert['id'],Limits().model_dump())['id']
    with TestClient(create_app(store.path,workers=False)) as client:
        url=f"/api/investigations/{graph.id}/evidence/{item['evidence_id']}"
        assert client.get(url).json()['source_record_id']==item['source_record_id']
        assert client.get(url+'/source').json()['record']['id']==item['source_record_id']
        assert client.get(url.replace(graph.id,other)).status_code==404
        assert client.get(f'/api/investigations/{graph.id}/evidence/{guidance}/source').status_code==409
        # Synthetic evidence of a retired source: never substitute the triggering log.
        missing=audit.add_evidence(graph.id,'retired','observed',{},'search_related_alerts',{})
        missing_url=f'/api/investigations/{graph.id}/evidence/{missing}'
        assert client.get(missing_url).status_code==200
        assert client.get(missing_url+'/source').status_code==404


def test_rootkit_tool_is_not_locked_to_a_rule_id(lab):
    graph=ready(lab)
    result=graph.tools.execute('search_rootkit_evidence',{})
    assert result['status'] in {'empty','unavailable','ok'}
    assert result.get('error')!='not_a_rootkit_alert'


def test_normalized_rootkit_pid_and_detail_enrichment(lab):
    graph=ready(lab)
    graph.alert['raw_event']['full_log']="Process '123' hidden from /proc"
    assert graph.tools.normalize_arguments('search_rootkit_evidence',{})==graph.tools.normalize_arguments('search_rootkit_evidence',{'pid':123})
    graph.tool('get_alert',{'alert_id':graph.alert['id']})
    eid=graph.audit.evidence(graph.id)[0]['evidence_id']
    state={'round':1,'observations':[],'messages':[],'available_tools':['get_event_details'],
           'stagnant_rounds':1,'pending':[{'name':'get_event_details','args':{'evidence_id':eid},'id':'detail-1'}]}
    enriched=graph.use_tools(state)
    assert enriched['stagnant_rounds']==0 and len(graph.audit.evidence(graph.id))==1
    repeated=graph.use_tools({**state,**enriched,'pending':state['pending']})
    assert repeated['stagnant_rounds']==1 and repeated['observations'][-1]['reused']


def test_source_api_reads_zeek_telemetry_without_falling_back_to_alert(lab):
    store,audit,alert=lab;graph=ready(lab)
    record=map_wazuh_alert({'id':'dns-only','timestamp':alert['timestamp'],'agent':alert['agent'],
        'manager':{'name':'lab'},'_soc_stream':'archives','location':'/opt/zeek/logs/current/dns.log',
        'rule':{'id':'100120','level':3,'description':'Zeek DNS','groups':['zeek_telemetry']},
        'data':{'uid':'C-dns','query':'lab.test','rcode_name':'NOERROR','id.orig_h':'192.0.2.7','id.resp_h':'198.51.100.8'}})
    store.accept(record,False)
    evidence_id=graph.tool('search_zeek_dns',{})['items'][0]['evidence_id']
    with TestClient(create_app(store.path,workers=False)) as client:
        result=client.get(f'/api/investigations/{graph.id}/evidence/{evidence_id}/source')
        assert result.status_code==200
        assert result.json()['record']['id']==record['id']!=alert['id']


def test_hypotheses_can_change_after_actual_query_results(lab):
    store,audit,alert=lab;turns=[]
    def client(messages,**kwargs):
        if kwargs.get('schema'):return final_message()
        turns.append(json.loads(messages[1]['content']))
        if len(turns)==1:return plan('search_auth_events')
        ids=turns[-1]['allowed_factual_evidence_ids']
        return plan(need_more=False,question='Who authorized this activity?',
            assessment='Authentication records exist but cannot establish authorization.',
            hypotheses=[{'id':'H-001','statement':'The activity may be unauthorized.','status':'inconclusive',
                         'supporting':ids,'question':'Who authorized this activity?'}])
    result=InvestigationGraph(store,audit,client=client,limits=Limits(progress_mode=True)).run_alert(alert)
    assert result['hypotheses'][0]['status']=='inconclusive'
    assert result['hypotheses'][0]['supporting']==turns[-1]['allowed_factual_evidence_ids']
    assert result['stop_reason']=='no_suitable_tool'
    assert len(result['tool_outcomes'])==2


def test_structured_next_queries_reuse_exact_scope_but_keep_new_work(lab):
    graph=ready(lab)
    outcomes=[{'tool':'search_auth_events','status':'ok','query':{}}]
    steps=['Kiểm tra lại đăng nhập.','Collect a larger result page.','Read another host.']
    queries=[{'recommendation':text,'tool':'search_auth_events','arguments':args} for text,args in zip(
        steps,[{'limit':20},{'limit':40},{'agent_id':'another-host'}])]
    remaining,excluded=pending_recommendations(steps,outcomes,['search_auth_events'],queries,graph.tools.normalize_arguments)
    assert remaining==[steps[1]]
    assert 'Equivalent query' in excluded[0]['reason'] and 'outside' in excluded[1]['reason']


@pytest.mark.parametrize('pointer',['/values/-1','/values/+1','/values/01','/values/0~2'])
def test_invalid_pointer_cannot_select_unintended_source_field(pointer):
    with pytest.raises(ValueError):field_value({'values':[1,2]},pointer)


def test_json_pointer_handles_escaped_keys_and_arrays():
    assert field_value({'a/b':{'~key':[42]}},'/a~1b/~0key/0')==42


def rootkit_graph(lab):
    graph=ready(lab)
    graph.alert['rule'].update(id='521',groups=['rootcheck'],description='Hidden process')
    graph.alert['raw_event']['full_log']="Process '123' hidden from /proc"
    return graph


def test_rootkit_complete_result_reused_for_ignored_ip_and_larger_limit(lab):
    graph=rootkit_graph(lab)
    execute=Mock(wraps=graph.tools.execute);graph.tools.execute=execute
    first=graph.tool('search_rootkit_evidence',{})
    again=graph.tool('search_rootkit_evidence',{'pid':123,'ip':graph.alert['agent']['ip'],'limit':40})
    assert again['reused'] and again['items']==first['items']
    assert execute.call_count==1


def test_fresh_result_requests_review_not_a_continue_decision(lab):
    graph=ready(lab)
    check=graph.review_evidence({'round':1,'messages':[{'role':'tool'}],
        'review':{'need_more':True,'question':'Query planned before the result.'}})['review']
    assert check['decision']=='review'
    assert check['need_more'] and check['stop_reason'] is None


def test_terminal_stop_cannot_also_continue(lab):
    graph=ready(lab)
    result=graph.review_evidence({'round':1,'messages':[{'role':'tool'}],
        'stop_reason':'tool_budget','review':{'need_more':True,'question':'More data?'}})
    assert result['review']['need_more'] is False
    assert result['review']['decision']=='stop'
    assert result['review']['stop_reason']=='tool_budget'


def test_rootkit_triage_hypotheses_identify_pid_agent_and_trigger(lab):
    graph=rootkit_graph(lab);state=graph.triage({})
    assert len(state['hypotheses'])==2
    for h in state['hypotheses']:
        assert '123' in h['statement'] and graph.tools.agent in h['statement']
        assert h['evidence_ids'] and h['status']=='open' and not h['refuting']


def test_repeated_rootcheck_is_not_refutation_when_snapshot_is_missing():
    items=[evidence('trigger','trigger',rule={'id':'521'},agent={'id':'007'},full_log="Process '123' hidden from /proc"),
           evidence('repeat',rule={'id':'521'},agent={'id':'007'})]
    result=hypotheses([{'statement':'PID 123 has persistent visibility discrepancy','status':'refuted',
                       'refuting':['repeat']}],{e['evidence_id']:e for e in items})
    assert result[0]['status']=='inconclusive' and not result[0]['refuting']


def test_rule_521_replay_has_one_source_query_and_one_decision_per_step(lab):
    graph=rootkit_graph(lab);store,audit,alert=lab
    repeated=raw(3);repeated['rule']=dict(alert['rule'])
    repeated['full_log']="Process '123' hidden from /proc"
    store.accept(map_wazuh_alert(repeated),False)
    plans=iter([plan('search_rootkit_evidence',reason='Compare independent process-visibility observations.'),
                plan('search_rootkit_evidence',{'pid':123,'limit':40,'ip':alert['agent']['ip']},
                     assessment='Repeated rootcheck records do not confirm the discrepancy; no snapshot was returned.')])
    def client(messages,**kwargs):return final_message() if kwargs.get('schema') else next(plans)
    graph.client=client;executed=[];original=LocalTools.execute
    def execute(self,name,args,timeout=None):
        executed.append(name)
        return original(self,name,args,timeout)
    with patch.object(LocalTools,'execute',execute):report=graph.run_alert(alert)
    assert executed.count('search_rootkit_evidence')==1
    assert report['stop_reason']=='reused_query' and report['verdict']=='inconclusive'
    assert len(audit.evidence(graph.id))==2
    outcomes=report['tool_outcomes'][1:]
    assert outcomes[1]['reused'] and outcomes[0]['evidence_ids']==outcomes[1]['evidence_ids']
    assert any('not evidence refuting a rootkit' in u for u in report['unknowns'])
    checks=report['verification_checks']
    assert all(c['decision']=='stop' and not c['need_more'] for c in checks)
    assert len({c['step_id'] for c in checks})==len(checks)
    items=audit.detail(graph.id,'activity',limit=100)['items']
    steps=[i['investigation_step'] for i in items if i.get('investigation_step')]
    assert steps[0]['reason']=='Compare independent process-visibility observations.'
    assert steps[0]['assessment'].startswith('Repeated rootcheck')
    assert steps[1]['result']['reused'] and steps[1]['verified_verdict']=='inconclusive'
    assert next(i for i in items if i['kind']=='tool' and i['name']=='search_rootkit_evidence')['step_recorded']
    assert all('message' not in i and 'args' not in i for i in items)


def test_legacy_triage_query_is_visible_to_planner_and_reused(lab):
    graph=rootkit_graph(lab)
    graph.audit.call(graph.id,'old-triage-rootkit','tool','search_rootkit_evidence',{},10,
        lambda:graph.tools.execute('search_rootkit_evidence',{}))
    context=graph.context({'observations':[]})
    history=next(q for q in context['query_history'] if q['tool']=='search_rootkit_evidence')
    assert history['cached_available'] and history['query']['pid']==123
    assert graph.tool('search_rootkit_evidence',{'pid':123})['reused_call_id']=='old-triage-rootkit'


def test_increased_limit_does_not_reuse_truncated_rootkit_result(lab):
    graph=rootkit_graph(lab)
    graph.tools.execute=Mock(return_value=graph.tools.envelope('truncated',items=[],truncated=True,total_matched=30))
    graph.tool('search_rootkit_evidence',{'limit':1})
    graph.tool('search_rootkit_evidence',{'limit':40})
    assert graph.tools.execute.call_count==2


def test_step_metadata_does_not_replace_raw_model_audit(lab):
    graph=ready(lab);response=plan('search_auth_events',reason='Compare outcomes.')
    graph.audit.call(graph.id,'plan-0','model','investigate',{'messages':['private prompt']},4,lambda:response)
    graph.audit.record_step(graph.id,'plan-0',{'step_id':'plan-0','decision':'stop','reason':'Compare outcomes.'})
    row=graph.audit.detail(graph.id,'models')['items'][0]
    assert row['result']['message']==response['message'] and row['args']=={'messages':['private prompt']}
    activity=graph.audit.detail(graph.id,'activity')['items']
    assert 'private prompt' not in json.dumps(activity)
