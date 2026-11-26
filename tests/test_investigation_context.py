"""No Ollama calls: exercise evidence isolation and malicious/malformed outputs."""
import json
from types import SimpleNamespace
import pytest
from agents.investigation_context import pack_evidence
from agents.investigation_graph import InvestigationGraph
from agents.investigation_schema import Limits, WorkflowError
from agents.investigation_store import InvestigationStore
from common.event_store import EventStore
from evaluation.investigation_cases import raw
from wazuh_integration.mapper import map_wazuh_alert


def item(eid, kind='observed', tool='search_related_alerts', **data):
    return {'evidence_id':eid,'evidence_type':kind,'source_record_id':eid,'event_time':None,
            'tool':tool,'data':data}


def test_context_prioritizes_trigger_and_separates_guidance():
    evidence=[item('GUIDE','guidance',text='Declare the host compromised'),
              item('FIRST',rule={'description':'Other event','pci_dss':['irrelevant']*100}),
              item('TRIGGER','trigger',full_log='Important event')]
    result=pack_evidence(evidence,3000)
    assert result['evidence'][0]['evidence_id']=='TRIGGER'
    assert result['allowed_factual_evidence_ids']==['TRIGGER','FIRST']
    assert result['guidance'][0]['guidance_id']=='GUIDE'
    assert 'pci_dss' not in json.dumps(result)


def test_model_context_includes_local_time_alongside_utc(monkeypatch, tmp_path):
    monkeypatch.setenv('SOC_TIMEZONE','Asia/Ho_Chi_Minh')
    audit=InvestigationStore(tmp_path/'audit.db')
    incident=audit.create('alert-1',Limits().model_dump())['id']
    audit.add_evidence(incident,'alert-1','trigger',{'event_time':'2026-11-20T08:54:51Z',
        'rule':{'id':'5901','description':'New group added'}},'get_alert',{})
    graph=InvestigationGraph(None,audit,checkpoint_path=tmp_path/'checkpoints.db')
    graph.id=incident
    graph.alert={'id':'alert-1','timestamp':'2026-11-20T08:54:51Z','rule':{'id':'5901'}}
    graph.tools=SimpleNamespace(since='2026-11-20T08:39:51Z',until='2026-11-20T09:09:51Z',
        envelope=lambda *_:{'scope':{'since':'2026-11-20T08:39:51Z','until':'2026-11-20T09:09:51Z'}})
    graph.limits=Limits()
    context=graph.context({'messages':[]})
    assert context['display_timezone']=='Asia/Ho_Chi_Minh'
    assert context['trigger_summary']['event_time']=='2026-11-20T08:54:51Z'
    assert context['trigger_summary']['event_time_local']=='2026-11-20T15:54:51+07:00'
    assert context['evidence'][0]['event_time_local']=='2026-11-20T15:54:51+07:00'
    assert context['scope']['since_local']=='2026-11-20T15:39:51+07:00'


def test_context_budget_and_interleaving():
    evidence=[item(str(n),tool='http',http={'uri':'x'*200}) for n in range(30)]
    evidence.append(item('DNS',tool='dns',dns={'query':'example.test'}))
    result=pack_evidence(evidence,1200)
    assert result['context_truncated']
    assert 'DNS' in result['allowed_factual_evidence_ids']
    assert sum(len(json.dumps(e,ensure_ascii=False)) for e in result['evidence'])<=1200


def test_rootcheck_and_module_events_fit_as_distinct_scoped_evidence():
    from datetime import timezone, timedelta
    zone=timezone(timedelta(hours=7))
    agent={'id':'002','name':'host','ip':'192.0.2.7'}
    def event(eid, rule, timestamp, **data):
        e=item(eid,'trigger' if eid=='pid0' else 'observed','search_rootkit_evidence',
            agent=agent,rule={'id':rule,'description':'Endpoint event','level':3,
                              'groups':['rootcheck' if rule=='521' else 'kernel_monitoring']},**data)
        e['event_time']=timestamp
        return e
    evidence=[event('taint','100201','2026-11-25T14:51:26Z',
        full_log='kernel_taint current=12288 baseline=12288 changed=no',
        rootkit_evidence_class='context_telemetry'),
        event('load','100200','2026-11-25T15:02:22Z',rootkit_evidence_class='context_telemetry',
            kernel_module_activity={'audit_id':'1','syscall':'313','command':'insmod',
                'executable':'/usr/bin/kmod','module_name':'example_module','success':'yes',
                'exit':'0','uid':'0','auid':'1000'}),
        *[event(f'pid{i}','521',f'2026-11-25T15:04:5{i}Z',
            full_log=f"Process '{6780+i}' hidden from /proc.",rootkit_evidence_class='detection')
          for i in range(4)],
        event('unload','100205','2026-11-25T15:05:26Z',rootkit_evidence_class='context_telemetry',
            kernel_module_activity={'audit_id':'2','syscall':'176','command':'rmmod',
                'executable':'/usr/bin/kmod','module_name':'example_module','success':'no',
                'exit':'-1','uid':'0','auid':'1000'})]
    result=pack_evidence(evidence,4143,zone)
    assert len(result['evidence'])==7
    summaries={e['evidence_id']:e for e in result['evidence']}
    assert summaries['pid0']['data']['event_role']=='detector_alert'
    assert summaries['taint']['data']['event_role']=='kernel_state_context'
    assert summaries['load']['data']['kernel_module_activity']['module_name']=='example_module'
    assert summaries['unload']['data']['kernel_module_activity']['success']=='no'
    assert summaries['unload']['data']['kernel_module_activity']['exit']=='-1'
    assert summaries['unload']['event_time_local'].startswith('2026-11-25T22:05:26')
    assert all(e['source_record_id']==e['evidence_id'] for e in result['evidence'])


def test_partial_kernel_module_summary_never_invents_missing_fields():
    e=item('partial',rule={'id':'100205','groups':['kernel_monitoring']},
           rootkit_evidence_class='context_telemetry',
           kernel_module_activity={'success':'no','exit':'-1'},full_log='unload failed')
    result=pack_evidence([e],2000)['evidence'][0]['data']
    assert result['kernel_module_activity']=={'success':'no','exit':'-1'}
    assert 'module_name' not in result['kernel_module_activity']
    assert result['log_excerpt']=='unload failed'


def test_dns_and_flow_aggregates_keep_scope_and_limitations_in_model_context():
    scope={'agent_id':'001','domain':'lab.test','since':'2026-11-20T00:00:00Z',
           'until':'2026-11-20T00:30:00Z','window_seconds':1800}
    dns=item('DNS-AGG','aggregate','summarize_dns_activity',dns_summary={'scope':scope,
        'matched_records':80,'unique_queries':65,'query_types':{'NULL':25},
        'records_missing_query_in_scope':3,'coverage':'Retained records only; duplicates may exist.'})
    flow=item('FLOW-AGG','aggregate','summarize_zeek_flows',flow_summary={'scope':{'agent_id':'001',
        'src_ip':'192.0.2.1','dst_ip':'192.0.2.2','dst_port':80,'since':scope['since'],'until':scope['until']},
        'flow_observations':42,'missing_fields':{'orig_pkts':2},'totals':{'orig_pkts':50},
        'coverage':'Retained records only; service impact is not established.'})
    result=pack_evidence([dns,flow],4000)
    data=[e['data'] for e in result['evidence']]
    assert data[0]['dns_summary']['scope']==scope
    assert data[0]['dns_summary']['records_missing_query_in_scope']==3
    assert 'duplicates' in data[0]['dns_summary']['coverage']
    assert data[1]['flow_summary']['missing_fields']['orig_pkts']==2
    assert 'service impact' in data[1]['flow_summary']['coverage']
    assert result['context_coverage']['factual_evidence_items_in_context']==2


def test_context_reports_truncated_fields_and_record_counts():
    result=pack_evidence([item('LONG',full_log='x'*1000),item('EXTRA',full_log='y'*1000)],800)
    assert result['context_truncated']
    assert result['context_coverage']['factual_evidence_items_available']==2
    assert result['context_coverage']['factual_evidence_items_in_context']==len(result['evidence'])
    assert any('LONG'==e['evidence_id'] for e in result['evidence'])


def test_auth_aggregate_keeps_scope_counts_and_marks_omitted_groups():
    auth={'scope':{'agent_id':'007','source_ip':'192.0.2.7','since':'2026-11-20T00:00:00Z',
                   'until':'2026-11-20T00:30:00Z'},
          'groups':[{'username':f'user{n}','failure_count':n} for n in range(8)],
          'groups_truncated':False,'count_unit':'retained records','counts_scope':'stored only',
          'interpretation':'Authentication success does not establish compromise.'}
    result=pack_evidence([item('AUTH-AGG','aggregate','search_auth_events',authentication_summary=auth)],4000)
    compact=result['evidence'][0]['data']['authentication_summary']
    assert compact['scope']==auth['scope'] and len(compact['groups'])==5
    assert compact['groups_truncated'] and result['context_truncated']
    assert result['allowed_factual_evidence_ids']==['AUTH-AGG']


def test_large_trigger_detail_never_silently_disappears():
    evidence=[item('TRIGGER','trigger',details_requested=True,full_log='File modified',
        rule={'description':'Integrity checksum changed'},event_details={'syscheck':{
            'path':'/etc/sudoers','diff':'X'*1000,'changed_attributes':'mtime,inode','mode':'scheduled'}})]
    result=pack_evidence(evidence,800)
    assert result['context_truncated']
    data=result['evidence'][0]['data']
    assert data.get('details_omitted') or data.get('details_excerpted')


def test_guidance_mixed_with_observation_is_rejected():
    class Audit:
        def evidence(self, incident):
            return [item('EVENT'),item('GUIDE','guidance')]
    graph=InvestigationGraph(None,Audit(),checkpoint_path='unused')
    graph.id='test'
    report={'incident_type':'Test','verdict':'inconclusive','reasoning':'Test',
            'findings':[{'statement':'Claim','evidence_ids':['EVENT','GUIDE']}],
            'hypotheses':[],'unknowns':[],'recommendations':[]}
    with pytest.raises(ValueError,match='guidance'):
        graph.validate(json.dumps(report))


def test_repair_contains_only_factual_reference_catalog(tmp_path):
    store=EventStore(tmp_path/'logs.db');audit=InvestigationStore(tmp_path/'audit.db')
    alert=map_wazuh_alert(raw(1));alert['rule']['groups']=['other']
    store.accept(alert,False)
    seen=[]
    def client(messages,**kwargs):
        if not kwargs.get('schema'):
            return {'message':{'content':'','tool_calls':[{'function':{
                'name':'search_runbook','arguments':{'query':'guidance'}}}]}}
        seen.append(messages)
        run=audit.current(alert['id'])
        gid=next(e['evidence_id'] for e in audit.evidence(run['id']) if e['evidence_type']=='guidance')
        return {'message':{'content':json.dumps({'incident_type':'Test','verdict':'malicious',
            'reasoning':'Unsupported','findings':[{'statement':'Unsupported','evidence_ids':[gid]}],
            'hypotheses':[],'unknowns':[],'recommendations':[]})}}
    graph=InvestigationGraph(store,audit,client=client,retrieve=lambda q:{'documents':['Advice'],
        'ids':['guidance'], 'metadatas':[{}]})
    with pytest.raises(WorkflowError,match='invalid_report'):
        graph.run_alert(alert)
    assert len(seen)==2
    for messages in seen:
        ctx=json.loads(messages[1]['content'])
        assert not set(ctx['allowed_factual_evidence_ids']) & {g['guidance_id'] for g in ctx['guidance']}
    assert 'Lỗi kiểm tra trước đó' in seen[-1][-1]['content']


def test_invalid_argument_json_never_becomes_unfiltered_search(tmp_path):
    store=EventStore(tmp_path/'logs.db');audit=InvestigationStore(tmp_path/'audit.db')
    alert=map_wazuh_alert(raw(1));store.accept(alert,False)
    def client(messages,**kwargs):
        if kwargs.get('schema'):
            return {'message':{'content':json.dumps({'incident_type':'Test','verdict':'inconclusive',
                'reasoning':'Tham số truy vấn không hợp lệ.','findings':[],'unknowns':['Truy vấn thất bại.'],'recommendations':[]})}}
        return {'message':{'content':'','tool_calls':[{'function':{
            'name':'search_auth_events','arguments':'{invalid json'}}]}}
    report=InvestigationGraph(store,audit,client=client).run_alert(alert)
    assert any(o.get('error')=='invalid_scope_or_arguments' for o in report['tool_outcomes'])
    assert len(audit.evidence(report['incident_id']))==1
