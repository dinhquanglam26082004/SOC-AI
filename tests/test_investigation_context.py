"""No Ollama calls: exercise evidence isolation and malicious/malformed outputs."""
import json
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


def test_context_budget_and_interleaving():
    evidence=[item(str(n),tool='http',http={'uri':'x'*200}) for n in range(30)]
    evidence.append(item('DNS',tool='dns',dns={'query':'example.test'}))
    result=pack_evidence(evidence,1200)
    assert result['context_truncated']
    assert 'DNS' in result['allowed_factual_evidence_ids']
    assert sum(len(json.dumps(e,ensure_ascii=False)) for e in result['evidence'])<=1200


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
    assert 'Previous validation error' in seen[-1][-1]['content']


def test_invalid_argument_json_never_becomes_unfiltered_search(tmp_path):
    store=EventStore(tmp_path/'logs.db');audit=InvestigationStore(tmp_path/'audit.db')
    alert=map_wazuh_alert(raw(1));store.accept(alert,False)
    def client(messages,**kwargs):
        if kwargs.get('schema'):
            return {'message':{'content':json.dumps({'incident_type':'Test','verdict':'inconclusive',
                'reasoning':'Invalid query','findings':[],'unknowns':['Query failed'],'recommendations':[]})}}
        return {'message':{'content':'','tool_calls':[{'function':{
            'name':'search_auth_events','arguments':'{invalid json'}}]}}
    report=InvestigationGraph(store,audit,client=client).run_alert(alert)
    assert any(o.get('error')=='invalid_scope_or_arguments' for o in report['tool_outcomes'])
    assert len(audit.evidence(report['incident_id']))==1
