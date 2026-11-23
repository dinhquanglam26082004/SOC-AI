import json
from unittest.mock import patch
from agents.investigation_graph import InvestigationGraph
from agents.investigation_schema import Limits
from agents.investigation_store import InvestigationStore
from agents.investigation_tools import LocalTools, MODELS
from common.event_store import EventStore
from evaluation.investigation_cases import raw
from wazuh_integration.mapper import map_wazuh_alert


def test_progress_mode_continues_past_fixed_limits_and_stops_without_new_evidence(tmp_path):
    store=EventStore(tmp_path/'events.db');audit=InvestigationStore(tmp_path/'audit.db')
    alert=map_wazuh_alert(raw(1));store.accept(alert,False)
    planner_calls=[];original=LocalTools.execute
    names=['search_auth_events','search_related_alerts','search_zeek_connections',
           'search_zeek_dns','search_zeek_http','search_privilege_events']
    def execute(self,name,args,timeout=None):
        if name not in names:return original(self,name,args,timeout)
        idx=names.index(name)+1
        if idx<=4:
            eid=self.audit.add_evidence(self.incident_id,'sample-'+str(idx),'observed',{'source':'fixture','event_time':self.alert['timestamp']},name,args)
            return self.envelope('ok',items=[{'evidence_id':eid}])
        return self.envelope('empty')
    def client(messages,**kwargs):
        if kwargs.get('schema'):
            return {'message':{'content':json.dumps({'incident_type':'Test','verdict':'inconclusive','reasoning':'Chưa đủ bằng chứng','findings':[], 'hypotheses':[], 'unknowns':['Chưa được xác minh'], 'recommendations':[]})}}
        planner_calls.append(len(planner_calls)+1)
        return {'message':{'content':'','tool_calls':[{'function':{'name':names[len(planner_calls)-1],'arguments':{}}}]}}
    graph=InvestigationGraph(store,audit,client=client,limits=Limits(progress_mode=True,rounds=1,model_calls=1,tool_calls=1))
    with patch.object(LocalTools,'execute',execute):result=graph.run_alert(alert)
    assert len(planner_calls)==6
    assert result['stop_reason']=='no_new_evidence'
    assert audit.counts(result['incident_id'])['model']==7
    assert audit.counts(result['incident_id'])['tool']==7


def test_progress_mode_finishes_after_repeated_cached_queries_add_no_evidence(tmp_path, monkeypatch):
    # Mechanics test for the unrouted tool set; routing is covered in test_investigation_profiles.py.
    monkeypatch.setenv("AI_TOOL_ROUTING", "false")
    store=EventStore(tmp_path/'events.db');audit=InvestigationStore(tmp_path/'audit.db')
    alert=map_wazuh_alert(raw(1));store.accept(alert,False)
    planner_calls=[];original=LocalTools.execute
    def execute(self,name,args,timeout=None):
        if name=='get_alert':return original(self,name,args,timeout)
        eid=self.audit.add_evidence(self.incident_id,'sample-'+name,'observed',
                                    {'source':'fixture','event_time':self.alert['timestamp']},name,args)
        return self.envelope('ok',items=[{'evidence_id':eid}])
    def client(messages,**kwargs):
        if kwargs.get('schema'):
            return {'message':{'content':json.dumps({'incident_type':'Test','verdict':'inconclusive',
                'reasoning':'Chưa đủ bằng chứng','findings':[],'hypotheses':[],
                'unknowns':['Chưa được xác minh'],'recommendations':[]})}}
        planner_calls.append(1)
        return {'message':{'content':'','tool_calls':[
            {'function':{'name':tool['function']['name'],'arguments':{}}} for tool in kwargs['tools']]}}
    graph=InvestigationGraph(store,audit,client=client,limits=Limits(progress_mode=True))
    with patch.object(LocalTools,'execute',execute):result=graph.run_alert(alert)
    assert len(planner_calls)==3
    assert result['stop_reason']=='no_new_evidence'
    assert audit.counts(result['incident_id'])=={'model':4,'tool':len(MODELS)}
    assert any(o.get('call_disposition')=='cached' for o in result['tool_outcomes'])
