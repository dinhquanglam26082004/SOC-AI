import json
from unittest.mock import patch
from agents.investigation_graph import InvestigationGraph
from agents.investigation_schema import Limits
from agents.investigation_store import InvestigationStore
from agents.investigation_tools import LocalTools
from common.event_store import EventStore
from evaluation.investigation_cases import raw
from wazuh_integration.mapper import map_wazuh_alert


def test_progress_mode_continues_past_fixed_limits_and_stops_without_new_evidence(tmp_path):
    store=EventStore(tmp_path/'events.db');audit=InvestigationStore(tmp_path/'audit.db')
    alert=map_wazuh_alert(raw(1));store.accept(alert,False)
    planner_calls=[];original=LocalTools.execute
    def execute(self,name,args,timeout=None):
        if name!='search_auth_events':return original(self,name,args,timeout)
        idx=args['limit']
        if idx<=4:
            eid=self.audit.add_evidence(self.incident_id,'sample-'+str(idx),'observed',{'source':'fixture','event_time':self.alert['timestamp']},name,args)
            return self.envelope('ok',items=[{'evidence_id':eid}])
        return self.envelope('empty')
    def client(messages,**kwargs):
        if kwargs.get('schema'):
            return {'message':{'content':json.dumps({'incident_type':'Test','verdict':'inconclusive','reasoning':'Insufficient evidence','findings':[], 'hypotheses':[], 'unknowns':['Unverified'], 'recommendations':[]})}}
        planner_calls.append(len(planner_calls)+1)
        return {'message':{'content':'','tool_calls':[{'function':{'name':'search_auth_events','arguments':{'limit':len(planner_calls)}}}]}}
    graph=InvestigationGraph(store,audit,client=client,limits=Limits(progress_mode=True,rounds=1,model_calls=1,tool_calls=1))
    with patch.object(LocalTools,'execute',execute):result=graph.run_alert(alert)
    assert len(planner_calls)==6
    assert result['stop_reason']=='no_new_evidence'
    assert audit.counts(result['incident_id'])['model']==7
    assert audit.counts(result['incident_id'])['tool']==7
