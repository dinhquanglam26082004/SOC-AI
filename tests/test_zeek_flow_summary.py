from copy import deepcopy
from agents.investigation_tools import LocalTools
from agents.investigation_schema import Limits
from agents.investigation_store import InvestigationStore
from common.event_store import EventStore
from wazuh_integration.mapper import map_wazuh_alert

def test_exact_scope_aggregate_and_duplicates(tmp_path):
    store=EventStore(tmp_path/'events.sqlite');audit=InvestigationStore(tmp_path/'audit.sqlite')
    def make(n,uid,src='192.0.2.1',port=80,packets=2):
        data={'uid':uid,'proto':'tcp','conn_state':'REJ','id':{'orig_h':src,'resp_h':'192.0.2.2','resp_p':port},'orig_pkts':str(packets),'resp_pkts':1,'orig_ip_bytes':100,'resp_ip_bytes':60}
        return {'id':str(n),'timestamp':'2026-11-09T07:12:04Z','agent':{'id':'001','name':'host'},'manager':{'name':'manager'},'rule':{'id':'100140','level':3,'description':'flow','groups':['zeek_telemetry']},'location':'/opt/zeek/logs/current/conn.log','full_log':str(data),'data':data,'_soc_stream':'archives'}
    for raw in [make(1,'u1'),make(2,'u1'),make(3,'u2',packets=3),make(4,'u3',src='192.0.2.9'),make(5,'u4',port=443)]:store.accept(map_wazuh_alert(raw),False)
    alert=map_wazuh_alert(make(6,'trigger'));alert['dst_port']=80;alert['src_ip']='192.0.2.1';alert['dst_ip']='192.0.2.2'
    run=audit.create(alert['id'],Limits().model_dump());tools=LocalTools(store,audit,run['id'],alert)
    args={'src_ip':'192.0.2.1','dst_ip':'192.0.2.2','dst_port':80,'since':'2026-11-09T07:12:00Z','until':'2026-11-09T07:12:10Z'}
    result=tools.execute('summarize_zeek_flows',args);assert result['status']=='ok',result
    s=result['summary'];assert s['matched_records']==3 and s['duplicate_records_removed']==1 and s['flow_observations']==2
    assert s['totals']['orig_pkts']==5 and s['flow_observations_per_second']==0.2
    assert audit.evidence(run['id']) and result['aggregate_evidence_id']
    assert tools.execute('summarize_zeek_flows',{**args,'src_ip':'192.0.2.9'})['status']=='error'
    assert tools.execute('summarize_zeek_flows',{**args,'since':'2026-11-08T00:00:00Z'})['status']=='error'
