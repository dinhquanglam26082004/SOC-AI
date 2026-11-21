"""Listener-change planning and incident-scoped query regression tests."""
import json

from agents.investigation_graph import InvestigationGraph
from agents.investigation_schema import Limits
from agents.investigation_store import InvestigationStore
from agents.investigation_tools import LocalTools
from agents.investigation_profiles import classify, tools_for
from agents.investigation_tools import MODELS
from agents.investigation_tools import compare_listener_snapshots
from common.event_store import EventStore
from wazuh_integration.mapper import map_wazuh_alert


def setup(tmp_path):
    store=EventStore(tmp_path/'events.db')
    audit=InvestigationStore(tmp_path/'audit.db')
    raw={'id':'listener-1','timestamp':'2026-11-20T10:00:00Z',
         'agent':{'id':'002','name':'endpoint','ip':'192.168.60.138'},
         'manager':{'name':'lab'},'location':'netstat listening ports',
         'rule':{'id':'533','level':7,'description':'Listened ports status changed','groups':['syslog']},
         'full_log':'Listened ports status changed: tcp 0.0.0.0:8080',
         'previous_output':'tcp 0.0.0.0:80'}
    alert=map_wazuh_alert(raw)
    store.accept(alert,False)
    return store,audit,alert


def test_listener_context_and_unsupported_attack_labels(tmp_path):
    store,audit,alert=setup(tmp_path)
    assert classify(alert)=='endpoint_listener_change'
    renamed=dict(alert,rule={**alert['rule'],'id':'99999'})
    assert classify(renamed)=='endpoint_listener_change'
    assert 'search_zeek_connections' not in tools_for(alert,list(MODELS))
    contexts=[]
    def client(messages,**kwargs):
        contexts.append(json.loads(messages[1]['content']))
        if kwargs.get('schema'):
            return {'message':{'content':json.dumps({
                'incident_type':'potential network reconnaissance',
                'verdict':'inconclusive','reasoning':'Chưa có bằng chứng xác định nguyên nhân.',
                'findings':[],'hypotheses':[{'statement':'Nghi DoS từ thay đổi cổng.',
                    'status':'open','question':'Cần xác minh nguyên nhân?'}],
                'unknowns':['Chưa rõ tiến trình liên quan.'],
                'recommendations':['Kiểm tra thay đổi cấu hình trên endpoint.']})}}
        return {'message':{'content':json.dumps({'hypotheses':[], 'need_more':False,'question':''})}}
    result=InvestigationGraph(store,audit,client=client,limits=Limits(progress_mode=True)).run_alert(alert)
    assert contexts[0]['investigation_frame']['question']
    assert contexts[0]['evidence'][0]['data']['previous_output']=='tcp 0.0.0.0:80'
    assert result['incident_type']=='Chưa xác định loại sự cố'
    assert result['model_incident_type']=='potential network reconnaissance'
    assert result['hypotheses'][0]['statement']=='Chưa rõ nguyên nhân của hoạt động được cảnh báo.'
    assert result['verdict']=='inconclusive'


def test_scope_rejects_fabricated_values_but_accepts_observed_peer_ip(tmp_path):
    store,audit,alert=setup(tmp_path)
    incident=audit.create(alert['id'],Limits().model_dump())['id']
    tools=LocalTools(store,audit,incident,alert)
    assert tools.execute('get_alert',{'alert_id':alert['id']})['status']=='ok'
    for args,reason in (({'agent_id':'agent-123'},'agent_id'),
                        ({'ip':'192.168.1.100'},'IP not present'),
                        ({'since':'2023-01-01T00:00:00Z'},'time window')):
        result=tools.execute('search_zeek_connections',args)
        assert result['status']=='error' and reason in result['detail']
    # A retained observation for this agent can introduce a different peer IP.
    audit.add_evidence(incident,'peer-1','observed',{'agent':alert['agent'],
        'event_time':tools.since,'source_product':'zeek','dst_ip':'192.168.60.200'},
        'search_zeek_connections',{})
    assert '192.168.60.200' in tools.scoped_ips()
    assert tools.execute('search_zeek_connections',{'ip':'192.168.60.200'})['status']=='empty'


def test_equivalent_query_cached_and_new_scope_allowed(tmp_path):
    store,audit,alert=setup(tmp_path)
    graph=InvestigationGraph(store,audit,limits=Limits(progress_mode=True))
    graph.run=audit.create(alert['id'],graph.default_limits.model_dump())
    graph.id=graph.run['id'];graph.alert=alert;graph.limits=graph.default_limits
    graph.tools=LocalTools(store,audit,graph.id,alert)
    first=graph.tool('search_related_alerts',{})
    second=graph.tool('search_related_alerts',{'agent_id':'002','limit':20,
        'since':graph.tools.since,'until':graph.tools.until})
    alias=graph.tool('search_related_alerts',{'agent_id':'192.168.60.138'})
    third=graph.tool('search_related_alerts',{'limit':1})
    narrower=graph.tool('search_related_alerts',{'since':'2026-11-20T09:55:00Z'})
    assert first['call_disposition']=='executed'
    assert second['call_disposition']=='cached'
    assert alias['call_disposition']=='cached'
    assert third['call_disposition']=='executed'
    assert narrower['call_disposition']=='executed'
    assert audit.counts(graph.id)['tool']==3


def test_new_evidence_can_authorize_a_previously_blocked_peer_ip(tmp_path):
    store,audit,alert=setup(tmp_path)
    graph=InvestigationGraph(store,audit,limits=Limits(progress_mode=True))
    graph.run=audit.create(alert['id'],graph.default_limits.model_dump())
    graph.id=graph.run['id'];graph.alert=alert;graph.limits=graph.default_limits
    graph.tools=LocalTools(store,audit,graph.id,alert)
    args={'ip':'192.168.60.200'}
    blocked=graph.tool('search_zeek_connections',args)
    assert blocked['status']=='error' and blocked['call_disposition']=='blocked'
    audit.add_evidence(graph.id,'peer-2','observed',{'agent':alert['agent'],
        'event_time':graph.tools.since,'source_product':'zeek','dst_ip':args['ip']},
        'search_zeek_connections',{})
    allowed=graph.tool('search_zeek_connections',args)
    assert allowed['status']=='empty' and allowed['call_disposition']=='executed'
    assert audit.counts(graph.id)['tool']==2


def test_listener_without_endpoint_corroboration_stays_inconclusive(tmp_path):
    store,audit,alert=setup(tmp_path)
    def client(messages,**kwargs):
        if kwargs.get('schema'):
            return {'message':{'content':json.dumps({
                'incident_type':'Thay đổi cổng lắng nghe','verdict':'malicious',
                'reasoning':'Chưa có dữ liệu endpoint xác định nguyên nhân.',
                'findings':[],'hypotheses':[], 'unknowns':[],
                'recommendations':['Kiểm tra tiến trình và cấu hình endpoint.']})}}
        return {'message':{'content':json.dumps({'hypotheses':[], 'need_more':False,'question':''})}}
    result=InvestigationGraph(store,audit,client=client,limits=Limits(progress_mode=True)).run_alert(alert)
    assert result['model_verdict']=='malicious' and result['verdict']=='inconclusive'
    assert any('endpoint' in unknown for unknown in result['unknowns'])


def test_retained_snapshots_expose_added_listener_before_tool_selection(tmp_path):
    store=EventStore(tmp_path/'events.db')
    audit=InvestigationStore(tmp_path/'audit.db')
    original=[f'tcp 127.0.0.1:{20000+n} 0.0.0.0:* {30000+n}/worker' for n in range(75)]
    raw={'id':'listener-18765','timestamp':'2026-11-20T18:11:52.720Z',
         'agent':{'id':'002','name':'endpoint','ip':'192.168.60.138'},
         'manager':{'name':'lab'},'location':'netstat listening ports',
         'rule':{'id':'533','level':7,'description':'Listened ports status changed','groups':['syslog']},
         'previous_output':'\n'.join(original),
         'full_log':'ossec: output: netstat listening ports\n'+'\n'.join(original+[
             'tcp 127.0.0.1:18765 0.0.0.0:* 67230/python3'])}
    alert=map_wazuh_alert(raw)
    store.accept(alert,False)
    assert len(raw['full_log'])>2000
    changes=compare_listener_snapshots(raw['full_log'],raw['previous_output'])
    assert changes['comparison_complete']
    assert changes['added']==[{'protocol':'tcp','address':'127.0.0.1','port':18765,
                               'pid':67230,'process':'python3'}]
    assert changes['removed']==[]
    contexts=[]
    def client(messages,**kwargs):
        contexts.append(json.loads(messages[1]['content']))
        if kwargs.get('schema'):
            return {'message':{'content':json.dumps({
                'incident_type':'Tấn công DHCP','verdict':'inconclusive',
                'reasoning':'Ghi nhận cổng mới; chưa rõ nguyên nhân.',
                'findings':[],'hypotheses':[{'statement':'Nghi tấn công DHCP từ log gần thời điểm.',
                    'status':'open','question':'Cần xác minh?' }],
                'unknowns':['Chưa rõ lệnh chạy tiến trình.'],
                'recommendations':['Kiểm tra tiến trình trên endpoint.']})}}
        return {'message':{'content':json.dumps({'hypotheses':[], 'need_more':False,'question':''})}}
    result=InvestigationGraph(store,audit,client=client,
        limits=Limits(progress_mode=True,context_chars=2000)).run_alert(alert)
    plan=contexts[0]
    source=plan['investigation_frame']['source_change']
    assert source['added']==changes['added'] and source['added_total']==1
    assert source['evidence_id']==plan['evidence'][0]['evidence_id']
    assert plan['evidence'][0]['data']['listener_changes']['added']==changes['added']
    assert '18765' not in plan['evidence'][0]['data']['log_excerpt']
    saved=audit.evidence(result['incident_id'])[0]
    assert saved['source_record_id']==alert['id']
    assert saved['data']['listener_changes']['added']==changes['added']
    assert result['model_incident_type']=='Tấn công DHCP'
    assert result['incident_type']=='Chưa xác định loại sự cố'
    assert result['hypotheses'][0]['statement']=='Chưa rõ nguyên nhân của hoạt động được cảnh báo.'
    assert result['verdict']=='inconclusive'


def test_unrelated_zeek_detail_is_blocked_but_matching_port_is_eligible(tmp_path):
    store,audit,alert=setup(tmp_path)
    alert['raw_event']['full_log']='tcp 0.0.0.0:8080 0.0.0.0:* 400/python3'
    graph=InvestigationGraph(store,audit,limits=Limits(progress_mode=True))
    graph.run=audit.create(alert['id'],graph.default_limits.model_dump())
    graph.id=graph.run['id'];graph.alert=alert;graph.limits=graph.default_limits
    graph.tools=LocalTools(store,audit,graph.id,alert)
    assert graph.tool('get_alert',{'alert_id':alert['id']})['status']=='ok'
    for name,port in (('dhcp',67),('listener',8080)):
        eid=audit.add_evidence(graph.id,name,'observed',{
            'source_product':'zeek','agent':alert['agent'],
            'zeek_connection':{'id.resp_p':port}},'search_related_alerts',{})
        result=graph.tool('get_event_details',{'evidence_id':eid})
        if name=='dhcp':
            assert result['error']=='irrelevant_to_source_change'
            assert result['call_disposition']=='blocked'
        else:
            assert result['error']=='collected_event_no_longer_retained_or_outside_scope'
            assert result['call_disposition']=='failed'


def test_snapshot_diff_reports_removed_listener_without_inventing_owner():
    before='tcp 127.0.0.1:1234 0.0.0.0:* 17/old\nudp 0.0.0.0:5353 0.0.0.0:*'
    after='udp 0.0.0.0:5353 0.0.0.0:*'
    changes=compare_listener_snapshots(after,before)
    assert changes['comparison_complete']
    assert changes['removed']==[{'protocol':'tcp','address':'127.0.0.1','port':1234,
                                 'pid':17,'process':'old'}]
    assert changes['added']==[]
    assert compare_listener_snapshots('tcp 127.0.0.1:18765 0.0.0.0:* 67230/python3','') \
        ['comparison_complete'] is False


def test_legitimate_listener_empty_process_search_cannot_become_malicious(tmp_path):
    # The operator ran python3 -m http.server 18766 --bind 127.0.0.1, but no
    # audit_command event was supplied to SOC; the agent must not infer intent.
    store=EventStore(tmp_path/'events.db')
    audit=InvestigationStore(tmp_path/'audit.db')
    raw={'id':'listener-18766','timestamp':'2026-11-20T18:11:52.720Z',
         'agent':{'id':'002','name':'endpoint','ip':'192.168.60.138'},
         'manager':{'name':'lab'},'location':'netstat listening ports',
         'rule':{'id':'9000','level':7,'description':'Listened ports status changed','groups':['syslog']},
         'previous_output':'tcp 127.0.0.1:22 0.0.0.0:* 100/sshd',
         'full_log':'tcp 127.0.0.1:22 0.0.0.0:* 100/sshd\n'
                    'tcp 127.0.0.1:18766 0.0.0.0:* 74704/python3'}
    alert=map_wazuh_alert(raw);store.accept(alert,False)
    plans=[]
    def client(messages,**kwargs):
        context=json.loads(messages[1]['content'])
        if kwargs.get('schema'):
            trigger_id=context['investigation_frame']['source_change']['evidence_id']
            return {'message':{'content':json.dumps({
                'incident_type':'Thay đổi cổng lắng nghe','verdict':'malicious',
                'reasoning':'Cổng mới có thể là hành vi nguy hiểm.',
                'findings':[{'statement':'Có listener mới trên endpoint.','evidence_ids':[trigger_id]}],
                'hypotheses':[{'statement':'Tiến trình có thể là một cuộc tấn công.',
                    'status':'supported','supporting':[trigger_id]}],
                'unknowns':['Chưa rõ mục đích chạy tiến trình.'],
                'recommendations':['Xác minh lệnh và người vận hành trên endpoint.']})}}
        plans.append(context)
        if len(plans)==1:
            return {'message':{'content':'','tool_calls':[{'function':{
                'name':'search_process_events','arguments':{}}}]}}
        return {'message':{'content':json.dumps({'hypotheses':[],
            'need_more':False,'question':''})}}
    result=InvestigationGraph(store,audit,client=client,limits=Limits(progress_mode=True)).run_alert(alert)
    process=next(o for o in result['tool_outcomes'] if o['tool']=='search_process_events')
    assert process['status']=='empty' and process['count']==0
    assert 'audit_command' in process['coverage']
    assert 'audit_command' in next(o for o in plans[1]['tool_outcomes']
                                   if o['tool']=='search_process_events')['coverage']
    assert result['model_verdict']=='malicious' and result['verdict']=='inconclusive'
    assert result['stop_reason']=='no_further_tool_requested'
    assert result['hypotheses'][0]['status']=='open'
    assert result['hypotheses'][0]['statement']=='Chưa rõ nguyên nhân của hoạt động được cảnh báo.'
    assert any('audit_command' in unknown for unknown in result['unknowns'])
    assert any('tín hiệu tấn công' in unknown for unknown in result['unknowns'])
    assert result['needs_analyst']
