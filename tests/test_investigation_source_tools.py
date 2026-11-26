"""Source tool boundaries and provenance using isolated SQLite only."""
import json
import pytest
from agents.investigation_schema import Limits
from agents.investigation_store import InvestigationStore
from agents.investigation_tools import LocalTools, observation
from common.event_store import EventStore
from wazuh_integration.mapper import map_wazuh_alert


@pytest.fixture
def sources(tmp_path):
    store=EventStore(tmp_path/'events.db');audit=InvestigationStore(tmp_path/'audit.db')
    sequence=[0]
    def add(kind='endpoint', data=None, **overrides):
        sequence[0]+=1
        raw={'id':str(sequence[0]),'timestamp':'2026-11-02T08:00:00Z',
            'agent':{'id':'001','name':'lab','ip':'192.0.2.7'},'manager':{'name':'lab'},
            'rule':{'id':'550','level':7,'description':'File changed','groups':['syscheck']},
            'data':data or {},'location':'syscheck'}
        if kind!='endpoint':
            raw.update(location='/opt/zeek/logs/current/'+kind+'.log',_soc_stream='archives',
                rule={'id':'100120','level':3,'description':'Zeek record','groups':['zeek_telemetry']})
            raw['data']={'uid':'C-lab','id':{'orig_h':'192.0.2.7','resp_h':'198.51.100.8'},**(data or {})}
        raw.update(overrides)
        record=map_wazuh_alert(raw);store.accept(record,False)
        return record
    trigger=add(syscheck={'path':'/etc/lab.conf','event':'modified'})
    incident=audit.create(trigger['id'],Limits().model_dump())['id']
    tools=LocalTools(store,audit,incident,trigger)
    return store,audit,incident,tools,add,trigger


def test_http_filters_bounds_and_complete_match_count(sources):
    _,_,_,tools,add,_=sources
    for _ in range(3):add('http',{'host':'LAB.TEST','uri':'/test?x=%27','method':'POST','status_code':403})
    add('http',{'host':'other.test','uri':'/test','method':'GET','status_code':200})
    add('http',{'host':'lab.test'},agent={'id':'002','name':'other'})
    add('dns',{'query':'lab.test'})
    result=tools.execute('search_zeek_http',{'host':'lab.test','method':'post','status_code':403,
        'uri_contains':'%27','limit':1})
    assert result['status']=='truncated' and result['total_matched']==3 and result['returned_count']==1
    assert result['items'][0]['http']['status_code']==403
    assert result['items'][0]['zeek_connection']['id']['orig_h']=='192.0.2.7'
    assert tools.execute('search_zeek_http',{'host':"lab.test' OR 1=1 --"})['status']=='empty'
    assert tools.execute('search_zeek_http',{'username':'root'})['error']=='invalid_scope_or_arguments'
    assert tools.execute('search_zeek_http',{'agent_id':'002'})['error']=='invalid_scope_or_arguments'
    assert tools.execute('search_zeek_http',{'since':'2026-11-01T00:00:00Z'})['error']=='invalid_scope_or_arguments'


def test_dns_keeps_answers_and_exact_filters(sources):
    _,_,_,tools,add,_=sources
    add('dns',{'query':'lab.test','qtype_name':'A','rcode_name':'NOERROR','answers':['192.0.2.80']})
    add('dns',{'query':'long.lab.test','rcode_name':'NXDOMAIN'})
    result=tools.execute('search_zeek_dns',{'query':'LAB.TEST','rcode_name':'noerror','uid':'C-lab'})
    assert result['total_matched']==1
    assert result['items'][0]['dns']['answers']==['192.0.2.80']
    assert tools.execute('search_zeek_dns',{'query':'*.test'})['status']=='empty'


def test_dns_aggregate_and_baseline_use_boundary_safe_suffix(sources):
    _,audit,incident,tools,add,_=sources
    add('dns',{'query':'A.LAB.TEST.','qtype_name':'TXT','rcode_name':'NOERROR'})
    add('dns',{'query':'lab.test','qtype_name':'A'})
    add('dns',{'query':'notlab.test','qtype_name':'A'})
    args={'domain':'lab.test','since':'2026-11-02T07:59:00Z','until':'2026-11-02T08:01:00Z'}
    result=tools.execute('summarize_dns_activity',args)
    assert result['status']=='ok',result
    assert result['summary']['matched_records']==2 and result['summary']['unique_subdomains']==1
    assert result['summary']['query_types']=={'TXT':1,'A':1}
    assert result['aggregate_evidence_id'] in {e['evidence_id'] for e in audit.evidence(incident)}
    result=tools.execute('compare_dns_baseline',{**args,'baseline_since':'2026-11-02T07:57:00Z','baseline_until':'2026-11-02T07:59:00Z'})
    assert result['status']=='ok' and result['summary']['baseline']['matched_records']==0
    assert result['summary']['incident']['matched_records']==2
    assert tools.execute('compare_dns_baseline',{**args,'baseline_since':'2026-11-02T07:58:00Z','baseline_until':'2026-11-02T07:59:00Z'})['status']=='error'
    assert tools.execute('summarize_dns_activity',{**args,'since':'2026-11-01T00:00:00Z'})['status']=='error'


def test_dns_aggregate_selects_diverse_traceable_examples(sources):
    _,audit,incident,tools,add,_=sources
    queries=['first.lab.test','a.lab.test','b.lab.test','c.lab.test',
             'longest-label-in-this-set.lab.test','last.lab.test']
    codes=['','NOERROR','NXDOMAIN','','','']
    records=[]
    for n,(query,code) in enumerate(zip(queries,codes)):
        records.append(add('dns',{'query':query,'rcode_name':code},timestamp=f'2026-11-02T08:00:0{n}Z'))
    result=tools.execute('summarize_dns_activity',{'domain':'lab.test',
        'since':'2026-11-02T07:59:00Z','until':'2026-11-02T08:01:00Z'})
    assert result['status']=='ok' and result['summary']['matched_records']==6
    sample_queries={x['dns']['query'] for x in result['items']}
    assert sample_queries=={queries[0],queries[1],queries[2],queries[4],queries[5]}
    assert len(result['items'])==5 and 'Not a representative sample' in result['summary']['sample_selection']
    saved={e['source_record_id'] for e in audit.evidence(incident)}
    assert {r['id'] for r in records if r['zeek_data']['query'] in sample_queries} <= saved


def test_audit_endpoint_tools_only_return_matching_audit_records(sources):
    _,_,_,tools,add,_=sources
    add(data={'audit':{'exe':'/usr/bin/iodine','command':'iodine'}},rule={'id':'80792','level':3,'description':'Audit command','groups':['audit','audit_command']})
    add(data={'audit':{'file':{'name':'/tmp/demo.txt'},'exe':'/usr/bin/cat'}},rule={'id':'80784','level':3,'description':'Read access','groups':['audit','audit_watch_read']})
    add(syscheck={'path':'/tmp/demo.txt','event':'modified'})
    proc=tools.execute('search_process_events',{})
    assert proc['total_matched']==1 and proc['items'][0]['audit']['exe']=='/usr/bin/iodine'
    read=tools.execute('search_file_access',{'file_path':'/tmp/demo.txt'})
    assert read['total_matched']==1 and read['items'][0]['audit']['exe']=='/usr/bin/cat'
    assert tools.execute('search_file_access',{'file_path':'/tmp/other.txt'})['status']=='empty'
    assert 'absence is not proof' in read['coverage']


def test_fim_preserves_actor_without_inventing_missing_attribution(sources):
    _,_,_,tools,add,_=sources
    add(syscheck={'path':'/etc/other.conf','event':'modified','sha256_before':'old','sha256_after':'new',
                  'audit':{'user':{'name':'operator'},'process':{'id':'123'}}})
    result=tools.execute('search_file_changes',{'file_path':'/etc/other.conf'})
    assert result['total_matched']==1
    assert result['items'][0]['file_change']['audit']['user']['name']=='operator'
    assert result['items'][0]['file_change']['sha256_before']=='old'
    unknown=tools.execute('search_file_changes',{'file_path':'/etc/lab.conf'})['items'][0]
    assert 'audit' not in unknown['file_change']


def test_account_event_tool_filters_linux_group_change_rules(sources):
    _,_,_,tools,add,_=sources
    expected=add(full_log='new group: name=wheel',rule={
        'id':'5901','level':8,'description':'New group added to the system.','groups':['syslog']})
    add(full_log='new user: name=other',rule={
        'id':'101200','level':7,'description':'Linux account created','groups':['account_management']})
    add(full_log='new group: name=wheel',rule={
        'id':'550','level':7,'description':'File changed','groups':['syscheck']})

    result=tools.execute('search_account_events',{'group':'WHEEL'})
    assert result['status']=='ok'
    assert result['total_matched']==1
    assert result['items'][0]['id']==expected['id']
    assert tools.execute('search_account_events',{'group':'missing'})['status']=='empty'


def test_privilege_actor_target_and_pam_sudo_records(sources):
    _,_,_,tools,add,_=sources
    add(data={'srcuser':'operator','dstuser':'root','command':'/usr/bin/id'},
        decoder={'name':'sudo'},rule={'id':'5402','level':3,'description':'Successful sudo','groups':['sudo']})
    add(data={'srcuser':'someone','dstuser':'operator'},predecoder={'program_name':'sudo'},
        rule={'id':'5503','level':5,'description':'PAM failure','groups':['pam','authentication_failed']})
    result=tools.execute('search_privilege_events',{'actor_user':'operator','target_user':'root'})
    assert result['total_matched']==1
    assert result['items'][0]['privilege']=={'srcuser':'operator','dstuser':'root','command':'/usr/bin/id'}
    assert tools.execute('search_privilege_events',{'actor_user':'root'})['status']=='empty'
    assert tools.execute('search_privilege_events',{})['total_matched']==2


def test_privilege_agent_ip_includes_only_scoped_ipless_local_records(sources):
    _,_,_,tools,add,_=sources
    local=add(data={'srcuser':'operator','dstuser':'root'},decoder={'name':'sudo'},
              rule={'id':'5402','level':3,'description':'Successful sudo','groups':['sudo']})
    add(data={'srcuser':'operator','dstuser':'other'},decoder={'name':'sudo'},
        rule={'id':'5402','level':3,'description':'Successful sudo','groups':['sudo']})
    add(data={'srcuser':'operator','dstuser':'root','srcip':'198.51.100.9'},decoder={'name':'sudo'},
        rule={'id':'5402','level':3,'description':'Successful sudo','groups':['sudo']})
    add(data={'srcuser':'operator','dstuser':'root'},decoder={'name':'sudo'},
        agent={'id':'002','name':'other','ip':'192.0.2.8'},
        rule={'id':'5402','level':3,'description':'Successful sudo','groups':['sudo']})
    result=tools.execute('search_privilege_events',{'ip':'192.0.2.7','target_user':'root'})
    assert result['status']=='ok' and result['total_matched']==1
    assert result['items'][0]['id']==local['id']
    assert 'không có trường IP' in result['scope_interpretation']
    assert 'không có trường IP' in result['coverage']
    assert 'rows without these IPs are excluded' not in result['coverage']
    assert result['items'][0]['src_ip'] is None and result['items'][0]['dst_ip'] is None
    assert tools.execute('search_privilege_events',{'ip':'203.0.113.99'})['error']=='invalid_scope_or_arguments'


def test_details_require_collected_event_and_preserve_evidence_identity(sources):
    store,audit,incident,tools,add,trigger=sources
    other=add(syscheck={'path':'/etc/other.conf'})
    assert tools.execute('get_event_details',{'evidence_id':other['id']})['error']=='invalid_scope_or_arguments'
    refs=tools.execute('get_alert',{'alert_id':trigger['id']})['items']
    result=tools.execute('get_event_details',{'evidence_id':refs[0]['evidence_id']})
    assert result['status']=='ok' and result['items'][0]['event_details']['syscheck']['path']=='/etc/lab.conf'
    evidence=audit.evidence(incident)
    assert len(evidence)==1 and evidence[0]['evidence_type']=='trigger'
    assert evidence[0]['data']['details_requested'] is True
    foreign=audit.create('foreign',{})['id']
    foreign_ref=audit.add_evidence(foreign,other['id'],'observed',observation(other),'test',{})
    assert tools.execute('get_event_details',{'evidence_id':foreign_ref})['status']=='error'
    guidance=audit.add_evidence(incident,'doc','guidance',{'text':'Instructions'},'test',{})
    assert tools.execute('get_event_details',{'evidence_id':guidance})['status']=='error'
    with store.connect() as db:
        assert db.execute('SELECT COUNT(*) FROM events').fetchone()[0]==2


def test_detail_truncation_is_explicit_and_does_not_read_paths(sources):
    _,audit,incident,tools,add,_=sources
    record=add(syscheck={'path':'/etc/large'},full_log='x'*15000)
    ref=tools.execute('search_file_changes',{'file_path':'/etc/large'})['items'][0]['evidence_id']
    result=tools.execute('get_event_details',{'evidence_id':ref})
    assert result['status']=='truncated' and result['items'][0]['details_truncated']
    assert len(json.dumps(result))<15000
    assert tools.execute('get_event_details',{'evidence_id':ref,'path':'/etc/passwd'})['status']=='error'
