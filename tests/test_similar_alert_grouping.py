"""Similar alerts remain searchable while redundant automatic AI jobs are grouped."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json

import pytest

from common.event_store import EventStore
from wazuh_integration.mapper import map_wazuh_alert


def dns_alert(number, *, seconds=0, agent='001', manager='soc-manager', rule='100181',
              level=7, src='192.0.2.10', dst='192.0.2.20', port=53,
              query=None, qtype='NULL'):
    when=datetime(2026,11,18,10,0,tzinfo=timezone.utc)+timedelta(seconds=seconds)
    data={'uid':f'dns-{number}','id':{'orig_h':src,'resp_h':dst,'resp_p':port},
          'query':query or f'part{number}.tunnel.lab.local','qtype_name':qtype,'proto':'udp'}
    raw={'id':str(number),'timestamp':when.isoformat(),
         'agent':{'id':agent,'name':'victim'},'manager':{'name':manager},
         'rule':{'id':rule,'level':level,'description':'DNS anomaly','groups':['zeek_detection']},
         'location':'/opt/zeek/logs/current/dns.log','data':data,'full_log':json.dumps(data)}
    return map_wazuh_alert(raw)


def test_queued_dns_duplicates_are_grouped_when_first_is_claimed(tmp_path):
    store=EventStore(tmp_path/'events.db')
    first=dns_alert(1);same=dns_alert(2,seconds=1);other=dns_alert(3,seconds=2,dst='192.0.2.21')
    for alert in (first,same,other):
        assert store.accept(alert,True)[0]['ai_status']=='queued'
    running=store.claim()
    assert running['id']==first['id']
    grouped=store.get(same['id'])
    assert grouped['ai_status']=='skipped' and grouped['ai_allowed'] is True
    assert grouped['ai_group']['representative_alert_id']==first['id']
    assert grouped['ai_group']['policy']=='active_similarity' and 'domain cha' in grouped['ai_group']['match']
    assert store.get(other['id'])['ai_status']=='queued'
    assert store.queue_stats()=={'queued':1,'running':1,'skipped':1}
    assert len(store.list_events())==3
    assert store.list_logs(kind='alert')['total']==3


def test_new_similar_alert_joins_running_investigation_without_new_job(tmp_path):
    store=EventStore(tmp_path/'events.db')
    first=dns_alert(1);store.accept(first,True);store.claim()
    same=dns_alert(2,seconds=1,query='DIFFERENT.Tunnel.Lab.Local.')
    saved,_=store.accept(same,True)
    assert saved['ai_status']=='skipped'
    assert saved['ai_group']['representative_alert_id']==first['id']
    assert store.queue_stats()=={'running':1}
    assert store.get(same['id'])['event_kind']=='alert'


@pytest.mark.parametrize('changes',[
    {'agent':'002'}, {'manager':'other'}, {'rule':'100153'}, {'level':10},
    {'src':'192.0.2.11'}, {'dst':'192.0.2.21'}, {'port':5353},
    {'query':'part2.different.lab.local'}, {'qtype':'TXT'}, {'qtype':None},
])
def test_different_or_missing_dns_scope_is_not_grouped(tmp_path,changes):
    store=EventStore(tmp_path/'events.db')
    first=dns_alert(1);store.accept(first,True);store.claim()
    other=dns_alert(2,seconds=1,**changes)
    assert store.accept(other,True)[0]['ai_status']=='queued'


def test_old_queued_event_is_not_merged_but_live_later_event_is(tmp_path):
    store=EventStore(tmp_path/'events.db')
    first=dns_alert(1);old=dns_alert(2,seconds=601)
    store.accept(first,True);store.accept(old,True);store.claim()
    assert store.get(old['id'])['ai_status']=='queued'
    later=dns_alert(3,seconds=602)
    assert store.accept(later,True)[0]['ai_status']=='skipped'
    stale=dns_alert(4,seconds=-601)
    assert store.accept(stale,True)[0]['ai_status']=='queued'


def test_manual_retry_is_not_automatically_suppressed(tmp_path):
    store=EventStore(tmp_path/'events.db')
    first=dns_alert(1);store.accept(first,True);store.claim()
    same=dns_alert(2,seconds=1);store.accept(same,True)
    assert store.retry(same['id']) is True
    assert store.group_queued_with_running()==0
    record=store.get(same['id'])
    assert record['ai_status']=='queued' and 'ai_group' not in record
    assert record['ai_skip_reason'] is None


def test_finish_groups_queued_events_left_by_previous_version(tmp_path):
    store=EventStore(tmp_path/'events.db')
    first=dns_alert(1);same=dns_alert(2,seconds=1)
    store.accept(first,True);store.accept(same,True);running=store.claim()
    # Simulate a queued job already present when a previous worker was running.
    with store.connect() as db:
        record=store.get(same['id']);record.update(ai_status='queued',ai_skip_reason=None)
        record.pop('ai_group',None)
        db.execute('UPDATE events SET payload=? WHERE id=?',(json.dumps(record),same['id']))
        db.execute("UPDATE ai_jobs SET state='queued' WHERE event_id=?",(same['id'],))
    assert store.finish(running)
    assert store.get(same['id'])['ai_status']=='skipped'
    assert store.get(first['id'])['ai_status']=='completed'


def test_claim_does_not_start_preexisting_duplicate_of_a_running_job(tmp_path):
    store=EventStore(tmp_path/'events.db')
    first=dns_alert(1);same=dns_alert(2,seconds=1)
    store.accept(first,True);store.accept(same,True);store.claim()
    with store.connect() as db:
        record=store.get(same['id']);record.update(ai_status='queued',ai_skip_reason=None)
        record.pop('ai_group',None)
        db.execute('UPDATE events SET payload=? WHERE id=?',(json.dumps(record),same['id']))
        db.execute("UPDATE ai_jobs SET state='queued' WHERE event_id=?",(same['id'],))
    assert store.claim() is None
    assert store.get(same['id'])['ai_status']=='skipped'
    assert store.get(first['id'])['ai_status']=='running'


def test_existing_queue_can_be_grouped_without_interrupting_running_job(tmp_path):
    store=EventStore(tmp_path/'events.db')
    first=dns_alert(1);same=dns_alert(2,seconds=1)
    store.accept(first,True);store.accept(same,True);store.claim()
    with store.connect() as db:
        record=store.get(same['id']);record.update(ai_status='queued',ai_skip_reason=None)
        record.pop('ai_group',None)
        db.execute('UPDATE events SET payload=? WHERE id=?',(json.dumps(record),same['id']))
        db.execute("UPDATE ai_jobs SET state='queued' WHERE event_id=?",(same['id'],))
    assert store.group_queued_with_running()==1
    assert store.group_queued_with_running()==0
    assert store.get(same['id'])['ai_group']['representative_alert_id']==first['id']
    assert store.get(first['id'])['ai_status']=='running'


def test_failed_representative_does_not_group_future_alerts(tmp_path):
    store=EventStore(tmp_path/'events.db')
    first=dns_alert(1);store.accept(first,True);running=store.claim()
    assert store.finish(running,error='model failed')
    assert store.accept(dns_alert(2,seconds=1),True)[0]['ai_status']=='queued'


def test_completed_dns_investigation_does_not_suppress_later_alert(tmp_path):
    store=EventStore(tmp_path/'events.db')
    first=dns_alert(1);store.accept(first,True);running=store.claim()
    assert store.finish(running)
    assert store.accept(dns_alert(2,seconds=1),True)[0]['ai_status']=='queued'


def test_simultaneous_alerts_do_not_create_duplicate_jobs(tmp_path):
    store=EventStore(tmp_path/'events.db')
    first=dns_alert(1);store.accept(first,True);store.claim()
    alerts=[dns_alert(i,seconds=i) for i in range(2,14)]
    with ThreadPoolExecutor(max_workers=6) as pool:
        results=list(pool.map(lambda event:store.accept(event,True)[0],alerts))
    assert all(item['ai_status']=='skipped' for item in results)
    assert store.queue_stats()=={'running':1}
    assert len(store.list_events())==13


def test_file_events_are_only_grouped_for_the_same_path(tmp_path):
    store=EventStore(tmp_path/'events.db')
    def file_alert(n,path):
        raw={'id':str(n),'timestamp':'2026-11-18T10:00:00Z','agent':{'id':'001','name':'victim'},
             'manager':{'name':'soc-manager'},'rule':{'id':'550','level':7,'description':'FIM',
             'groups':['syscheck']},'syscheck':{'path':path,'event':'modified'},'data':{}}
        return map_wazuh_alert(raw)
    first=file_alert(1,'/etc/passwd');same=file_alert(2,'/etc/passwd');other=file_alert(3,'/etc/shadow')
    store.accept(first,True);store.claim()
    assert store.accept(same,True)[0]['ai_status']=='skipped'
    assert store.accept(other,True)[0]['ai_status']=='queued'


def test_authentication_requires_same_source_and_username(tmp_path):
    store=EventStore(tmp_path/'events.db')
    def auth_alert(n,ip,user):
        return map_wazuh_alert({'id':str(n),'timestamp':'2026-11-18T10:00:00Z',
            'agent':{'id':'001','name':'victim'},'manager':{'name':'soc-manager'},
            'rule':{'id':'5710','level':8,'description':'Authentication failed',
                    'groups':['authentication_failed']},'data':{'srcip':ip,'srcuser':user}})
    first=auth_alert(1,'192.0.2.1','victim');store.accept(first,True);store.claim()
    assert store.accept(auth_alert(2,'192.0.2.1','victim'),True)[0]['ai_status']=='skipped'
    assert store.accept(auth_alert(3,'192.0.2.2','victim'),True)[0]['ai_status']=='queued'
    assert store.accept(auth_alert(4,'192.0.2.1','admin'),True)[0]['ai_status']=='queued'
    assert store.accept(auth_alert(5,None,'victim'),True)[0]['ai_status']=='queued'


def test_sudo_membership_alerts_group_by_account_and_group_while_running(tmp_path):
    store = EventStore(tmp_path / 'events.db')

    def sudo_alert(number, account, second, method='usermod'):
        rule_id = '101202' if method == 'gpasswd' else '101201'
        message = (f'gpasswd[123]: user {account} added by root to group sudo'
                   if method == 'gpasswd' else
                   f"usermod[123]: add '{account}' to group 'sudo'")
        raw = {
            'id': str(number), 'timestamp': f'2026-11-18T10:00:{second:02}Z',
            'agent': {'id': '001', 'name': 'victim'}, 'manager': {'name': 'soc-manager'},
            'rule': {'id': rule_id, 'level': 10, 'description': 'Linux account added to sudo group',
                     'groups': ['account_management', 'privilege_escalation']},
            'location': 'journald', 'full_log': message,
        }
        return map_wazuh_alert(raw)

    first = sudo_alert(1, 'soc-lab-user', 0)
    store.accept(first, True)
    store.claim()
    same = store.accept(sudo_alert(2, 'soc-lab-user', 1, method='gpasswd'), True)[0]
    other = store.accept(sudo_alert(3, 'another-user', 2), True)[0]

    assert same['ai_status'] == 'skipped'
    assert same['ai_group']['representative_alert_id'] == first['id']
    assert same['ai_group']['match'] == 'Cùng manager, agent, tài khoản và nhóm sudo.'
    assert other['ai_status'] == 'queued'


def test_sudo_alert_without_target_account_is_not_grouped_by_actor(tmp_path):
    store = EventStore(tmp_path / 'events.db')
    first = map_wazuh_alert({
        'id': '1', 'timestamp': '2026-11-18T10:00:00Z',
        'agent': {'id': '001', 'name': 'victim'}, 'manager': {'name': 'soc-manager'},
        'rule': {'id': '101201', 'level': 10, 'description': 'Linux account added to sudo group',
                 'groups': ['account_management', 'privilege_escalation']},
        'location': 'journald', 'full_log': "usermod[123]: add 'soc-lab-user' to group 'sudo'",
    })
    missing_target = map_wazuh_alert({
        'id': '2', 'timestamp': '2026-11-18T10:00:01Z',
        'agent': {'id': '001', 'name': 'victim'}, 'manager': {'name': 'soc-manager'},
        'rule': {'id': '101201', 'level': 10, 'description': 'Linux account added to sudo group',
                 'groups': ['account_management', 'privilege_escalation']},
        'location': 'journald', 'data': {'srcuser': 'root'},
    })
    store.accept(first, True)
    store.claim()

    assert store.accept(missing_target, True)[0]['ai_status'] == 'queued'


def test_exact_duplicate_source_event_groups_even_if_prior_investigation_completed(tmp_path):
    store = EventStore(tmp_path / 'events.db')

    def group_alert(number, rule_id='5901'):
        return map_wazuh_alert({
            'id': str(number), 'timestamp': '2026-11-18T10:00:00Z',
            'agent': {'id': '001', 'name': 'victim'}, 'manager': {'name': 'soc-manager'},
            'rule': {'id': rule_id, 'level': 8, 'description': 'New group added to the system.',
                     'groups': ['syslog']},
            'location': 'journald', 'full_log': 'groupadd[123]: group added to /etc/group: name=labgrp',
        })

    first = group_alert(1)
    store.accept(first, True)
    running = store.claim()
    assert store.finish(running)

    duplicate = store.accept(group_alert(2), True)[0]
    assert duplicate['ai_status'] == 'skipped'
    assert duplicate['ai_group']['policy'] == 'exact_source_event'
    assert duplicate['ai_group']['representative_alert_id'] == first['id']
    assert duplicate['ai_group']['representative_state'] == 'completed'


def test_distinct_source_messages_at_same_time_are_not_grouped(tmp_path):
    store = EventStore(tmp_path / 'events.db')

    def group_alert(number, name):
        return map_wazuh_alert({
            'id': str(number), 'timestamp': '2026-11-18T10:00:00Z',
            'agent': {'id': '001', 'name': 'victim'}, 'manager': {'name': 'soc-manager'},
            'rule': {'id': '5901', 'level': 8, 'description': 'New group added to the system.',
                     'groups': ['syslog']},
            'location': 'journald', 'full_log': f'groupadd[123]: group added to /etc/group: name={name}',
        })

    first = group_alert(1, 'labgrp-one')
    store.accept(first, True)
    running = store.claim()
    assert store.finish(running)

    distinct = store.accept(group_alert(2, 'labgrp-two'), True)[0]
    assert distinct['ai_status'] == 'queued'
