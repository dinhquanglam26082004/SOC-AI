from copy import deepcopy
from datetime import datetime,timedelta,timezone
from common.event_store import EventStore
from wazuh_integration.mapper import map_wazuh_alert,ai_eligible

def test_related_dos_alerts_are_retained_and_only_first_queued(tmp_path):
 s=EventStore(tmp_path/'events.db')
 def event(n,second=0,src='192.0.2.1',dst='192.0.2.2',port=80,rule='100142'):
  t=datetime(2026,11,9,8,0,tzinfo=timezone.utc)+timedelta(seconds=second)
  raw={'id':str(n),'timestamp':t.isoformat(),'agent':{'id':'001','name':'lab'},'manager':{'name':'manager'},'rule':{'id':rule,'level':8,'description':'suspected DoS','groups':['zeek_detection']},'location':'/opt/zeek/logs/current/conn.log','full_log':str(n),'data':{'uid':'uid'+str(n),'id':{'orig_h':src,'resp_h':dst,'resp_p':port},'proto':'tcp'}}
  return map_wazuh_alert(raw)
 a=event(1);x,_=s.accept(a,ai_eligible(a));assert x['ai_status']=='queued'
 b=event(2,second=10);y,_=s.accept(b,ai_eligible(b));assert y['ai_status']=='skipped' and y['ai_group']['representative_alert_id']==a['id']
 assert s.get(b['id'])['ai_skip_reason'].startswith('Grouped')
 for c in (event(3,second=11,src='192.0.2.5'),event(4,second=12,port=443),event(5,second=301),event(6,second=13,rule='100145')):
  assert s.accept(c,ai_eligible(c))[0]['ai_status']=='queued'
 assert s.retry(b['id']) is True

def test_distributed_group_ignores_source_but_not_destination(tmp_path):
 s=EventStore(tmp_path/'events.db')
 def event(n,src,dst):
  return map_wazuh_alert({'id':str(n),'timestamp':'2026-11-09T08:00:00Z','agent':{'id':'1','name':'lab'},'manager':{'name':'m'},'rule':{'id':'100145','level':10,'description':'distributed','groups':['zeek_detection']},'location':'/opt/zeek/logs/current/conn.log','full_log':str(n),'data':{'uid':str(n),'src':src,'dst':dst,'p':80}})
 a=event(1,'192.0.2.1','192.0.2.2');s.accept(a,True)
 b=event(2,'192.0.2.3','192.0.2.2');assert s.accept(b,True)[0]['ai_status']=='skipped'
 c=event(3,'192.0.2.3','192.0.2.4');assert s.accept(c,True)[0]['ai_status']=='queued'

def test_failed_representative_does_not_hide_new_alert(tmp_path):
 s=EventStore(tmp_path/'events.db')
 def event(n):
  return map_wazuh_alert({'id':str(n),'timestamp':'2026-11-09T08:00:00Z','agent':{'id':'1','name':'lab'},'manager':{'name':'m'},'rule':{'id':'100142','level':8,'description':'suspected DoS','groups':['zeek_detection']},'location':'/opt/zeek/logs/current/conn.log','full_log':str(n),'data':{'uid':str(n),'src':'192.0.2.1','dst':'192.0.2.2','p':80}})
 a=event(1);s.accept(a,True)
 with s.connect() as db:db.execute("UPDATE ai_jobs SET state='failed' WHERE event_id=?",(a['id'],))
 b=event(2);assert s.accept(b,True)[0]['ai_status']=='queued'
 c=event(3);c['src_ip']=None;assert s.accept(c,True)[0]['ai_status']=='queued'
