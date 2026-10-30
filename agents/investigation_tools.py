"""Allowlisted, bounded local reads. Log contents are untrusted observations."""
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from datetime import datetime, timedelta, timezone
import json
import sqlite3
import time
from pathlib import Path
from pydantic import BaseModel, ConfigDict, Field
from common.log_index import utc_stamp
from common.auth_events import auth_outcome

# One outstanding retrieval at most; a timeout does not start unbounded threads.
_rag_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix='investigation-rag')
_rag_pending = None


class SearchArgs(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    agent_id: str | None = Field(default=None, max_length=128)
    ip: str | None = Field(default=None, max_length=64)
    username: str | None = Field(default=None, max_length=256)
    since: str | None = Field(default=None, max_length=64)
    until: str | None = Field(default=None, max_length=64)
    limit: int = Field(default=50, ge=1, le=100)


class AlertArgs(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    alert_id: str = Field(min_length=1, max_length=256)


class RunbookArgs(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    query: str = Field(min_length=1, max_length=600)


MODELS = {'get_alert': AlertArgs, 'search_auth_events': SearchArgs,
          'search_related_alerts': SearchArgs, 'search_zeek_connections': SearchArgs,
          'search_runbook': RunbookArgs}
DESCRIPTIONS = {
    'get_alert': 'Read the triggering alert only. alert_id must match the investigation.',
    'search_auth_events': 'Read collected authentication success AND failure events for this agent within the incident window.',
    'search_related_alerts': 'Read related Wazuh security alerts for this agent within the incident window.',
    'search_zeek_connections': 'Read historical Zeek conn observations; these are not live sockets or process ownership.',
    'search_runbook': 'Retrieve local response guidance, never proof that an event happened.'}


def definitions(allowed_tools=None):
    names = MODELS if allowed_tools is None else allowed_tools
    return [{'type':'function','function':{'name':name,'description':DESCRIPTIONS[name],
            'parameters':MODELS[name].model_json_schema()}} for name in names if name in MODELS]


def observation(record):
    """Keep evidence small without reinterpreting packet direction or inventing fields."""
    raw=record.get('raw_event') or {}
    return {**{k:record.get(k) for k in ('id','timestamp','received_at','source_product','log_type',
             'agent','rule','src_ip','dst_ip','username','event_id','process','file_path','title')},
            'event_time':utc_stamp(record['timestamp']) if record.get('timestamp') else None, 'source':'soc-ai-sqlite',
            'auth_outcome':auth_outcome(record),
            'full_log':str(raw.get('full_log') or '')[:2000],
            'data':json.dumps(raw.get('data') or {},ensure_ascii=False)[:2500],
            'zeek_connection':{k:v for k,v in (record.get('zeek_data') or {}).items() if k in
                {'ts','uid','proto','service','conn_state','duration','orig_bytes','resp_bytes',
                 'orig_pkts','resp_pkts','history','missed_bytes','id.orig_h','id.resp_h','id.orig_p','id.resp_p','id'}}}


class LocalTools:
    def __init__(self, event_store, audit, incident_id, alert, seconds=15, retrieve=None,
                 allowed_tools=None):
        self.store, self.audit, self.incident_id, self.alert = event_store,audit,incident_id,alert
        self.seconds, self.retrieve = seconds,retrieve
        self.allowed_tools = set(MODELS if allowed_tools is None else allowed_tools)
        self.agent=str((alert.get('agent') or {}).get('id') or '')
        anchor=datetime.fromisoformat(alert['timestamp'].replace('Z','+00:00'))
        self.since=utc_stamp((anchor-timedelta(minutes=15)).isoformat())
        self.until=utc_stamp((anchor+timedelta(minutes=15)).isoformat())
        self.ips={str(x) for x in (alert.get('src_ip'),alert.get('dst_ip'),(alert.get('agent') or {}).get('ip')) if x}

    def envelope(self, status, **kwargs):
        return {'status':status,'items':[], 'scope':{'agent_id':self.agent,'since':self.since,'until':self.until},
                'coverage':'Only events actually retained in SOC SQLite; absence is not proof of safety.', **kwargs}

    def execute(self, name, arguments, timeout=None):
        if name not in MODELS or name not in self.allowed_tools:
            return self.envelope('error',error='tool_not_allowed')
        try:
            args=MODELS[name].model_validate(arguments).model_dump()
            if name=='get_alert':
                if args['alert_id']!=self.alert['id']:
                    raise ValueError('alert outside incident scope')
                return self.collect(name,args,[self.alert],False,'trigger')
            if name=='search_runbook':
                return self.runbook(args,min(timeout or self.seconds,self.seconds))
            if not self.agent:
                return self.envelope('unavailable',error='agent identity missing')
            if args['agent_id'] not in (None,self.agent) or args['ip'] is not None and args['ip'] not in self.ips:
                raise ValueError('host/IP outside incident scope')
            since=utc_stamp(args['since']) if args['since'] else self.since
            until=utc_stamp(args['until']) if args['until'] else self.until
            if since<self.since or until>self.until or since>until:
                raise ValueError('time window outside incident scope')
            args.update(agent_id=self.agent,since=since,until=until)
            deadline=time.monotonic()+min(timeout or self.seconds,self.seconds)
            # mode=ro and query_only enforce the read-only boundary independently of tool arguments.
            db=sqlite3.connect(Path(self.store.path).resolve().as_uri()+'?mode=ro',uri=True,timeout=.5)
            try:
                db.execute('PRAGMA query_only=ON')
                db.set_progress_handler(lambda: int(time.monotonic()>deadline),1000)
                where=['i.agent_id=?','i.event_time>=?','i.event_time<=?']
                params=[self.agent,since,until]
                if name=='search_auth_events':
                    where.append("i.category='auth'")
                elif name=='search_zeek_connections':
                    where.extend(["i.category='network'","l.log_type='conn'"])
                else:
                    where.append("l.kind='alert'")
                if args['ip']:
                    if name=='search_auth_events':
                        where.append('i.src_ip=?'); params.append(args['ip'])
                    else:
                        where.append('(i.src_ip=? OR i.dst_ip=?)'); params.extend([args['ip'],args['ip']])
                if args['username']:
                    where.append('i.username=?');params.append(args['username'])
                auth_summary=None
                if name=='search_auth_events':
                    # Exact aggregate of the scoped retained dataset, independent of the row display limit.
                    groups=db.execute("""SELECT i.agent_id,i.username,i.src_ip,
                        SUM(f.outcome='failure'),SUM(f.outcome='success'),SUM(f.outcome='unknown'),
                        MIN(CASE WHEN f.outcome='failure' THEN i.event_time END),
                        MAX(CASE WHEN f.outcome='success' THEN i.event_time END)
                        FROM investigation_event_index i JOIN authentication_facts f ON f.id=i.id
                        WHERE """+' AND '.join(where)+' GROUP BY i.agent_id,i.username,i.src_ip ORDER BY i.agent_id,i.username,i.src_ip LIMIT 101',params).fetchall()
                    buckets={}
                    for agent,user,ip,failed,success,unknown,first,last in groups[:100]:
                        buckets[(agent,user,ip)]={'agent_id':agent,'username':user,'source_ip':ip,
                            'failure_count':failed,'success_count':success,'unknown_count':unknown,
                            'first_failure':first,'last_success':last}
                    for bucket in buckets.values():
                        bucket['failure_before_success']=bool(bucket['username'] and bucket['source_ip'] and
                            bucket['first_failure'] and bucket['last_success'] and bucket['first_failure']<bucket['last_success'])
                    auth_summary={'groups':list(buckets.values()),'groups_truncated':len(groups)>100,
                        'count_unit':'Retained normalized records, not unique authentication sessions.',
                        'counts_scope':'Exact for included agent/user/source-IP groups in retained data; not collection completeness.',
                        'interpretation':'Failure followed by success does not establish unauthorized access or compromise.'}
                params.append(args['limit']+1)
                rows=db.execute('''SELECT COALESCE(e.payload,z.payload) FROM investigation_event_index i
                    JOIN log_index l ON l.id=i.id LEFT JOIN events e ON e.id=i.id
                    LEFT JOIN zeek_logs z ON z.id=i.id WHERE '''+' AND '.join(where)+
                    ' ORDER BY i.event_time,i.id LIMIT ?',params).fetchall()
            finally:
                db.close()
            result=self.collect(name,args,[json.loads(r[0]) for r in rows[:args['limit']]],len(rows)>args['limit'])
            if auth_summary is not None:
                result['authentication_summary']=auth_summary
            return result
        except (ValueError,TypeError) as exc:
            return self.envelope('error',error='invalid_scope_or_arguments',detail=str(exc)[:500])
        except sqlite3.Error as exc:
            return self.envelope('error',error='local_query_failed',detail=str(exc)[:300])
        except Exception as exc:
            return self.envelope('error',error='tool_failed',detail=type(exc).__name__)

    def collect(self,name,args,records,truncated,kind='observed'):
        items=[]
        for record in records:
            payload=observation(record)
            # The trigger retains one identity even when returned by a related-alert search.
            evidence_kind='trigger' if record['id']==self.alert['id'] else kind
            evidence_id=self.audit.add_evidence(self.incident_id,record['id'],evidence_kind,payload,name,args)
            items.append({'evidence_id':evidence_id,**payload})
        return self.envelope('truncated' if truncated else 'ok' if items else 'empty',items=items,
                             truncated=truncated,query=args)

    def runbook(self,args,timeout):
        global _rag_pending
        if self.retrieve is None:
            def retrieve(query):
                from rag.query import smart_retrieve
                return smart_retrieve(query,top_k=3,doc_type='playbooks')
        else:
            retrieve=self.retrieve
        if _rag_pending is not None and not _rag_pending.done():
            return self.envelope('unavailable',error='local_retrieval_busy')
        _rag_pending=_rag_pool.submit(retrieve,args['query'])
        try:
            result=_rag_pending.result(timeout=timeout)
        except FutureTimeout:
            return self.envelope('unavailable',error='retrieval_timeout')
        except Exception as exc:
            return self.envelope('unavailable',error='knowledge_source_unavailable',detail=type(exc).__name__)
        if result.get('error'):
            return self.envelope('unavailable',error='knowledge_source_unavailable',detail=str(result['error'])[:300])
        items=[]
        for index,text in enumerate(result.get('documents') or []):
            metadata=(result.get('metadatas') or [{}]*3)[index]
            source_id=str((result.get('ids') or [str(i) for i in range(3)])[index])
            payload={'source':'local-knowledge-base','text':str(text)[:1800],'metadata':metadata}
            eid=self.audit.add_evidence(self.incident_id,source_id,'guidance',payload,'search_runbook',args)
            items.append({'evidence_id':eid,**payload})
        return self.envelope('ok' if items else 'empty',items=items,guidance_only=True)
