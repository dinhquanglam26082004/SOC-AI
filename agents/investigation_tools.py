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


class ScopeArgs(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    agent_id: str | None = Field(default=None, max_length=128)
    ip: str | None = Field(default=None, max_length=64)
    since: str | None = Field(default=None, max_length=64)
    until: str | None = Field(default=None, max_length=64)
    limit: int = Field(default=20, ge=1, le=100)


class SearchArgs(ScopeArgs):
    username: str | None = Field(default=None, max_length=256)


class HttpArgs(ScopeArgs):
    host: str | None = Field(default=None, min_length=1, max_length=256)
    uri_contains: str | None = Field(default=None, min_length=1, max_length=512)
    method: str | None = Field(default=None, min_length=1, max_length=32)
    status_code: int | None = Field(default=None, ge=100, le=599)
    uid: str | None = Field(default=None, min_length=1, max_length=128)


class DnsArgs(ScopeArgs):
    query: str | None = Field(default=None, min_length=1, max_length=512)
    rcode_name: str | None = Field(default=None, min_length=1, max_length=64)
    uid: str | None = Field(default=None, min_length=1, max_length=128)


class FileArgs(ScopeArgs):
    file_path: str | None = Field(default=None, min_length=1, max_length=1024)


class PrivilegeArgs(ScopeArgs):
    actor_user: str | None = Field(default=None, min_length=1, max_length=256)
    target_user: str | None = Field(default=None, min_length=1, max_length=256)


class DetailArgs(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    evidence_id: str = Field(min_length=1, max_length=128)


class FlowSummaryArgs(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    src_ip: str = Field(min_length=1, max_length=64)
    dst_ip: str = Field(min_length=1, max_length=64)
    dst_port: int = Field(ge=1, le=65535)
    since: str = Field(min_length=1, max_length=64)
    until: str = Field(min_length=1, max_length=64)


class AlertArgs(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    alert_id: str = Field(min_length=1, max_length=256)


class RunbookArgs(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    query: str = Field(min_length=1, max_length=600)


MODELS = {'get_alert': AlertArgs, 'search_auth_events': SearchArgs,
          'search_related_alerts': SearchArgs, 'search_zeek_connections': SearchArgs,
          'search_zeek_http': HttpArgs, 'search_zeek_dns': DnsArgs,
          'search_file_changes': FileArgs, 'search_privilege_events': PrivilegeArgs,
          'summarize_zeek_flows': FlowSummaryArgs,
          'get_event_details': DetailArgs,
          'search_runbook': RunbookArgs}
DESCRIPTIONS = {
    'get_alert': 'Read the triggering alert only. alert_id must match the investigation.',
    'search_auth_events': 'Read collected authentication success AND failure events for this agent within the incident window.',
    'search_related_alerts': 'Read related Wazuh security alerts for this agent within the incident window.',
    'search_zeek_connections': 'Read historical Zeek conn observations; these are not live sockets or process ownership.',
    'summarize_zeek_flows': 'Aggregate retained TCP conn records for exact alert source IP, destination IP and destination port in a bounded time window. Counts are observations, not proof of attack or service impact.',
    'search_zeek_http': 'Read retained Zeek HTTP requests/responses. Exact host, method, status and uid filters; uri_contains is literal. HTTPS content may be unavailable. A response code does not prove exploitation.',
    'search_zeek_dns': 'Read retained Zeek DNS queries/answers. query is an exact case-insensitive DNS name; uid and rcode_name are exact. Long queries alone do not prove exfiltration.',
    'search_file_changes': 'Read retained Wazuh FIM records, optionally for one exact file_path. Attribution exists only when source who-data fields exist; temporal proximity is not ownership.',
    'search_privilege_events': 'Read sudo/su records, including failures and successful command records. actor_user filters srcuser and target_user filters dstuser; these are distinct identities. A sudo request does not prove execution.',
    'get_event_details': 'Expand one already collected incident evidence_id into a bounded original record. No arbitrary record or file access. Read details when a summary is insufficient.',
    'search_runbook': 'Retrieve local response guidance, never proof that an event happened.'}


def definitions(allowed_tools=None):
    def compact(schema):
        if isinstance(schema,dict):
            return {k:compact(v) for k,v in schema.items() if k!='title'}
        if isinstance(schema,list):
            return [compact(v) for v in schema]
        return schema
    names = MODELS if allowed_tools is None else allowed_tools
    return [{'type':'function','function':{'name':name,'description':DESCRIPTIONS[name],
            'parameters':compact(MODELS[name].model_json_schema())}} for name in names if name in MODELS]


def bounded(value, budget=6000):
    """Preserve structured data and explicitly report omitted content, never cut JSON text."""
    remaining=[budget]; truncated=[False]
    def visit(item, depth=0):
        if remaining[0]<=0 or depth>8:
            truncated[0]=True
            return None
        if isinstance(item,dict):
            out={}
            for key,val in item.items():
                if remaining[0]<=0:
                    truncated[0]=True;break
                key=str(key)
                if len(key)>min(256,remaining[0]):
                    truncated[0]=True;continue
                remaining[0]-=len(key)+4
                out[key]=visit(val,depth+1)
            return out
        if isinstance(item,list):
            out=[]
            for val in item:
                if remaining[0]<=0:
                    truncated[0]=True;break
                out.append(visit(val,depth+1))
            return out
        if isinstance(item,str):
            size=min(len(item),max(0,remaining[0]));remaining[0]-=size
            truncated[0]|=size<len(item)
            return item[:size]
        remaining[0]-=len(str(item))+2
        return item
    result=visit(value)
    return result,truncated[0]


def observation(record):
    """Keep evidence small without reinterpreting packet direction or inventing fields."""
    raw=record.get('raw_event') or {}
    data=raw.get('data') or {};zeek=record.get('zeek_data') or {}
    fields=('ts','uid','id','id.orig_h','id.orig_p','id.resp_h','id.resp_p','proto','service',
            'conn_state','duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','history','missed_bytes')
    network={k:zeek[k] for k in fields if k in zeek}
    http={k:zeek[k] for k in ('method','host','uri','status_code','status_msg','user_agent',
         'request_body_len','response_body_len','trans_depth') if k in zeek}
    dns={k:zeek[k] for k in ('query','qtype_name','rcode_name','answers','TTLs','rejected') if k in zeek}
    privilege_source=bool(set((record.get('rule') or {}).get('groups') or []) & {'sudo','su'}) or (
        (raw.get('decoder') or {}).get('name') in {'sudo','su'} or
        (raw.get('predecoder') or {}).get('program_name') in {'sudo','su'})
    structured,cut=bounded({'zeek_connection':network,'http':http,'dns':dns,
        'file_change':raw.get('syscheck') or {},
        'privilege':{k:data[k] for k in ('srcuser','dstuser','command','tty','pwd') if k in data} if privilege_source else {}})
    return {**{k:record.get(k) for k in ('id','timestamp','received_at','source_product','log_type',
             'agent','rule','src_ip','dst_ip','src_port','dst_port','username','event_id','process','file_path','title')},
            'event_time':utc_stamp(record['timestamp']) if record.get('timestamp') else None, 'source':'soc-ai-sqlite',
            'auth_outcome':auth_outcome(record),
            'full_log':str(raw.get('full_log') or '')[:2000],
            'data':json.dumps(raw.get('data') or {},ensure_ascii=False)[:2500],
            **structured,'summary_truncated':cut or len(str(raw.get('full_log') or ''))>2000
                or len(json.dumps(data,ensure_ascii=False))>2500}


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
                'coverage':'Only events actually retained in SOC SQLite; absence is not proof of safety. Empty results cannot establish whether collection is configured.', **kwargs}

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
            if name=='summarize_zeek_flows':
                return self.summarize_flows(args,min(timeout or self.seconds,self.seconds))
            if name=='get_event_details':
                return self.event_details(args,min(timeout or self.seconds,self.seconds))
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
                payload='COALESCE(e.payload,z.payload)'
                def field(path):
                    # Paths are constants defined by the tool, never supplied SQL.
                    return "json_extract("+payload+", '$."+path+"')"
                if name=='search_auth_events':
                    where.append("i.category='auth'")
                elif name in {'search_zeek_connections','search_zeek_http','search_zeek_dns'}:
                    kind={'search_zeek_connections':'conn','search_zeek_http':'http','search_zeek_dns':'dns'}[name]
                    where.extend(["i.category='network'","l.origin='zeek'","l.log_type=?"])
                    params.append(kind)
                elif name=='search_file_changes':
                    where.extend(["i.category!='network'",field('raw_event.syscheck.path')+' IS NOT NULL'])
                elif name=='search_privilege_events':
                    where.extend(["i.category!='network'",'('+field('raw_event.decoder.name')+" IN ('sudo','su') OR "+
                        field('raw_event.predecoder.program_name')+" IN ('sudo','su') OR EXISTS (SELECT 1 FROM json_each("+
                        payload+", '$.rule.groups') WHERE value IN ('sudo','su')))"])
                else:
                    where.append("l.kind='alert'")
                if args['ip']:
                    if name=='search_auth_events':
                        where.append('i.src_ip=?'); params.append(args['ip'])
                    else:
                        where.append('(i.src_ip=? OR i.dst_ip=?)'); params.extend([args['ip'],args['ip']])
                if args.get('username'):
                    where.append('i.username=?');params.append(args['username'])
                exact_fields={'uid':'zeek_data.uid','file_path':'raw_event.syscheck.path',
                    'actor_user':'raw_event.data.srcuser','target_user':'raw_event.data.dstuser'}
                for arg,path in exact_fields.items():
                    if args.get(arg) is not None:
                        where.append(field(path)+'=?');params.append(args[arg])
                for arg in ('host','query','method','rcode_name'):
                    if args.get(arg) is not None:
                        where.append('LOWER('+field('zeek_data.'+arg)+')=LOWER(?)');params.append(args[arg])
                if args.get('uri_contains') is not None:
                    where.append('instr('+field('zeek_data.uri')+',?)>0');params.append(args['uri_contains'])
                if args.get('status_code') is not None:
                    where.append('CAST('+field('zeek_data.status_code')+' AS INTEGER)=?');params.append(args['status_code'])
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
                source=''' FROM investigation_event_index i
                    JOIN log_index l ON l.id=i.id LEFT JOIN events e ON e.id=i.id
                    LEFT JOIN zeek_logs z ON z.id=i.id WHERE '''+' AND '.join(where)
                total=db.execute('SELECT COUNT(*)'+source,params).fetchone()[0]
                rows=db.execute('SELECT '+payload+source+
                    ' ORDER BY i.event_time,i.id LIMIT ?',params+[args['limit']+1]).fetchall()
            finally:
                db.close()
            result=self.collect(name,args,[json.loads(r[0]) for r in rows[:args['limit']]],len(rows)>args['limit'])
            if auth_summary is not None:
                result['authentication_summary']=auth_summary
            result.update(total_matched=total,returned_count=len(result['items']),
                count_unit='Retained records matching this query; not unique sessions or proof of collection completeness.')
            return result
        except (ValueError,TypeError) as exc:
            return self.envelope('error',error='invalid_scope_or_arguments',detail=str(exc)[:500])
        except sqlite3.Error as exc:
            return self.envelope('error',error='local_query_failed',detail=str(exc)[:300])
        except Exception as exc:
            return self.envelope('error',error='tool_failed',detail=type(exc).__name__)

    def summarize_flows(self,args,timeout):
        from agents.zeek_flow_summary import summarize
        result=summarize(self.store.path,self.agent,self.alert,args,self.since,self.until,timeout)
        if result['status']!='ok':
            return self.envelope(**result)
        samples=self.collect('summarize_zeek_flows',args,result.pop('samples'),False)
        import hashlib
        source_id='aggregate-'+hashlib.sha256(json.dumps([self.agent,args],sort_keys=True).encode()).hexdigest()
        payload={'source':'derived-soc-sqlite','event_time':args['until'],'flow_summary':result['summary']}
        eid=self.audit.add_evidence(self.incident_id,source_id,'aggregate',payload,'summarize_zeek_flows',args)
        return self.envelope('ok',items=samples['items'],summary=result['summary'],aggregate_evidence_id=eid,query=args)

    def event_details(self,args,timeout):
        evidence=next((e for e in self.audit.evidence(self.incident_id)
                       if e['evidence_id']==args['evidence_id'] and e['evidence_type']!='guidance'),None)
        if evidence is None:
            raise ValueError('evidence ID is not a collected event in this investigation')
        deadline=time.monotonic()+timeout
        db=sqlite3.connect(Path(self.store.path).resolve().as_uri()+'?mode=ro',uri=True,timeout=.5)
        try:
            db.execute('PRAGMA query_only=ON')
            db.set_progress_handler(lambda:int(time.monotonic()>deadline),1000)
            row=db.execute('''SELECT COALESCE(e.payload,z.payload) FROM investigation_event_index i
                LEFT JOIN events e ON e.id=i.id LEFT JOIN zeek_logs z ON z.id=i.id
                WHERE i.id=? AND i.agent_id=? AND i.event_time>=? AND i.event_time<=?''',
                (evidence['source_record_id'],self.agent,self.since,self.until)).fetchone()
        finally:
            db.close()
        if row is None:
            return self.envelope('unavailable',error='collected_event_no_longer_retained_or_outside_scope')
        record=json.loads(row[0]);detail,cut=bounded(record.get('raw_event') or {},budget=10000)
        evidence['data'].update(event_details=detail,details_requested=True,details_truncated=cut)
        # Enrich the same evidence identity. A repeated read is not independent corroboration.
        with self.audit.connect() as audit_db:
            audit_db.execute('UPDATE evidence SET payload=? WHERE incident_id=? AND id=?',
                (json.dumps(evidence,ensure_ascii=False),self.incident_id,evidence['evidence_id']))
        return self.envelope('truncated' if cut else 'ok',items=[{
            'evidence_id':evidence['evidence_id'],'evidence_type':evidence['evidence_type'],
            **evidence['data']}],truncated=cut,query=args)

    def collect(self,name,args,records,truncated,kind='observed'):
        items=[]
        for record in records:
            payload=observation(record)
            # The trigger retains one identity even when returned by a related-alert search.
            evidence_kind='trigger' if record['id']==self.alert['id'] else kind
            evidence_id=self.audit.add_evidence(self.incident_id,record['id'],evidence_kind,payload,name,args)
            items.append({'evidence_id':evidence_id,'evidence_type':evidence_kind,**payload})
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
            items.append({'evidence_id':eid,'evidence_type':'guidance',**payload})
        return self.envelope('ok' if items else 'empty',items=items,guidance_only=True)
