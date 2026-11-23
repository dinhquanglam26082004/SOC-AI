"""Allowlisted, bounded local reads. Log contents are untrusted observations."""
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from collections import Counter
from datetime import datetime, timedelta, timezone
import json
import ipaddress
import re
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
    domain_suffix: str | None = Field(default=None, min_length=3, max_length=253)
    qtype_name: str | None = Field(default=None, min_length=1, max_length=16)
    rcode_name: str | None = Field(default=None, min_length=1, max_length=64)
    uid: str | None = Field(default=None, min_length=1, max_length=128)


class DnsSummaryArgs(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    domain: str = Field(min_length=1, max_length=253)
    since: str = Field(min_length=1, max_length=64)
    until: str = Field(min_length=1, max_length=64)


class DnsBaselineArgs(DnsSummaryArgs):
    baseline_since: str = Field(min_length=1, max_length=64)
    baseline_until: str = Field(min_length=1, max_length=64)


class FileArgs(ScopeArgs):
    file_path: str | None = Field(default=None, min_length=1, max_length=1024)


class PrivilegeArgs(ScopeArgs):
    actor_user: str | None = Field(default=None, min_length=1, max_length=256)
    target_user: str | None = Field(default=None, min_length=1, max_length=256)


class AccountArgs(ScopeArgs):
    account: str | None = Field(default=None, min_length=1, max_length=256)
    group: str | None = Field(default=None, min_length=1, max_length=256)


class RootkitArgs(ScopeArgs):
    pid: int | None = Field(
        default=None,
        ge=1,
        le=4194304,
    )

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
          'search_account_events': AccountArgs,
          'summarize_zeek_flows': FlowSummaryArgs,
          'summarize_dns_activity': DnsSummaryArgs, 'compare_dns_baseline': DnsBaselineArgs,
          'search_process_events': ScopeArgs, 'search_file_access': FileArgs,
          'get_event_details': DetailArgs,
          'search_runbook': RunbookArgs,
          'search_rootkit_evidence': RootkitArgs,
          }
DESCRIPTIONS = {
    # Rule IDs are examples for interpretation, not an automatic routing policy.
    # Keep descriptions compact because all tool schemas share the model context.
    'get_alert': (
        'System-called first for any rule: read the triggering alert, agent, time and fields. '
        'alert_id must equal the investigation alert.'),
    'search_auth_events': (
        'For login failures or SSH brute force, e.g. rules 2502/100172: find retained '
        'auth successes and failures, with counts by user and source IP. The IP must be '
        'in incident scope; records are not unique sessions or proof of compromise.'),
    'search_related_alerts': (
        'For any rule, look for other retained security alerts on the same agent and time '
        'window; optionally filter by scoped IP or user. May include the trigger itself. '
        'Proximity alone does not prove a causal link.'),
    'search_zeek_connections': (
        'For scan, DoS or DNS activity, e.g. rules 100141/100142/100143/100145, '
        'inspect retained Zeek conn flows and bytes. Scoped IP matches either endpoint; '
        'there is no port filter. Rows are bounded historical observations, not live sockets.'),
    'summarize_zeek_flows': (
        'For single-source TCP bursts, e.g. rule 100142, aggregate retained flows, '
        'packets and IP bytes and their average rates. Source, destination and port must '
        'exactly match the trigger. It cannot total all sources in DDoS or prove impact.'),
    'search_zeek_http': (
        'For web alerts 100130-100134, inspect retained HTTP method, host, URI and status. '
        'host/method/status/uid are exact; uri_contains is literal. HTTPS content can be '
        'missing; a response code does not prove exploitation.'),
    'search_zeek_dns': (
        'For DNS anomaly/tunneling rules 100151/100153/100156/100157/100181, '
        'list retained queries, types and answers. Filter with domain_suffix (the domain and '
        'all its subdomains) and/or qtype_name, otherwise unrelated lookups (PTR, NTP) dominate. '
        'query matches one full name exactly; use summarize_dns_activity for counts.'),
    'summarize_dns_activity': (
        'For DNS tunneling or query bursts, e.g. 100153/100156/100157/100181, count '
        'retained queries for the supplied domain and subdomains: distinct names, types, '
        'response codes, lengths and counts per minute. Duplicates may exist; not proof of tunneling.'),
    'compare_dns_baseline': (
        'For DNS anomaly/tunneling, compare the same domain in two equal-length windows: '
        'baseline first, no overlap, both within incident scope. Reports retained counts '
        'and distributions, not a historical multi-day baseline or proof of normality.'),
    'search_process_events': (
        'For suspected execution after DNS, SSH or file alerts, inspect retained Wazuh '
        'audit_command records for the agent and window. Requires collection of that group; '
        'not live process enumeration and no result does not prove absence.'),
    'search_file_access': (
        'For suspected file reads or exfiltration, inspect retained audit_watch_read events; '
        'file_path is exact. Requires the relevant audit records to be collected. FIM '
        'changes do not prove a read, and no result does not prove no access.'),
    'search_file_changes': (
        'For FIM alerts such as rule 550 or suspected persistence, read retained syscheck '
        'file changes; file_path is exact. A user/process is attributable only when '
        'who-data is present; a file change is not a file-read event.'),
    'search_privilege_events': (
        'For suspicious sudo/su or escalation around any alert, inspect retained sudo/su '
        'records. actor_user matches srcuser and target_user matches dstuser; they are '
        'different identities. A request or failure alone does not prove execution.'),
    'search_account_events': (
        'For Linux account or group changes, especially rules 5901/101200/101201/101202, '
        'find retained account creation and group membership alerts for this agent and time window. '
        'Filter by account/group text when known. This is historical alert evidence, not live account state.'),
    'get_event_details': (
        'When a collected event summary is insufficient, expand its evidence_id into a '
        'bounded original record. Only incident event evidence is accepted; guidance and '
        'aggregates are not raw event IDs. Details may be truncated or no longer retained.'),
    'search_runbook': (
        'For any incident needing investigation or response steps, search local indexed '
        'playbooks by query. Retrieved guidance is not evidence and does not perform an action.'),
    'search_rootkit_evidence': (
        'Only for rule 521 or rootcheck alerts whose description mentions rootkit/hidden: '
        'find retained related alerts and existing endpoint snapshots for the agent/window. '
        'If supplied, pid must match the trigger. No live scan; repeated alerts are not independent proof.'),
    }


def definitions(allowed_tools=None):
    # Tool schemas are rendered into every planning prompt of a small-context local model.
    # Publish only names, types and descriptions; Pydantic still enforces optionality,
    # length and range limits on every call, so dropping them here loses no safety.
    def compact(schema):
        if isinstance(schema,dict):
            options=schema.get('anyOf')
            if isinstance(options,list):
                concrete=[o for o in options if o.get('type')!='null']
                if len(concrete)==1:
                    schema={**{k:v for k,v in schema.items() if k!='anyOf'},**concrete[0]}
            return {k:compact(v) for k,v in schema.items()
                    if k not in {'title','maxLength','minLength','additionalProperties','minimum','maximum'}
                    and not (k=='default' and v is None)}
        if isinstance(schema,list):
            return [compact(v) for v in schema]
        return schema
    names = (name for name in MODELS if name != 'get_alert') if allowed_tools is None else allowed_tools
    result=[]
    for name in names:
        if name not in MODELS:
            continue
        schema=compact(MODELS[name].model_json_schema())
        schema.setdefault('properties', {}).update({
            '_verification_question': {'type':'string', 'description':'Câu hỏi cần xác minh'},
            '_selection_reason': {'type':'string', 'description':'Lý do chọn'},
        })
        result.append({'type':'function','function':{'name':name,'description':DESCRIPTIONS[name], 'parameters':schema}})
    return result


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


_LISTENER_LINE = re.compile(r'^\s*(tcp6?|udp6?)\s+(.+)$', re.I)
_LOCAL_ENDPOINT = re.compile(r'^(\[[^\]]+\]|[^:\s]+):(\d{1,5})$')
_PROCESS_OWNER = re.compile(r'(?<!\S)(\d+)/([^\s]+)')


def _listener_rows(value):
    """Parse local socket rows only; leave unrecognized source text unclaimed."""
    rows={}
    for line in value.splitlines():
        match=_LISTENER_LINE.match(line)
        if not match:
            continue
        protocol=match.group(1).lower()
        tokens=match.group(2).split()
        endpoint=next((m for token in tokens if (m:=_LOCAL_ENDPOINT.fullmatch(token))
                       and 0<int(m.group(2))<=65535),None)
        if not endpoint:
            continue
        address=endpoint.group(1).strip('[]')
        port=int(endpoint.group(2))
        owner=_PROCESS_OWNER.search(match.group(2))
        row={'protocol':protocol,'address':address,'port':port}
        if owner:
            row.update(pid=int(owner.group(1)),process=owner.group(2))
        rows[(protocol,address,port)]=row
    return rows


def compare_listener_snapshots(full_log,previous_output):
    """Derive snapshot differences from retained alert fields, never from model text."""
    current=_listener_rows(full_log)
    previous=_listener_rows(previous_output)
    if not current and not previous:
        return None
    comparable=bool(full_log.strip() and previous_output.strip() and current and previous)
    added=[current[key] for key in sorted(current.keys()-previous.keys())] if comparable else []
    removed=[previous[key] for key in sorted(previous.keys()-current.keys())] if comparable else []
    return {'source_fields':['raw_event.full_log','raw_event.previous_output'],
            'comparison_complete':comparable,
            'current_listeners':len(current),'previous_listeners':len(previous),
            'added':added[:30],'removed':removed[:30],
            'added_total':len(added),'removed_total':len(removed),
            'changes_omitted':len(added)>30 or len(removed)>30,
            'interpretation':'Snapshot difference only; process intent, authorization and cause are unknown.'}


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
    rootkit_snapshot = (data if isinstance(data, dict) and data.get('producer') == 'soc-ai-rootkit-snapshot-v1' else {})
    structured,cut=bounded({'zeek_connection':network,'http':http,'dns':dns,'audit':data.get('audit') if isinstance(data.get('audit'),dict) else {},
        'file_change':raw.get('syscheck') or {},
        'privilege':{k:data[k] for k in ('srcuser','dstuser','command','tty','pwd') if k in data} if privilege_source else {},
        'rootkit_snapshot': {
            k: rootkit_snapshot.get(k)
            for k in (
               'producer',
               'observed_at',
               'scan',
               'suspects',
               'modules',
               'interpretation',
            )
            if k in rootkit_snapshot
        },
    })
    full_log=str(raw.get('full_log') or '')
    previous_output=str(raw.get('previous_output') or data.get('previous_output') or '')
    listener_changes=compare_listener_snapshots(full_log,previous_output)
    return {**{k:record.get(k) for k in ('id','timestamp','received_at','source_product','log_type',
             'agent','rule','src_ip','dst_ip','src_port','dst_port','username','event_id','process','file_path','title')},
            'event_time':utc_stamp(record['timestamp']) if record.get('timestamp') else None, 'source':'soc-ai-sqlite',
            'auth_outcome':auth_outcome(record),
            'full_log':full_log[:2000],
            'previous_output':previous_output[:3000],
            **({'listener_changes':listener_changes} if listener_changes else {}),
            'data':json.dumps(raw.get('data') or {},ensure_ascii=False)[:2500],
            **structured,'summary_truncated':cut or len(full_log)>2000
                or len(previous_output)>3000
                or len(json.dumps(data,ensure_ascii=False))>2500}


def summarize_dns_records(path, agent, domain, since, until, timeout):
    domain=domain.lower().rstrip('.')
    if not domain or len(domain)>253 or any(not part for part in domain.split('.')):
        raise ValueError('A valid exact domain suffix is required')
    since,until=utc_stamp(since),utc_stamp(until)
    if since>=until: raise ValueError('Window must have positive duration')
    deadline=time.monotonic()+timeout
    db=sqlite3.connect(Path(path).resolve().as_uri()+'?mode=ro',uri=True,timeout=.5)
    db.execute('PRAGMA query_only=ON');db.set_progress_handler(lambda:int(time.monotonic()>deadline),1000)
    count=0;missing=0;names=set();types=Counter();rcodes=Counter();minutes=Counter();fallback=[];lengths=[];first=None;last=None
    first_sample=last_sample=longest_sample=success_sample=error_sample=None
    try:
        rows=db.execute('''SELECT i.event_time,COALESCE(e.payload,z.payload) FROM investigation_event_index i
            JOIN log_index l ON l.id=i.id LEFT JOIN events e ON e.id=i.id LEFT JOIN zeek_logs z ON z.id=i.id
            WHERE i.agent_id=? AND i.event_time>=? AND i.event_time<? AND l.origin='zeek' AND l.log_type='dns'
            ORDER BY i.event_time,i.id''',(agent,since,until))
        scanned=0
        for stamp,payload in rows:
            scanned+=1
            if scanned>100000: return {'status':'unavailable','error':'aggregation_record_limit','detail':'Narrow the window; no partial totals returned.'}
            record=json.loads(payload);z=record.get('zeek_data') or {};q=z.get('query')
            if not isinstance(q,str) or not q.strip(): missing+=1;continue
            q=q.lower().rstrip('.')
            if q!=domain and not q.endswith('.'+domain): continue
            count+=1;names.add(q);lengths.append(len(q));types[str(z.get('qtype_name') or 'unknown')]+=1;rcodes[str(z.get('rcode_name') or 'unknown')]+=1;minutes[stamp[:16]]+=1
            first=first or stamp;last=stamp
            if first_sample is None:first_sample=record
            last_sample=record
            if longest_sample is None or len(q)>longest_sample[0]:longest_sample=(len(q),record)
            response=str(z.get('rcode_name') or '').upper()
            if response=='NOERROR' and success_sample is None:success_sample=record
            if response and response not in ('NOERROR','UNKNOWN') and error_sample is None:error_sample=record
            if len(fallback)<5:fallback.append(record)
    finally: db.close()
    # These are deliberately diverse examples, not a random or representative sample.
    samples=[];sample_ids=set()
    candidates=[first_sample,last_sample,longest_sample[1] if longest_sample else None,error_sample,success_sample,*fallback]
    for record in candidates:
        if record is not None and record['id'] not in sample_ids:
            samples.append(record);sample_ids.add(record['id'])
            if len(samples)==5:break
    seconds=(datetime.fromisoformat(until.replace('Z','+00:00'))-datetime.fromisoformat(since.replace('Z','+00:00'))).total_seconds()
    return {'status':'ok','summary':{'scope':{'agent_id':agent,'domain':domain,'since':since,'until':until,'window_seconds':seconds},
        'matched_records':count,'unique_queries':len(names),'unique_subdomains':sum(q!=domain for q in names),
        'first_event_time':first,'last_event_time':last,'query_types':dict(types),'response_codes':dict(rcodes),
        'counts_by_minute_utc':dict(minutes),'average_query_length':sum(lengths)/len(lengths) if lengths else None,
        'max_query_length':max(lengths) if lengths else None,'records_missing_query_in_scope':missing,
        'timestamp_basis':'normalized event time; half-open window [since, until)',
        'sample_selection':'Up to five distinct records: first, last, longest query, first error and first NOERROR where available; remaining slots use early records. Not a representative sample.',
        'coverage':'Counts are retained records, not unique DNS requests or complete capture; duplicates may exist. Missing query records cannot be attributed to a domain.'},'samples':samples}


def compare_dns_records(path, agent, args, timeout):
    names=('baseline_since','baseline_until','since','until')
    values=[utc_stamp(args[n]) for n in names]
    b0,b1,i0,i1=values
    stamp=lambda v:datetime.fromisoformat(v.replace('Z','+00:00'))
    if not b0<b1<=i0<i1 or (stamp(b1)-stamp(b0))!=(stamp(i1)-stamp(i0)):
        raise ValueError('Baseline must precede incident without overlap; windows must have equal duration')
    before=summarize_dns_records(path,agent,args['domain'],b0,b1,timeout/2)
    if before['status']!='ok':return before
    during=summarize_dns_records(path,agent,args['domain'],i0,i1,timeout/2)
    if during['status']!='ok':return during
    return {'status':'ok','baseline':before['summary'],'incident':during['summary'],
            'samples':during['samples'], 'interpretation':'Comparison of retained records only; missing data and normal variability are not ruled out.'}


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

    def normalized_args(self, name, arguments):
        """Canonical query identity, including defaults and the effective incident scope."""
        args = MODELS[name].model_validate(arguments).model_dump()
        if name in {'get_alert', 'get_event_details', 'search_runbook'}:
            return args
        for key in ('since', 'until', 'baseline_since', 'baseline_until'):
            if key in args and args[key] is not None:
                args[key] = utc_stamp(args[key])
        if 'agent_id' in args:
            # Preserve an invalid requested agent so scope validation still rejects it.
            args['agent_id'] = self.agent if args['agent_id'] is None else args['agent_id']
            if args['agent_id'] == str((self.alert.get('agent') or {}).get('ip') or ''):
                # The alert gives an unambiguous mapping from its agent IP to agent ID.
                args['agent_id'] = self.agent
            args['since'] = args['since'] or self.since
            args['until'] = args['until'] or self.until
        for key in ('host', 'query', 'method', 'rcode_name', 'qtype_name', 'domain_suffix', 'domain'):
            if args.get(key) is not None:
                args[key] = args[key].lower().rstrip('.') if key in {'domain', 'domain_suffix'} else args[key].lower()
        return args

    def scoped_ips(self):
        """IPs observed for this agent and incident; never infer them from prose."""
        ips=set(self.ips)
        for item in self.audit.evidence(self.incident_id):
            if item.get('evidence_type') not in {'trigger','observed'}:
                continue
            data=item.get('data') or {}
            agent=data.get('agent') or {}
            if str(agent.get('id') or '')!=self.agent:
                continue
            stamp=item.get('event_time')
            if not stamp or not self.since<=stamp<=self.until:
                continue
            conn=data.get('zeek_connection') or {}
            endpoints=conn.get('id') or {}
            for value in (data.get('src_ip'),data.get('dst_ip'),conn.get('id.orig_h'),
                          conn.get('id.resp_h'),endpoints.get('orig_h'),endpoints.get('resp_h')):
                if isinstance(value,str):
                    try: ips.add(str(ipaddress.ip_address(value)))
                    except ValueError: pass
        return ips

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
            if name in {'summarize_dns_activity','compare_dns_baseline'}:
                return self.dns_aggregate(name,args,min(timeout or self.seconds,self.seconds))
            if name=='summarize_zeek_flows':
                return self.summarize_flows(args,min(timeout or self.seconds,self.seconds))
            if name=='get_event_details':
                return self.event_details(args,min(timeout or self.seconds,self.seconds))
            if args['agent_id'] not in (None,self.agent):
                raise ValueError('agent_id outside incident scope')
            if args['ip'] is not None and args['ip'] not in self.scoped_ips():
                raise ValueError('IP not present in alert or collected incident evidence')
            since=utc_stamp(args['since']) if args['since'] else self.since
            until=utc_stamp(args['until']) if args['until'] else self.until
            if since<self.since or until>self.until or since>until:
                raise ValueError('time window outside incident scope')
            args.update(agent_id=self.agent,since=since,until=until)
            if name == 'search_rootkit_evidence':
                return self.rootkit_evidence(args, min(timeout or self.seconds, self.seconds,),)
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
                elif name in {'search_process_events','search_file_access'}:
                    group='audit_command' if name=='search_process_events' else 'audit_watch_read'
                    where.extend(["i.category!='network'", "EXISTS (SELECT 1 FROM json_each("+payload+", '$.rule.groups') WHERE value=?)"])
                    params.append(group)
                elif name=='search_privilege_events':
                    where.extend(["i.category!='network'",'('+field('raw_event.decoder.name')+" IN ('sudo','su') OR "+
                        field('raw_event.predecoder.program_name')+" IN ('sudo','su') OR EXISTS (SELECT 1 FROM json_each("+
                        payload+", '$.rule.groups') WHERE value IN ('sudo','su')))"])
                elif name=='search_account_events':
                    where.extend(["l.kind='alert'",
                        "(CAST("+field('rule.id')+" AS TEXT) IN ('5901','101200','101201','101202') OR EXISTS (SELECT 1 FROM json_each("+
                        payload+", '$.rule.groups') WHERE value IN ('account_management','privilege_escalation')))"])
                else:
                    where.append("l.kind='alert'")
                if args['ip']:
                    if name=='search_auth_events':
                        where.append('i.src_ip=?'); params.append(args['ip'])
                    else:
                        where.append('(i.src_ip=? OR i.dst_ip=?)'); params.extend([args['ip'],args['ip']])
                if args.get('username'):
                    where.append('i.username=?');params.append(args['username'])
                if args.get('account'):
                    where.append("(instr(LOWER(COALESCE("+field('raw_event.full_log')+",'')),?)>0 OR LOWER(COALESCE(i.username,''))=?)")
                    account=args['account'].lower()
                    params.extend([account,account])
                if args.get('group'):
                    where.append("instr(LOWER(COALESCE("+field('raw_event.full_log')+",'')),?)>0")
                    params.append(args['group'].lower())
                exact_fields={'uid':'zeek_data.uid','file_path':('raw_event.data.audit.file.name' if name=='search_file_access' else 'raw_event.syscheck.path'),
                    'actor_user':'raw_event.data.srcuser','target_user':'raw_event.data.dstuser'}
                for arg,path in exact_fields.items():
                    if args.get(arg) is not None:
                        where.append(field(path)+'=?');params.append(args[arg])
                if args.get('domain_suffix') is not None:
                    suffix=args['domain_suffix'].lower().rstrip('.')
                    q='LOWER('+field('zeek_data.query')+')'
                    where.append('('+q+'=? OR substr('+q+',-?)=?)');params.extend([suffix,len(suffix)+1,'.'+suffix])
                if args.get('qtype_name') is not None:
                    where.append('UPPER('+field('zeek_data.qtype_name')+')=UPPER(?)');params.append(args['qtype_name'])
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
                    auth_summary={'scope':{'agent_id':self.agent,'since':since,'until':until,
                                           'source_ip':args.get('ip'),'username':args.get('username')},
                        'groups':list(buckets.values()),'groups_truncated':len(groups)>100,
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
                import hashlib
                source_id='auth-aggregate-'+hashlib.sha256(json.dumps(auth_summary['scope'],sort_keys=True).encode()).hexdigest()
                result['aggregate_evidence_id']=self.audit.add_evidence(
                    self.incident_id,source_id,'aggregate',
                    {'source':'derived-soc-sqlite','event_time':until,'authentication_summary':auth_summary},name,args)
            result.update(total_matched=total,returned_count=len(result['items']),
                count_unit='Retained records matching this query; not unique sessions or proof of collection completeness.')
            if name=='search_process_events':
                result['coverage']=('Only retained Wazuh events with rule.groups containing audit_command '
                    'for this agent and time window. This is not live process enumeration or a general '
                    'process-creation feed; collection and forwarding completeness are unknown.')
                if total==0:
                    result['detail']=('No retained audit_command event matched this query. '
                        'This does not establish that the process did not run or that its activity was malicious.')
            return result
        except (ValueError,TypeError) as exc:
            return self.envelope('error',error='invalid_scope_or_arguments',detail=str(exc)[:500])
        except sqlite3.Error as exc:
            return self.envelope('error',error='local_query_failed',detail=str(exc)[:300])
        except Exception as exc:
            return self.envelope('error',error='tool_failed',detail=type(exc).__name__)
    def rootkit_evidence(self, args, timeout):
        from agents.rootkit_evidence import search

        rule = self.alert.get('rule') or {}
        groups = set(rule.get('groups') or [])
        description = str(rule.get('description') or '').lower()
        is_rootkit = (
            str(rule.get('id')) == '521'
            or 'rootcheck' in groups
            and ('rootkit' in description or 'hidden' in description)
        )

        if not is_rootkit:
            return self.envelope('error', error='not_a_rootkit_alert')

        query = search(
            db_path=self.store.path,
            agent_id=self.agent,
            since=args['since'],
            until=args['until'],
            alert=self.alert,
            pid=args.get('pid'),
            limit=args['limit'],
            timeout=timeout,
        )
        result = self.collect(
            'search_rootkit_evidence',
            args,
            query['records'],
            query['truncated'],
        )
        result['status'] = 'truncated' if query['truncated'] else query['status']

        for key, value in query.items():
            if key not in {'records', 'status', 'truncated'}:
                result[key] = value
        result['returned_count'] = len(result['items'])
        return result

    def dns_aggregate(self,name,args,timeout):
        for key in ('since','until','baseline_since','baseline_until'):
            if key in args:
                args[key]=utc_stamp(args[key])
                if args[key]<self.since or args[key]>self.until:
                    raise ValueError('time window outside incident scope')
        result=(summarize_dns_records(self.store.path,self.agent,args['domain'],args['since'],args['until'],timeout)
                if name=='summarize_dns_activity' else compare_dns_records(self.store.path,self.agent,args,timeout))
        if result['status']!='ok':return self.envelope(**result)
        samples=self.collect(name,args,result.pop('samples'),False)
        import hashlib
        source_id='aggregate-'+hashlib.sha256(json.dumps([name,self.agent,args],sort_keys=True).encode()).hexdigest()
        summary=result.get('summary') or {'baseline':result['baseline'],'incident':result['incident'],'interpretation':result['interpretation']}
        payload={'source':'derived-soc-sqlite','event_time':args['until'],'dns_summary':summary}
        eid=self.audit.add_evidence(self.incident_id,source_id,'aggregate',payload,name,args)
        return self.envelope('ok',items=samples['items'],summary=summary,aggregate_evidence_id=eid,query=args)

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
        dossier=self.audit.evidence(self.incident_id)
        evidence=next((e for e in dossier
                       if e['evidence_id']==args['evidence_id'] and e['evidence_type']!='guidance'),None)
        if evidence is None:
            raise ValueError('evidence ID is not a collected event in this investigation')
        trigger=next((e for e in dossier if e['evidence_type']=='trigger'),None)
        change=((trigger or {}).get('data') or {}).get('listener_changes') or {}
        if (evidence['data'].get('source_product')=='zeek' and change.get('comparison_complete')
                and not change.get('changes_omitted')):
            changed_ports={row['port'] for row in change.get('added',[])+change.get('removed',[])}
            network=evidence['data'].get('zeek_connection') or {}
            ports=(evidence['data'].get('src_port'),evidence['data'].get('dst_port'),
                   network.get('id.orig_p'),network.get('id.resp_p'))
            related_ports={int(port) for port in ports if str(port).isdigit()}
            if changed_ports and not changed_ports.intersection(related_ports):
                return self.envelope('error',error='irrelevant_to_source_change',
                    detail='Zeek event has no port matching a changed listener; proximity alone does not justify expanding it.')
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
