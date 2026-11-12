"""Bounded aggregation of retained Zeek TCP records; never infer service impact."""
from collections import Counter
from datetime import datetime
import hashlib
import ipaddress
import json
from pathlib import Path
import sqlite3
import time

from common.log_index import utc_stamp


def summarize(path, agent, alert, args, lower, upper, timeout):
    try:
        src=str(ipaddress.ip_address(args['src_ip'])); dst=str(ipaddress.ip_address(args['dst_ip']))
        since=utc_stamp(args['since']); until=utc_stamp(args['until'])
        if src != alert.get('src_ip') or dst != alert.get('dst_ip') or str(args['dst_port']) != str(alert.get('dst_port')):
            raise ValueError('Source, destination and port must match the triggering alert')
        seconds=(datetime.fromisoformat(until.replace('Z','+00:00'))-datetime.fromisoformat(since.replace('Z','+00:00'))).total_seconds()
        if since<lower or until>upper or not 0<seconds<=1800:
            raise ValueError('Window must be within incident scope and have positive duration')
    except (ValueError,TypeError) as exc:
        return {'status':'error','error':'invalid_scope_or_arguments','detail':str(exc)[:300]}
    deadline=time.monotonic()+timeout
    db=sqlite3.connect(Path(path).resolve().as_uri()+'?mode=ro',uri=True,timeout=.5)
    db.execute('PRAGMA query_only=ON');db.set_progress_handler(lambda:int(time.monotonic()>deadline),1000)
    fields=('orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes')
    totals=Counter();missing=Counter();states=Counter();seen=set();samples=[];duplicates=0;unknown_identity=0;count=0
    try:
        rows=db.execute('''SELECT COALESCE(e.payload,z.payload) FROM investigation_event_index i
            JOIN log_index l ON l.id=i.id LEFT JOIN events e ON e.id=i.id LEFT JOIN zeek_logs z ON z.id=i.id
            WHERE i.agent_id=? AND i.category='network' AND l.origin='zeek' AND l.log_type='conn'
              AND i.event_time>=? AND i.event_time<=? AND i.src_ip=? AND i.dst_ip=?
              AND CAST(json_extract(COALESCE(e.payload,z.payload),'$.dst_port') AS INTEGER)=?
            ORDER BY i.event_time,i.id''',(agent,since,until,src,dst,args['dst_port']))
        for row in rows:
            record=json.loads(row[0]);z=record.get('zeek_data') or {}
            if z.get('proto')!='tcp': continue
            count+=1
            if count>100000:return {'status':'unavailable','error':'aggregation_record_limit','detail':'More than 100000 candidate records; narrow the window.'}
            uid=z.get('uid');line=(record.get('raw_event') or {}).get('full_log')
            if uid and isinstance(line,str) and line:
                fingerprint=(uid,hashlib.sha256(line.encode()).digest())
                if fingerprint in seen:duplicates+=1;continue
                seen.add(fingerprint)
            else:unknown_identity+=1
            totals['flows']+=1;states[str(z.get('conn_state') or 'unknown')]+=1
            for field in fields:
                value=z.get(field)
                if isinstance(value,str) and value.isascii() and value.isdigit() and len(value)<=18:
                    value=int(value)
                if isinstance(value,int) and not isinstance(value,bool) and value>=0:totals[field]+=value
                else:missing[field]+=1
            if len(samples)<5:samples.append(record)
    except sqlite3.Error as exc:
        return {'status':'unavailable','error':'aggregation_query_failed','detail':str(exc)[:200]}
    finally:db.close()
    result={'scope':{'agent_id':agent,'src_ip':src,'dst_ip':dst,'dst_port':args['dst_port'],'protocol':'tcp','since':since,'until':until,'window_seconds':seconds},
        'timestamp_basis':'Wazuh normalized event timestamp; inclusive window, not Zeek connection start time',
        'matched_records':count,'duplicate_records_removed':duplicates,'records_without_dedup_identity':unknown_identity,
        'flow_observations':totals['flows'],'connection_states':dict(states),'totals':{k:totals[k] for k in fields},
        'missing_fields':{k:missing[k] for k in fields},'flow_observations_per_second':totals['flows']/seconds,
        'packet_rates_per_second':{k:totals[k]/seconds for k in ('orig_pkts','resp_pkts')},
        'ip_byte_rates_per_second':{k:totals[k]/seconds for k in ('orig_ip_bytes','resp_ip_bytes')},
        'rate_basis':'Total retained deduplicated observations divided by requested window seconds, not peak rate or attack duration',
        'coverage':'Retained TCP conn records only. Logs may be missing, delayed or duplicated. IP bytes are on-wire IP packet bytes, not payload bytes. No service impact inferred.'}
    return {'status':'ok','summary':result,'samples':samples}
