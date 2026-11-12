"""Compact, typed evidence for small local models; full records remain in audit."""
import json
from collections import deque


def bounded(value, text=300, width=12, depth=4):
    if isinstance(value, str):
        return value if len(value) <= text else value[:text] + '… [excerpt]'
    if isinstance(value, (dict, list)) and depth <= 0:
        return '[nested data omitted; inspect evidence details]'
    if isinstance(value, dict):
        result = {k: bounded(v, text, width, depth-1) for k, v in list(value.items())[:width] if v is not None}
        if len(value) > width:
            result['_omitted_fields'] = len(value) - width
        return result
    if isinstance(value, list):
        result = [bounded(v, text, width, depth-1) for v in value[:width]]
        if len(value) > width:
            result.append('[more items omitted]')
        return result
    return value


def evidence_summary(e):
    data = e['data']
    fields = ('agent', 'src_ip', 'dst_ip', 'username', 'auth_outcome', 'file_path',
              'process', 'log_type', 'http', 'dns', 'file_change', 'privilege',
              'zeek_connection', 'flow_summary', 'summary_truncated', 'details_truncated')
    compact = {k: bounded(data[k]) for k in fields if data.get(k) not in (None, {}, '')}
    rule = data.get('rule') or {}
    compact['rule'] = {k: bounded(rule[k]) for k in ('id', 'description', 'level') if k in rule}
    if data.get('full_log'):
        compact['log_excerpt'] = bounded(data['full_log'], text=400)
    if data.get('details_requested'):
        detail=data.get('event_details', data.get('raw_event', {}))
        # Put actual event fields before repeated envelope/compliance metadata.
        if isinstance(detail,dict):
            detail={**{k:detail[k] for k in ('full_log','data','syscheck','decoder','predecoder') if k in detail},**detail}
        compact['event_details'] = bounded(detail, text=400)
        compact['details_excerpted'] = compact['event_details'] != detail
    return {'evidence_id': e['evidence_id'], 'kind': e['evidence_type'],
            'event_time': e.get('event_time'), 'source_record_id': e['source_record_id'], 'data': compact}


def pack_evidence(evidence, allowance):
    # Trigger first, then interleave tools so one large query cannot hide other sources.
    trigger = [e for e in evidence if e['evidence_type'] == 'trigger']
    groups = {}
    for e in evidence:
        if e['evidence_type'] in {'observed','aggregate'}:
            groups.setdefault(e.get('tool', ''), deque()).append(e)
    ordered = list(trigger)
    # A requested detail takes precedence over a generic search row.
    for group in groups.values():
        ordered.extend(e for e in group if e['data'].get('details_requested'))
    while any(groups.values()):
        for group in groups.values():
            if group:
                e = group.popleft()
                if not e['data'].get('details_requested'):
                    ordered.append(e)
    facts, guidance, used, details_omitted = [], [], 0, False
    for e in ordered:
        item = evidence_summary(e)
        size = len(json.dumps(item, ensure_ascii=False))
        if used + size > allowance:
            # Keep a small observation when a large detail would displace all context.
            detail = item['data'].get('event_details')
            item['data'] = {**{k:bounded(v,text=100,width=4,depth=3) for k,v in item['data'].items()
                              if k in {'rule','file_path','src_ip','dst_ip','privilege','http','dns','file_change'}},
                            'log_excerpt': bounded(e['data'].get('full_log', ''), text=180),
                            'summary_excerpted': True}
            if detail is not None:
                item['data']['event_details'] = bounded(detail,text=80,width=4,depth=3)
                item['data']['details_excerpted'] = True
            size = len(json.dumps(item, ensure_ascii=False))
            if used + size > allowance and detail is not None:
                item['data'].pop('event_details')
                item['data']['details_omitted'] = True
                size = len(json.dumps(item, ensure_ascii=False))
        if used + size <= allowance:
            facts.append(item)
            used += size
            details_omitted |= bool(item['data'].get('summary_excerpted') or item['data'].get('details_omitted')
                                    or item['data'].get('details_excerpted'))
    for e in evidence:
        if e['evidence_type'] != 'guidance':
            continue
        item = {'guidance_id': e['evidence_id'], 'use': 'Recommendations only; not incident evidence',
                'text': bounded(e['data'].get('text', ''), text=450),
                'metadata': bounded(e['data'].get('metadata', {}))}
        size = len(json.dumps(item, ensure_ascii=False))
        if used + size <= allowance:
            guidance.append(item)
            used += size
    return {'evidence': facts, 'guidance': guidance,
            'allowed_factual_evidence_ids': [e['evidence_id'] for e in facts],
            'context_truncated': details_omitted or len(facts) + len(guidance) < len(evidence)}
