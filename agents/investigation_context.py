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


def contains_excerpt(value):
    if isinstance(value, str):
        return value.endswith('… [excerpt]') or value in ('[more items omitted]', '[nested data omitted; inspect evidence details]')
    if isinstance(value, dict):
        return bool(value.get('_omitted_fields') or value.get('summary_truncated') or value.get('details_truncated') or value.get('groups_truncated')) or any(contains_excerpt(v) for v in value.values())
    return isinstance(value, list) and any(contains_excerpt(v) for v in value)


DNS_SUMMARY_KEYS = ('matched_records', 'unique_queries', 'unique_subdomains', 'query_types', 'response_codes',
                    'average_query_length', 'max_query_length', 'first_event_time', 'last_event_time',
                    'records_missing_query_in_scope', 'timestamp_basis', 'coverage', 'sample_selection')


def compact_dns_summary(summary):
    """Decision-relevant DNS counts only; full aggregate stays in the audit dossier."""
    if not isinstance(summary, dict):
        return summary
    if 'baseline' in summary and 'incident' in summary:
        return {'baseline': compact_dns_summary(summary['baseline']),
                'incident': compact_dns_summary(summary['incident'])}
    scope = summary.get('scope') or {}
    out = {'scope': {k: scope[k] for k in ('agent_id', 'domain', 'since', 'until', 'window_seconds') if scope.get(k) is not None}}
    for key in DNS_SUMMARY_KEYS:
        if summary.get(key) is not None:
            value = summary[key]
            out[key] = round(value, 1) if isinstance(value, float) else bounded(value, text=240, width=12)
    return out


def compact_flow_summary(summary):
    """Keep the scope, completeness and units beside flow totals."""
    if not isinstance(summary, dict):
        return summary
    keys = ('scope', 'matched_records', 'duplicate_records_removed', 'records_without_dedup_identity',
            'flow_observations', 'flow_observations_per_second', 'totals', 'missing_fields',
            'connection_states', 'rate_basis', 'timestamp_basis', 'coverage')
    return {k: bounded(summary[k], text=240, width=12) for k in keys if summary.get(k) is not None}


def compact_auth_summary(summary):
    if not isinstance(summary, dict):
        return summary
    groups = summary.get('groups') or []
    return {'scope': bounded(summary.get('scope') or {}),
            'groups': bounded(groups[:5]),
            'groups_truncated': bool(summary.get('groups_truncated') or len(groups)>5),
            'count_unit': summary.get('count_unit'), 'counts_scope': summary.get('counts_scope'),
            'interpretation': summary.get('interpretation')}


def evidence_summary(e):
    data = e['data']
    fields = ('agent', 'src_ip', 'dst_ip', 'username', 'auth_outcome', 'file_path',
              'process', 'log_type', 'http', 'dns', 'file_change', 'privilege',
              'zeek_connection', 'flow_summary', 'dns_summary', 'authentication_summary', 'audit',
              'listener_changes', 'summary_truncated', 'details_truncated')
    compact = {k: bounded(data[k]) for k in fields if data.get(k) not in (None, {}, '')}
    if isinstance(data.get('listener_changes'), dict):
        change=data['listener_changes']
        compact['listener_changes']={k:bounded(change[k],text=160,width=12) for k in
            ('source_fields','comparison_complete','current_listeners','previous_listeners',
             'added','removed','added_total','removed_total','changes_omitted','interpretation') if k in change}
    if isinstance(data.get('dns_summary'), dict):
        compact['dns_summary'] = compact_dns_summary(data['dns_summary'])
    if isinstance(data.get('flow_summary'), dict):
        compact['flow_summary'] = compact_flow_summary(data['flow_summary'])
    if isinstance(data.get('authentication_summary'), dict):
        compact['authentication_summary'] = compact_auth_summary(data['authentication_summary'])
    rule = data.get('rule') or {}
    compact['rule'] = {k: bounded(rule[k]) for k in ('id', 'description', 'level') if k in rule}
    if data.get('full_log'):
        compact['log_excerpt'] = bounded(data['full_log'], text=400)
    if data.get('previous_output'):
        compact['previous_output'] = bounded(data['previous_output'], text=700)
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
    # Aggregates summarise many records in little space; they go right after the trigger.
    for group in groups.values():
        aggregates = [e for e in group if e['evidence_type'] == 'aggregate']
        ordered.extend(aggregates)
        for e in aggregates:
            group.remove(e)
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
            aggregate = {k:item['data'][k] for k in ('dns_summary','flow_summary','authentication_summary') if k in item['data']}
            item['data'] = {**{k:bounded(v,text=100,width=4,depth=3) for k,v in item['data'].items()
                              if k in {'rule','file_path','src_ip','dst_ip','privilege','http','dns','file_change'}},
                            'log_excerpt': bounded(e['data'].get('full_log', ''), text=180),
                            'summary_excerpted': True}
            if isinstance(e['data'].get('listener_changes'),dict):
                change=e['data']['listener_changes']
                item['data']['listener_changes']={k:change[k] for k in
                    ('comparison_complete','added_total','removed_total') if k in change}
                for key in ('added','removed'):
                    item['data']['listener_changes'][key]=change.get(key,[])[:3]
                item['data']['listener_changes']['context_rows_limited']=True
            # Never replace a scoped aggregate with an empty log excerpt: if it
            # does not fit, omit it and report truncation rather than lose scope.
            if aggregate:
                item['data'] = {**aggregate, 'summary_excerpted': True}
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
                                    or item['data'].get('details_excerpted') or contains_excerpt(item['data']))
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
            details_omitted |= contains_excerpt(item)
    factual_total = sum(e['evidence_type'] in {'trigger','observed','aggregate'} for e in evidence)
    guidance_total = sum(e['evidence_type'] == 'guidance' for e in evidence)
    return {'evidence': facts, 'guidance': guidance,
            'allowed_factual_evidence_ids': [e['evidence_id'] for e in facts],
            'context_coverage': {'factual_evidence_items_available': factual_total, 'factual_evidence_items_in_context': len(facts),
                                 'guidance_available': guidance_total, 'guidance_in_context': len(guidance),
                                 'scope': 'Counts dossier evidence items, not all collected source logs.'},
            'context_truncated': details_omitted or len(facts) + len(guidance) < len(evidence)}
