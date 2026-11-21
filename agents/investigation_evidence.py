"""Conservative content checks. A matching reference is not semantic entailment."""
import json
import re


def field_value(data, pointer):
    if not pointer.startswith('/'):
        raise ValueError('Field must be a JSON pointer')
    for part in pointer[1:].split('/'):
        if re.search(r'~(?![01])',part):
            raise ValueError('Invalid JSON pointer escape')
        part=part.replace('~1','/').replace('~0','~')
        if isinstance(data,list):
            if not re.fullmatch(r'0|[1-9][0-9]*',part):
                raise ValueError('Invalid array index')
            data=data[int(part)]
        else:data=data[part]
    if isinstance(data,(dict,list)):
        raise ValueError('Assertions must identify a scalar field')
    return data


def verify_findings(findings, evidence):
    """Render checked field assertions ourselves; never bless unrelated model prose."""
    registry={item['evidence_id']:item for item in evidence}
    checked=[]
    for finding in findings:
        facts=[]
        issues=[]
        for assertion in finding.get('assertions',[]):
            eid=assertion['evidence_id']
            entry=registry.get(eid)
            if not entry or entry['evidence_type']=='guidance' or eid not in finding['evidence_ids']:
                issues.append('Assertion does not reference cited factual evidence.')
                continue
            try:
                actual=field_value(entry['data'],assertion['field'])
                # In particular, True must not compare equal to the number 1.
                if type(actual) is not type(assertion['value']) or actual!=assertion['value']:
                    issues.append('Source value does not match assertion: '+assertion['field'])
                    continue
            except (KeyError,IndexError,ValueError,TypeError):
                issues.append('Source field unavailable: '+assertion['field'])
                continue
            facts.append({**assertion,'text':assertion['field']+' = '+json.dumps(actual,ensure_ascii=False)})
        if set(finding['evidence_ids'])-{fact['evidence_id'] for fact in facts}:
            issues.append('Some cited records have no matching field assertion.')
        grounded=bool(facts) and not issues
        recorded=grounded and finding.get('claim_type')=='recorded_fact'
        item={**finding,'verification':{'status':'recorded_fact' if recorded else 'supported_inference' if grounded else 'unverified',
            'facts':facts,'issues':issues or ([] if recorded else ['The meaning of this narrative has not been independently verified.']),
            'scope':'Checks retained source values, not entailment of the narrative, real-world truth, intent or causation.'}}
        if recorded:
            item['model_statement']=finding['statement']
            item['statement']='Recorded: '+'; '.join(fact['text'] for fact in facts)
        checked.append(item)
    return checked


def independent_ids(evidence):
    """Collapse the trigger, repeated source records and same-detector repetitions."""
    trigger=next((e for e in evidence if e['evidence_type']=='trigger'),None)
    ids=set()
    seen=set();sources=set();logs=set()
    for item in ([trigger] if trigger else [])+[e for e in evidence if e is not trigger]:
        if item['evidence_type'] not in {'trigger','observed'}:
            continue
        data=item['data'];rule=data.get('rule') or {};agent=data.get('agent') or {}
        signature=(agent.get('id'),str(rule.get('id'))) if rule.get('id') else ('source',item['source_record_id'])
        source=item['source_record_id']
        log=data.get('full_log')
        duplicate=signature in seen or source in sources or bool(log and (agent.get('id'),log) in logs)
        if not duplicate and item['evidence_type']=='observed':
            ids.add(item['evidence_id'])
        seen.add(signature)
        sources.add(source)
        if log:logs.add((agent.get('id'),log))
    return ids


def pending_recommendations(recommendations, outcomes, tool_names, queries=(), normalize=None):
    """Suppress explicit repeat-tool tasks; keep new external work and manual review."""
    completed={o['tool'] for o in outcomes if o['status'] in {'ok','empty'} and not o.get('truncated')}
    pending=[];omitted=[];seen=set()
    for text in recommendations:
        key=' '.join(text.casefold().split())
        if key in seen:
            continue
        seen.add(key)
        query=next((q for q in queries if q['recommendation']==text),None)
        if query and normalize:
            try:
                args=normalize(query['tool'],query['arguments'])
                equivalent=any(o['tool']==query['tool'] and o['status'] in {'ok','empty'}
                    and not o.get('truncated') and 'query' in o and normalize(o['tool'],o['query'])==args for o in outcomes)
            except (KeyError,TypeError,ValueError):
                omitted.append({'recommendation':text,'reason':'Proposed tool arguments are invalid or outside the incident scope; analyst must define the next query.'})
                continue
            if equivalent:
                omitted.append({'recommendation':text,'reason':'Equivalent query already completed; inspect its saved result.'})
            else:pending.append(text)
            continue
        tools={name for name in tool_names if re.search(r'\b'+re.escape(name)+r'\b',text)}
        repeat=re.fullmatch(r'(?:run|call|repeat|rerun)\s+([a-z_]+)(?:\s+again)?[.!]?',key)
        if repeat and tools and tools<=completed:
            omitted.append({'recommendation':text,'reason':'This tool query was already completed; inspect its saved result.'})
        else:
            pending.append(text)
    return pending,omitted
