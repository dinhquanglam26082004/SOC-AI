"""Evidence reference checks and conservative verdict policy; independent of model prose."""
from agents.investigation_schema import Hypothesis


def recommended_tools(alert):
    """Deterministic incident context, not model-generated tool requests."""
    rule=alert.get('rule') or {};groups=set(rule.get('groups') or [])
    description=str(rule.get('description','')).lower()
    if alert.get('source_product')=='zeek' or groups & {'zeek_detection','zeek_dos'} or any(
            word in description for word in ('denial of service','suspected dos','failed connections','dns failure')):
        return ['search_zeek_connections','search_related_alerts']
    if groups & {'syscheck','malware','virus','yara','rootcheck','ransomware'}:
        return ['search_related_alerts','search_runbook']
    if groups & {'authentication_failed','authentication_success','invalid_login','sshd','pam'} or str(alert.get('event_id')) in {'4624','4625'}:
        return ['search_auth_events','search_related_alerts']
    return ['search_related_alerts','search_runbook']


def hypotheses(items,evidence,previous=()):
    previous=[h for h in previous if isinstance(h,dict)]
    known={h['id']:h for h in previous if isinstance(h,dict) and h.get('id')}
    result=[]
    for raw in items[:5]:
        if isinstance(raw,str):raw={'statement':raw[:600] or 'Unresolved activity hypothesis.','status':'open'}
        h=Hypothesis.model_validate(raw).model_dump()
        if h['status']=='supported' and not h['supporting']:
            h['supporting']=list(h['evidence_ids'])
        if h['status']=='refuted' and not h['refuting']:
            h['refuting']=list(h['evidence_ids'])
        refs=set(h['evidence_ids']+h['supporting']+h['refuting'])
        if refs-set(evidence):raise ValueError('Unknown hypothesis evidence ID')
        if set(h['supporting'])&set(h['refuting']):raise ValueError('Evidence cannot both support and refute one hypothesis')
        for ref in h['supporting']+h['refuting']:
            if evidence[ref]['evidence_type']=='guidance':raise ValueError('Guidance cannot resolve an incident hypothesis')
        if h['status']=='supported' and not h['supporting']:raise ValueError('Supported hypothesis needs supporting observations')
        if h['status']=='refuted' and not h['refuting']:raise ValueError('Refuted hypothesis needs refuting observations')
        h['id']=h['id'] if h['id'] in known else next((old['id'] for old in previous if old.get('statement')==h['statement']),f'H-{len(known)+1:03}')
        if any(old['id']==h['id'] for old in result):raise ValueError('Duplicate hypothesis ID')
        known[h['id']]=h
        h['evidence_ids']=sorted(refs)
        if h['status'] in {'open','inconclusive'} and not h['question']:
            h['question']='Verify authorization and obtain corroborating observations for this hypothesis.'
        result.append(h)
    for old in previous:
        if old.get('id') and not any(h['id']==old['id'] for h in result):
            result.append(Hypothesis.model_validate(old).model_dump())
    priority={old.get('id'):i for i,old in enumerate(previous)}
    result.sort(key=lambda h:priority.get(h['id'],len(priority)))
    return result[:5]


def assess_verdict(report,evidence,outcomes,context_omitted=False,suspected_dos=False):
    observed={e['evidence_id'] for e in evidence if e['evidence_type']=='observed'}
    cited={ref for finding in report['findings'] for ref in finding['evidence_ids']}
    reasons=[]
    gaps=context_omitted or any(o['status'] in {'empty','error','unavailable','truncated'} for o in outcomes if o['tool']!='search_runbook')
    if report['verdict']!='inconclusive' and not observed&cited:
        reasons.append('No cited corroborating observation beyond the triggering alert.')
    if report['verdict']=='benign':
        # This installation has no trusted maintenance/authorization connector. Neither
        # successful login, lack of alerts, nor model prose can provide that authorization.
        reasons.append('Benign requires positive authorization evidence verified by an analyst; no trusted authorization source is connected.')
    if report['verdict']=='malicious' and suspected_dos:
        reasons.append('Service impact and attack intent are not independently verified.')
    cited_observations=[e for e in evidence if e['evidence_id'] in cited and e['evidence_type']!='guidance']
    if report['verdict']=='malicious' and cited_observations and all(
            e['data'].get('auth_outcome') in {'failure','success'} for e in cited_observations):
        reasons.append('Authentication outcomes alone do not establish attacker identity, authorization or successful compromise.')
    if gaps and report['verdict']=='benign':reasons.append('Incomplete sources prevent a benign conclusion.')
    if reasons:
        report['verdict']='inconclusive';report['confidence']=None
        report['unknowns']=list(dict.fromkeys(report['unknowns']+reasons))
    report['policy_adjustments']=list(dict.fromkeys(report.get('policy_adjustments',[])+reasons))
    review=[]
    if report['verdict']=='inconclusive':review.append('The investigation did not establish a definitive conclusion.')
    if gaps:review.append('Some relevant source results are missing, unavailable or incomplete.')
    if any(h['status'] in {'open','inconclusive'} for h in report['hypotheses']):review.append('One or more hypotheses remain unresolved.')
    if any(check.get('validation_error') for check in report.get('verification_checks',[])):
        review.append('A model review failed structured validation; inspect its recorded error.')
    if report.get('stop_reason') in {'time_budget','model_budget','tool_budget','round_budget'}:review.append('The investigation reached a configured budget.')
    report.update(needs_analyst=bool(review),review_status='pending' if review else 'not_required',
                  review_reasons=review,analyst_tasks=list(dict.fromkeys(
                    [h['question'] for h in report['hypotheses'] if h.get('question') and h['status'] in {'open','inconclusive'}]
                    +report['unknowns']))[:12])
    return report
