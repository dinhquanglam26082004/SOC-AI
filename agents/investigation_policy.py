"""Evidence reference checks and conservative verdict policy; independent of model prose."""
import re
from agents.investigation_schema import Hypothesis


_ATTACK_CLAIM = re.compile(r'\b(?:attack|malicious|compromise|exploit|intrusion|dos|ddos|reconnaissance|rootkit)\b|tấn công|xâm nhập|trái phép',re.I)
_ATTACK_SIGNAL = re.compile(r'\b(?:attack|malware|exploit|intrusion|brute.force|port.scan|ddos|dos|rootkit)\b|tấn công|xâm nhập',re.I)
_ATTACK_GROUPS = {'attack','web_attack','malware','intrusion','exploit','zeek_scan','zeek_dos',
                  'dhcp_attack','dhcp_spoofing','dhcp_starvation','privilege_escalation','rootkit'}


def listener_attack_signal(evidence, cited=None):
    """Require an independent, explicit endpoint attack signal; proximity is insufficient."""
    for item in evidence:
        if item.get('evidence_type')!='observed' or (cited is not None and item.get('evidence_id') not in cited):
            continue
        data=item.get('data') or {}
        if data.get('source_product')=='zeek':
            continue
        rule=data.get('rule') or {}
        groups={str(group).lower() for group in rule.get('groups') or []}
        if groups & _ATTACK_GROUPS or _ATTACK_SIGNAL.search(str(rule.get('description') or '')):
            return True
    return False


def unsupported_attack_label(statement, evidence):
    """Reject named attack categories without a matching source signal.

    This is a narrow category guard, not proof that a matching detection is true.
    """
    label=str(statement or '').lower()
    categories=[]
    if re.search(r'\b(?:ddos|dos|denial.of.service)\b',label): categories.append('dos')
    if re.search(r'\b(?:reconnaissance|recon|scann?ing|port.scan)\b',label): categories.append('scan')
    if re.search(r'(?:dhcp.{0,24}(?:attack|spoof|starvation|rogue|tấn công)|(?:attack|tấn công).{0,24}dhcp)',label):
        categories.append('dhcp_attack')
    if 'rootkit' in label: categories.append('rootkit')
    if re.search(r'\b(?:privilege.escalation|leo thang đặc quyền)\b',label): categories.append('privilege')
    if not categories: return False
    signals=set()
    for item in evidence:
        if item.get('evidence_type') not in {'trigger','observed','aggregate'}: continue
        data=item.get('data') or {}
        rule=data.get('rule') or {}
        groups={str(g).lower() for g in rule.get('groups') or []}
        description=str(rule.get('description') or '').lower()
        if 'zeek_dos' in groups or 'suspected_dos' in groups or re.search(r'\b(?:ddos|dos|denial.of.service)\b',description): signals.add('dos')
        if groups & {'zeek_scan','recon','network_scan'} or re.search(r'\b(?:reconnaissance|port.scan)\b',description): signals.add('scan')
        if groups & {'dhcp_attack','dhcp_spoofing','dhcp_starvation'} or re.search(
                r'(?:dhcp.{0,24}(?:attack|spoof|starvation|rogue|tấn công)|(?:attack|tấn công).{0,24}dhcp)',description):
            signals.add('dhcp_attack')
        if groups & {'rootcheck','rootkit'} or data.get('rootkit_snapshot'): signals.add('rootkit')
        if groups & {'sudo','su','privilege_escalation'} or data.get('privilege'): signals.add('privilege')
    return any(category not in signals for category in categories)


def ground_hypotheses(items, evidence):
    listener_trigger=any(item.get('evidence_type')=='trigger' and
        (item.get('data') or {}).get('listener_changes') for item in evidence)
    listener_signal=listener_attack_signal(evidence) if listener_trigger else False
    for item in items:
        if (unsupported_attack_label(item.get('statement'), evidence) or
                (listener_trigger and not listener_signal and _ATTACK_CLAIM.search(item.get('statement') or ''))):
            item.update(statement='Chưa rõ nguyên nhân của hoạt động được cảnh báo.', status='open',
                        supporting=[], refuting=[], evidence_ids=[],
                        question='Cần bằng chứng endpoint hoặc xác nhận thay đổi cấu hình để xác định nguyên nhân.')
    return items


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
    gaps=context_omitted or any(
        o['status'] in {'empty','error','unavailable','truncated'} or o.get('error')=='tool_already_used'
        for o in outcomes if o['tool']!='search_runbook')
    is_rootkit_case = any(
        item.get('evidence_type') == 'trigger'
        and str(((item.get('data') or {}).get('rule') or {}).get('id')) == '521'
        for item in evidence
    )
    is_account_management_case = any(
        item.get('evidence_type') == 'trigger'
        and (
            str(((item.get('data') or {}).get('rule') or {}).get('id')) in {'5901','101200','101201','101202'}
            or 'account_management' in set(((item.get('data') or {}).get('rule') or {}).get('groups') or [])
        )
        for item in evidence
    )
    if is_account_management_case:
        reasons.append(
            'Linux account or sudo-group changes require positive authorization verification '
            'by an analyst; the alert and system logs alone do not establish approval.'
        )
    if report['verdict']!='inconclusive' and not observed&cited:
        reasons.append('No cited corroborating observation beyond the triggering alert.')
    if is_rootkit_case and report['verdict'] == 'malicious':
        positive = False

        for item in evidence:
            if item['evidence_id'] not in cited:
                continue

            if item.get('evidence_type') != 'observed':
                continue

            snapshot = (
                (item.get('data') or {})
                .get('rootkit_snapshot') or {}
            )

            for suspect in (
                snapshot.get('suspects') or []
            ):
                if not isinstance(suspect, dict):
                    continue

                if (
                    suspect.get('finding')
                    == 'stable_process_visibility_discrepancy'
                    and suspect.get('recheck_kill0')
                    == 'exists'
                    and suspect.get('recheck_proc_visible')
                    is False
                    and suspect.get('recheck_ps_visible')
                    is False
                ):
                    positive = True

        if not positive:
            reasons.append(
                'No independent positive endpoint '
                'snapshot confirms the hidden '
                'process. Repeated rootcheck alerts '
                'alone are insufficient.'
            )
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
    report['policy_adjustments']=list(dict.fromkeys(report.get('policy_adjustments',[])+reasons))
    review=[]
    if reasons:review.append('The model conclusion has evidence limitations and requires analyst review.')
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
