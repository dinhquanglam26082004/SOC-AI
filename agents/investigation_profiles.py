"""Deterministic alert profiles: which tools fit an alert type and which baseline evidence to collect.

The model still decides *additional* tools, but only from the tools that apply to the alert
category. A small local model cannot reliably pick from every tool, and every published tool
schema consumes prompt space that would otherwise carry evidence.

Set AI_TOOL_ROUTING=false to offer every tool (previous behaviour).
"""
import os
from datetime import datetime, timedelta, timezone

# Tools usable for every alert in addition to the category tools.
COMMON_TOOLS = ('search_related_alerts', 'get_event_details', 'search_runbook')

DNS_RULES = {'100151', '100152', '100153', '100154', '100155', '100156', '100157', '100181', '100183'}
DNS_GROUPS = {'zeek_dns_anomaly', 'zeek_dns_tunneling'}

PROFILES = {
    'dns_tunneling': {
        'label': 'Nghi DNS tunneling / DNS C2 (MITRE T1071.004)',
        'focus': ('Xác định domain cha nhận nhiều subdomain ngẫu nhiên, loại query (NULL/TXT/CNAME/MX), '
                  'số subdomain duy nhất, tần suất so với cửa sổ trước đó, và tiến trình trên máy nguồn. '
                  'Query PTR/A tới DNS gateway thông thường là nhiễu nền, không phải bằng chứng tunneling.'),
        'tools': ('search_zeek_dns', 'summarize_dns_activity', 'compare_dns_baseline',
                  'search_zeek_connections', 'search_process_events'),
    },
    'authentication': {
        'label': 'Đăng nhập thất bại / brute force',
        'focus': 'Đếm thất bại/thành công theo user và IP nguồn; kiểm tra thành công sau chuỗi thất bại và sudo sau đó.',
        'tools': ('search_auth_events', 'search_privilege_events', 'search_process_events'),
    },
    'web': {
        'label': 'Tấn công ứng dụng web',
        'focus': 'Đọc request HTTP (method, host, URI, status) từ IP nguồn và lưu lượng liên quan.',
        'tools': ('search_zeek_http', 'search_zeek_connections', 'search_process_events'),
    },
    'network_scan_dos': {
        'label': 'Quét mạng / nghi DoS',
        'focus': 'Tổng hợp luồng, gói, byte theo nguồn/đích/cổng; không suy ra tác động dịch vụ khi chưa có dữ liệu.',
        'tools': ('search_zeek_connections', 'summarize_zeek_flows'),
    },
    'file_integrity': {
        'label': 'Thay đổi file (FIM)',
        'focus': 'Đọc thay đổi file, người/tiến trình thay đổi (nếu có who-data) và lệnh liên quan.',
        'tools': ('search_file_changes', 'search_file_access', 'search_process_events', 'search_privilege_events'),
    },
    'rootkit': {
        'label': 'Rootcheck / nghi rootkit',
        'focus': 'Tìm snapshot endpoint độc lập xác nhận tiến trình ẩn; cảnh báo lặp lại không phải bằng chứng độc lập.',
        'tools': ('search_rootkit_evidence', 'search_process_events', 'search_file_changes'),
    },
    'privilege': {
        'label': 'Leo thang đặc quyền (sudo/su)',
        'focus': 'Đọc sudo/su của actor và target, lệnh đã chạy và đăng nhập trước đó.',
        'tools': ('search_privilege_events', 'search_auth_events', 'search_process_events'),
    },
}


def routing_enabled():
    return os.getenv('AI_TOOL_ROUTING', 'true').lower() != 'false'


def classify(alert):
    """Return a profile name, or None when the alert type is not recognised."""
    rule = alert.get('rule') or {}
    rid = str(rule.get('id') or '')
    groups = {str(g).lower() for g in rule.get('groups') or []}
    mitre = {str(m) for m in ((rule.get('mitre') or {}).get('id') or [])}
    desc = str(rule.get('description') or '').lower()
    if rid in DNS_RULES or groups & DNS_GROUPS or 'T1071.004' in mitre or 'dns tunneling' in desc:
        return 'dns_tunneling'
    if rid == '521' or ('rootcheck' in groups and ('rootkit' in desc or 'hidden' in desc)):
        return 'rootkit'
    if groups & {'syscheck', 'fim'} or rid in {'550', '553', '554'}:
        return 'file_integrity'
    if groups & {'web', 'zeek_http', 'attack', 'web_attack'} or rid.startswith('10013'):
        return 'web'
    if groups & {'authentication_failed', 'authentication_failures', 'sshd', 'invalid_login'} or rid in {'2502', '5710', '5712', '5716', '100172'}:
        return 'authentication'
    if groups & {'sudo', 'su'}:
        return 'privilege'
    if groups & {'zeek_scan', 'zeek_dos', 'recon'} or rid in {'100141', '100142', '100143', '100145'} \
            or (alert.get('detection') or {}).get('category') == 'suspected_dos':
        return 'network_scan_dos'
    return None


def tools_for(alert, all_tools):
    """Ordered tool names offered to the model for this alert."""
    name = classify(alert) if routing_enabled() else None
    if name is None:
        return [t for t in all_tools if t != 'get_alert']
    wanted = PROFILES[name]['tools'] + COMMON_TOOLS
    return [t for t in wanted if t in all_tools]


def context_hint(alert):
    name = classify(alert) if routing_enabled() else None
    if name is None:
        return None
    profile = PROFILES[name]
    return {'category': name, 'label': profile['label'], 'investigation_focus': profile['focus']}


def _query(alert):
    data = alert.get('zeek_data') or ((alert.get('raw_event') or {}).get('data')) or {}
    query = data.get('query') if isinstance(data, dict) else None
    return query.strip().lower().rstrip('.') if isinstance(query, str) and query.strip() else None


def parent_domain(query):
    """Strip the leftmost (data-carrying) label: vaaaakaq3eq.tunnel.lab.local -> tunnel.lab.local.

    Keep at least two labels so a bare TLD is never used as the aggregation suffix.
    """
    if not query or query.endswith('.arpa'):
        return None
    labels = [p for p in query.split('.') if p]
    if len(labels) < 3:
        return '.'.join(labels) if len(labels) == 2 else None
    return '.'.join(labels[1:])


def _stamp(value):
    return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def baseline_calls(alert, scope_since, scope_until):
    """Deterministic evidence collected before the model plans, as (tool, args) pairs."""
    if not routing_enabled() or classify(alert) != 'dns_tunneling':
        return []
    domain = parent_domain(_query(alert))
    if not domain:
        return []
    anchor = datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00'))
    lo = datetime.fromisoformat(scope_since.replace('Z', '+00:00'))
    hi = datetime.fromisoformat(scope_until.replace('Z', '+00:00'))
    # Equal 10-minute windows: baseline immediately before the incident window.
    incident_since = max(lo + timedelta(minutes=10), anchor - timedelta(minutes=5))
    incident_until = min(hi, incident_since + timedelta(minutes=10))
    incident_since = incident_until - timedelta(minutes=10)
    baseline_since = incident_since - timedelta(minutes=10)
    calls = [
        ('summarize_dns_activity', {'domain': domain, 'since': scope_since, 'until': scope_until}),
        ('search_zeek_dns', {'domain_suffix': domain, 'limit': 30}),
    ]
    if baseline_since >= lo:
        calls.append(('compare_dns_baseline', {
            'domain': domain,
            'baseline_since': _stamp(baseline_since), 'baseline_until': _stamp(incident_since),
            'since': _stamp(incident_since), 'until': _stamp(incident_until)}))
    src = alert.get('src_ip')
    if src:
        calls[1][1]['ip'] = str(src)
    return calls
