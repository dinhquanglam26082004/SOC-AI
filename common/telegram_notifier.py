"""Telegram notifications for completed SOC-AI investigations."""
import os
import re
from datetime import datetime, timedelta, timezone

import requests

_LOCAL_TIMEZONE = timezone(timedelta(hours=7))

_ACTION_LABELS = {'block_domain':'Chặn domain', 'block_ip':'Chặn IP', 'isolate_host':'Cô lập máy',
                  'kill_process':'Dừng tiến trình', 'disable_service':'Vô hiệu dịch vụ',
                  'disable_account':'Khóa tài khoản', 'collect_forensics':'Bảo toàn chứng cứ',
                  'increase_monitoring':'Tăng giám sát'}


def _short(value, limit=500):
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _local_time(value):
    """Convert an ISO timestamp to Vietnam time while preserving unparseable values."""
    try:
        stamp = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except ValueError:
        return _short(value, 40)
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.astimezone(_LOCAL_TIMEZONE).isoformat()


def _window(scope):
    """Use the aggregation's actual query window, never the rule's timeframe."""
    scope = scope if isinstance(scope, dict) else {}
    since, until = scope.get('since'), scope.get('until')
    if not since or not until:
        return 'Phạm vi thời gian: chưa được ghi'
    return f"Phạm vi (UTC+07:00): {_local_time(since)} → {_local_time(until)}"


def _evidence_lines(record, outcomes):
    lines = []
    dns = next((o.get('dns_summary') for o in outcomes
                if o.get('tool') == 'summarize_dns_activity' and o.get('status') == 'ok'
                and isinstance(o.get('dns_summary'), dict)), None)
    if dns and dns.get('matched_records') is not None:
        scope = dns.get('scope') or {}
        detail = f"DNS: {dns['matched_records']} bản ghi đã lưu"
        if dns.get('unique_queries') is not None:
            detail += f" · {dns['unique_queries']} tên truy vấn khác nhau"
        if scope.get('domain'):
            detail += f" · {_short(scope['domain'], 80)}"
        lines += [detail, _window(scope)]
        types = dns.get('query_types') or {}
        if isinstance(types, dict) and types:
            trigger_type = str((record.get('zeek_data') or {}).get('qtype_name') or '').upper()
            def type_rank(item):
                name, count = item
                number = count if isinstance(count, (int, float)) and not isinstance(count, bool) else 0
                return (str(name).upper() != trigger_type, -number, str(name))
            labels = [f"{_short(k, 15)}: {_short(v, 12)}" for k, v in sorted(types.items(), key=type_rank)[:3]]
            lines.append('Loại query: ' + ', '.join(labels))
        if dns.get('records_missing_query_in_scope'):
            lines.append(f"Thiếu tên query: {dns['records_missing_query_in_scope']} bản ghi trong phạm vi.")
        lines.append('Số bản ghi có thể bao gồm trùng lặp; không khẳng định đã thu thập đủ.')

    flow = next((o.get('flow_summary') for o in outcomes
                 if o.get('tool') == 'summarize_zeek_flows' and o.get('status') == 'ok'
                 and isinstance(o.get('flow_summary'), dict)), None)
    if flow and flow.get('flow_observations') is not None:
        scope = flow.get('scope') or {}
        lines += [f"Flow: {flow['flow_observations']} quan sát đã lưu", _window(scope)]
        totals, missing = flow.get('totals') or {}, flow.get('missing_fields') or {}
        if totals.get('orig_pkts') is not None and totals.get('resp_pkts') is not None:
            packets = f"Gói nguồn / phản hồi: {totals['orig_pkts']} / {totals['resp_pkts']}"
            if missing.get('orig_pkts') or missing.get('resp_pkts'):
                packets += f" (thiếu trường: {missing.get('orig_pkts', 0)} / {missing.get('resp_pkts', 0)} bản ghi)"
            lines.append(packets)

    auth = next((o.get('authentication_summary') for o in outcomes
                 if isinstance(o.get('authentication_summary'), dict)), None)
    groups = auth.get('groups') if auth else None
    if isinstance(groups, list) and groups and isinstance(groups[0], dict):
        group = groups[0]
        values = []
        for key, label in [('failure_count', 'thất bại'), ('success_count', 'thành công'), ('unknown_count', 'không rõ')]:
            if group.get(key) is not None:
                values.append(f"{label}: {group[key]}")
        if values:
            name = _short(group.get('username') or 'không rõ tài khoản', 60)
            ip = _short(group.get('source_ip') or 'không rõ IP nguồn', 45)
            lines.append(f"Xác thực (một nhóm) {name} · {ip}: " + ' | '.join(values))
            lines.append('Số đếm là bản ghi đã lưu trong phạm vi truy vấn, không nhất thiết là số lần thử duy nhất.')

    summary = record.get('dos_summary') or {}
    if isinstance(summary, dict) and summary.get('observed') is not None and summary.get('window_seconds') is not None:
        lines.append(f"Sensor {_short(summary.get('metric') or 'DoS', 30)}: {summary['observed']} quan sát trong {summary['window_seconds']} giây.")
    elif not flow and record.get('source_product') == 'zeek' and record.get('log_type') == 'conn':
        zeek = record.get('zeek_data') or {}
        orig, resp = zeek.get('orig_pkts'), zeek.get('resp_pkts')
        if orig is not None or resp is not None:
            lines.append(f"Kết nối kích hoạt: {orig if orig is not None else '?'} / {resp if resp is not None else '?'} gói nguồn / phản hồi; không phải tổng lưu lượng.")
    return lines


def format_investigation_alert(record):
    """Summarize the actual model report and retained evidence in plain text."""
    report = record.get('investigation_report') or {}
    rule, agent = record.get('rule') or {}, record.get('agent') or {}
    outcomes = [o for o in (report.get('tool_outcomes') or []) if isinstance(o, dict)]
    lines = ['🛡️ SOC-AI | ĐIỀU TRA', '', '📍 CẢNH BÁO', _short(rule.get('description') or 'Không rõ cảnh báo', 160)]
    metadata = []
    if agent.get('name'):
        metadata.append('Agent: ' + _short(agent['name'], 60))
    if rule.get('id'):
        metadata.append('Rule: ' + _short(rule['id'], 30))
    if rule.get('level') is not None:
        metadata.append('Mức: ' + _short(rule['level'], 10))
    if metadata:
        lines.append(' | '.join(metadata))
    if record.get('timestamp'):
        lines.append('Thời gian (UTC+07:00): ' + _local_time(record['timestamp']))
    if record.get('src_ip') or record.get('dst_ip'):
        destination = _short(record.get('dst_ip') or '?', 45)
        if record.get('dst_port') is not None:
            destination += ':' + _short(record['dst_port'], 8)
        lines.append(f"Nguồn → đích: {_short(record.get('src_ip') or '?', 45)} → {destination}")

    verdicts = {'malicious': 'Độc hại', 'benign': 'Lành tính', 'inconclusive': 'Chưa đủ kết luận'}
    verdict = report.get('verdict')
    heading = 'TÌNH TRẠNG ĐIỀU TRA' if report.get('generated_by') == 'workflow_budget_stop' else 'ĐÁNH GIÁ CỦA AI'
    lines += ['', f"🧠 {heading}: {verdicts.get(verdict, _short(verdict, 50) if verdict else 'Chưa có kết luận')}"]
    if report.get('reasoning'):
        reasoning = re.sub(r'\b(?:WAZUH|EV)-[a-f0-9]{16,}\b', '[ID]', str(report['reasoning']), flags=re.IGNORECASE)
        lines.append(_short(reasoning, 350))

    evidence = _evidence_lines(record, outcomes)
    if evidence:
        lines += ['', '📊 SỐ LIỆU ĐÃ GHI NHẬN', *evidence]

    attempted = [o for o in outcomes if o.get('status') != 'skipped']
    if attempted:
        statuses = {'truncated': 'bị cắt', 'empty': 'không có kết quả', 'unavailable': 'không khả dụng', 'error': 'lỗi'}
        tools = []
        for item in sorted(attempted, key=lambda o: o.get('status') not in statuses and not o.get('truncated')):
            name = _short(item.get('tool') or 'không rõ', 40)
            status = statuses.get(item.get('status')) or ('bị cắt' if item.get('truncated') else None)
            label = f"{name} ({status})" if status else name
            if label not in tools:
                tools.append(label)
        lines += ['', '🛠 Công cụ: ' + ', '.join(tools[:4]) + (f" (+{len(tools)-4})" if len(tools) > 4 else '')]
    skipped = list(dict.fromkeys(_short(o.get('tool') or 'không rõ', 40) for o in outcomes if o.get('error') == 'tool_already_used'))
    if skipped:
        lines.append('Đã bỏ qua gọi lại: ' + ', '.join(skipped[:3]))
    if any(o.get('status') in ('truncated', 'unavailable', 'error') or o.get('truncated') for o in outcomes):
        lines.append('⚠️ Một số kết quả bị cắt hoặc không khả dụng; xem chi tiết trong SOC.')

    unknowns = [x for x in (report.get('unknowns') or []) if isinstance(x, str) and x.strip()]
    if unknowns:
        lines += ['', '❓ CHƯA XÁC MINH', '• ' + _short(unknowns[0], 160)]
    grounded = record.get('grounded_response') or {}
    incident_id = report.get('incident_id') or (record.get('investigation') or {}).get('incident_id')
    kb = grounded.get('knowledge_guidance') or {}
    passages = {p.get('id'):p for p in (kb.get('passages') or []) if isinstance(p, dict) and p.get('id') and p.get('text')}
    actions = [a for a in (grounded.get('actions') or []) if isinstance(a, dict) and a.get('status') == 'proposed'
               and a.get('guidance_ids') and all(ref in passages for ref in a['guidance_ids'])]
    if grounded.get('status') == 'available' and incident_id and grounded.get('incident_id') == incident_id and kb.get('playbook_id') and actions:
        lines += ['', '🧭 GỢI Ý PHẢN ỨNG CỦA AI']
        for action in actions[:2]:
            label = _short(_ACTION_LABELS.get(action.get('action')) or action.get('action') or 'Hành động', 40)
            target = _short(action.get('target') or 'chưa rõ mục tiêu', 80)
            reason = _short(action.get('reason') or '', 160)
            refs = ', '.join(_short(ref, 15) for ref in action['guidance_ids'][:3])
            lines.append(f"• {label} · {target}" + (f": {reason}" if reason else '') + f" [{refs}]")
            first_ref = action['guidance_ids'][0]
            lines.append(f"  ↳ {_short(first_ref, 15)}: {_short(passages[first_ref]['text'], 110)}")
        lines.append('📘 Nguồn: ' + _short(kb['playbook_id'], 80) + ' · ' + _short(kb.get('source') or 'không rõ tệp', 100))
    elif grounded.get('status') not in ('not_applicable',):
        lines += ['', '🧭 Chưa có gợi ý phản ứng gắn nguồn; xem SOC để kiểm tra.']
    if report.get('needs_analyst') is True:
        lines += ['', '👤 Cần chuyên viên xem xét.']
    lines += ['', 'Xem log gốc, phạm vi và kế hoạch phản ứng trong SOC.']
    return '\n'.join(lines)[:3999]


def send_investigation_alert(record):
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    if not token and not chat_id:
        return False
    if not token or not chat_id:
        raise RuntimeError("Both Telegram bot token and chat ID are required")

    response = requests.post(
        f"https://api.telegram.org/bot{token}/sendMessage",
        json={"chat_id": chat_id, "text": format_investigation_alert(record)},
        timeout=(3, 8),
    )
    response.raise_for_status()
    if response.json().get("ok") is not True:
        raise RuntimeError("Telegram rejected the notification")
    return True
