"""Telegram notifications for completed SOC-AI investigations."""
import os

import requests


def _short(value, limit=500):
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def format_investigation_alert(record):
    """Report source measurements and executed tools, without model confidence claims."""
    report = record.get("investigation_report") or {}
    rule = record.get("rule") or {}
    agent = record.get("agent") or {}
    zeek = record.get("zeek_data") or {}
    summary = record.get("dos_summary") or {}
    lines = ["🛡️ SOC-AI | INVESTIGATION RECORD", "━━━━━━━━━━━━━━━━━━━━",
        "📍 ALERT", f"{_short(rule.get('description', 'Unknown'), 200)}",
        f"Rule: {_short(rule.get('id') or 'unknown', 40)} | Level: {_short(rule.get('level') if rule.get('level') is not None else 'unknown', 10)}",
        f"Agent: {_short(agent.get('name') or 'unknown', 80)} ({_short(agent.get('ip') or 'IP unavailable', 64)})",
        f"Event time (UTC): {_short(record.get('timestamp') or 'not available', 64)}"]
    if record.get('username'):
        lines.append(f"User: {_short(record['username'], 100)}")
    if record.get('file_path'):
        lines.append(f"File: {_short(record['file_path'], 200)}")
    if record.get('src_ip') or record.get('dst_ip'):
        destination = _short(record.get('dst_ip') or 'unknown', 64)
        if record.get('dst_port') is not None:
            destination += ':' + _short(record['dst_port'], 12)
        lines.append(f"Source → destination: {_short(record.get('src_ip') or 'unknown', 64)} → {destination}")
    if summary or (record.get('source_product') == 'zeek' and record.get('log_type') == 'conn'):
        lines += ["", "📊 RECORDED MEASUREMENTS"]
    if summary:
        lines += [f"Sensor metric: {_short(summary.get('metric', 'unknown'), 80)}",
            f"Observed: {summary.get('observed')} in {summary.get('window_seconds')} seconds",
            f"Rate: {summary.get('observed_per_second', 0):.2f} observations/second",
            f"Sources observed: {summary.get('source_count')}" + (" (count capped)" if summary.get('source_count_capped') else ""),
            "Source: Zeek DoS sensor summary; these are flow/request observations, not packet counts."]
    elif record.get('source_product') == 'zeek' and record.get('log_type') == 'conn':
        orig,resp=zeek.get('orig_pkts'),zeek.get('resp_pkts')
        lines += [f"Triggering connection packets (origin / response): {orig if orig is not None else 'unavailable'} / {resp if resp is not None else 'unavailable'}",
                  f"Connection duration: {zeek.get('duration') if zeek.get('duration') is not None else 'unavailable'} seconds",
                  "Source: triggering Zeek conn.log record; not the total for the attack window.",
                  "Window-wide packet count, rate and duration: unavailable from this record."]
    outcomes=report.get('tool_outcomes') or []
    flow=next((o for o in outcomes if o.get('tool')=='summarize_zeek_flows' and o.get('status')=='ok' and o.get('flow_summary')),None)
    if flow:
        f=flow['flow_summary'];scope=f['scope'];totals=f['totals'];missing=f['missing_fields']
        lines += ["", "📈 SCOPED FLOW AGGREGATE", f"Window (UTC): {scope['since']} → {scope['until']} ({scope['window_seconds']} s)",
                  f"Tuple: {scope['src_ip']} → {scope['dst_ip']}:{scope['dst_port']} TCP",
                  f"Records: {f['matched_records']}; duplicate copies removed: {f['duplicate_records_removed']}; identity missing: {f['records_without_dedup_identity']}",
                  f"Retained flow observations: {f['flow_observations']}; average: {f['flow_observations_per_second']:.2f} flows/s",
                  f"Packets origin / response: {totals['orig_pkts']} / {totals['resp_pkts']} (missing: {missing['orig_pkts']} / {missing['resp_pkts']} records)",
                  f"Average packets/s origin / response: {f['packet_rates_per_second']['orig_pkts']:.2f} / {f['packet_rates_per_second']['resp_pkts']:.2f} (partial if fields missing)",
                  f"IP bytes origin / response: {totals['orig_ip_bytes']} / {totals['resp_ip_bytes']} (missing: {missing['orig_ip_bytes']} / {missing['resp_ip_bytes']} records)",
                  'States: '+', '.join(f'{k}={v}' for k,v in f['connection_states'].items()),
                  f"Evidence: {flow.get('aggregate_evidence_id') or 'unavailable'}",
                  'Window average uses Wazuh event timestamps; not attack duration or confirmed impact. Missing records and capture loss are unknown.']
    auth = next((o.get('authentication_summary') for o in outcomes if o.get('authentication_summary')), None)
    if auth:
        lines += ["", "🔐 AUTHENTICATION OBSERVATIONS"]
        for group in (auth.get('groups') or [])[:3]:
            lines.append(f"• {_short(group.get('username') or 'unknown user', 80)} | {_short(group.get('source_ip') or 'source IP unavailable', 64)}")
            lines.append(f"  Failed: {group.get('failure_count', 0)} | Success: {group.get('success_count', 0)} | Unknown: {group.get('unknown_count', 0)}")
        lines.append("Counts are retained records, not unique attempts; collection may be incomplete.")
        if auth.get('groups_truncated') or auth.get('display_truncated'):
            lines.append("Some groups omitted; open SOC evidence for details.")
    lines += ["", "🛠️ TOOLS USED"]
    if outcomes:
        for item in outcomes[:10]:
            name=_short(item.get('tool','unknown'),80);status=_short(item.get('status','unknown'),30)
            count=item.get('count');total=item.get('total_matched')
            detail=f" · {count} returned" if count is not None else ""
            if total is not None: detail+=f" / {total} matching retained records"
            lines.append(f"• {name}: {status}{detail}")
        if len(outcomes)>10: lines.append(f"• {len(outcomes)-10} additional tool entries in SOC")
        lines.append("Counts describe retained records, not packets or complete capture.")
    else: lines.append("Tool history unavailable for this investigation.")
    gaps = any(o.get('status') in ('truncated','unavailable','error') or o.get('truncated') for o in outcomes)
    lines += ["", "⚠️ LIMITATIONS", "Results cover collected records only; authorization and impact are not established."]
    if gaps:
        lines.append("Some tool results are incomplete or unavailable; review their scope in SOC.")
    lines += [
              f"Alert ID: {_short(record.get('id','unknown'),120)}",
              "Open the SOC evidence view for source records, timestamps and query scope."]
    return "\n".join(lines)[:3999]


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
