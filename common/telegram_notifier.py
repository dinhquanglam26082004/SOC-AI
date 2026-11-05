"""Telegram notifications for completed SOC-AI investigations."""
import os

import requests


def _short(value, limit=500):
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def format_investigation_alert(record):
    report = record.get("investigation_report") or {}
    proposal = record.get("playbook_proposal") or {}
    rule = record.get("rule") or {}
    agent = record.get("agent") or {}
    confidence = report.get("confidence")
    confidence_text = f"{confidence:.0%}" if isinstance(confidence, (int, float)) else "not provided"

    lines = [
        "SOC-AI: Investigation completed",
        f"Alert: {_short(record.get('id', 'unknown'), 120)}",
        f"Incident: {_short(report.get('incident_type', 'Unknown'), 200)}",
        f"Verdict: {_short(report.get('verdict', 'unknown'), 40)}",
        f"Confidence: {confidence_text}",
        f"Rule: {_short(rule.get('description', 'Unknown'), 200)}",
        f"Agent: {_short(agent.get('name', 'Unknown'), 120)}",
    ]

    findings = report.get("findings") or []
    if findings:
        lines.append("Findings:")
        lines.extend(f"- {_short(item.get('statement', ''), 400)}" for item in findings[:3])

    unknowns = report.get("unknowns") or []
    if unknowns:
        lines.append("Unverified:")
        lines.extend(f"- {_short(item, 300)}" for item in unknowns[:2])

    recommendations = report.get("recommendations") or []
    if recommendations:
        lines.append("Recommendations:")
        lines.extend(f"- {_short(item, 400)}" for item in recommendations[:3])

    lines.append(f"Playbook: {_short(proposal.get('playbook_name') or proposal.get('status', 'not selected'), 200)}")
    if proposal.get("playbook_text"):
        lines.append(f"Playbook excerpt: {_short(proposal['playbook_text'], 1200)}")
    if proposal.get("notes"):
        lines.append(f"Playbook note: {_short(proposal['notes'], 300)}")

    message = "\n".join(lines)
    if len(message) > 4000:
        message = message[:3999] + "…"
    return message


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
