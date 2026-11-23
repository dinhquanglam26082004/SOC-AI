"""Retrieve the best-matching existing incident response playbook."""
import json
from pathlib import Path, PureWindowsPath
import re

PLAYBOOK_ROOT = Path(__file__).resolve().parent.parent / "rag" / "documents" / "playbooks"
SSH_PLAYBOOK_SOURCE = "ssh_bruteforce.txt"
PRIVILEGE_PLAYBOOK_SOURCE = "PB-PRV-001_privilege_escalation.txt"
ACCOUNT_PLAYBOOK_SOURCE = "PB-ACC-001_account_management.txt"


def _build_query(report: dict, alert: dict | None = None) -> str:
    alert = alert or {}
    rule = alert.get("rule") or {}
    parts = [
        report.get("incident_type", ""),
        report.get("severity", ""),
        " ".join(report.get("mitre_techniques", [])),
        " ".join(
            finding.get("statement", "")
            for finding in report.get("findings", [])
            if isinstance(finding, dict)
        ),
        " ".join(report.get("unknowns", [])),
        rule.get("description", ""),
        " ".join(rule.get("groups", [])),
        "suspected DoS denial of service PB-DOS-001" if _is_dos_alert(alert) else "",
        "incident response playbook",
    ]
    return " ".join(str(part) for part in parts if part)[:2000]


def _skipped(report: dict, status: str, reason: str) -> dict:
    return {
        "_alert_id": report.get("_alert_id"),
        "status": status,
        "playbook_id": None,
        "playbook_name": None,
        "playbook_text": None,
        "actions": [],
        "notes": reason,
    }


def _is_dos_report(report: dict) -> bool:
    parts = [report.get("incident_type", ""), *report.get("unknowns", [])]
    parts.extend(
        finding.get("statement", "")
        for finding in report.get("findings", [])
        if isinstance(finding, dict)
    )
    text = " ".join(str(part) for part in parts).lower()
    return bool(re.search(r"\b(?:dos|ddos)\b|denial of service", text))


def _is_dos_alert(alert: dict) -> bool:
    rule = alert.get("rule") or {}
    groups = set(rule.get("groups") or [])
    detection = alert.get("detection") or {}
    return (
        detection.get("category") == "suspected_dos"
        or bool(groups & {"zeek_dos", "zeek_dos_single_source", "zeek_dos_distributed", "zeek_dos_summary"})
        or str(rule.get("id", "")) == "100142"
    )


def _is_ssh_context(report: dict, alert: dict) -> bool:
    rule = alert.get("rule") or {}
    raw = alert.get("raw_event") or {}
    decoder = raw.get("decoder") or {}
    predecoder = raw.get("predecoder") or {}
    groups = rule.get("groups") or []
    if isinstance(groups, str):
        groups = re.split(r"[\s,]+", groups)
    if any(group.lower() in {"ssh", "sshd", "ssh_bruteforce"} or group.lower().startswith("zeek_ssh")
           for group in groups if isinstance(group, str)):
        return True

    text = " ".join(str(value) for value in (
        report.get("incident_type", ""),
        rule.get("description", ""),
        decoder.get("name", ""),
        predecoder.get("program_name", ""),
        raw.get("full_log", ""),
        alert.get("log_type", ""),
    )).lower()
    return bool(re.search(r"\bssh(?:d)?\b|zeek_ssh", text))


def _read_playbook(source: str) -> str:
    if not source or Path(source).name != source or PureWindowsPath(source).name != source:
        raise ValueError("Retrieved playbook has an invalid source filename")
    path = PLAYBOOK_ROOT / source
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Retrieved playbook source is unavailable: {source}") from exc


def _retrieve_playbooks(query: str, top_k: int):
    from rag.query import retrieve

    return retrieve(query, top_k=top_k, doc_type="playbooks")


def playbook_compatible(alert: dict, playbook: dict) -> bool:
    """Basic topic check, not a semantic validation of individual actions."""
    from agents.investigation_profiles import classify
    patterns = {
        'dns_tunneling': r'dns\s*tunnel|dns\s*c2|t1071\.004|t1572',
        'authentication': r'\bssh\b|\bsshd\b|brute\s*force|authentication|t1110',
        'network_scan_dos': r'\bdos\b|\bddos\b|denial.of.service|network.scan',
        'rootkit': r'rootkit|rootcheck|t1014',
        'privilege': r'privilege escalation|sudo|su\b|t1098|t1548',
        'account_management': r'account management|account creation|new user|new group|t1136',
    }
    pattern = patterns.get(classify(alert))
    if not pattern:
        return True
    text = ' '.join(str(playbook.get(k) or '') for k in ('playbook_id','playbook_name','playbook_source','playbook_text'))
    return bool(re.search(pattern, text[:3500], re.I))


def propose_playbook(report: dict, on_progress=None, alert: dict | None = None, allow_inconclusive: bool = False) -> dict:
    """Return a verbatim existing playbook; never generate response actions."""
    if on_progress:
        on_progress("retrieving_playbook", 4)

    if report.get("_parse_error"):
        return _skipped(
            report,
            "skipped",
            "Playbook lookup skipped because the investigation report could not be parsed.",
        )
    verdict = report.get("verdict")
    dos_context = _is_dos_report(report) or _is_dos_alert(alert or {})
    ssh_context = _is_ssh_context(report, alert or {})
    from agents.investigation_profiles import classify
    alert_profile = classify(alert or {})
    account_context = alert_profile in {'account_management', 'privilege'}
    if verdict == "benign" or (verdict == "inconclusive" and not dos_context and not ssh_context
                               and not account_context and not allow_inconclusive):
        return _skipped(
            report,
            "not_applicable",
            "No playbook selected because the investigation did not conclude malicious activity.",
        )
    if verdict not in {"malicious", "inconclusive"}:
        return _skipped(report, "not_applicable", "No supported investigation verdict for playbook lookup.")

    if ssh_context:
        selected = {"metadata": {"source": SSH_PLAYBOOK_SOURCE, "type": "playbooks"}}
    elif alert_profile == 'privilege':
        selected = {"metadata": {"source": PRIVILEGE_PLAYBOOK_SOURCE, "type": "playbooks"}}
    elif alert_profile == 'account_management':
        selected = {"metadata": {"source": ACCOUNT_PLAYBOOK_SOURCE, "type": "playbooks"}}
    else:
        matches = _retrieve_playbooks(_build_query(report, alert), top_k=16)
        if not matches:
            return _skipped(
                report,
                "not_found",
                "No existing playbook was found in the knowledge base.",
            )
        if dos_context:
            selected = next(
                (
                    match for match in matches
                    if (match.get("metadata") or {}).get("source")
                    == "PB-DOS-001_denial_of_service.txt"
                ),
                None,
            )
            if not selected:
                return _skipped(
                    report,
                    "not_found",
                    "The DoS playbook is not indexed. Rebuild the knowledge base before retrying.",
                )
        elif allow_inconclusive:
            selected = None
            for match in matches:
                metadata = match.get('metadata') or {}
                if metadata.get('type') != 'playbooks':
                    continue
                try:
                    text = _read_playbook(metadata.get('source'))
                except (ValueError, RuntimeError):
                    continue
                usable = (re.search(r'^PLAYBOOK ID:\s*\S+', text, re.M)
                          and re.search(r'^NAME:\s*\n\s*\S', text, re.M)
                          and re.search(r'^RESPONSE:\s*\n\s*\S', text, re.M))
                if usable and playbook_compatible(alert or {}, {'playbook_source':metadata.get('source'),'playbook_text':text}):
                    selected = match
                    break
            if not selected:
                return _skipped(report, 'not_found', 'No compatible indexed playbook was found for this alert.')
        else:
            selected = matches[0]
    metadata = selected.get("metadata") or {}
    source = metadata.get("source")
    if metadata.get("type") != "playbooks":
        raise ValueError("Retrieved document is not a playbook")
    playbook_text = _read_playbook(source)

    id_match = re.search(r"^PLAYBOOK ID:\s*(\S+)", playbook_text, re.MULTILINE)
    name_match = re.search(r"^NAME:\s*\n\s*(.+)", playbook_text, re.MULTILINE)
    if not id_match or not name_match:
        raise ValueError(f"Playbook source is missing its ID or name: {source}")

    if on_progress:
        on_progress("playbook_selected", 5)
    if verdict == "inconclusive" and ssh_context:
        notes = (
            "Existing SSH response playbook selected for review; a successful login after failures alone "
            "does not establish compromise. No actions were generated or executed."
        )
    elif verdict == "inconclusive" and dos_context:
        notes = (
            "Existing playbook retrieved from the knowledge base; the DoS assessment remains inconclusive "
            "until service impact is corroborated. No actions were generated or executed."
        )
    elif verdict == "inconclusive":
        notes = "Existing playbook retrieved for review; the investigation remains inconclusive. No actions were generated or executed."
    else:
        notes = "Existing playbook retrieved from the knowledge base; no actions were generated or executed."
    return {
        "_alert_id": report.get("_alert_id"),
        "status": "matched",
        "playbook_id": id_match.group(1),
        "playbook_name": name_match.group(1).strip(),
        "playbook_source": source,
        "playbook_text": playbook_text,
        "actions": [],
        "notes": notes,
        "citations": [metadata],
    }


if __name__ == "__main__":
    sample_report = {
        "_alert_id": "test-001",
        "incident_type": "SSH Brute Force",
        "severity": "HIGH",
        "verdict": "malicious",
        "confidence": 0.94,
        "mitre_techniques": ["T1110"],
        "findings": [{"statement": "Repeated failed SSH logins from one source."}],
    }
    print(json.dumps(propose_playbook(sample_report), ensure_ascii=False, indent=2))
