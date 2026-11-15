
"""Read-only rootkit evidence correlation for SOC-AI."""

import json
import re
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

PRODUCER = "soc-ai-rootkit-snapshot-v1"

PID_RE = re.compile(
    r"Process\s+['\"]?(\d{1,8})['\"]?\s+hidden\s+from\s+/proc",
    re.IGNORECASE,
)


def parse_time(value):
    dt = datetime.fromisoformat(
        str(value).replace("Z", "+00:00")
    )
    if dt.tzinfo is None:
        raise ValueError("Timestamp must contain timezone")
    return dt.astimezone(timezone.utc)


def extract_pid(alert):
    """Extract hidden PID from Wazuh Rule 521."""
    raw = alert.get("raw_event") or {}
    data = raw.get("data") or {}

    if not isinstance(data, dict):
        data = {}

    sources = [
        raw.get("full_log"),
        data.get("title"),
        alert.get("full_log"),
    ]

    for source in sources:
        match = PID_RE.search(str(source or ""))
        if match:
            pid = int(match.group(1))
            if 1 <= pid <= 4194304:
                return pid

    return None


def get_snapshot(record):
    """Identify a snapshot forwarded by Wazuh."""
    raw = record.get("raw_event") or {}
    data = raw.get("data") or {}

    if isinstance(data, dict):
        if data.get("producer") == PRODUCER:
            return data

    return None


def snapshot_covers_pid(snapshot, pid):
    if pid is None:
        return True

    scan = snapshot.get("scan") or {}

    if scan.get("mode") == "targeted":
        return scan.get("target_pid") == pid

    try:
        start = int(scan.get("start_pid", 1))
        end = int(scan.get("end_pid", 0))
        return start <= pid <= end
    except (TypeError, ValueError):
        return False


def snapshot_positive(snapshot, pid):
    """Require repeated process-visibility discrepancy."""
    if pid is None:
        return False

    for suspect in snapshot.get("suspects") or []:
        if not isinstance(suspect, dict):
            continue

        if suspect.get("pid") != pid:
            continue

        if (
            suspect.get("finding")
            == "stable_process_visibility_discrepancy"
            and suspect.get("recheck_kill0") == "exists"
            and suspect.get("recheck_proc_visible") is False
            and suspect.get("recheck_ps_visible") is False
        ):
            return True

    return False


def search(
    db_path,
    agent_id,
    since,
    until,
    alert,
    pid=None,
    limit=20,
    timeout=10.0,
):
    """Find rootkit evidence for the same agent and incident."""

    target_pid = extract_pid(alert)

    if pid is not None:
        if target_pid is None or pid != target_pid:
            raise ValueError(
                "PID must match the triggering alert"
            )

    if not 1 <= limit <= 100:
        raise ValueError("Invalid result limit")

    start = parse_time(since)
    end = parse_time(until)

    if start > end:
        raise ValueError("Invalid time window")

    deadline = time.monotonic() + min(
        max(timeout, 0.1), 30.0
    )

    uri = Path(db_path).resolve().as_uri() + "?mode=ro"

    db = sqlite3.connect(
        uri, uri=True, timeout=0.5
    )

    try:
        db.execute("PRAGMA query_only=ON")
        db.set_progress_handler(
            lambda: int(time.monotonic() > deadline),
            1000,
        )

        rows = db.execute(
            """
            SELECT
                i.id,
                COALESCE(e.payload, z.payload)
            FROM investigation_event_index i
            LEFT JOIN events e ON e.id = i.id
            LEFT JOIN zeek_logs z ON z.id = i.id
            WHERE
                i.agent_id = ?
                AND i.event_time >= ?
                AND i.event_time <= ?
                AND i.category != 'network'
                AND (
                    json_extract(
                        COALESCE(e.payload, z.payload),
                        '$.raw_event.data.producer'
                    ) = ?
                    OR CAST(
                        json_extract(
                            COALESCE(e.payload, z.payload),
                            '$.rule.id'
                        ) AS TEXT
                    ) IN ('521', '5132')
                )
            ORDER BY i.event_time, i.id
            LIMIT 201
            """,
            (agent_id, since, until, PRODUCER),
        ).fetchall()

    finally:
        db.close()

    records = []
    snapshots = 0
    positives = 0
    related_alerts = 0

    for record_id, payload in rows[:200]:
        if not payload:
            continue

        if record_id == alert.get("id"):
            continue

        record = json.loads(payload)
        snapshot = get_snapshot(record)

        if snapshot:
            if not snapshot_covers_pid(
                snapshot, target_pid
            ):
                continue

            try:
                observed = parse_time(
                    snapshot["observed_at"]
                )
            except (KeyError, ValueError, TypeError):
                continue

            if not start <= observed <= end:
                continue

            snapshots += 1

            if snapshot_positive(
                snapshot, target_pid
            ):
                positives += 1
        else:
            related_alerts += 1

        records.append(record)

    # Prefer endpoint observations over repeated alerts.
    records.sort(
        key=lambda r: (
            0 if get_snapshot(r) else 1,
            str(r.get("timestamp") or ""),
            str(r.get("id") or ""),
        )
    )

    truncated = (
        len(rows) > 200 or len(records) > limit
    )

    return {
        "status": (
            "ok" if records else "unavailable"
        ),
        "records": records[:limit],
        "truncated": truncated,
        "target_pid": target_pid,
        "snapshot_count": snapshots,
        "positive_snapshot_count": positives,
        "related_alert_count": related_alerts,
        "total_matched": len(records),
        "source_coverage": (
            "Endpoint snapshots available"
            if snapshots
            else "No endpoint snapshot available"
        ),
        "interpretation": (
            "Repeated rootcheck alerts are not "
            "independent process confirmation. "
            "A positive snapshot is additional "
            "evidence of a visibility discrepancy, "
            "not automatic proof of malicious intent."
        ),
    }
