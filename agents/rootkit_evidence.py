
"""Read-only rootkit evidence correlation for SOC-AI."""

import json
import re
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

PRODUCER = "soc-ai-rootkit-snapshot-v1"
MAX_CANDIDATES = 2000
MAX_SOURCE_IDS = 20
LATE_ARRIVAL_HOURS = 24

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


def _int(value, name, minimum=0, maximum=4194304, decimal_string=False):
    # Wazuh's JSON decoder renders scalar data fields as strings. The nested
    # snapshot_json remains typed JSON and must still contain real integers.
    if decimal_string and isinstance(value, str) and re.fullmatch(r"[0-9]{1,16}", value):
        value = int(value)
    if type(value) is not int:
        raise ValueError(f"{name} must be an integer")
    result = value
    if not minimum <= result <= maximum:
        raise ValueError(f"{name} outside supported range")
    return result


def normalize_snapshot(data):
    """Decode and validate the endpoint envelope without discarding raw data.

    Invalid observations are deliberately rejected from evidence correlation but
    remain available in raw_event for audit and diagnostics.
    """
    if not isinstance(data, dict) or data.get("producer") != PRODUCER:
        return None, "producer_mismatch"
    try:
        observed_at = parse_time(data["observed_at"]).isoformat().replace("+00:00", "Z")
        target_pid = _int(data["target_pid"], "target_pid", 1, decimal_string=True)
        finding = data["finding"]
        if not isinstance(finding, str) or not finding or len(finding) > 128:
            raise ValueError("finding must be a non-empty string")
        encoded = data["snapshot_json"]
        if not isinstance(encoded, str) or not encoded:
            raise ValueError("snapshot_json must be a JSON string")
        snapshot = json.loads(encoded)
        if not isinstance(snapshot, dict):
            raise ValueError("snapshot_json must contain an object")
        if snapshot.get("producer") != PRODUCER:
            raise ValueError("snapshot producer mismatch")
        snapshot_observed = parse_time(snapshot["observed_at"])
        if snapshot_observed != parse_time(data["observed_at"]):
            raise ValueError("envelope and snapshot timestamps differ")
        if "started_at" in snapshot:
            parse_time(snapshot["started_at"])
        boot_id = snapshot.get("boot_id")
        if not isinstance(boot_id, str):
            raise ValueError("boot_id is required")
        uuid.UUID(boot_id)
        scan = snapshot.get("scan")
        if not isinstance(scan, dict) or scan.get("mode") != "targeted":
            raise ValueError("targeted scan metadata is required")
        if _int(scan.get("target_pid"), "scan.target_pid", 1) != target_pid:
            raise ValueError("target PID mismatch")
        suspects = snapshot.get("suspects")
        if not isinstance(suspects, list):
            raise ValueError("suspects must be an array")
        normalized_suspects = []
        for suspect in suspects:
            if not isinstance(suspect, dict):
                raise ValueError("suspect must be an object")
            item = dict(suspect)
            if "pid" in item:
                item["pid"] = _int(item["pid"], "suspect.pid", 1)
            if "identity" in item and item["identity"] is not None:
                identity = item["identity"]
                if not isinstance(identity, dict):
                    raise ValueError("identity must be an object or null")
                for key in ("pid", "tgid", "start_ticks"):
                    if key in identity:
                        identity[key] = _int(identity[key], f"identity.{key}", 0)
            normalized_suspects.append(item)
        normalized = dict(snapshot)
        normalized.update(producer=PRODUCER, observed_at=observed_at,
                          target_pid=target_pid, finding=finding,
                          boot_id=boot_id, suspects=normalized_suspects)
        return normalized, None
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None, "invalid_snapshot_schema"


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

    normalized = record.get("rootkit_snapshot")
    if isinstance(normalized, dict) and normalized.get("producer") == PRODUCER:
        return normalized
    if isinstance(data, dict) and data.get("producer") == PRODUCER:
        snapshot, _ = normalize_snapshot(data)
        return snapshot

    return None


def snapshot_covers_pid(snapshot, pid):
    if pid is None:
        return True

    if snapshot.get("target_pid") != snapshot.get("scan", {}).get("target_pid"):
        return False
    if pid is not None and snapshot.get("target_pid") not in (None, pid):
        return False
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

        if suspect.get("pid") != pid or suspect.get("tgid") not in (None, pid):
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
    trigger_snapshot = get_snapshot(alert)
    trigger_boot_id = trigger_snapshot.get("boot_id") if trigger_snapshot else None

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

    deadline = time.monotonic() + min(max(timeout, 0.1), 30.0)
    # Bound the indexed event-time range even when a snapshot arrives after its
    # observation. The Python check below still enforces the incident window.
    late_until = (end + timedelta(hours=LATE_ARRIVAL_HOURS)).isoformat().replace("+00:00", "Z")

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
                COALESCE(e.payload, z.payload),
                CAST(json_extract(COALESCE(e.payload, z.payload),
                    '$.raw_event.data.target_pid') AS TEXT) AS envelope_pid
            FROM investigation_event_index i
            LEFT JOIN events e ON e.id = i.id
            LEFT JOIN zeek_logs z ON z.id = i.id
            WHERE
                i.agent_id = ?
                AND i.event_time >= ?
                AND i.event_time <= ?
                AND (
                    i.event_time <= ?
                    OR (
                        json_extract(COALESCE(e.payload, z.payload), '$.raw_event.data.producer') = ?
                        AND julianday(json_extract(COALESCE(e.payload, z.payload),
                            '$.raw_event.data.observed_at')) BETWEEN julianday(?) AND julianday(?)
                    )
                )
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
                    ) IN ('521', '5132', '100200', '100201', '100205', '100206')
                )
            ORDER BY CASE
                WHEN json_extract(COALESCE(e.payload, z.payload), '$.raw_event.data.producer') = ?
                     AND length(envelope_pid) BETWEEN 1 AND 16
                     AND envelope_pid NOT GLOB '*[^0-9]*'
                     AND CAST(envelope_pid AS INTEGER) = ?
                     AND json_extract(COALESCE(e.payload, z.payload),
                         '$.raw_event.data.finding') = 'stable_process_visibility_discrepancy' THEN 0
                WHEN json_extract(COALESCE(e.payload, z.payload), '$.raw_event.data.producer') = ?
                     AND length(envelope_pid) BETWEEN 1 AND 16
                     AND envelope_pid NOT GLOB '*[^0-9]*'
                     AND CAST(envelope_pid AS INTEGER) = ? THEN 1
                WHEN CAST(json_extract(COALESCE(e.payload, z.payload), '$.rule.id') AS TEXT)
                     IN ('521', '5132') THEN 2
                WHEN CAST(json_extract(COALESCE(e.payload, z.payload), '$.rule.id') AS TEXT)
                     IN ('100200', '100205') THEN 3
                WHEN CAST(json_extract(COALESCE(e.payload, z.payload), '$.rule.id') AS TEXT)
                     = '100201' THEN 4
                ELSE 5 END, i.event_time, i.id
            LIMIT ?
            """,
            (agent_id, since, late_until, until, PRODUCER, since, until,
             PRODUCER, PRODUCER, target_pid or -1, PRODUCER, target_pid or -1,
             MAX_CANDIDATES + 1),
        ).fetchall()

    finally:
        db.close()

    candidate_limit_reached = len(rows) > MAX_CANDIDATES
    snapshot_groups = {}
    taint_groups = {}
    other_records = {}
    matched_source_count = 0
    duplicate_records = 0
    periodic_taint_records = 0
    invalid_snapshots = 0
    invalid_source_ids = []
    unscoped_snapshots = 0
    related_alerts = 0

    for record_id, payload, _ in rows[:MAX_CANDIDATES]:
        if not payload:
            continue

        if record_id == alert.get("id"):
            continue

        record = json.loads(payload)
        rule_id = str((record.get("rule") or {}).get("id") or "")
        raw_data = (record.get("raw_event") or {}).get("data") or {}
        snapshot_candidate = (isinstance(raw_data, dict) and raw_data.get("producer") == PRODUCER
                              or rule_id == "100206")
        if snapshot_candidate:
            snapshot = get_snapshot(record)
            if snapshot is None:
                invalid_snapshots += 1
                if len(invalid_source_ids) < MAX_SOURCE_IDS:
                    invalid_source_ids.append(record_id)
                continue
            if target_pid is None:
                unscoped_snapshots += 1
                continue
            if not snapshot_covers_pid(snapshot, target_pid):
                continue
            try:
                observed = parse_time(snapshot["observed_at"])
            except (KeyError, ValueError, TypeError):
                invalid_snapshots += 1
                if len(invalid_source_ids) < MAX_SOURCE_IDS:
                    invalid_source_ids.append(record_id)
                continue
            if not start <= observed <= end:
                continue
            if trigger_boot_id and snapshot.get("boot_id") != trigger_boot_id:
                continue
            # Reparse historical rows on read: a prior mapper version may have
            # stored a schema error for Wazuh's string-valued target_pid.
            record["rootkit_snapshot"] = snapshot
            record.pop("rootkit_snapshot_error", None)
            record["rootkit_evidence_class"] = "endpoint_observation"
            key = (snapshot["observed_at"], snapshot["target_pid"], snapshot["boot_id"],
                   raw_data.get("snapshot_json"))
            groups = snapshot_groups
        else:
            related_alerts += 1
            record["rootkit_evidence_class"] = (
                "detection" if rule_id in {"521", "5132"} else "context_telemetry"
            )
            if rule_id == "100201":
                full_log = (record.get("raw_event") or {}).get("full_log")
                key = (rule_id, full_log) if full_log else (rule_id, record_id)
                groups = taint_groups
            else:
                full_log = (record.get("raw_event") or {}).get("full_log")
                key = (rule_id, record.get("timestamp"), full_log) if full_log else (rule_id, record_id)
                groups = other_records
        matched_source_count += 1
        group = groups.get(key)
        if group is None:
            groups[key] = {"record": record, "source_ids": [record_id],
                           "event_times": {record.get("timestamp")}}
        else:
            if groups is taint_groups and record.get("timestamp") not in group["event_times"]:
                periodic_taint_records += 1
            else:
                duplicate_records += 1
            group["event_times"].add(record.get("timestamp"))
            group["source_ids"].append(record_id)
            if (group["record"].get("ingest_stream") == "archives"
                    and record.get("ingest_stream") != "archives"):
                group["record"] = record

    records = []
    positives = 0
    for group in snapshot_groups.values():
        record = group["record"]
        record["rootkit_source_record_ids"] = group["source_ids"][:MAX_SOURCE_IDS]
        record["rootkit_source_ids_omitted"] = max(0, len(group["source_ids"]) - MAX_SOURCE_IDS)
        positives += snapshot_positive(record["rootkit_snapshot"], target_pid)
        records.append(record)
    for group in other_records.values():
        record = group["record"]
        record["rootkit_source_record_ids"] = group["source_ids"][:MAX_SOURCE_IDS]
        record["rootkit_source_ids_omitted"] = max(0, len(group["source_ids"]) - MAX_SOURCE_IDS)
        records.append(record)
    for group in taint_groups.values():
        record = group["record"]
        times = sorted(t for t in group["event_times"] if t)
        record["rootkit_telemetry_summary"] = {
            "kind": "kernel_taint", "source_record_count": len(group["source_ids"]),
            "observation_count": len(times), "first_event_time": times[0] if times else None,
            "last_event_time": times[-1] if times else None,
            "source_record_ids_sample": group["source_ids"][:MAX_SOURCE_IDS],
            "source_record_ids_omitted": max(0, len(group["source_ids"]) - MAX_SOURCE_IDS),
            "interpretation": "Repeated identical taint observations are context, not proof of a new attack.",
        }
        records.append(record)
    records.sort(key=lambda record: (
        0 if record.get("rootkit_snapshot") and snapshot_positive(record["rootkit_snapshot"], target_pid)
        else 1 if record.get("rootkit_snapshot")
        else 2 if record["rootkit_evidence_class"] == "detection"
        else 3 if str((record.get("rule") or {}).get("id")) in {"100200", "100205"}
        else 4,
        str(record.get("timestamp") or ""), str(record.get("id") or ""),
    ))
    truncated = candidate_limit_reached or len(records) > limit

    return {
        "status": (
            "ok" if records else "unavailable"
        ),
        "records": records[:limit],
        "truncated": truncated,
        "target_pid": target_pid,
        "snapshot_count": len(snapshot_groups),
        "positive_snapshot_count": positives,
        "related_alert_count": related_alerts,
        "total_matched": matched_source_count,
        "consolidated_count": len(records),
        "duplicate_record_count": duplicate_records,
        "periodic_taint_record_count": periodic_taint_records,
        "invalid_snapshot_count": invalid_snapshots,
        "invalid_snapshot_source_ids": invalid_source_ids,
        "invalid_snapshot_ids_omitted": max(0, invalid_snapshots - len(invalid_source_ids)),
        "unscoped_snapshot_count": unscoped_snapshots,
        "candidate_limit_reached": candidate_limit_reached,
        "total_matched_is_lower_bound": candidate_limit_reached,
        "coverage": ("Only retained records in the same agent and incident window; "
                     f"{invalid_snapshots} invalid snapshot records excluded; "
                     f"{unscoped_snapshots} snapshots excluded without a trigger PID; "
                     f"at most {MAX_CANDIDATES} priority-ordered candidates inspected; "
                     f"late arrival limited to {LATE_ARRIVAL_HOURS} hours. "
                     "Snapshot boot ID is observed, not independently cross-verified. "
                     "ip is scope-checked only, not a result filter."),
        "source_coverage": (
            "Endpoint snapshots available"
            if snapshot_groups
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
