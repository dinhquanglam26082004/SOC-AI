"""Fixed-window alert time series aggregation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable


RANGE_CONFIG: dict[str, tuple[int, int]] = {
    "1h": (300, 12),
    "6h": (1800, 12),
    "24h": (3600, 24),
    "7d": (21600, 28),
}
SEVERITIES = ("critical", "high", "medium", "low")


def _utc_datetime(value: Any) -> datetime | None:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def bucket_spec(time_range: str) -> tuple[int, int]:
    try:
        return RANGE_CONFIG[time_range]
    except KeyError as exc:
        raise ValueError(f"Unsupported alert time range: {time_range}") from exc


def build_alert_buckets(
    alerts: Iterable[dict[str, Any]],
    time_range: str = "24h",
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Return fixed UTC buckets, including zero-count buckets."""
    bucket_seconds, bucket_count = bucket_spec(time_range)
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    epoch = int(current.timestamp())
    end_epoch = epoch - (epoch % bucket_seconds)
    start_epoch = end_epoch - (bucket_count - 1) * bucket_seconds

    buckets = [
        {
            "bucket_start": datetime.fromtimestamp(
                start_epoch + index * bucket_seconds, tz=timezone.utc
            ).isoformat().replace("+00:00", "Z"),
            **{severity: 0 for severity in SEVERITIES},
        }
        for index in range(bucket_count)
    ]

    for alert in alerts:
        timestamp = _utc_datetime(alert.get("created_at"))
        if timestamp is None:
            timestamp = _utc_datetime(alert.get("timestamp"))
        if timestamp is None:
            continue
        alert_epoch = timestamp.timestamp()
        if alert_epoch < start_epoch or alert_epoch > epoch:
            continue
        index = int((alert_epoch - start_epoch) // bucket_seconds)
        if 0 <= index < bucket_count:
            severity = str(alert.get("severity", "LOW")).lower()
            if severity in SEVERITIES:
                buckets[index][severity] += 1

    return buckets
