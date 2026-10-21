from datetime import datetime, timezone

import pytest

from common.alert_timeseries import build_alert_buckets


NOW = datetime(2026, 10, 3, 8, 7, 30, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    ("time_range", "expected_count"),
    [("1h", 12), ("6h", 12), ("24h", 24), ("7d", 28)],
)
def test_builds_fixed_bucket_count_and_fills_zeros(time_range, expected_count):
    buckets = build_alert_buckets([], time_range, now=NOW)

    assert len(buckets) == expected_count
    assert all(
        sum(bucket[severity] for severity in ("critical", "high", "medium", "low")) == 0
        for bucket in buckets
    )


def test_counts_alerts_in_bucket_without_cumulative_values():
    alerts = [
        {"created_at": NOW.timestamp() - 60, "severity": "HIGH"},
        {"created_at": NOW.timestamp() - 60, "severity": "LOW"},
        {"created_at": NOW.timestamp() - 301, "severity": "CRITICAL"},
    ]

    buckets = build_alert_buckets(alerts, "1h", now=NOW)

    assert sum(bucket["high"] for bucket in buckets) == 1
    assert sum(bucket["low"] for bucket in buckets) == 1
    assert sum(bucket["critical"] for bucket in buckets) == 1
    assert max(bucket["high"] for bucket in buckets) == 1


def test_alert_at_window_start_is_included_and_old_alert_is_excluded():
    start = datetime(2026, 10, 3, 7, 10, tzinfo=timezone.utc)
    alerts = [
        {"created_at": start.timestamp(), "severity": "MEDIUM"},
        {"created_at": start.timestamp() - 1, "severity": "MEDIUM"},
    ]

    buckets = build_alert_buckets(alerts, "1h", now=NOW)

    assert sum(bucket["medium"] for bucket in buckets) == 1
