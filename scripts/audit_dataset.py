"""
Audit Dataset Quality — SOC-AI RAG System
==========================================
Scans all rag/documents/ and data/ files, checks for quality issues,
and generates audit_report.md.

Usage:
    python scripts/audit_dataset.py [--out PATH]
"""

import os
import re
import sys
import json
import glob
import argparse
from pathlib import Path
from collections import defaultdict

# ─── Paths ────────────────────────────────────────────────────────────────────
REPO_ROOT  = Path(__file__).resolve().parent.parent
DOCS_ROOT  = REPO_ROOT / "rag" / "documents"
DATA_DIR   = REPO_ROOT / "data"
REPORT_OUT = REPO_ROOT / "audit_report.md"

DOC_TYPES = ["mitre", "cve", "playbooks", "policies"]

MIN_WORDS = 50  # Files below this → "too short"

# Required keywords/sections per doc type
CVE_REQUIRED_FIELDS   = ["CVSS:", "Affected Products:", "Description:"]
MITRE_REQUIRED_FIELDS = ["Detection:", "Mitigation:"]

# JSON alert required top-level paths
ALERT_REQUIRED = [
    ("_source", "timestamp"),
    ("_source", "rule", "level"),
    ("_source", "agent"),
]

# ─── Helpers ──────────────────────────────────────────────────────────────────

def word_count(text: str) -> int:
    return len(text.split())


def has_replacement_char(text: str) -> bool:
    return "\ufffd" in text


def read_text(path: Path) -> tuple[str | None, str | None]:
    """Read file, return (content, error_msg). Tries utf-8 then latin-1."""
    try:
        content = path.read_text(encoding="utf-8")
        return content, None
    except UnicodeDecodeError as e:
        try:
            content = path.read_text(encoding="latin-1")
            return content, f"UTF-8 decode error (fallback to latin-1): {e}"
        except Exception as e2:
            return None, f"Unreadable: {e2}"


def deep_get(obj: dict, *keys):
    """Safely navigate nested dict."""
    cur = obj
    for k in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


# ─── Checkers ─────────────────────────────────────────────────────────────────

def check_txt_file(path: Path, doc_type: str) -> list[str]:
    """Returns list of issue strings for a .txt file. Empty = OK."""
    issues = []
    content, read_err = read_text(path)

    if read_err:
        issues.append(f"ENCODING: {read_err}")

    if content is None:
        return issues  # can't check further

    if has_replacement_char(content):
        issues.append("ENCODING: contains replacement character \\ufffd")

    wc = word_count(content)
    if wc < MIN_WORDS:
        issues.append(f"TOO_SHORT: {wc} words (min {MIN_WORDS})")

    if doc_type == "cve":
        for field in CVE_REQUIRED_FIELDS:
            if field not in content:
                issues.append(f"MISSING_FIELD: '{field}'")

    if doc_type == "mitre":
        for field in MITRE_REQUIRED_FIELDS:
            if field not in content:
                issues.append(f"MISSING_FIELD: '{field}'")

    # Generic check for placeholder/dummy content
    lower = content.lower()
    placeholders = ["lorem ipsum", "todo", "fixme", "placeholder", "n/a\nn/a"]
    for ph in placeholders:
        if ph in lower:
            issues.append(f"PLACEHOLDER: found '{ph}'")

    return issues


def check_json_file(path: Path) -> list[str]:
    """Returns list of issue strings for a .json alert file."""
    issues = []
    try:
        raw = path.read_text(encoding="utf-8")
    except Exception as e:
        return [f"UNREADABLE: {e}"]

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        return [f"JSON_PARSE_ERROR: {e}"]

    # Alerts can be a list of event objects or a single object
    events = data if isinstance(data, list) else [data]

    if not events:
        return ["EMPTY: JSON file contains empty array"]

    for i, event in enumerate(events):
        prefix = f"[item {i}]"
        # Check required fields
        if deep_get(event, "_source", "timestamp") is None:
            issues.append(f"{prefix} MISSING_FIELD: _source.timestamp")
        if deep_get(event, "_source", "rule", "level") is None:
            issues.append(f"{prefix} MISSING_FIELD: _source.rule.level")
        if deep_get(event, "_source", "agent") is None:
            issues.append(f"{prefix} MISSING_FIELD: _source.agent")
        # Validate types
        level = deep_get(event, "_source", "rule", "level")
        if level is not None and not isinstance(level, (int, float)):
            issues.append(f"{prefix} TYPE_ERROR: rule.level should be int, got {type(level).__name__}")
        ts = deep_get(event, "_source", "timestamp")
        if ts is not None and not isinstance(ts, str):
            issues.append(f"{prefix} TYPE_ERROR: timestamp should be str, got {type(ts).__name__}")

    return issues


# ─── Stats ────────────────────────────────────────────────────────────────────

def collect_stats(path: Path, doc_type: str) -> dict:
    """Collect basic stats for a txt file."""
    content, _ = read_text(path)
    if content is None:
        return {"words": 0, "chars": 0}
    return {"words": word_count(content), "chars": len(content)}


# ─── Main audit ───────────────────────────────────────────────────────────────

def audit() -> dict:
    results = {
        "ok": [],
        "issues": [],   # (path, [issue_str])
        "stats_by_type": defaultdict(list),  # doc_type -> [word_count]
    }

    # ── Audit txt docs ──
    for doc_type in DOC_TYPES:
        type_dir = DOCS_ROOT / doc_type
        if not type_dir.is_dir():
            print(f"  [WARN] Directory not found: {type_dir}")
            continue
        files = sorted(type_dir.glob("*"))
        txt_files = [f for f in files if f.suffix.lower() in (".txt", ".md")]
        print(f"  {doc_type:12s}: {len(txt_files)} files")

        for path in txt_files:
            issues = check_txt_file(path, doc_type)
            stats  = collect_stats(path, doc_type)
            results["stats_by_type"][doc_type].append(stats["words"])

            if issues:
                results["issues"].append((path, issues))
            else:
                results["ok"].append(path)

    # ── Audit JSON alerts ──
    json_files = sorted(DATA_DIR.glob("*.json"))
    print(f"  {'data (json)':12s}: {len(json_files)} files")
    for path in json_files:
        issues = check_json_file(path)
        if issues:
            results["issues"].append((path, issues))
        else:
            results["ok"].append(path)

    return results


# ─── Report ───────────────────────────────────────────────────────────────────

def generate_report(results: dict, out_path: Path) -> str:
    ok_count     = len(results["ok"])
    issue_count  = len(results["issues"])
    total        = ok_count + issue_count

    # Categorise issues
    by_severity = {"ERROR": [], "WARNING": [], "INFO": []}
    for path, issues in results["issues"]:
        worst = "INFO"
        for iss in issues:
            if any(k in iss for k in ("UNREADABLE", "JSON_PARSE_ERROR", "ENCODING")):
                worst = "ERROR"
            elif any(k in iss for k in ("MISSING_FIELD", "TOO_SHORT", "TYPE_ERROR")):
                if worst != "ERROR":
                    worst = "WARNING"
        by_severity[worst].append((path, issues))

    lines = []
    lines.append("# SOC-AI RAG Dataset — Audit Report\n")
    lines.append(f"**Generated:** {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    lines.append("---\n")

    # Summary table
    lines.append("## Summary\n")
    lines.append("| Status | Count |")
    lines.append("|--------|-------|")
    lines.append(f"| ✅ OK | {ok_count} |")
    lines.append(f"| ⚠️ Warning | {len(by_severity['WARNING'])} |")
    lines.append(f"| ❌ Error | {len(by_severity['ERROR'])} |")
    lines.append(f"| ℹ️ Info | {len(by_severity['INFO'])} |")
    lines.append(f"| **Total scanned** | **{total}** |")
    lines.append("")

    # Word count stats per type
    lines.append("## Word Count Statistics (txt files)\n")
    lines.append("| Type | Files | Min | Max | Average |")
    lines.append("|------|-------|-----|-----|---------|")
    for doc_type in DOC_TYPES:
        wcs = results["stats_by_type"].get(doc_type, [])
        if wcs:
            lines.append(
                f"| {doc_type} | {len(wcs)} "
                f"| {min(wcs)} | {max(wcs)} | {sum(wcs)//len(wcs)} |"
            )
        else:
            lines.append(f"| {doc_type} | 0 | — | — | — |")
    lines.append("")

    # Issue sections
    for severity, label, icon in [
        ("ERROR",   "Errors (must fix)",   "❌"),
        ("WARNING", "Warnings (review)",   "⚠️"),
        ("INFO",    "Info (low priority)", "ℹ️"),
    ]:
        entries = by_severity[severity]
        if not entries:
            continue
        lines.append(f"## {icon} {label} — {len(entries)} file(s)\n")
        for path, issues in entries:
            rel = path.relative_to(REPO_ROOT) if path.is_relative_to(REPO_ROOT) else path
            lines.append(f"### `{rel}`")
            for iss in issues:
                lines.append(f"- {iss}")
            lines.append("")

    # OK files (condensed)
    lines.append(f"## ✅ OK Files — {ok_count} file(s)\n")
    lines.append("<details><summary>Click to expand</summary>\n")
    for path in results["ok"]:
        rel = path.relative_to(REPO_ROOT) if path.is_relative_to(REPO_ROOT) else path
        lines.append(f"- `{rel}`")
    lines.append("\n</details>\n")

    report = "\n".join(lines)
    out_path.write_text(report, encoding="utf-8")
    return report


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Audit SOC-AI RAG dataset quality")
    parser.add_argument("--out", default=str(REPORT_OUT), help="Output report path")
    args = parser.parse_args()

    out_path = Path(args.out)
    print("=" * 60)
    print("SOC-AI Dataset Audit")
    print("=" * 60)
    print(f"Docs root : {DOCS_ROOT}")
    print(f"Data dir  : {DATA_DIR}")
    print(f"Report    : {out_path}")
    print()

    print("Scanning files...")
    results = audit()

    ok     = len(results["ok"])
    issues = len(results["issues"])
    total  = ok + issues

    print()
    print("Generating report...")
    generate_report(results, out_path)

    print()
    print("=" * 60)
    print(f"AUDIT COMPLETE: {total} files scanned")
    print(f"  [OK]     : {ok}")
    print(f"  [ISSUES] : {issues}")
    print(f"Report written to: {out_path}")
    print("=" * 60)

    # Print issues to console too
    if results["issues"]:
        print()
        print("Issues found:")
        for path, iss_list in results["issues"]:
            rel = path.relative_to(REPO_ROOT) if path.is_relative_to(REPO_ROOT) else path
            print(f"\n  {rel}")
            for iss in iss_list:
                print(f"    - {iss}")


if __name__ == "__main__":
    main()
