"""
Build Dataset Script for SOC-AI RAG System
==========================================
Downloads and parses:
  1. MITRE ATT&CK enterprise JSON (STIX 2.0)
  2. CVE NVD JSON feeds (fkie-cad releases, 2023-2025)

Then creates individual .txt files in rag/documents/mitre/ and rag/documents/cve/

Usage:
    python scripts/build_dataset.py [--mitre] [--cve] [--all]

Options:
    --mitre   Build only MITRE ATT&CK data
    --cve     Build only CVE data
    --all     Build everything (default if no flag given)
"""

import os
import re
import sys
import json
import lzma
import argparse
import textwrap
import urllib.request
from pathlib import Path

# ─── Paths ────────────────────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parent.parent
MITRE_DIR = REPO_ROOT / "rag" / "documents" / "mitre"
CVE_DIR   = REPO_ROOT / "rag" / "documents" / "cve"

MITRE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    "/master/enterprise-attack/enterprise-attack.json"
)

# fkie-cad NVD JSON feeds — one file per year
CVE_YEARS = [2023, 2024, 2025]
CVE_BASE_URL = (
    "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download"
)

# ─── Filtering config ─────────────────────────────────────────────────────────
# Keep ATT&CK techniques for these platforms (case-insensitive match)
MITRE_PLATFORMS = {"windows", "linux", "network"}

# Minimum CVSS score for CVE inclusion
CVE_MIN_CVSS = 7.0

# Vendor/product keywords to prioritize for CVE (if empty → take all HIGH+CRITICAL)
CVE_RELEVANT_KEYWORDS = {
    "windows", "microsoft", "linux", "kernel", "apache", "nginx",
    "openssh", "ssl", "openssl", "vmware", "cisco", "juniper",
    "samba", "exchange", "iis", "rdp", "smb", "wordpress", "log4j",
    "spring", "fortinet", "palo alto", "checkpoint",
}

# Max CVE files to generate per year (0 = unlimited)
CVE_MAX_PER_YEAR = 300

# ─── Helpers ──────────────────────────────────────────────────────────────────

def slugify(text: str, maxlen: int = 50) -> str:
    """Convert text to a safe filename slug."""
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    text = text.strip("_")
    return text[:maxlen]


def download(url: str, label: str) -> bytes:
    """Download URL with progress indicator, return raw bytes."""
    print(f"  [download] {label}")
    print(f"    URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "SOC-AI-DataBuilder/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        total = int(resp.headers.get("Content-Length", 0))
        data = bytearray()
        chunk = 1 << 16  # 64 KB
        while True:
            block = resp.read(chunk)
            if not block:
                break
            data.extend(block)
            if total:
                pct = len(data) * 100 // total
                print(f"\r    {len(data) // 1024:,} KB / {total // 1024:,} KB  ({pct}%)",
                      end="", flush=True)
    print()
    return bytes(data)


def wrap(text: str, width: int = 78, indent: str = "") -> str:
    """Wrap a long text block."""
    if not text:
        return ""
    return textwrap.fill(text.strip(), width=width, initial_indent=indent,
                         subsequent_indent=indent)


# ─── MITRE ATT&CK ─────────────────────────────────────────────────────────────

def build_mitre():
    """Download enterprise-attack.json, parse, write per-technique .txt files."""
    MITRE_DIR.mkdir(parents=True, exist_ok=True)

    print("\n=== MITRE ATT&CK ===")
    raw = download(MITRE_URL, "enterprise-attack.json")
    data = json.loads(raw)

    objects = data.get("objects", [])
    print(f"  Total STIX objects: {len(objects)}")

    # Build lookup: id -> object (for relationships)
    obj_by_id = {o["id"]: o for o in objects}

    # Build tactic name lookup from x-mitre-tactic
    tactic_lookup: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic":
            short = obj.get("x_mitre_shortname", "")
            name  = obj.get("name", "")
            if short:
                tactic_lookup[short] = name

    # Build mitigation lookup: technique_id -> list of mitigation names
    # via "mitigates" relationships
    mitigations_map: dict[str, list[str]] = {}
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "mitigates":
            continue
        src_id = obj.get("source_ref", "")
        tgt_id = obj.get("target_ref", "")
        src = obj_by_id.get(src_id)
        tgt = obj_by_id.get(tgt_id)
        if src and tgt:
            tech_id = tgt.get("external_references", [{}])[0].get("external_id", "")
            mit_name = src.get("name", "")
            if tech_id and mit_name:
                mitigations_map.setdefault(tech_id, []).append(mit_name)

    # Filter attack-patterns
    techniques = [
        o for o in objects
        if o.get("type") == "attack-pattern"
        and not o.get("x_mitre_deprecated", False)
        and not o.get("revoked", False)
    ]
    print(f"  Active attack-patterns (before platform filter): {len(techniques)}")

    written = 0
    skipped = 0
    for tech in techniques:
        platforms = {p.lower() for p in tech.get("x_mitre_platforms", [])}
        if not platforms.intersection(MITRE_PLATFORMS):
            skipped += 1
            continue

        # External ID (e.g. T1110, T1110.001)
        ext_refs = tech.get("external_references", [])
        tech_id  = next(
            (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
            None
        )
        if not tech_id:
            skipped += 1
            continue

        name        = tech.get("name", "Unknown")
        description = tech.get("description", "")
        detection   = tech.get("x_mitre_detection", "")

        # Tactics from kill chain phases
        tactics = [
            tactic_lookup.get(kcp["phase_name"], kcp["phase_name"].replace("-", " ").title())
            for kcp in tech.get("kill_chain_phases", [])
            if kcp.get("kill_chain_name") == "mitre-attack"
        ]

        # Sub-techniques (objects whose parent this is)
        sub_techs = [
            o.get("external_references", [{}])[0].get("external_id", "") + " - " + o.get("name", "")
            for o in techniques
            if o.get("x_mitre_is_subtechnique")
            and any(
                r.get("external_id", "").startswith(tech_id + ".")
                for r in o.get("external_references", [])
                if r.get("source_name") == "mitre-attack"
            )
        ]

        mitigations = mitigations_map.get(tech_id, [])

        # ── Format file content ──
        lines = []
        lines.append(f"{tech_id} - {name}")
        lines.append("")
        lines.append(f"Tactic: {', '.join(tactics) if tactics else 'Unknown'}")
        lines.append(f"Platform: {', '.join(sorted(platforms))}")
        lines.append("")
        lines.append("Description:")
        # Strip markdown links and clean up
        clean_desc = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", description)
        clean_desc = re.sub(r"\(Citation:[^)]+\)", "", clean_desc).strip()
        lines.append(wrap(clean_desc, width=78))
        lines.append("")

        if sub_techs:
            lines.append("Sub-techniques:")
            for st in sub_techs:
                lines.append(f"  {st}")
            lines.append("")

        lines.append("Detection:")
        if detection:
            clean_det = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", detection)
            clean_det = re.sub(r"\(Citation:[^)]+\)", "", clean_det).strip()
            lines.append(wrap(clean_det, width=78))
        else:
            lines.append("Monitor for anomalous behavior related to this technique.")
        lines.append("")

        lines.append("Mitigation:")
        if mitigations:
            for m in mitigations:
                lines.append(f"  - {m}")
        else:
            lines.append("  - Follow vendor hardening guidelines.")
            lines.append("  - Apply least-privilege principle.")
        lines.append("")

        filename = f"{tech_id.replace('.', '_')}_{slugify(name)}.txt"
        filepath = MITRE_DIR / filename
        filepath.write_text("\n".join(lines), encoding="utf-8")
        written += 1

    print(f"  Written: {written} technique files  |  Skipped (platform/no-id): {skipped}")
    print(f"  Output: {MITRE_DIR}")
    return written


# ─── CVE ──────────────────────────────────────────────────────────────────────

def _cvss_score(cve_item: dict) -> float:
    """Extract the highest available CVSS base score from a CVE item."""
    metrics = cve_item.get("metrics", {})
    # Try CVSSv3.1 first, then v3.0, then v2
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            try:
                return float(entries[0]["cvssData"]["baseScore"])
            except (KeyError, TypeError, ValueError):
                pass
    return 0.0


def _cvss_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"


def _is_relevant(cve_item: dict) -> bool:
    """Check if a CVE matches relevant vendor/product keywords."""
    if not CVE_RELEVANT_KEYWORDS:
        return True
    desc = " ".join(
        d.get("value", "") for d in cve_item.get("descriptions", [])
        if d.get("lang") == "en"
    ).lower()
    # Check fkie-cad "affected" field (vendor/product)
    aff_str = json.dumps(cve_item.get("affected", {})).lower()
    combined = desc + " " + aff_str
    return any(kw in combined for kw in CVE_RELEVANT_KEYWORDS)


def build_cve():
    """Download CVE NVD feeds, parse, write per-CVE .txt files."""
    CVE_DIR.mkdir(parents=True, exist_ok=True)

    print("\n=== CVE Data ===")
    total_written = 0

    for year in CVE_YEARS:
        url = f"{CVE_BASE_URL}/CVE-{year}.json.xz"
        label = f"CVE-{year}.json.xz"
        print(f"\n  --- Year {year} ---")

        try:
            compressed = download(url, label)
        except Exception as e:
            print(f"  [WARN] Could not download {label}: {e}")
            # Try alternative URL format
            alt_url = (
                f"https://github.com/fkie-cad/nvd-json-data-feeds"
                f"/releases/download/latest/CVE-{year}.json.xz"
            )
            try:
                print(f"  [retry] Trying alternative URL...")
                compressed = download(alt_url, label)
            except Exception as e2:
                print(f"  [ERROR] Both URLs failed for {year}: {e2}")
                continue

        print(f"  Decompressing {label}...")
        try:
            raw_json = lzma.decompress(compressed)
        except Exception as e:
            print(f"  [ERROR] Decompression failed: {e}")
            continue

        print(f"  Parsing JSON...")
        try:
            feed = json.loads(raw_json)
        except Exception as e:
            print(f"  [ERROR] JSON parse failed: {e}")
            continue

        # fkie-cad format: {"cve_items": [...], "cve_count": N, ...}
        # Each item is a flat CVE dict (not nested under "cve" key)
        if isinstance(feed, dict):
            vulnerabilities = (
                feed.get("cve_items") or
                feed.get("vulnerabilities") or
                []
            )
        elif isinstance(feed, list):
            vulnerabilities = feed
        else:
            vulnerabilities = []

        print(f"  Total CVEs in feed: {len(vulnerabilities)}")

        written_year = 0
        for item in vulnerabilities:
            if CVE_MAX_PER_YEAR and written_year >= CVE_MAX_PER_YEAR:
                break

            # fkie-cad items are flat (no nested "cve" key)
            cve_data = item

            score = _cvss_score(cve_data)
            if score < CVE_MIN_CVSS:
                continue

            if not _is_relevant(cve_data):
                continue

            cve_id = cve_data.get("id", "CVE-UNKNOWN")
            severity = _cvss_severity(score)
            published = cve_data.get("published", "")[:10]

            # Description (English)
            desc_en = next(
                (d["value"] for d in cve_data.get("descriptions", [])
                 if d.get("lang") == "en"),
                "No description available."
            )

            # CWE
            cwes = []
            for weakness in cve_data.get("weaknesses", []):
                for wd in weakness.get("description", []):
                    if wd.get("lang") == "en" and wd.get("value", "").startswith("CWE-"):
                        cwes.append(wd["value"])

            # Affected products — fkie-cad uses "affected[].affectedData[].vendor/product"
            affected = []
            for aff_block in cve_data.get("affected", []):
                for aff_data in aff_block.get("affectedData", []):
                    vendor  = aff_data.get("vendor", "")
                    product = aff_data.get("product", "")
                    if vendor or product:
                        entry = f"{vendor} {product}".strip()
                        if entry not in affected:
                            affected.append(entry)
                if len(affected) >= 5:
                    break

            # References (top 2)
            refs = [
                r.get("url", "") for r in cve_data.get("references", [])
            ][:2]

            # Attack vector from CVSS
            attack_vector = "Unknown"
            metrics = cve_data.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key, [])
                if entries:
                    try:
                        cvss_data = entries[0]["cvssData"]
                        attack_vector = cvss_data.get(
                            "attackVector",
                            cvss_data.get("accessVector", "Unknown")
                        )
                    except (KeyError, IndexError):
                        pass
                    break

            # ── Format file ──
            vendor_prod_summary = ", ".join(affected[:3]) if affected else "Unknown"
            lines = []
            lines.append(f"[{cve_id} | {severity} | {vendor_prod_summary}]")
            lines.append(f"CVE ID: {cve_id}")
            lines.append(f"Severity: {severity} (CVSS: {score:.1f})")
            lines.append(f"Published: {published}")
            lines.append(f"Attack Vector: {attack_vector}")
            if cwes:
                lines.append(f"CWE: {', '.join(cwes[:3])}")
            lines.append("")
            lines.append("Affected Products:")
            if affected:
                for prod in affected[:5]:
                    lines.append(f"  - {prod}")
            else:
                lines.append("  - See CVE references for details.")
            lines.append("")
            lines.append("Description:")
            lines.append(wrap(desc_en, width=78))
            lines.append("")
            lines.append("Mitigation:")
            lines.append("  - Apply vendor-provided security patches immediately.")
            lines.append("  - Review vendor advisories for workarounds.")
            lines.append("  - Monitor for exploitation indicators in logs.")
            lines.append("")
            if refs:
                lines.append("References:")
                for r in refs:
                    lines.append(f"  - {r}")
                lines.append("")

            safe_id = cve_id.replace("/", "_")
            filepath = CVE_DIR / f"{safe_id}.txt"
            filepath.write_text("\n".join(lines), encoding="utf-8")
            written_year += 1

        print(f"  Written: {written_year} CVE files for {year}")
        total_written += written_year

    print(f"\n  Total CVE files written: {total_written}")
    print(f"  Output: {CVE_DIR}")
    return total_written


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Build SOC-AI RAG dataset")
    parser.add_argument("--mitre", action="store_true", help="Build MITRE data only")
    parser.add_argument("--cve",   action="store_true", help="Build CVE data only")
    parser.add_argument("--all",   action="store_true", help="Build all (default)")
    args = parser.parse_args()

    do_all   = args.all or (not args.mitre and not args.cve)
    do_mitre = args.mitre or do_all
    do_cve   = args.cve   or do_all

    results = {}

    if do_mitre:
        results["mitre"] = build_mitre()

    if do_cve:
        results["cve"] = build_cve()

    print("\n" + "=" * 60)
    print("BUILD COMPLETE")
    print("=" * 60)
    for k, v in results.items():
        print(f"  {k.upper():10s}: {v} files written")
    print()
    print("Next step: run  python -m rag.ingest  to index into ChromaDB.")


if __name__ == "__main__":
    main()
