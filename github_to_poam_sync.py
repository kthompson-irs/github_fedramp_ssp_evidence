#!/usr/bin/env python3

import csv
import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List

from openpyxl import Workbook

GH_OWNER = os.getenv("GH_OWNER", "")
GH_REPO = os.getenv("GH_REPO", "")
AUDIT_FILE = Path(os.getenv("AUDIT_FINDINGS_JSON", "findings.json"))

OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "poam-output"))
OUTPUT_CSV = Path(os.getenv("OUTPUT_CSV", OUTPUT_DIR / "poam_github.csv"))
OUTPUT_JSON = Path(os.getenv("OUTPUT_JSON", OUTPUT_DIR / "poam_github.json"))
OUTPUT_SUMMARY = Path(os.getenv("OUTPUT_SUMMARY", OUTPUT_DIR / "poam_summary.json"))
OUTPUT_XLSX = Path(os.getenv("OUTPUT_XLSX", OUTPUT_DIR / "fedramp_poam_populated.xlsx"))

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class PoamRow:
    poam_id: str
    weakness_name: str
    weakness_description: str
    source_identifying_weakness: str
    asset_identifier: str
    severity: str
    risk_rating: str
    date_identified: str
    scheduled_completion_date: str
    actual_completion_date: str
    status: str
    owner: str
    remediation_action: str
    source_url: str


def map_severity(s):
    s = (s or "").lower()
    if s in ["high", "critical"]:
        return "High"
    if s in ["medium", "moderate"]:
        return "Moderate"
    return "Low"


def load_findings():
    if not AUDIT_FILE.exists():
        raise SystemExit(f"Missing findings file: {AUDIT_FILE}")
    return json.loads(AUDIT_FILE.read_text())


def convert(findings) -> List[PoamRow]:
    rows = []
    today = datetime.now(timezone.utc).date().isoformat()
    future = (datetime.now(timezone.utc) + timedelta(days=30)).date().isoformat()

    for i, f in enumerate(findings, 1):
        severity = map_severity(f.get("severity"))

        rows.append(PoamRow(
            poam_id=f"AUD-{i:05d}",
            weakness_name=f.get("category", "audit finding"),
            weakness_description=f.get("reason", ""),
            source_identifying_weakness="GitHub Audit Log",
            asset_identifier=f"{GH_OWNER}/{GH_REPO}" if GH_REPO else GH_OWNER,
            severity=severity,
            risk_rating=severity,
            date_identified=today,
            scheduled_completion_date=future,
            actual_completion_date="",
            status="Open",
            owner="Security",
            remediation_action="Investigate and remediate",
            source_url=""
        ))

    return rows


def write_csv(rows):
    with OUTPUT_CSV.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=asdict(rows[0]).keys())
        writer.writeheader()
        for r in rows:
            writer.writerow(asdict(r))


def write_json(rows):
    OUTPUT_JSON.write_text(json.dumps([asdict(r) for r in rows], indent=2))


def write_summary(rows):
    summary = {
        "total_count": len(rows),
        "high_count": sum(1 for r in rows if r.severity == "High"),
        "moderate_count": sum(1 for r in rows if r.severity == "Moderate"),
        "low_count": sum(1 for r in rows if r.severity == "Low"),
    }
    OUTPUT_SUMMARY.write_text(json.dumps(summary, indent=2))


def write_excel(rows):
    wb = Workbook()
    ws = wb.active
    ws.title = "POAM"

    headers = list(asdict(rows[0]).keys())
    ws.append(headers)

    for r in rows:
        ws.append(list(asdict(r).values()))

    wb.save(OUTPUT_XLSX)


def main():
    findings = load_findings()
    rows = convert(findings)

    write_csv(rows)
    write_json(rows)
    write_summary(rows)
    write_excel(rows)

    print(f"Converted {len(rows)} findings into POA&M")


if __name__ == "__main__":
    main()
