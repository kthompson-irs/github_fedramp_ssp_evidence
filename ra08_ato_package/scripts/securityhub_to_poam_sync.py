#!/usr/bin/env python3
"""Export AWS Security Hub findings to POA&M rows."""
from __future__ import annotations

import csv
import json
import os
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import boto3

AWS_REGION = os.getenv("AWS_REGION")
OUTPUT_CSV = os.getenv("OUTPUT_CSV", "poam_securityhub.csv")
OUTPUT_JSON = os.getenv("OUTPUT_JSON", "poam_securityhub.json")
SEVERITY_FILTER = {s.strip().upper() for s in os.getenv("SEVERITY_FILTER", "CRITICAL,HIGH,MEDIUM,LOW").split(",") if s.strip()}

if not AWS_REGION:
    sys.exit("AWS_REGION is required.")

client = boto3.client("securityhub", region_name=AWS_REGION)

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


def _today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def _risk(sev: str) -> str:
    s = (sev or "").upper()
    if s in {"CRITICAL", "HIGH"}:
        return "High"
    if s in {"MEDIUM", "MODERATE"}:
        return "Moderate"
    return "Low"


def get_findings() -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    token: Optional[str] = None
    while True:
        kwargs = {
            "Filters": {
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                "SeverityLabel": [{"Value": s, "Comparison": "EQUALS"} for s in SEVERITY_FILTER],
            },
            "MaxResults": 100,
        }
        if token:
            kwargs["NextToken"] = token
        resp = client.get_findings(**kwargs)
        findings.extend(resp.get("Findings", []))
        token = resp.get("NextToken")
        if not token:
            break
    return findings


def to_rows(findings: List[Dict[str, Any]]) -> List[PoamRow]:
    rows: List[PoamRow] = []
    today = _today()
    for f in findings:
        sev = f.get("Severity", {}).get("Label", "LOW").upper()
        risk = _risk(sev)
        title = f.get("Title", "Security Hub finding")
        desc = f.get("Description", title)
        resource = (f.get("Resources") or [{}])[0].get("Id", "unknown-resource")
        rows.append(PoamRow(
            poam_id=f"SH-{f.get('Id', '')[:18]}",
            weakness_name=title[:120],
            weakness_description=desc,
            source_identifying_weakness="AWS Security Hub",
            asset_identifier=resource,
            severity=sev,
            risk_rating=risk,
            date_identified=today,
            scheduled_completion_date=today,
            actual_completion_date="",
            status="Open",
            owner="Cloud Operations",
            remediation_action="Review Security Hub finding and remediate underlying issue.",
            source_url=f.get("SourceUrl", ""),
        ))
    return rows


def write_outputs(rows: List[PoamRow]) -> None:
    fields = list(asdict(rows[0]).keys()) if rows else list(asdict(PoamRow("", "", "", "", "", "", "", "", "", "", "", "", "", "")).keys())
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in rows], f, indent=2)


def main() -> int:
    rows = to_rows(get_findings())
    write_outputs(rows)
    print(f"Wrote {len(rows)} POA&M rows to {OUTPUT_CSV} and {OUTPUT_JSON}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
