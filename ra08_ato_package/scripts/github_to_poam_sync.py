#!/usr/bin/env python3
"""Pull GitHub code scanning alerts and repository security advisories and emit POA&M rows."""
from __future__ import annotations

import csv
import json
import os
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

import requests

API_VERSION = os.getenv("GITHUB_API_VERSION", "2022-11-28")
TOKEN = os.getenv("GITHUB_TOKEN")
OWNER = os.getenv("GITHUB_OWNER")
REPO = os.getenv("GITHUB_REPO")
OUTPUT_CSV = os.getenv("OUTPUT_CSV", "poam_github.csv")
OUTPUT_JSON = os.getenv("OUTPUT_JSON", "poam_github.json")

if not TOKEN or not OWNER:
    sys.exit("GITHUB_TOKEN and GITHUB_OWNER are required.")

session = requests.Session()
session.headers.update({
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": API_VERSION,
})

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


def _paged_get(url: str, params: Optional[dict] = None) -> Iterable[Dict[str, Any]]:
    next_url = url
    while next_url:
        resp = session.get(next_url, params=params)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            for item in data:
                yield item
        else:
            yield data
        next_url = None
        link = resp.headers.get("Link", "")
        for part in link.split(","):
            if 'rel="next"' in part:
                next_url = part[part.find("<") + 1 : part.find(">")]
                params = None
                break


def _map_severity(sev: str) -> str:
    s = (sev or "").lower()
    if s in {"critical", "high"}:
        return "High"
    if s in {"medium", "moderate"}:
        return "Moderate"
    return "Low"


def _today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def code_scanning_alerts() -> Iterable[Dict[str, Any]]:
    if REPO:
        url = f"https://api.github.com/repos/{OWNER}/{REPO}/code-scanning/alerts"
    else:
        url = f"https://api.github.com/orgs/{OWNER}/code-scanning/alerts"
    return _paged_get(url, params={"state": "open", "per_page": 100})


def repo_security_advisories() -> Iterable[Dict[str, Any]]:
    if not REPO:
        return []
    url = f"https://api.github.com/repos/{OWNER}/{REPO}/security-advisories"
    return _paged_get(url, params={"state": "open", "per_page": 100})


def to_poam_rows() -> List[PoamRow]:
    rows: List[PoamRow] = []
    today = _today()

    for alert in code_scanning_alerts():
        severity = _map_severity(alert.get("rule", {}).get("security_severity_level") or alert.get("most_recent_instance", {}).get("severity"))
        path = (alert.get("most_recent_instance") or {}).get("location", {}).get("path", "repository")
        title = alert.get("rule", {}).get("description") or alert.get("rule", {}).get("id") or "Code scanning alert"
        rows.append(PoamRow(
            poam_id=f"GHA-{alert.get('number', '')}",
            weakness_name=title[:120],
            weakness_description=f"GitHub code scanning alert on {path}. Alert: {title}.",
            source_identifying_weakness="GitHub Code Scanning / CodeQL",
            asset_identifier=f"{OWNER}/{REPO}" if REPO else OWNER,
            severity=severity,
            risk_rating=severity,
            date_identified=today,
            scheduled_completion_date=today,
            actual_completion_date="",
            status="Open",
            owner="DevSecOps",
            remediation_action="Review code scanning alert and remediate vulnerable code or dependency.",
            source_url=alert.get("html_url", ""),
        ))

    for adv in repo_security_advisories():
        gh_sev = (adv.get("severity") or "moderate").capitalize()
        risk = _map_severity(gh_sev)
        rows.append(PoamRow(
            poam_id=f"GHA-ADV-{adv.get('ghsa_id', '')}",
            weakness_name=adv.get("summary", "Repository security advisory")[:120],
            weakness_description=adv.get("description", "Open GitHub repository advisory."),
            source_identifying_weakness="GitHub Repository Security Advisory",
            asset_identifier=f"{OWNER}/{REPO}" if REPO else OWNER,
            severity=gh_sev,
            risk_rating=risk,
            date_identified=today,
            scheduled_completion_date=today,
            actual_completion_date="",
            status="Open",
            owner="DevSecOps",
            remediation_action="Patch dependency or apply available GitHub advisory fix.",
            source_url=adv.get("html_url", ""),
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
    rows = to_poam_rows()
    write_outputs(rows)
    print(f"Wrote {len(rows)} POA&M rows to {OUTPUT_CSV} and {OUTPUT_JSON}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
