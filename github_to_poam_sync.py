#!/usr/bin/env python3
"""Pull GitHub code scanning alerts and repository security advisories and emit POA&M rows."""

from __future__ import annotations

import csv
import json
import os
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests

GH_TOKEN = os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN")
GH_OWNER = os.getenv("GH_OWNER") or os.getenv("GITHUB_OWNER")
GH_REPO = os.getenv("GH_REPO") or os.getenv("GITHUB_REPO") or ""
GH_API_VERSION = os.getenv("GH_API_VERSION") or os.getenv("GITHUB_API_VERSION", "2022-11-28")

OUTPUT_DIR = os.getenv("OUTPUT_DIR", "poam-output")
OUTPUT_CSV = os.getenv("OUTPUT_CSV", str(Path(OUTPUT_DIR) / "poam_github.csv"))
OUTPUT_JSON = os.getenv("OUTPUT_JSON", str(Path(OUTPUT_DIR) / "poam_github.json"))
OUTPUT_SUMMARY = os.getenv("OUTPUT_SUMMARY", str(Path(OUTPUT_DIR) / "poam_summary.json"))

if not GH_TOKEN or not GH_OWNER:
    sys.exit("GH_TOKEN and GH_OWNER are required.")

Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

session = requests.Session()
session.headers.update(
    {
        "Authorization": f"Bearer {GH_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": GH_API_VERSION,
        "User-Agent": "github-to-poam-sync/1.2",
    }
)


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
    next_params = dict(params or {})

    while next_url:
        resp = session.get(next_url, params=next_params, timeout=30)
        if resp.status_code >= 400:
            raise RuntimeError(f"GET {resp.url} failed: {resp.status_code} {resp.text[:600]}")
        data = resp.json()

        if isinstance(data, list):
            for item in data:
                yield item
        else:
            yield data

        next_url = None
        next_params = {}
        link = resp.headers.get("Link", "")
        for part in link.split(","):
            if 'rel="next"' in part and "<" in part and ">" in part:
                next_url = part[part.find("<") + 1 : part.find(">")]
                break


def _safe_list(url: str, params: Optional[dict], label: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    try:
        return list(_paged_get(url, params)), None
    except Exception as e:
        return [], f"{label} unavailable: {e}"


def _map_severity(sev: str) -> str:
    s = (sev or "").lower()
    if s in {"critical", "high"}:
        return "High"
    if s in {"medium", "moderate"}:
        return "Moderate"
    return "Low"


def _today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def collect_rows() -> Tuple[List[PoamRow], List[str]]:
    rows: List[PoamRow] = []
    errors: List[str] = []
    today = _today()

    if GH_REPO:
        alerts_url = f"https://api.github.com/repos/{GH_OWNER}/{GH_REPO}/code-scanning/alerts"
        advisories_url = f"https://api.github.com/repos/{GH_OWNER}/{GH_REPO}/security-advisories"
    else:
        alerts_url = f"https://api.github.com/orgs/{GH_OWNER}/code-scanning/alerts"
        advisories_url = None

    alerts, err = _safe_list(alerts_url, {"state": "open", "per_page": 100}, "code scanning alerts")
    if err:
        errors.append(err)

    advisories: List[Dict[str, Any]] = []
    if advisories_url:
        advisories, err = _safe_list(advisories_url, {"state": "open", "per_page": 100}, "security advisories")
        if err:
            errors.append(err)

    for alert in alerts:
        severity = _map_severity(
            alert.get("rule", {}).get("security_severity_level")
            or alert.get("most_recent_instance", {}).get("severity")
        )

        title = (
            alert.get("rule", {}).get("description")
            or alert.get("rule", {}).get("id")
            or "Code scanning alert"
        )

        rows.append(
            PoamRow(
                poam_id=f"GHA-{alert.get('number', '')}",
                weakness_name=title[:120],
                weakness_description=title,
                source_identifying_weakness="GitHub Code Scanning",
                asset_identifier=f"{GH_OWNER}/{GH_REPO}" if GH_REPO else GH_OWNER,
                severity=severity,
                risk_rating=severity,
                date_identified=today,
                scheduled_completion_date=today,
                actual_completion_date="",
                status="Open",
                owner="DevSecOps",
                remediation_action="Fix vulnerability",
                source_url=alert.get("html_url", ""),
            )
        )

    for adv in advisories:
        sev = (adv.get("severity") or "moderate").capitalize()
        rows.append(
            PoamRow(
                poam_id=f"GHA-ADV-{adv.get('ghsa_id', '')}",
                weakness_name=adv.get("summary", "")[:120],
                weakness_description=adv.get("description", ""),
                source_identifying_weakness="GitHub Advisory",
                asset_identifier=f"{GH_OWNER}/{GH_REPO}" if GH_REPO else GH_OWNER,
                severity=sev,
                risk_rating=_map_severity(sev),
                date_identified=today,
                scheduled_completion_date=today,
                actual_completion_date="",
                status="Open",
                owner="DevSecOps",
                remediation_action="Patch dependency",
                source_url=adv.get("html_url", ""),
            )
        )

    return rows, errors


def write_outputs(rows: List[PoamRow], errors: List[str]) -> None:
    csv_path = Path(OUTPUT_CSV)
    json_path = Path(OUTPUT_JSON)
    summary_path = Path(OUTPUT_SUMMARY)

    csv_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    fields = list(asdict(rows[0]).keys()) if rows else list(
        asdict(PoamRow("", "", "", "", "", "", "", "", "", "", "", "", "", "")).keys()
    )

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))

    with json_path.open("w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in rows], f, indent=2)

    summary = {
        "owner": GH_OWNER,
        "repo": GH_REPO,
        "total_count": len(rows),
        "high_count": len([r for r in rows if r.severity.lower() == "high"]),
        "source_errors": errors,
    }

    high_rows = [asdict(r) for r in rows if r.severity.lower() == "high"]
    summary["high_rows"] = high_rows

    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(f"Wrote CSV: {csv_path.resolve()}")
    print(f"Wrote JSON: {json_path.resolve()}")
    print(f"Wrote summary: {summary_path.resolve()}")


def main() -> int:
    rows, errors = collect_rows()
    write_outputs(rows, errors)

    print(f"Wrote {len(rows)} POA&M rows")
    print(f"Owner: {GH_OWNER}")
    if GH_REPO:
        print(f"Repository: {GH_REPO}")
    else:
        print("Repository: org-level scan")

    if errors:
        print("Source errors detected:")
        for err in errors:
            print(f"- {err}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
