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

API_VERSION = os.getenv("GITHUB_API_VERSION", "2022-11-28")
TOKEN = os.getenv("GITHUB_TOKEN")
OWNER = os.getenv("GITHUB_OWNER")
REPO = os.getenv("GITHUB_REPO") or ""
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "poam-output")
OUTPUT_CSV = os.getenv("OUTPUT_CSV", str(Path(OUTPUT_DIR) / "poam_github.csv"))
OUTPUT_JSON = os.getenv("OUTPUT_JSON", str(Path(OUTPUT_DIR) / "poam_github.json"))
OUTPUT_SUMMARY = os.getenv("OUTPUT_SUMMARY", str(Path(OUTPUT_DIR) / "poam_summary.json"))

if not TOKEN or not OWNER:
    sys.exit("GITHUB_TOKEN and GITHUB_OWNER are required.")

output_dir_path = Path(OUTPUT_DIR)
output_dir_path.mkdir(parents=True, exist_ok=True)

session = requests.Session()
session.headers.update(
    {
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
        "User-Agent": "github-to-poam-sync/1.0",
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
        resp.raise_for_status()
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


def _map_severity(sev: str) -> str:
    s = (sev or "").lower()
    if s in {"critical", "high"}:
        return "High"
    if s in {"medium", "moderate"}:
        return "Moderate"
    return "Low"


def _today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def _safe_list_with_error(url: str, params: Optional[dict], source_name: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    try:
        return list(_paged_get(url, params=params)), None
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else None
        body = exc.response.text[:400].strip() if exc.response is not None else str(exc)

        if status in {403, 404}:
            return [], f"{source_name} unavailable ({status}) for {url}: {body}"

        raise


def code_scanning_alerts() -> Tuple[List[Dict[str, Any]], Optional[str]]:
    if REPO:
        url = f"https://api.github.com/repos/{OWNER}/{REPO}/code-scanning/alerts"
    else:
        url = f"https://api.github.com/orgs/{OWNER}/code-scanning/alerts"

    return _safe_list_with_error(
        url,
        params={"state": "open", "per_page": 100},
        source_name="code scanning alerts",
    )


def repo_security_advisories() -> Tuple[List[Dict[str, Any]], Optional[str]]:
    if not REPO:
        return [], None

    url = f"https://api.github.com/repos/{OWNER}/{REPO}/security-advisories"
    return _safe_list_with_error(
        url,
        params={"state": "open", "per_page": 100},
        source_name="repository security advisories",
    )


def to_poam_rows() -> Tuple[List[PoamRow], List[str]]:
    rows: List[PoamRow] = []
    source_errors: List[str] = []
    today = _today()

    alerts, err = code_scanning_alerts()
    if err:
        source_errors.append(err)

    advisories, err = repo_security_advisories()
    if err:
        source_errors.append(err)

    for alert in alerts:
        severity = _map_severity(
            alert.get("rule", {}).get("security_severity_level")
            or alert.get("most_recent_instance", {}).get("severity")
        )

        path = (alert.get("most_recent_instance") or {}).get("location", {}).get("path", "repository")
        title = (
            alert.get("rule", {}).get("description")
            or alert.get("rule", {}).get("id")
            or "Code scanning alert"
        )

        rows.append(
            PoamRow(
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
            )
        )

    for adv in advisories:
        gh_sev = (adv.get("severity") or "moderate").capitalize()
        risk = _map_severity(gh_sev)

        rows.append(
            PoamRow(
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
            )
        )

    return rows, source_errors


def write_outputs(rows: List[PoamRow], source_errors: List[str]) -> None:
    fields = list(asdict(rows[0]).keys()) if rows else list(
        asdict(PoamRow("", "", "", "", "", "", "", "", "", "", "", "", "", "")).keys()
    )

    csv_path = Path(OUTPUT_CSV)
    json_path = Path(OUTPUT_JSON)
    summary_path = Path(OUTPUT_SUMMARY)

    csv_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))

    with json_path.open("w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in rows], f, indent=2)

    high_rows = [asdict(r) for r in rows if r.severity.lower() == "high"]
    moderate_rows = [asdict(r) for r in rows if r.severity.lower() == "moderate"]
    low_rows = [asdict(r) for r in rows if r.severity.lower() == "low"]

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "owner": OWNER,
        "repo": REPO,
        "total_count": len(rows),
        "high_count": len(high_rows),
        "moderate_count": len(moderate_rows),
        "low_count": len(low_rows),
        "high_rows": high_rows,
        "source_errors": source_errors,
    }

    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(f"Wrote CSV: {csv_path.resolve()}")
    print(f"Wrote JSON: {json_path.resolve()}")
    print(f"Wrote summary: {summary_path.resolve()}")


def main() -> int:
    rows, source_errors = to_poam_rows()
    write_outputs(rows, source_errors)

    print(f"Wrote {len(rows)} POA&M rows")
    print(f"Owner: {OWNER}")
    if REPO:
        print(f"Repository: {REPO}")
    else:
        print("Repository: org-level scan")

    if source_errors:
        print("Source errors detected:")
        for err in source_errors:
            print(f"- {err}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
