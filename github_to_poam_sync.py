#!/usr/bin/env python3
"""Pull GitHub enterprise code scanning alerts and repository security advisories and emit POA&M rows."""

from __future__ import annotations

import csv
import json
import os
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests

GH_TOKEN = os.getenv("GH_TOKEN")
GH_ENTERPRISE_SLUG = os.getenv("GH_ENTERPRISE_SLUG")
GH_API_URL = os.getenv("GH_API_URL", "https://api.github.com")
GH_API_VERSION = os.getenv("GH_API_VERSION", "2022-11-28")

OUTPUT_DIR = os.getenv("OUTPUT_DIR", "poam-output")
OUTPUT_CSV = os.getenv("OUTPUT_CSV", f"{OUTPUT_DIR}/poam_github.csv")
OUTPUT_JSON = os.getenv("OUTPUT_JSON", f"{OUTPUT_DIR}/poam_github.json")
OUTPUT_SUMMARY = os.getenv("OUTPUT_SUMMARY", f"{OUTPUT_DIR}/poam_summary.json")

if not GH_TOKEN or not GH_ENTERPRISE_SLUG:
    sys.exit("GH_TOKEN and GH_ENTERPRISE_SLUG are required.")

Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

session = requests.Session()
session.headers.update(
    {
        "Authorization": f"Bearer {GH_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": GH_API_VERSION,
        "User-Agent": "github-enterprise-to-poam-sync/1.0",
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


class GitHubEnterpriseClient:
    def __init__(self, token: str, api_url: str, api_version: str) -> None:
        self.api_url = api_url.rstrip("/")
        self.api_version = api_version
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": api_version,
                "User-Agent": "github-enterprise-to-poam-sync/1.0",
            }
        )

    def paginate(self, path: str, params: Optional[Dict[str, Any]] = None) -> Iterable[Dict[str, Any]]:
        next_url = f"{self.api_url}/{path.lstrip('/')}"
        next_params = dict(params or {})
        next_params.setdefault("per_page", 100)

        while next_url:
            resp = self.session.get(next_url, params=next_params, timeout=30)
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

    def graphql(self, query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.api_url}/graphql"
        resp = self.session.post(
            url,
            json={"query": query, "variables": variables},
            timeout=30,
        )
        if resp.status_code >= 400:
            raise RuntimeError(f"GraphQL request failed: {resp.status_code} {resp.text[:600]}")
        payload = resp.json()
        if payload.get("errors"):
            raise RuntimeError(f"GraphQL errors: {json.dumps(payload['errors'], ensure_ascii=False)}")
        return payload["data"]


def _today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def _map_severity(sev: str) -> str:
    s = (sev or "").lower()
    if s in {"critical", "high"}:
        return "High"
    if s in {"medium", "moderate"}:
        return "Moderate"
    return "Low"


def _safe_rest_list(
    client: GitHubEnterpriseClient,
    path: str,
    params: Optional[Dict[str, Any]],
    source_name: str,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    try:
        return list(client.paginate(path, params=params)), None
    except RuntimeError as exc:
        msg = str(exc)
        if any(code in msg for code in ("404", "403")):
            return [], f"{source_name} unavailable: {msg}"
        raise


def list_enterprise_orgs(client: GitHubEnterpriseClient, enterprise_slug: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    query = """
    query($slug: String!, $first: Int!, $after: String) {
      enterprise(slug: $slug) {
        organizations(first: $first, after: $after) {
          nodes {
            login
            name
          }
          pageInfo {
            hasNextPage
            endCursor
          }
        }
      }
    }
    """

    orgs: List[Dict[str, Any]] = []
    after: Optional[str] = None

    try:
        while True:
            data = client.graphql(query, {"slug": enterprise_slug, "first": 100, "after": after})
            enterprise = data.get("enterprise")
            if not enterprise:
                return [], f"Enterprise not found or inaccessible: {enterprise_slug}"

            organizations = enterprise["organizations"]
            for node in organizations["nodes"]:
                if node and node.get("login"):
                    orgs.append({"login": node["login"], "name": node.get("name")})

            page_info = organizations["pageInfo"]
            if not page_info["hasNextPage"]:
                break
            after = page_info["endCursor"]

        deduped = []
        seen = set()
        for org in orgs:
            login = org["login"]
            if login not in seen:
                seen.add(login)
                deduped.append(org)
        return deduped, None

    except RuntimeError as exc:
        return [], f"Unable to enumerate enterprise organizations: {exc}"


def collect_enterprise_code_scanning_alerts(client: GitHubEnterpriseClient, enterprise_slug: str) -> Tuple[List[PoamRow], List[str]]:
    rows: List[PoamRow] = []
    source_errors: List[str] = []

    alerts, err = _safe_rest_list(
        client,
        f"/enterprises/{enterprise_slug}/code-scanning/alerts",
        params={"state": "open", "per_page": 100},
        source_name="enterprise code scanning alerts",
    )
    if err:
        source_errors.append(err)

    for alert in alerts:
        repository = alert.get("repository") or {}
        full_name = repository.get("full_name") or repository.get("name") or enterprise_slug
        severity = _map_severity(
            alert.get("rule", {}).get("security_severity_level")
            or alert.get("most_recent_instance", {}).get("severity")
            or alert.get("rule", {}).get("severity")
        )

        path = (alert.get("most_recent_instance") or {}).get("location", {}).get("path", "repository")
        title = (
            alert.get("rule", {}).get("description")
            or alert.get("rule", {}).get("id")
            or "Code scanning alert"
        )

        rows.append(
            PoamRow(
                poam_id=f"GHA-{str(alert.get('number', ''))}",
                weakness_name=title[:120],
                weakness_description=f"Enterprise code scanning alert on {path}. Alert: {title}.",
                source_identifying_weakness="GitHub Code Scanning / CodeQL",
                asset_identifier=full_name,
                severity=severity,
                risk_rating=severity,
                date_identified=_today(),
                scheduled_completion_date=_today(),
                actual_completion_date="",
                status="Open",
                owner="DevSecOps",
                remediation_action="Review code scanning alert and remediate vulnerable code or dependency.",
                source_url=alert.get("html_url", ""),
            )
        )

    return rows, source_errors


def collect_org_security_advisories(client: GitHubEnterpriseClient, org_login: str) -> Tuple[List[PoamRow], List[str]]:
    rows: List[PoamRow] = []
    source_errors: List[str] = []

    advisories, err = _safe_rest_list(
        client,
        f"/orgs/{org_login}/security-advisories",
        params={"state": "open", "per_page": 100},
        source_name=f"organization security advisories for {org_login}",
    )
    if err:
        source_errors.append(err)

    for adv in advisories:
        gh_sev = (adv.get("severity") or "moderate").capitalize()
        risk = _map_severity(gh_sev)
        repository = adv.get("repository") or {}
        asset_identifier = repository.get("full_name") or org_login

        rows.append(
            PoamRow(
                poam_id=f"GHA-ADV-{adv.get('ghsa_id', '')}",
                weakness_name=(adv.get("summary", "Repository security advisory") or "")[:120],
                weakness_description=adv.get("description", "Open GitHub repository advisory."),
                source_identifying_weakness="GitHub Repository Security Advisory",
                asset_identifier=asset_identifier,
                severity=gh_sev,
                risk_rating=risk,
                date_identified=_today(),
                scheduled_completion_date=_today(),
                actual_completion_date="",
                status="Open",
                owner="DevSecOps",
                remediation_action="Patch dependency or apply available GitHub advisory fix.",
                source_url=adv.get("html_url", ""),
            )
        )

    return rows, source_errors


def collect_rows(client: GitHubEnterpriseClient, enterprise_slug: str) -> Tuple[List[PoamRow], List[str], int]:
    all_rows: List[PoamRow] = []
    source_errors: List[str] = []

    enterprise_alert_rows, err = collect_enterprise_code_scanning_alerts(client, enterprise_slug)
    all_rows.extend(enterprise_alert_rows)
    if err:
        source_errors.extend(err)

    orgs, err = list_enterprise_orgs(client, enterprise_slug)
    if err:
        source_errors.append(err)
        return all_rows, source_errors, 0

    for org in orgs:
        rows, err = collect_org_security_advisories(client, org["login"])
        all_rows.extend(rows)
        if err:
            source_errors.extend(err)

    return all_rows, source_errors, len(orgs)


def write_outputs(rows: List[PoamRow], source_errors: List[str], org_count: int) -> None:
    csv_path = Path(OUTPUT_CSV)
    json_path = Path(OUTPUT_JSON)
    summary_path = Path(OUTPUT_SUMMARY)

    csv_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    if rows:
        fields = list(asdict(rows[0]).keys())
    else:
        fields = list(asdict(PoamRow("", "", "", "", "", "", "", "", "", "", "", "", "", "")).keys())

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))

    with json_path.open("w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in rows], f, indent=2, ensure_ascii=False)

    high_rows = [asdict(r) for r in rows if r.severity.lower() == "high"]
    moderate_rows = [asdict(r) for r in rows if r.severity.lower() == "moderate"]
    low_rows = [asdict(r) for r in rows if r.severity.lower() == "low"]

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": "enterprise",
        "enterprise_slug": GH_ENTERPRISE_SLUG,
        "org_count": org_count,
        "total_count": len(rows),
        "high_count": len(high_rows),
        "moderate_count": len(moderate_rows),
        "low_count": len(low_rows),
        "high_rows": high_rows,
        "source_errors": source_errors,
    }

    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Wrote CSV: {csv_path.resolve()}")
    print(f"Wrote JSON: {json_path.resolve()}")
    print(f"Wrote summary: {summary_path.resolve()}")


def main() -> int:
    client = GitHubEnterpriseClient(GH_TOKEN, GH_API_URL, GH_API_VERSION)
    rows, source_errors, org_count = collect_rows(client, GH_ENTERPRISE_SLUG)
    write_outputs(rows, source_errors, org_count)

    print(f"Wrote {len(rows)} POA&M rows")
    print(f"Enterprise slug: {GH_ENTERPRISE_SLUG}")
    print(f"Organizations scanned: {org_count}")
    if source_errors:
        print("Source errors detected:")
        for err in source_errors:
            print(f"- {err}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
