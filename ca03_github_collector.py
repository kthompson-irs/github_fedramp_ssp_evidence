#!/usr/bin/env python3

import argparse
import csv
import json
import os
import sys
import zipfile
from collections import defaultdict#!/usr/bin/env python3
"""
CA-03 GitHub.com Evidence Collector

Purpose
-------
Collect auditable evidence for a GitHub.com interconnection used in a FedRAMP ATO package.
The script gathers:
  - Organization metadata
  - Repository inventory and repo security posture
  - Team / member access evidence
  - Branch protection / rulesets
  - Webhooks
  - Audit log events (when permissions allow)
  - A CA-03 evidence report and manifest

Important
---------
This script collects configuration and metadata only. It does NOT scan repository source code.
For FTI / data-content attestations, retain a separate manual attestation from the system owner
or a controlled code review evidence source approved by your organization.

Authentication
--------------
Set one of the following environment variables:
  - GITHUB_TOKEN
  - GH_TOKEN
  - CA03_GITHUB_TOKEN

The token should be a GitHub PAT or GitHub App installation token with the minimum permissions
needed to read org metadata, repositories, teams, and audit logs (when available).

Usage examples
--------------
python ca03_github_collector.py --org my-org --outdir ./evidence
python ca03_github_collector.py --org my-org --repos repo-a,repo-b --outdir ./evidence
python ca03_github_collector.py --org my-org --include-audit-log --include-webhooks
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import zipfile
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests


API_VERSION = "2022-11-28"
BASE_URL = "https://api.github.com"


@dataclass
class ApiResult:
    status_code: int
    data: Any
    url: str
    note: str = ""


class GitHubCollector:
    def __init__(self, token: str, org: str, timeout: int = 30) -> None:
        if not token:
            raise ValueError("A GitHub token is required.")
        self.org = org
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "ca03-github-evidence-collector",
            }
        )

    def _request(self, method: str, url: str, params: Optional[dict] = None) -> ApiResult:
        resp = self.session.request(method, url, params=params, timeout=self.timeout)
        note = ""
        if resp.status_code == 204:
            return ApiResult(resp.status_code, None, resp.url)
        if resp.headers.get("Content-Type", "").startswith("application/json"):
            try:
                data = resp.json()
            except Exception:
                data = {"raw_text": resp.text}
        else:
            data = resp.text

        if resp.status_code in (403, 404):
            note = f"{resp.status_code} returned; may indicate missing permissions or unavailable endpoint."
        if resp.status_code >= 400 and resp.status_code not in (403, 404):
            resp.raise_for_status()
        return ApiResult(resp.status_code, data, resp.url, note=note)

    def _paginate(self, url: str, params: Optional[dict] = None, max_pages: int = 20) -> List[Any]:
        items: List[Any] = []
        page = 1
        params = dict(params or {})
        while True:
            params.update({"per_page": 100, "page": page})
            resp = self.session.get(url, params=params, timeout=self.timeout)
            if resp.status_code in (403, 404):
                break
            resp.raise_for_status()
            payload = resp.json()
            if isinstance(payload, list):
                items.extend(payload)
            else:
                items.append(payload)
                break
            link = resp.headers.get("Link", "")
            if 'rel="next"' not in link or page >= max_pages:
                break
            page += 1
        return items

    def get_org(self) -> ApiResult:
        return self._request("GET", f"{BASE_URL}/orgs/{self.org}")

    def list_org_repos(self) -> List[Dict[str, Any]]:
        return self._paginate(f"{BASE_URL}/orgs/{self.org}/repos", params={"type": "all", "sort": "full_name"})

    def list_org_members(self) -> List[Dict[str, Any]]:
        return self._paginate(f"{BASE_URL}/orgs/{self.org}/members")

    def list_org_teams(self) -> List[Dict[str, Any]]:
        return self._paginate(f"{BASE_URL}/orgs/{self.org}/teams")

    def get_team_repos(self, team_slug: str) -> List[Dict[str, Any]]:
        return self._paginate(f"{BASE_URL}/orgs/{self.org}/teams/{team_slug}/repos")

    def get_repo(self, repo_name: str) -> ApiResult:
        return self._request("GET", f"{BASE_URL}/repos/{self.org}/{repo_name}")

    def list_repo_collaborators(self, repo_name: str) -> List[Dict[str, Any]]:
        return self._paginate(f"{BASE_URL}/repos/{self.org}/{repo_name}/collaborators")

    def list_repo_hooks(self, repo_name: str) -> List[Dict[str, Any]]:
        return self._paginate(f"{BASE_URL}/repos/{self.org}/{repo_name}/hooks")

    def get_branch_protection(self, repo_name: str, branch: str) -> ApiResult:
        return self._request("GET", f"{BASE_URL}/repos/{self.org}/{repo_name}/branches/{branch}/protection")

    def list_rulesets(self, repo_name: str) -> List[Dict[str, Any]]:
        return self._paginate(f"{BASE_URL}/repos/{self.org}/{repo_name}/rulesets")

    def list_dependabot_alerts(self, repo_name: str) -> List[Dict[str, Any]]:
        return self._paginate(f"{BASE_URL}/repos/{self.org}/{repo_name}/dependabot/alerts")

    def list_secret_scanning_alerts(self, repo_name: str) -> List[Dict[str, Any]]:
        return self._paginate(f"{BASE_URL}/repos/{self.org}/{repo_name}/secret-scanning/alerts")

    def list_audit_log(self, limit_pages: int = 5) -> List[Dict[str, Any]]:
        return self._paginate(f"{BASE_URL}/orgs/{self.org}/audit-log", max_pages=limit_pages)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_json_dump(obj: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=True, ensure_ascii=False)


def safe_text_write(text: str, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def build_manifest(files: List[Path], outdir: Path) -> List[Dict[str, Any]]:
    manifest: List[Dict[str, Any]] = []
    for file_path in files:
        if file_path.is_file():
            manifest.append(
                {
                    "relative_path": str(file_path.relative_to(outdir)),
                    "bytes": file_path.stat().st_size,
                }
            )
    return manifest


def make_report(
    org_payload: Dict[str, Any],
    repos: List[Dict[str, Any]],
    members: List[Dict[str, Any]],
    teams: List[Dict[str, Any]],
    team_repo_map: Dict[str, List[str]],
    audit_log_available: bool,
    errors: List[str],
    scope_repos: Optional[List[str]] = None,
) -> str:
    lines: List[str] = []
    lines.append("# CA-03 GitHub Evidence Report")
    lines.append("")
    lines.append(f"- Collected: {utc_now_iso()}")
    lines.append(f"- Organization: `{org_payload.get('login', '')}`")
    lines.append(f"- Org name: {org_payload.get('name') or ''}")
    lines.append(f"- Visibility: {org_payload.get('public_repos', 0)} public repos, {org_payload.get('total_private_repos', 0)} private repos (if visible)")
    lines.append(f"- Two-factor requirement enabled: {org_payload.get('two_factor_requirement_enabled', 'unavailable')}")
    lines.append(f"- Audit log collection: {'enabled' if audit_log_available else 'unavailable or permission denied'}")
    if scope_repos:
        lines.append(f"- Scoped repositories: {', '.join(scope_repos)}")
    lines.append("")
    lines.append("## CA-03 Summary")
    lines.append("")
    lines.append(
        "GitHub.com is treated as an external SaaS interconnection. "
        "This evidence package captures the organization, repository, access, and monitoring data needed to support CA-03."
    )
    lines.append("")
    lines.append("## Repository Inventory")
    lines.append("")
    for repo in repos:
        lines.append(f"- `{repo.get('full_name')}` | private={repo.get('private')} | default branch={repo.get('default_branch')} | archived={repo.get('archived')}")
    if not repos:
        lines.append("- No repositories collected.")
    lines.append("")
    lines.append("## Access Control Evidence")
    lines.append("")
    lines.append(f"- Members collected: {len(members)}")
    lines.append(f"- Teams collected: {len(teams)}")
    lines.append("")
    for team in teams:
        slug = team.get("slug")
        repos_for_team = team_repo_map.get(slug, [])
        lines.append(f"- Team `{slug}` has {len(repos_for_team)} repo associations captured")
    lines.append("")
    lines.append("## Repo Security Signals")
    lines.append("")
    for repo in repos:
        security = repo.get("security_and_analysis", {})
        lines.append(
            f"- `{repo.get('full_name')}`: private={repo.get('private')}, "
            f"forking={repo.get('allow_forking')}, "
            f"branch protection target={repo.get('default_branch')}, "
            f"security_and_analysis={'present' if security else 'unavailable'}"
        )
    lines.append("")
    lines.append("## Audit / Logging")
    lines.append("")
    lines.append(
        "Audit log collection was attempted using the organization audit-log endpoint. "
        "If the endpoint is unavailable, retain a manual GitHub UI export or alternate administrative evidence."
    )
    lines.append("")
    lines.append("## Gaps / Follow-up")
    lines.append("")
    if errors:
        for err in errors:
            lines.append(f"- {err}")
    else:
        lines.append("- None recorded during collection.")
    lines.append("")
    lines.append("## Manual Evidence Still Required")
    lines.append("")
    lines.append("- Screenshot or export proving organization-wide MFA requirement.")
    lines.append("- Screenshot or export proving repository creation / visibility restrictions.")
    lines.append("- Signed attestation that no FTI is stored, processed, or transmitted in GitHub.com.")
    lines.append("- Any SaaS risk acceptance / interconnection agreement used by the system owner.")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect CA-03 evidence for GitHub.com.")
    parser.add_argument("--org", required=True, help="GitHub organization name")
    parser.add_argument(
        "--repos",
        help="Optional comma-separated repository list. If omitted, all org repos are collected.",
    )
    parser.add_argument("--outdir", default=None, help="Output directory for evidence")
    parser.add_argument(
        "--include-audit-log",
        action="store_true",
        help="Attempt to collect org audit log events",
    )
    parser.add_argument(
        "--include-webhooks",
        action="store_true",
        help="Collect repository webhook settings",
    )
    parser.add_argument(
        "--include-secret-scanning",
        action="store_true",
        help="Collect secret scanning alerts when available",
    )
    parser.add_argument(
        "--include-dependabot",
        action="store_true",
        help="Collect Dependabot alerts when available",
    )
    parser.add_argument(
        "--max-audit-pages",
        type=int,
        default=5,
        help="Maximum audit log pages to collect",
    )
    args = parser.parse_args()

    token = (
        os.environ.get("CA03_GITHUB_TOKEN")
        or os.environ.get("GITHUB_TOKEN")
        or os.environ.get("GH_TOKEN")
    )
    if not token:
        print(
            "Missing token. Set CA03_GITHUB_TOKEN, GITHUB_TOKEN, or GH_TOKEN.",
            file=sys.stderr,
        )
        return 2

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    outdir = Path(args.outdir or f"ca03_github_evidence_{args.org}_{ts}").resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    raw_dir = outdir / "raw"
    csv_dir = outdir / "csv"
    report_dir = outdir / "report"
    raw_dir.mkdir(exist_ok=True)
    csv_dir.mkdir(exist_ok=True)
    report_dir.mkdir(exist_ok=True)

    collector = GitHubCollector(token=token, org=args.org)

    errors: List[str] = []
    collected_files: List[Path] = []

    org_res = collector.get_org()
    org_payload = org_res.data if isinstance(org_res.data, dict) else {}
    safe_json_dump(
        {
            "status_code": org_res.status_code,
            "url": org_res.url,
            "data": org_payload,
            "note": org_res.note,
        },
        raw_dir / "org.json",
    )
    collected_files.append(raw_dir / "org.json")

    all_repos = collector.list_org_repos()
    selected_repo_names = None
    if args.repos:
        selected_repo_names = [r.strip() for r in args.repos.split(",") if r.strip()]
        repo_map = {repo.get("name"): repo for repo in all_repos}
        repos = [repo_map[name] for name in selected_repo_names if name in repo_map]
        missing = [name for name in selected_repo_names if name not in repo_map]
        for m in missing:
            errors.append(f"Repository not found in org listing: {m}")
    else:
        repos = all_repos

    safe_json_dump(repos, raw_dir / "repos.json")
    collected_files.append(raw_dir / "repos.json")

    members = collector.list_org_members()
    safe_json_dump(members, raw_dir / "members.json")
    collected_files.append(raw_dir / "members.json")

    teams = collector.list_org_teams()
    safe_json_dump(teams, raw_dir / "teams.json")
    collected_files.append(raw_dir / "teams.json")

    team_repo_map: Dict[str, List[str]] = defaultdict(list)
    raw_team_repos_dir = raw_dir / "team_repos"
    for team in teams:
        slug = team.get("slug")
        if not slug:
            continue
        team_repos = collector.get_team_repos(slug)
        team_repo_map[slug] = [r.get("full_name", "") for r in team_repos]
        safe_json_dump(team_repos, raw_team_repos_dir / f"{slug}.json")
        collected_files.append(raw_team_repos_dir / f"{slug}.json")

    repo_rows: List[Dict[str, Any]] = []
    access_rows: List[Dict[str, Any]] = []
    inventory_rows: List[Dict[str, Any]] = []
    webhook_rows: List[Dict[str, Any]] = []
    branch_rows: List[Dict[str, Any]] = []
    ruleset_rows: List[Dict[str, Any]] = []
    dependabot_rows: List[Dict[str, Any]] = []
    secret_rows: List[Dict[str, Any]] = []
    audit_rows: List[Dict[str, Any]] = []

    raw_repos_dir = raw_dir / "repos"
    raw_hooks_dir = raw_dir / "hooks"
    raw_branch_dir = raw_dir / "branch_protection"
    raw_ruleset_dir = raw_dir / "rulesets"
    raw_dep_dir = raw_dir / "dependabot"
    raw_secret_dir = raw_dir / "secret_scanning"

    for repo_stub in repos:
        repo_name = repo_stub.get("name")
        if not repo_name:
            continue
        try:
            repo_res = collector.get_repo(repo_name)
            repo = repo_res.data if isinstance(repo_res.data, dict) else {}
        except requests.HTTPError as exc:
            errors.append(f"Repo fetch failed for {repo_name}: {exc}")
            continue

        safe_json_dump(
            {"status_code": repo_res.status_code, "url": repo_res.url, "data": repo, "note": repo_res.note},
            raw_repos_dir / f"{repo_name}.json",
        )
        collected_files.append(raw_repos_dir / f"{repo_name}.json")

        repo_rows.append(
            {
                "full_name": repo.get("full_name"),
                "private": repo.get("private"),
                "visibility": repo.get("visibility"),
                "default_branch": repo.get("default_branch"),
                "archived": repo.get("archived"),
                "disabled": repo.get("disabled"),
                "allow_forking": repo.get("allow_forking"),
                "has_issues": repo.get("has_issues"),
                "has_wiki": repo.get("has_wiki"),
                "has_projects": repo.get("has_projects"),
                "has_discussions": repo.get("has_discussions"),
            }
        )

        inventory_rows.append(
            {
                "connection_name": f"GitHub SaaS / {repo.get('full_name')}",
                "external_system": "GitHub.com",
                "connection_type": "HTTPS / API / UI",
                "endpoint": "https://github.com",
                "protocol": "TLS 1.2+",
                "data_type": "Source code / repo metadata",
                "direction": "Outbound",
                "authorization": "Organization approval required",
                "owner": args.org,
                "evidence_source": f"repo:{repo.get('full_name')}",
            }
        )

        if args.include_webhooks:
            hooks = collector.list_repo_hooks(repo_name)
            webhook_rows.extend(
                [
                    {
                        "repo": repo.get("full_name"),
                        "hook_id": h.get("id"),
                        "name": h.get("name"),
                        "active": h.get("active"),
                        "events": ",".join(h.get("events", [])) if isinstance(h.get("events"), list) else h.get("events"),
                        "config_url": (h.get("config") or {}).get("url"),
                    }
                    for h in hooks
                ]
            )
            safe_json_dump(hooks, raw_hooks_dir / f"{repo_name}.json")
            collected_files.append(raw_hooks_dir / f"{repo_name}.json")

        collaborators = collector.list_repo_collaborators(repo_name)
        for c in collaborators:
            access_rows.append(
                {
                    "repo": repo.get("full_name"),
                    "principal": c.get("login") or (c.get("user") or {}).get("login"),
                    "type": c.get("type"),
                    "permissions": json.dumps(c.get("permissions"), sort_keys=True),
                    "role_name": c.get("role_name"),
                    "site_admin": c.get("site_admin"),
                }
            )

        default_branch = repo.get("default_branch")
        if default_branch:
            try:
                bp = collector.get_branch_protection(repo_name, default_branch)
                branch_rows.append(
                    {
                        "repo": repo.get("full_name"),
                        "branch": default_branch,
                        "status_code": bp.status_code,
                        "required_status_checks": json.dumps((bp.data or {}).get("required_status_checks"), sort_keys=True),
                        "enforce_admins": json.dumps((bp.data or {}).get("enforce_admins"), sort_keys=True),
                        "required_pull_request_reviews": json.dumps(
                            (bp.data or {}).get("required_pull_request_reviews"), sort_keys=True
                        ),
                        "restrictions": json.dumps((bp.data or {}).get("restrictions"), sort_keys=True),
                    }
                )
                safe_json_dump(
                    {"status_code": bp.status_code, "url": bp.url, "data": bp.data, "note": bp.note},
                    raw_branch_dir / f"{repo_name}_{default_branch}.json",
                )
                collected_files.append(raw_branch_dir / f"{repo_name}_{default_branch}.json")
            except requests.HTTPError as exc:
                errors.append(f"Branch protection unavailable for {repo.get('full_name')}:{default_branch} ({exc})")

        try:
            rulesets = collector.list_rulesets(repo_name)
            for rs in rulesets:
                ruleset_rows.append(
                    {
                        "repo": repo.get("full_name"),
                        "ruleset_id": rs.get("id"),
                        "name": rs.get("name"),
                        "target": rs.get("target"),
                        "enforcement": rs.get("enforcement"),
                        "conditions": json.dumps(rs.get("conditions"), sort_keys=True),
                    }
                )
            safe_json_dump(rulesets, raw_ruleset_dir / f"{repo_name}.json")
            collected_files.append(raw_ruleset_dir / f"{repo_name}.json")
        except requests.HTTPError:
            pass

        if args.include_dependabot:
            try:
                alerts = collector.list_dependabot_alerts(repo_name)
                for alert in alerts:
                    dependabot_rows.append(
                        {
                            "repo": repo.get("full_name"),
                            "number": alert.get("number"),
                            "state": alert.get("state"),
                            "severity": (alert.get("security_advisory") or {}).get("severity"),
                            "package": ((alert.get("security_advisory") or {}).get("package") or {}).get("name"),
                            "manifest_path": alert.get("manifest_path"),
                        }
                    )
                safe_json_dump(alerts, raw_dep_dir / f"{repo_name}.json")
                collected_files.append(raw_dep_dir / f"{repo_name}.json")
            except requests.HTTPError:
                pass

        if args.include_secret_scanning:
            try:
                alerts = collector.list_secret_scanning_alerts(repo_name)
                for alert in alerts:
                    secret_rows.append(
                        {
                            "repo": repo.get("full_name"),
                            "number": alert.get("number"),
                            "state": alert.get("state"),
                            "secret_type": alert.get("secret_type"),
                            "resolution": alert.get("resolution"),
                        }
                    )
                safe_json_dump(alerts, raw_secret_dir / f"{repo_name}.json")
                collected_files.append(raw_secret_dir / f"{repo_name}.json")
            except requests.HTTPError:
                pass

    audit_log_available = False
    if args.include_audit_log:
        try:
            audit_log = collector.list_audit_log(limit_pages=args.max_audit_pages)
            audit_log_available = bool(audit_log)
            safe_json_dump(audit_log, raw_dir / "audit_log.json")
            collected_files.append(raw_dir / "audit_log.json")
            for event in audit_log:
                audit_rows.append(
                    {
                        "action": event.get("action"),
                        "actor": event.get("actor"),
                        "repo": event.get("repo"),
                        "created_at": event.get("@timestamp") or event.get("created_at"),
                        "user": event.get("user"),
                        "org": event.get("org"),
                        "ip": event.get("ip"),
                        "operation_type": event.get("operation_type"),
                        "transport_protocol": event.get("transport_protocol"),
                    }
                )
        except requests.HTTPError as exc:
            errors.append(f"Audit log collection failed or unavailable: {exc}")
        except Exception as exc:
            errors.append(f"Audit log collection failed or unavailable: {exc}")

    write_csv(
        csv_dir / "inventory.csv",
        inventory_rows,
        [
            "connection_name",
            "external_system",
            "connection_type",
            "endpoint",
            "protocol",
            "data_type",
            "direction",
            "authorization",
            "owner",
            "evidence_source",
        ],
    )
    write_csv(
        csv_dir / "repos.csv",
        repo_rows,
        [
            "full_name",
            "private",
            "visibility",
            "default_branch",
            "archived",
            "disabled",
            "allow_forking",
            "has_issues",
            "has_wiki",
            "has_projects",
            "has_discussions",
        ],
    )
    write_csv(
        csv_dir / "access.csv",
        access_rows,
        ["repo", "principal", "type", "permissions", "role_name", "site_admin"],
    )
    if webhook_rows:
        write_csv(
            csv_dir / "webhooks.csv",
            webhook_rows,
            ["repo", "hook_id", "name", "active", "events", "config_url"],
        )
    if branch_rows:
        write_csv(
            csv_dir / "branch_protection.csv",
            branch_rows,
            [
                "repo",
                "branch",
                "status_code",
                "required_status_checks",
                "enforce_admins",
                "required_pull_request_reviews",
                "restrictions",
            ],
        )
    if ruleset_rows:
        write_csv(
            csv_dir / "rulesets.csv",
            ruleset_rows,
            ["repo", "ruleset_id", "name", "target", "enforcement", "conditions"],
        )
    if dependabot_rows:
        write_csv(
            csv_dir / "dependabot.csv",
            dependabot_rows,
            ["repo", "number", "state", "severity", "package", "manifest_path"],
        )
    if secret_rows:
        write_csv(
            csv_dir / "secret_scanning.csv",
            secret_rows,
            ["repo", "number", "state", "secret_type", "resolution"],
        )
    if audit_rows:
        write_csv(
            csv_dir / "audit_log.csv",
            audit_rows,
            ["action", "actor", "repo", "created_at", "user", "org", "ip", "operation_type", "transport_protocol"],
        )

    report = make_report(
        org_payload=org_payload,
        repos=[r if isinstance(r, dict) else {} for r in repos],
        members=members,
        teams=teams,
        team_repo_map=team_repo_map,
        audit_log_available=audit_log_available,
        errors=errors,
        scope_repos=selected_repo_names,
    )
    safe_text_write(report, report_dir / "CA03_GitHub_Evidence_Report.md")
    collected_files.append(report_dir / "CA03_GitHub_Evidence_Report.md")

    controls = {
        "CA-03": {
            "status": "supported",
            "artifacts": [
                "csv/inventory.csv",
                "report/CA03_GitHub_Evidence_Report.md",
                "raw/org.json",
                "raw/repos.json",
                "raw/teams.json",
                "raw/members.json",
            ],
        },
        "AC-2": {
            "status": "supported",
            "artifacts": ["raw/members.json", "raw/teams.json", "csv/access.csv"],
        },
        "IA-2": {
            "status": "partial",
            "artifacts": ["raw/org.json"],
            "note": "Organization MFA status may be visible in org metadata; retain manual screenshot evidence if the API does not expose the setting in your tenant.",
        },
        "SC-7": {
            "status": "supported",
            "artifacts": ["csv/inventory.csv", "csv/repos.csv", "csv/branch_protection.csv"],
        },
    }
    safe_json_dump(controls, outdir / "controls.json")
    collected_files.append(outdir / "controls.json")

    manifest = build_manifest(collected_files, outdir)
    safe_json_dump(manifest, outdir / "evidence_manifest.json")
    collected_files.append(outdir / "evidence_manifest.json")

    zip_path = outdir.with_suffix(".zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in collected_files:
            if file_path.is_file():
                zf.write(file_path, file_path.relative_to(outdir))

    print(f"Evidence bundle created: {outdir}")
    print(f"Zip archive: {zip_path}")
    if errors:
        print("\nWarnings:")
        for err in errors:
            print(f"- {err}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

BASE_URL = "https://api.github.com"


class GitHubCollector:
    def __init__(self, token: str, org: str, timeout: int = 30):
        if not token:
            raise ValueError("GH_TOKEN is required")

        self.org = org
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json"
        })

    def _request(self, url: str, params: Optional[dict] = None):
        resp = self.session.get(url, params=params, timeout=self.timeout)

        if resp.status_code in [403, 404, 400, 422]:
            return {"error": resp.text, "status": resp.status_code}

        resp.raise_for_status()
        return resp.json()

    def _paginate(self, url: str):
        results = []
        page = 1

        while True:
            resp = self.session.get(
                url,
                params={"per_page": 100, "page": page},
                timeout=self.timeout
            )

            if resp.status_code in [403, 404, 400, 422]:
                return []

            resp.raise_for_status()
            data = resp.json()

            if not data:
                break

            results.extend(data)

            if "next" not in resp.links:
                break

            page += 1

        return results

    def get_org(self):
        return self._request(f"{BASE_URL}/orgs/{self.org}")

    def list_repos(self):
        return self._paginate(f"{BASE_URL}/orgs/{self.org}/repos")

    def list_members(self):
        return self._paginate(f"{BASE_URL}/orgs/{self.org}/members")

    def list_teams(self):
        return self._paginate(f"{BASE_URL}/orgs/{self.org}/teams")

    def get_team_repos(self, team_slug: str) -> List[Dict[str, Any]]:
        return self._paginate(
            f"{BASE_URL}/orgs/{self.org}/teams/{team_slug}/repos"
        )

    def list_collaborators(self, repo):
        return self._paginate(f"{BASE_URL}/repos/{self.org}/{repo}/collaborators")

    def get_branch_protection(self, repo, branch):
        return self._request(
            f"{BASE_URL}/repos/{self.org}/{repo}/branches/{branch}/protection"
        )

    def list_hooks(self, repo):
        return self._paginate(f"{BASE_URL}/repos/{self.org}/{repo}/hooks")

    def list_dependabot(self, repo):
        try:
            return self._paginate(f"{BASE_URL}/repos/{self.org}/{repo}/dependabot/alerts")
        except requests.HTTPError as exc:
            status = getattr(exc.response, "status_code", None)
            if status in (400, 403, 404, 422):
                return []
            raise

    def list_secret_scanning(self, repo):
        try:
            return self._paginate(f"{BASE_URL}/repos/{self.org}/{repo}/secret-scanning/alerts")
        except requests.HTTPError as exc:
            status = getattr(exc.response, "status_code", None)
            if status in (400, 403, 404, 422):
                return []
            raise

    def list_audit_log(self):
        return self._paginate(f"{BASE_URL}/orgs/{self.org}/audit-log")


def write_json(data, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def write_csv(rows, path):
    if not rows:
        return

    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--org", required=True)
    parser.add_argument("--outdir", default="evidence")
    parser.add_argument("--include-audit-log", action="store_true")
    parser.add_argument("--include-webhooks", action="store_true")
    parser.add_argument("--include-secret-scanning", action="store_true")
    parser.add_argument("--include-dependabot", action="store_true")

    args = parser.parse_args()

    token = os.getenv("GH_TOKEN")

    if not token:
        print("ERROR: GH_TOKEN not set")
        sys.exit(1)

    collector = GitHubCollector(token, args.org)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    outdir = Path(f"{args.outdir}_{ts}")

    raw_dir = outdir / "raw"
    csv_dir = outdir / "csv"

    print("[+] Collecting org data...")
    org = collector.get_org()
    write_json(org, raw_dir / "org.json")

    print("[+] Collecting repos...")
    repos = collector.list_repos()
    write_json(repos, raw_dir / "repos.json")

    print("[+] Collecting members...")
    members = collector.list_members()
    write_json(members, raw_dir / "members.json")

    print("[+] Collecting teams...")
    teams = collector.list_teams()
    write_json(teams, raw_dir / "teams.json")

    team_repo_map = defaultdict(list)

    for team in teams:
        slug = team.get("slug")
        if not slug:
            continue

        repos_for_team = collector.get_team_repos(slug)
        team_repo_map[slug] = repos_for_team

        write_json(repos_for_team, raw_dir / f"team_{slug}_repos.json")

    repo_rows = []
    access_rows = []

    for repo in repos:
        name = repo["name"]

        repo_rows.append({
            "name": name,
            "private": repo.get("private"),
            "default_branch": repo.get("default_branch")
        })

        print(f"[+] Processing repo: {name}")

        collaborators = collector.list_collaborators(name)
        for c in collaborators:
            access_rows.append({
                "repo": name,
                "user": c.get("login"),
                "permissions": json.dumps(c.get("permissions"))
            })

        if args.include_webhooks:
            hooks = collector.list_hooks(name)
            write_json(hooks, raw_dir / f"{name}_hooks.json")

        if args.include_dependabot:
            dep = collector.list_dependabot(name)
            write_json(dep, raw_dir / f"{name}_dependabot.json")

        if args.include_secret_scanning:
            sec = collector.list_secret_scanning(name)
            write_json(sec, raw_dir / f"{name}_secret_scanning.json")

        try:
            bp = collector.get_branch_protection(name, repo.get("default_branch"))
            write_json(bp, raw_dir / f"{name}_branch_protection.json")
        except Exception:
            pass

    if args.include_audit_log:
        print("[+] Collecting audit log...")
        audit = collector.list_audit_log()
        write_json(audit, raw_dir / "audit_log.json")

    write_csv(repo_rows, csv_dir / "repos.csv")
    write_csv(access_rows, csv_dir / "access.csv")

    zip_path = outdir.with_suffix(".zip")

    print("[+] Creating zip bundle...")

    with zipfile.ZipFile(zip_path, "w") as z:
        for file in outdir.rglob("*"):
            z.write(file, file.relative_to(outdir))

    print(f"[+] DONE: {zip_path}")


if __name__ == "__main__":
    main()
