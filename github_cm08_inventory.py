#!/usr/bin/env python3
"""Collect a CM-08-style inventory for a GitHub organization.

Outputs a timestamped evidence package containing:
- inventory_summary.json
- repositories.csv
- members.csv
- outside_collaborators.csv
- app_installations.csv
- org_webhooks.csv
- repo_webhooks.csv (optional)
- audit_log.csv (optional)
- evidence_manifest.json
- summary.md

Environment variables:
  GITHUB_TOKEN          Required. Token with access to the organization.
  GITHUB_ORG            Required. Organization login.
  GITHUB_API_URL        Optional. Defaults to https://api.github.com.
  GITHUB_API_VERSION    Optional. Defaults to 2022-11-28.
  OUTPUT_DIR            Optional. Defaults to ./evidence.
  INCLUDE_REPO_WEBHOOKS Optional. true/false, default false.
  INCLUDE_COLLABORATORS Optional. true/false, default false.
  GITHUB_ENTERPRISE     Optional. Enterprise slug for audit log export.
  AUDIT_LOG_INCLUDE     Optional. web/git/all, default web.
  AUDIT_LOG_PHRASE      Optional. Search phrase for enterprise audit log.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urljoin

import requests


DEFAULT_API_URL = "https://api.github.com"
DEFAULT_API_VERSION = "2022-11-28"
DEFAULT_TIMEOUT = 30


class GitHubAPIError(RuntimeError):
    pass


@dataclass
class EvidenceFile:
    path: str
    sha256: str
    bytes: int


class GitHubCollector:
    def __init__(self, token: str, api_url: str, api_version: str):
        self.api_url = api_url.rstrip("/") + "/"
        self.api_version = api_version
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": api_version,
                "User-Agent": "cm08-evidence-collector",
            }
        )

    def request(self, method: str, path: str, params: Optional[Dict[str, Any]] = None) -> requests.Response:
        url = urljoin(self.api_url, path.lstrip("/"))
        resp = self.session.request(method, url, params=params, timeout=DEFAULT_TIMEOUT)
        if resp.status_code >= 400:
            message = resp.text.strip()
            raise GitHubAPIError(f"{method} {path} failed with {resp.status_code}: {message}")
        return resp

    def get_json(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        return self.request("GET", path, params=params).json()

    def paginate(self, path: str, params: Optional[Dict[str, Any]] = None) -> Iterable[Any]:
        url = urljoin(self.api_url, path.lstrip("/"))
        q = dict(params or {})
        q.setdefault("per_page", 100)
        while url:
            resp = self.session.get(url, params=q, timeout=DEFAULT_TIMEOUT)
            if resp.status_code >= 400:
                raise GitHubAPIError(f"GET {resp.url} failed with {resp.status_code}: {resp.text.strip()}")
            data = resp.json()
            if isinstance(data, list):
                for item in data:
                    yield item
            else:
                yield data
            url = resp.links.get("next", {}).get("url")
            q = None


def utc_now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def sanitize_scalar(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [sanitize_scalar(v) for v in value]
    if isinstance(value, dict):
        return {k: sanitize_scalar(v) for k, v in value.items()}
    return str(value)


def write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v for k, v in row.items()})


def write_json(path: Path, data: Any) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def collect_repositories(client: GitHubCollector, org: str) -> List[Dict[str, Any]]:
    repos: List[Dict[str, Any]] = []
    for repo in client.paginate(f"/orgs/{org}/repos", {"type": "all", "sort": "full_name", "direction": "asc"}):
        repos.append(
            {
                "id": repo.get("id"),
                "name": repo.get("name"),
                "full_name": repo.get("full_name"),
                "private": repo.get("private"),
                "visibility": repo.get("visibility"),
                "archived": repo.get("archived"),
                "disabled": repo.get("disabled"),
                "fork": repo.get("fork"),
                "default_branch": repo.get("default_branch"),
                "created_at": repo.get("created_at"),
                "updated_at": repo.get("updated_at"),
                "pushed_at": repo.get("pushed_at"),
                "owner_login": (repo.get("owner") or {}).get("login"),
                "language": repo.get("language"),
                "open_issues_count": repo.get("open_issues_count"),
                "topics": repo.get("topics"),
                "has_issues": repo.get("has_issues"),
                "has_projects": repo.get("has_projects"),
                "has_wiki": repo.get("has_wiki"),
                "has_discussions": repo.get("has_discussions"),
                "allow_squash_merge": repo.get("allow_squash_merge"),
                "allow_merge_commit": repo.get("allow_merge_commit"),
                "allow_rebase_merge": repo.get("allow_rebase_merge"),
                "allow_auto_merge": repo.get("allow_auto_merge"),
                "delete_branch_on_merge": repo.get("delete_branch_on_merge"),
                "security_and_analysis": repo.get("security_and_analysis"),
            }
        )
    return repos


def collect_members(client: GitHubCollector, org: str) -> List[Dict[str, Any]]:
    members: List[Dict[str, Any]] = []
    for member in client.paginate(f"/orgs/{org}/members"):
        members.append(
            {
                "login": member.get("login"),
                "id": member.get("id"),
                "type": member.get("type"),
                "site_admin": member.get("site_admin"),
            }
        )
    return members


def collect_outside_collaborators(client: GitHubCollector, org: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for user in client.paginate(f"/orgs/{org}/outside_collaborators"):
        rows.append(
            {
                "login": user.get("login"),
                "id": user.get("id"),
                "type": user.get("type"),
                "site_admin": user.get("site_admin"),
            }
        )
    return rows


def collect_app_installations(client: GitHubCollector, org: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for inst in client.paginate(f"/orgs/{org}/installations"):
        app = inst.get("app") or {}
        account = inst.get("account") or {}
        rows.append(
            {
                "installation_id": inst.get("id"),
                "app_id": app.get("id"),
                "app_slug": app.get("slug"),
                "app_name": app.get("name"),
                "app_owner": (app.get("owner") or {}).get("login"),
                "account_login": account.get("login"),
                "account_type": account.get("type"),
                "target_type": inst.get("target_type"),
                "repository_selection": inst.get("repository_selection"),
                "created_at": inst.get("created_at"),
                "updated_at": inst.get("updated_at"),
            }
        )
    return rows


def collect_org_webhooks(client: GitHubCollector, org: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for hook in client.paginate(f"/orgs/{org}/hooks"):
        config = hook.get("config") or {}
        rows.append(
            {
                "hook_id": hook.get("id"),
                "name": hook.get("name"),
                "active": hook.get("active"),
                "events": hook.get("events"),
                "created_at": hook.get("created_at"),
                "updated_at": hook.get("updated_at"),
                "config_url": config.get("url"),
                "config_content_type": config.get("content_type"),
                "config_insecure_ssl": config.get("insecure_ssl"),
            }
        )
    return rows


def collect_repo_webhooks(client: GitHubCollector, org: str, repositories: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for repo in repositories:
        full_name = repo["full_name"]
        if not full_name:
            continue
        owner, name = full_name.split("/", 1)
        for hook in client.paginate(f"/repos/{owner}/{name}/hooks"):
            config = hook.get("config") or {}
            rows.append(
                {
                    "repository": full_name,
                    "hook_id": hook.get("id"),
                    "name": hook.get("name"),
                    "active": hook.get("active"),
                    "events": hook.get("events"),
                    "created_at": hook.get("created_at"),
                    "updated_at": hook.get("updated_at"),
                    "config_url": config.get("url"),
                    "config_content_type": config.get("content_type"),
                    "config_insecure_ssl": config.get("insecure_ssl"),
                }
            )
    return rows


def collect_enterprise_audit_log(client: GitHubCollector, enterprise: str, include: str, phrase: Optional[str]) -> List[Dict[str, Any]]:
    params: Dict[str, Any] = {"include": include, "per_page": 100}
    if phrase:
        params["phrase"] = phrase
    rows: List[Dict[str, Any]] = []
    for event in client.paginate(f"/enterprises/{enterprise}/audit-log", params):
        if isinstance(event, dict):
            rows.append(sanitize_scalar(event))
        else:
            rows.append({"value": sanitize_scalar(event)})
    return rows


def build_summary_md(summary: Dict[str, Any]) -> str:
    lines = []
    lines.append("# CM-08 GitHub Inventory Evidence Summary")
    lines.append("")
    lines.append(f"Generated: {summary['generated_at']} UTC")
    lines.append(f"Organization: `{summary['org']}`")
    lines.append(f"API base: `{summary['api_url']}`")
    if summary.get("enterprise"):
        lines.append(f"Enterprise: `{summary['enterprise']}`")
    lines.append("")
    lines.append("## Counts")
    for key in ["repositories", "members", "outside_collaborators", "app_installations", "org_webhooks", "repo_webhooks", "audit_log_events"]:
        if key in summary["counts"]:
            lines.append(f"- {key.replace('_', ' ').title()}: {summary['counts'][key]}")
    lines.append("")
    lines.append("## Evidence files")
    for file in summary["evidence_files"]:
        lines.append(f"- `{file['path']}` ({file['bytes']} bytes, sha256 `{file['sha256']}`)")
    lines.append("")
    lines.append("## Notes")
    lines.append("- Repository inventory includes repository configuration and basic security-related fields when visible to the token.")
    lines.append("- Org members, outside collaborators, app installations, and webhooks are collected as separate evidence sets.")
    lines.append("- If enterprise audit log export is enabled, the package includes the selected audit log scope.")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect GitHub CM-08 evidence package.")
    parser.add_argument("--org", default=os.environ.get("GITHUB_ORG"), help="GitHub organization login")
    parser.add_argument("--output-dir", default=os.environ.get("OUTPUT_DIR", "evidence"), help="Output directory")
    parser.add_argument("--api-url", default=os.environ.get("GITHUB_API_URL", DEFAULT_API_URL), help="GitHub API base URL")
    parser.add_argument("--api-version", default=os.environ.get("GITHUB_API_VERSION", DEFAULT_API_VERSION), help="GitHub API version header")
    parser.add_argument("--enterprise", default=os.environ.get("GITHUB_ENTERPRISE"), help="Optional enterprise slug for audit log export")
    parser.add_argument("--audit-log-include", default=os.environ.get("AUDIT_LOG_INCLUDE", "web"), choices=["web", "git", "all"], help="Enterprise audit log event scope")
    parser.add_argument("--audit-log-phrase", default=os.environ.get("AUDIT_LOG_PHRASE"), help="Optional audit-log search phrase")
    parser.add_argument("--include-repo-webhooks", action="store_true", default=os.environ.get("INCLUDE_REPO_WEBHOOKS", "false").lower() == "true", help="Collect repository webhook inventory")
    parser.add_argument("--include-collaborators", action="store_true", default=os.environ.get("INCLUDE_COLLABORATORS", "false").lower() == "true", help="Collect repository collaborators (per repo)")
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN"), help="GitHub token")
    args = parser.parse_args()

    if not args.token:
        print("ERROR: GITHUB_TOKEN is required", file=sys.stderr)
        return 2
    if not args.org:
        print("ERROR: GITHUB_ORG is required", file=sys.stderr)
        return 2

    outdir = Path(args.output_dir).resolve()
    ensure_dir(outdir)

    client = GitHubCollector(args.token, args.api_url, args.api_version)
    generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    repositories = collect_repositories(client, args.org)
    members = collect_members(client, args.org)
    outside_collaborators = collect_outside_collaborators(client, args.org)
    app_installations = collect_app_installations(client, args.org)
    org_webhooks = collect_org_webhooks(client, args.org)
    repo_webhooks: List[Dict[str, Any]] = []
    collaborators: List[Dict[str, Any]] = []

    if args.include_repo_webhooks:
        repo_webhooks = collect_repo_webhooks(client, args.org, repositories)

    if args.include_collaborators:
        for repo in repositories:
            full_name = repo.get("full_name")
            if not full_name:
                continue
            owner, name = full_name.split("/", 1)
            for collab in client.paginate(f"/repos/{owner}/{name}/collaborators"):
                permissions = collab.get("permissions") or {}
                collaborators.append(
                    {
                        "repository": full_name,
                        "login": collab.get("login"),
                        "id": collab.get("id"),
                        "type": collab.get("type"),
                        "site_admin": collab.get("site_admin"),
                        "permission_admin": permissions.get("admin"),
                        "permission_push": permissions.get("push"),
                        "permission_pull": permissions.get("pull"),
                    }
                )

    audit_log_events: List[Dict[str, Any]] = []
    if args.enterprise:
        audit_log_events = collect_enterprise_audit_log(client, args.enterprise, args.audit_log_include, args.audit_log_phrase)

    # Write artifacts.
    inventory_summary = {
        "generated_at": generated_at,
        "org": args.org,
        "api_url": args.api_url,
        "api_version": args.api_version,
        "enterprise": args.enterprise,
        "counts": {
            "repositories": len(repositories),
            "members": len(members),
            "outside_collaborators": len(outside_collaborators),
            "app_installations": len(app_installations),
            "org_webhooks": len(org_webhooks),
            "repo_webhooks": len(repo_webhooks),
            "collaborators": len(collaborators),
            "audit_log_events": len(audit_log_events),
        },
    }

    write_json(outdir / "inventory_summary.json", inventory_summary)
    write_csv(outdir / "repositories.csv", repositories, [
        "id", "name", "full_name", "private", "visibility", "archived", "disabled", "fork", "default_branch",
        "created_at", "updated_at", "pushed_at", "owner_login", "language", "open_issues_count", "topics",
        "has_issues", "has_projects", "has_wiki", "has_discussions", "allow_squash_merge", "allow_merge_commit",
        "allow_rebase_merge", "allow_auto_merge", "delete_branch_on_merge", "security_and_analysis",
    ])
    write_csv(outdir / "members.csv", members, ["login", "id", "type", "site_admin"])
    write_csv(outdir / "outside_collaborators.csv", outside_collaborators, ["login", "id", "type", "site_admin"])
    write_csv(outdir / "app_installations.csv", app_installations, [
        "installation_id", "app_id", "app_slug", "app_name", "app_owner", "account_login", "account_type",
        "target_type", "repository_selection", "created_at", "updated_at",
    ])
    write_csv(outdir / "org_webhooks.csv", org_webhooks, [
        "hook_id", "name", "active", "events", "created_at", "updated_at", "config_url", "config_content_type", "config_insecure_ssl",
    ])

    if repo_webhooks:
        write_csv(outdir / "repo_webhooks.csv", repo_webhooks, [
            "repository", "hook_id", "name", "active", "events", "created_at", "updated_at", "config_url", "config_content_type", "config_insecure_ssl",
        ])
    else:
        # still create an empty file so auditors know the check ran
        write_csv(outdir / "repo_webhooks.csv", [], [
            "repository", "hook_id", "name", "active", "events", "created_at", "updated_at", "config_url", "config_content_type", "config_insecure_ssl",
        ])

    if args.include_collaborators:
        write_csv(outdir / "repository_collaborators.csv", collaborators, [
            "repository", "login", "id", "type", "site_admin", "permission_admin", "permission_push", "permission_pull",
        ])

    if args.enterprise:
        write_csv(outdir / "audit_log.csv", audit_log_events, sorted({k for row in audit_log_events for k in row.keys()}))
    else:
        write_csv(outdir / "audit_log.csv", [], ["note"])

    summary_md = build_summary_md({
        "generated_at": generated_at,
        "org": args.org,
        "api_url": args.api_url,
        "enterprise": args.enterprise,
        "counts": inventory_summary["counts"],
        "evidence_files": [],
    })
    (outdir / "summary.md").write_text(summary_md, encoding="utf-8")

    evidence_files: List[EvidenceFile] = []
    for artifact in sorted(outdir.iterdir()):
        if artifact.is_file() and artifact.name != "evidence_manifest.json":
            evidence_files.append(EvidenceFile(path=artifact.name, sha256=sha256_file(artifact), bytes=artifact.stat().st_size))

    manifest = {
        "generated_at": generated_at,
        "org": args.org,
        "api_url": args.api_url,
        "api_version": args.api_version,
        "files": [asdict(f) for f in evidence_files],
    }
    write_json(outdir / "evidence_manifest.json", manifest)

    # Refresh the summary now that the file list is complete.
    summary_md = build_summary_md({
        "generated_at": generated_at,
        "org": args.org,
        "api_url": args.api_url,
        "enterprise": args.enterprise,
        "counts": inventory_summary["counts"],
        "evidence_files": [asdict(f) for f in evidence_files],
    })
    (outdir / "summary.md").write_text(summary_md, encoding="utf-8")

    print(summary_md)
    print(f"Wrote evidence package to {outdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
