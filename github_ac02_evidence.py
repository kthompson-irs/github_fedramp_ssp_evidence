#!/usr/bin/env python3
"""
Collect FedRAMP AC-02 evidence from GitHub Enterprise Cloud / GitHub.com.

Outputs a timestamped evidence package containing:

- inventory_summary.json
- members.csv
- org_admins.csv
- outside_collaborators.csv
- teams.csv
- team_members.csv
- repositories.csv
- repo_collaborators.csv
- audit_log.json
- errors.json
- evidence_manifest.json
- summary.md

Environment variables:

- GH_TOKEN: required. GitHub token with access to the organization.
- GITHUB_ORG: required. Organization login.
- GITHUB_API_URL: optional. Defaults to https://api.github.com
- GITHUB_API_VERSION: optional. Defaults to 2022-11-28
- OUTPUT_DIR: optional. Defaults to ./evidence_output
- GITHUB_ENTERPRISE: optional. Enterprise slug for enterprise audit log export.
- AUDIT_LOG_INCLUDE: optional. web/git/all for enterprise audit log, default web.
- AUDIT_LOG_PHRASE: optional. Search phrase for audit log export.
- INCLUDE_REPO_COLLABORATORS: optional. true/false, default true
- INCLUDE_OUTSIDE_COLLABORATORS: optional. true/false, default true
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
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


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def json_safe(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [json_safe(v) for v in value]
    if isinstance(value, dict):
        return {k: json_safe(v) for k, v in value.items()}
    return str(value)


def write_json(path: Path, data: Any) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")


def write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    k: json.dumps(v, ensure_ascii=False)
                    if isinstance(v, (dict, list))
                    else v
                    for k, v in row.items()
                }
            )


def build_summary_md(summary: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("# AC-02 GitHub Evidence Summary")
    lines.append("")
    lines.append(f"Generated: {summary['generated_at']}")
    lines.append(f"Organization: `{summary['org']}`")
    lines.append(f"API base: `{summary['api_url']}`")
    if summary.get("enterprise"):
        lines.append(f"Enterprise: `{summary['enterprise']}`")
    lines.append("")
    lines.append("## Counts")
    for key, label in [
        ("members", "Organization members"),
        ("org_admins", "Organization admins"),
        ("outside_collaborators", "Outside collaborators"),
        ("teams", "Teams"),
        ("team_members", "Team memberships"),
        ("repositories", "Repositories"),
        ("repo_collaborators", "Repository collaborators"),
        ("audit_log_events", "Audit log events"),
    ]:
        if key in summary["counts"]:
            lines.append(f"- {label}: {summary['counts'][key]}")
    lines.append("")
    lines.append("## Evidence files")
    for item in summary["evidence_files"]:
        lines.append(f"- `{item['path']}` ({item['bytes']} bytes, sha256 `{item['sha256']}`)")
    lines.append("")
    lines.append("## Notes")
    lines.append("- This package is intended to support FedRAMP AC-02 evidence review.")
    lines.append("- Repository collaborator collection is optional and may be limited by token permissions.")
    lines.append("- Audit-log export uses the enterprise audit-log endpoint when `GITHUB_ENTERPRISE` is set.")
    lines.append("")
    return "\n".join(lines)


class GitHubCollector:
    def __init__(self, token: str, api_url: str, api_version: str) -> None:
        self.api_url = api_url.rstrip("/") + "/"
        self.api_version = api_version
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": api_version,
                "User-Agent": "github-ac02-evidence-collector",
            }
        )

    def request(self, method: str, path: str, params: Optional[Dict[str, Any]] = None) -> requests.Response:
        url = urljoin(self.api_url, path.lstrip("/"))
        resp = self.session.request(method, url, params=params, timeout=DEFAULT_TIMEOUT)
        if resp.status_code >= 400:
            raise GitHubAPIError(f"{method} {path} failed with {resp.status_code}: {resp.text.strip()}")
        return resp

    def get_json(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        return self.request("GET", path, params=params).json()

    def paginate(self, path: str, params: Optional[Dict[str, Any]] = None) -> Iterable[Any]:
        url = urljoin(self.api_url, path.lstrip("/"))
        query = dict(params or {})
        query.setdefault("per_page", 100)

        while url:
            resp = self.session.get(url, params=query, timeout=DEFAULT_TIMEOUT)
            if resp.status_code >= 400:
                raise GitHubAPIError(f"GET {resp.url} failed with {resp.status_code}: {resp.text.strip()}")

            data = resp.json()
            if isinstance(data, list):
                for item in data:
                    yield item
            else:
                yield data

            url = resp.links.get("next", {}).get("url")
            query = None


def normalize_member(member: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "login": member.get("login"),
        "id": member.get("id"),
        "node_id": member.get("node_id"),
        "type": member.get("type"),
        "site_admin": member.get("site_admin"),
    }


def normalize_team(team: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": team.get("id"),
        "node_id": team.get("node_id"),
        "slug": team.get("slug"),
        "name": team.get("name"),
        "description": team.get("description"),
        "privacy": team.get("privacy"),
        "permission": team.get("permission"),
        "parent": (team.get("parent") or {}).get("slug") if isinstance(team.get("parent"), dict) else None,
        "members_count": team.get("members_count"),
        "repos_count": team.get("repos_count"),
        "created_at": team.get("created_at"),
        "updated_at": team.get("updated_at"),
    }


def normalize_repo(repo: Dict[str, Any]) -> Dict[str, Any]:
    owner = repo.get("owner") or {}
    return {
        "id": repo.get("id"),
        "node_id": repo.get("node_id"),
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
        "owner_login": owner.get("login"),
    }


def collect_members(client: GitHubCollector, org: str) -> List[Dict[str, Any]]:
    return [normalize_member(m) for m in client.paginate(f"/orgs/{org}/members")]


def collect_org_admins(client: GitHubCollector, org: str) -> List[Dict[str, Any]]:
    return [normalize_member(m) for m in client.paginate(f"/orgs/{org}/members", {"role": "admin"})]


def collect_outside_collaborators(client: GitHubCollector, org: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for user in client.paginate(f"/orgs/{org}/outside_collaborators"):
        rows.append(normalize_member(user))
    return rows


def collect_teams(client: GitHubCollector, org: str) -> List[Dict[str, Any]]:
    return [normalize_team(team) for team in client.paginate(f"/orgs/{org}/teams")]


def collect_team_members(client: GitHubCollector, org: str, teams: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for team in teams:
        slug = team.get("slug")
        if not slug:
            continue
        for member in client.paginate(f"/orgs/{org}/teams/{slug}/members"):
            rows.append(
                {
                    "team_slug": slug,
                    "team_name": team.get("name"),
                    "member_login": member.get("login"),
                    "member_id": member.get("id"),
                    "member_type": member.get("type"),
                    "member_site_admin": member.get("site_admin"),
                }
            )
    return rows


def collect_repositories(client: GitHubCollector, org: str) -> List[Dict[str, Any]]:
    repos: List[Dict[str, Any]] = []
    for repo in client.paginate(f"/orgs/{org}/repos", {"type": "all", "sort": "full_name", "direction": "asc"}):
        repos.append(normalize_repo(repo))
    return repos


def collect_repo_collaborators(client: GitHubCollector, repositories: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for repo in repositories:
        full_name = repo.get("full_name")
        if not full_name:
            continue
        owner, name = full_name.split("/", 1)
        try:
            for collab in client.paginate(f"/repos/{owner}/{name}/collaborators"):
                perms = collab.get("permissions") or {}
                rows.append(
                    {
                        "repository": full_name,
                        "login": collab.get("login"),
                        "id": collab.get("id"),
                        "type": collab.get("type"),
                        "site_admin": collab.get("site_admin"),
                        "permission_admin": perms.get("admin"),
                        "permission_push": perms.get("push"),
                        "permission_pull": perms.get("pull"),
                    }
                )
        except GitHubAPIError as exc:
            rows.append(
                {
                    "repository": full_name,
                    "login": None,
                    "id": None,
                    "type": None,
                    "site_admin": None,
                    "permission_admin": None,
                    "permission_push": None,
                    "permission_pull": None,
                    "error": str(exc),
                }
            )
    return rows


def collect_audit_log(
    client: GitHubCollector,
    org: str,
    enterprise: Optional[str],
    include: str,
    phrase: Optional[str],
) -> List[Dict[str, Any]]:
    params: Dict[str, Any] = {"per_page": 100}

    if enterprise:
        params["include"] = include
        if phrase:
            params["phrase"] = phrase
        path = f"/enterprises/{enterprise}/audit-log"
    else:
        if phrase:
            params["phrase"] = phrase
        path = f"/orgs/{org}/audit-log"

    events: List[Dict[str, Any]] = []
    for event in client.paginate(path, params):
        events.append(json_safe(event))
    return events


def build_manifest(files: List[Path], root: Path) -> List[Dict[str, Any]]:
    manifest: List[Dict[str, Any]] = []
    for path in sorted(files):
        if not path.is_file():
            continue
        manifest.append(
            {
                "path": str(path.relative_to(root)),
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return manifest


def parse_bool(env_name: str, default: str = "true") -> bool:
    return os.environ.get(env_name, default).strip().lower() in {"1", "true", "yes", "y", "on"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect GitHub AC-02 evidence.")
    parser.add_argument("--org", default=os.environ.get("GITHUB_ORG"), help="GitHub organization login")
    parser.add_argument("--token", default=os.environ.get("GH_TOKEN"), help="GitHub token")
    parser.add_argument("--api-url", default=os.environ.get("GITHUB_API_URL", DEFAULT_API_URL), help="GitHub API base URL")
    parser.add_argument(
        "--api-version",
        default=os.environ.get("GITHUB_API_VERSION", DEFAULT_API_VERSION),
        help="GitHub API version header",
    )
    parser.add_argument(
        "--output-dir",
        default=os.environ.get("OUTPUT_DIR", "evidence_output"),
        help="Base evidence output directory",
    )
    parser.add_argument(
        "--enterprise",
        default=os.environ.get("GITHUB_ENTERPRISE"),
        help="Optional enterprise slug for enterprise audit log export",
    )
    parser.add_argument(
        "--audit-log-include",
        default=os.environ.get("AUDIT_LOG_INCLUDE", "web"),
        choices=["web", "git", "all"],
        help="Enterprise audit-log scope",
    )
    parser.add_argument(
        "--audit-log-phrase",
        default=os.environ.get("AUDIT_LOG_PHRASE"),
        help="Optional audit-log search phrase",
    )
    parser.add_argument(
        "--include-repo-collaborators",
        action="store_true",
        default=parse_bool("INCLUDE_REPO_COLLABORATORS", "true"),
        help="Collect repository collaborators",
    )
    parser.add_argument(
        "--include-outside-collaborators",
        action="store_true",
        default=parse_bool("INCLUDE_OUTSIDE_COLLABORATORS", "true"),
        help="Collect organization outside collaborators",
    )
    args = parser.parse_args()

    if not args.token:
        print("ERROR: GH_TOKEN is required", file=sys.stderr)
        return 2
    if not args.org:
        print("ERROR: GITHUB_ORG is required", file=sys.stderr)
        return 2

    output_root = Path(args.output_dir).resolve()
    run_dir = output_root / utc_stamp()
    ensure_dir(run_dir)

    client = GitHubCollector(args.token, args.api_url, args.api_version)

    errors: List[Dict[str, Any]] = []

    def trap(label: str, fn):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - we want to capture evidence collection failures
            errors.append({"section": label, "error": str(exc)})
            return []

    members = trap("members", lambda: collect_members(client, args.org))
    org_admins = trap("org_admins", lambda: collect_org_admins(client, args.org))
    outside_collaborators = []
    if args.include_outside_collaborators:
        outside_collaborators = trap("outside_collaborators", lambda: collect_outside_collaborators(client, args.org))
    teams = trap("teams", lambda: collect_teams(client, args.org))
    team_members = trap("team_members", lambda: collect_team_members(client, args.org, teams))
    repositories = trap("repositories", lambda: collect_repositories(client, args.org))
    repo_collaborators: List[Dict[str, Any]] = []
    if args.include_repo_collaborators:
        repo_collaborators = trap("repo_collaborators", lambda: collect_repo_collaborators(client, repositories))

    audit_log_events: List[Dict[str, Any]] = []
    audit_log_events = trap(
        "audit_log",
        lambda: collect_audit_log(client, args.org, args.enterprise, args.audit_log_include, args.audit_log_phrase),
    )

    # Write artifacts.
    write_csv(
        run_dir / "members.csv",
        members,
        ["login", "id", "node_id", "type", "site_admin"],
    )
    write_csv(
        run_dir / "org_admins.csv",
        org_admins,
        ["login", "id", "node_id", "type", "site_admin"],
    )
    write_csv(
        run_dir / "outside_collaborators.csv",
        outside_collaborators,
        ["login", "id", "node_id", "type", "site_admin"],
    )
    write_csv(
        run_dir / "teams.csv",
        teams,
        ["id", "node_id", "slug", "name", "description", "privacy", "permission", "parent", "members_count", "repos_count", "created_at", "updated_at"],
    )
    write_csv(
        run_dir / "team_members.csv",
        team_members,
        ["team_slug", "team_name", "member_login", "member_id", "member_type", "member_site_admin"],
    )
    write_csv(
        run_dir / "repositories.csv",
        repositories,
        [
            "id",
            "node_id",
            "name",
            "full_name",
            "private",
            "visibility",
            "archived",
            "disabled",
            "fork",
            "default_branch",
            "created_at",
            "updated_at",
            "pushed_at",
            "language",
            "open_issues_count",
            "topics",
            "has_issues",
            "has_projects",
            "has_wiki",
            "has_discussions",
            "allow_squash_merge",
            "allow_merge_commit",
            "allow_rebase_merge",
            "allow_auto_merge",
            "delete_branch_on_merge",
            "owner_login",
        ],
    )
    write_csv(
        run_dir / "repo_collaborators.csv",
        repo_collaborators,
        [
            "repository",
            "login",
            "id",
            "type",
            "site_admin",
            "permission_admin",
            "permission_push",
            "permission_pull",
            "error",
        ],
    )

    write_json(run_dir / "audit_log.json", audit_log_events)

    summary: Dict[str, Any] = {
        "generated_at": utc_iso(),
        "org": args.org,
        "api_url": args.api_url,
        "enterprise": args.enterprise,
        "counts": {
            "members": len(members),
            "org_admins": len(org_admins),
            "outside_collaborators": len(outside_collaborators),
            "teams": len(teams),
            "team_members": len(team_members),
            "repositories": len(repositories),
            "repo_collaborators": len(repo_collaborators),
            "audit_log_events": len(audit_log_events),
        },
    }

    files_to_manifest = [
        run_dir / "members.csv",
        run_dir / "org_admins.csv",
        run_dir / "outside_collaborators.csv",
        run_dir / "teams.csv",
        run_dir / "team_members.csv",
        run_dir / "repositories.csv",
        run_dir / "repo_collaborators.csv",
        run_dir / "audit_log.json",
    ]

    evidence_manifest = build_manifest(files_to_manifest, run_dir)
    summary["evidence_files"] = evidence_manifest
    summary["errors"] = errors

    write_json(run_dir / "inventory_summary.json", summary)
    write_json(run_dir / "errors.json", errors)
    write_json(run_dir / "evidence_manifest.json", evidence_manifest)
    (run_dir / "summary.md").write_text(build_summary_md(summary), encoding="utf-8")

    print(f"Evidence written to: {run_dir}")
    print(json.dumps(summary["counts"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
