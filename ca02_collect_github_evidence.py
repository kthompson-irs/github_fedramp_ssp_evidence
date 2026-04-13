#!/usr/bin/env python3
"""
Collect GitHub evidence for an ATO / FedRAMP package.

Outputs:
- org.json
- repos.json
- audit_log.jsonl
- branches/<repo>_<branch>_protection.json
- dependabot/<repo>_alerts.json
- secret_scanning/<repo>_alerts.json
- manifest.json

Environment variables:
- GH_TOKEN   Required. GitHub personal access token or app token with read access.
- GH_ORG     Required. GitHub organization name.
- GH_REPOS   Optional. Comma-separated list of repos. If omitted, all repos in org are scanned.
- GH_BRANCH  Optional. Branch name to inspect for protection settings. Default: main
- OUTPUT_DIR Optional. Output directory. Default: ./evidence
- GH_AUDIT_LOG_PHRASE Optional. Phrase filter for org audit-log endpoint, if desired.

Notes:
- Some endpoints require GitHub Advanced Security or org-admin permissions.
- Missing permissions are captured in the output rather than failing the run.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests


API_BASE = "https://api.github.com"


@dataclass
class Config:
    token: str
    org: str
    repos: Optional[List[str]]
    branch: str
    output_dir: Path
    audit_log_phrase: Optional[str]


def env(name: str, default: Optional[str] = None, required: bool = False) -> str:
    value = os.getenv(name, default)
    if required and not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value or ""


def get_config() -> Config:
    repos_raw = env("GH_REPOS", "")
    repos = [r.strip() for r in repos_raw.split(",") if r.strip()] if repos_raw else None
    return Config(
        token=env("GH_TOKEN", required=True),
        org=env("GH_ORG", required=True),
        repos=repos,
        branch=env("GH_BRANCH", "main"),
        output_dir=Path(env("OUTPUT_DIR", "./evidence")).resolve(),
        audit_log_phrase=env("GH_AUDIT_LOG_PHRASE", "") or None,
    )


def request_json(session: requests.Session, method: str, url: str, *, params: Optional[dict] = None) -> Dict[str, Any]:
    response = session.request(method, url, params=params, timeout=60)
    result: Dict[str, Any] = {
        "url": response.url,
        "status_code": response.status_code,
        "ok": response.ok,
    }
    try:
        payload = response.json()
    except Exception:
        payload = {"text": response.text}

    if response.ok:
        if isinstance(payload, dict):
            return payload
        return {"data": payload}

    result["error"] = payload
    return result


def paged_get(
    session: requests.Session,
    url: str,
    *,
    params: Optional[dict] = None,
    max_pages: int = 20,
) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    page_params = dict(params or {})
    page_params.setdefault("per_page", 100)

    for _ in range(max_pages):
        response = session.get(url, params=page_params, timeout=60)
        if not response.ok:
            items.append({
                "url": response.url,
                "status_code": response.status_code,
                "ok": False,
                "error": response.text,
            })
            break

        payload = response.json()
        if isinstance(payload, list):
            items.extend(payload)
        else:
            items.append(payload)
            break

        next_link = response.links.get("next", {}).get("url")
        if not next_link:
            break

        url = next_link
        page_params = None

    return items


def safe_write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def safe_write_jsonl(path: Path, rows: List[Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True))
            f.write("\n")


def collect_org(session: requests.Session, org: str) -> Dict[str, Any]:
    return request_json(session, "GET", f"{API_BASE}/orgs/{org}")


def collect_repos(session: requests.Session, org: str, repos_filter: Optional[List[str]]) -> List[Dict[str, Any]]:
    if repos_filter:
        repos = []
        for repo in repos_filter:
            repos.append(request_json(session, "GET", f"{API_BASE}/repos/{org}/{repo}"))
        return repos
    return paged_get(session, f"{API_BASE}/orgs/{org}/repos", params={"type": "all"})


def collect_audit_log(session: requests.Session, org: str, phrase: Optional[str]) -> List[Dict[str, Any]]:
    params = {}
    if phrase:
        params["phrase"] = phrase
    return paged_get(session, f"{API_BASE}/orgs/{org}/audit-log", params=params, max_pages=10)


def collect_branch_protection(session: requests.Session, org: str, repo: str, branch: str) -> Dict[str, Any]:
    return request_json(session, "GET", f"{API_BASE}/repos/{org}/{repo}/branches/{branch}/protection")


def collect_dependabot(session: requests.Session, org: str, repo: str) -> Dict[str, Any]:
    return request_json(session, "GET", f"{API_BASE}/repos/{org}/{repo}/dependabot/alerts")


def collect_secret_scanning(session: requests.Session, org: str, repo: str) -> Dict[str, Any]:
    return request_json(session, "GET", f"{API_BASE}/repos/{org}/{repo}/secret-scanning/alerts")


def main() -> int:
    cfg = get_config()
    cfg.output_dir.mkdir(parents=True, exist_ok=True)

    headers = {
        "Authorization": f"Bearer {cfg.token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "FedRAMP-GitHub-Evidence-Collector",
    }

    session = requests.Session()
    session.headers.update(headers)

    manifest: Dict[str, Any] = {
        "org": cfg.org,
        "branch": cfg.branch,
        "repos_filter": cfg.repos,
        "audit_log_phrase": cfg.audit_log_phrase,
        "outputs": {},
    }

    org_data = collect_org(session, cfg.org)
    safe_write_json(cfg.output_dir / "org.json", org_data)
    manifest["outputs"]["org"] = "org.json"

    repos = collect_repos(session, cfg.org, cfg.repos)
    safe_write_json(cfg.output_dir / "repos.json", repos)
    manifest["outputs"]["repos"] = "repos.json"

    audit_log = collect_audit_log(session, cfg.org, cfg.audit_log_phrase)
    safe_write_jsonl(cfg.output_dir / "audit_log.jsonl", audit_log)
    manifest["outputs"]["audit_log"] = "audit_log.jsonl"

    branch_dir = cfg.output_dir / "branches"
    dependabot_dir = cfg.output_dir / "dependabot"
    secret_dir = cfg.output_dir / "secret_scanning"
    branch_dir.mkdir(exist_ok=True)
    dependabot_dir.mkdir(exist_ok=True)
    secret_dir.mkdir(exist_ok=True)

    repo_names: List[str] = []
    for repo_entry in repos:
        if isinstance(repo_entry, dict) and repo_entry.get("name"):
            repo_names.append(repo_entry["name"])

    repo_records: Dict[str, Any] = {}
    for repo in repo_names:
        repo_record: Dict[str, Any] = {"repo": repo}

        branch_protection = collect_branch_protection(session, cfg.org, repo, cfg.branch)
        repo_record["branch_protection"] = branch_protection
        safe_write_json(branch_dir / f"{repo}_{cfg.branch}_protection.json", branch_protection)

        dependabot_alerts = collect_dependabot(session, cfg.org, repo)
        repo_record["dependabot_alerts"] = dependabot_alerts
        safe_write_json(dependabot_dir / f"{repo}_alerts.json", dependabot_alerts)

        secret_scanning_alerts = collect_secret_scanning(session, cfg.org, repo)
        repo_record["secret_scanning_alerts"] = secret_scanning_alerts
        safe_write_json(secret_dir / f"{repo}_alerts.json", secret_scanning_alerts)

        repo_records[repo] = repo_record

    safe_write_json(cfg.output_dir / "repo_records.json", repo_records)

    manifest["repo_count"] = len(repo_names)
    manifest["repo_names"] = repo_names
    manifest["outputs"]["repo_records"] = "repo_records.json"

    safe_write_json(cfg.output_dir / "manifest.json", manifest)

    print(json.dumps({
        "output_dir": str(cfg.output_dir),
        "repo_count": len(repo_names),
        "files": sorted([str(p.relative_to(cfg.output_dir)) for p in cfg.output_dir.rglob("*") if p.is_file()]),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
