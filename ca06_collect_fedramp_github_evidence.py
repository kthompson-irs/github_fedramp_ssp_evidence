#!/usr/bin/env python3
"""
Collect GitHub evidence for FedRAMP CA-6 / SA-9 support.

Expected location:
  Repository root:
    ca06_collect_fedramp_github_evidence.py

Usage:
  python ca06_collect_fedramp_github_evidence.py --org <ORG> --out <OUT_DIR>

Environment:
  GH_TOKEN   GitHub token with permission to read org/repo/audit data
  GH_ORG     Optional default org name
  OUT_DIR    Optional default output dir

Outputs:
  <out>/
    manifest.json
    README.md
    org.json
    repos.json
    audit_log.json
    members.json
    outside_collaborators.json
    security_managers.json
    rulesets/
      org_rulesets.json
    repos/<repo>/
      repo.json
      rulesets.json
      secret_scanning_alerts.json
      code_scanning_alerts.json
      dependabot_alerts.json
      branch_protection.json
      error.txt   (only if a repo endpoint fails)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests

API_BASE = "https://api.github.com/"
API_VERSION = "2022-11-28"


class GitHubAPIError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect GitHub FedRAMP evidence.")
    parser.add_argument("--org", default=os.getenv("GH_ORG"), help="GitHub organization name")
    parser.add_argument("--token", default=os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN"), help="GitHub token")
    parser.add_argument("--out", default=os.getenv("OUT_DIR", "ca06_evidence"), help="Output directory")
    parser.add_argument(
        "--include-code-scanning",
        action="store_true",
        default=True,
        help="Collect code scanning alerts when available",
    )
    parser.add_argument(
        "--include-dependabot",
        action="store_true",
        default=True,
        help="Collect Dependabot alerts when available",
    )
    return parser.parse_args()


def make_session(token: str) -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "fedramp-evidence-collector",
        }
    )
    return s


def api_get(
    session: requests.Session,
    path: str,
    params: Optional[Dict[str, Any]] = None,
    optional: bool = False,
) -> Optional[requests.Response]:
    url = path if path.startswith("http") else urljoin(API_BASE, path.lstrip("/"))
    resp = session.get(url, params=params, timeout=60)

    if resp.status_code == 404 and optional:
        return None
    if resp.status_code >= 400:
        msg = f"GET {url} failed: {resp.status_code} {resp.text[:500]}"
        if optional:
            return None
        raise GitHubAPIError(msg)
    return resp


def paginate_json(
    session: requests.Session,
    path: str,
    params: Optional[Dict[str, Any]] = None,
    optional: bool = False,
) -> List[Any]:
    items: List[Any] = []
    url: Optional[str] = urljoin(API_BASE, path.lstrip("/"))
    next_params = params.copy() if params else {}

    while url:
        resp = api_get(session, url, params=next_params, optional=optional)
        if resp is None:
            return []
        payload = resp.json()
        if isinstance(payload, list):
            items.extend(payload)
        else:
            items.append(payload)

        url = resp.links.get("next", {}).get("url")
        next_params = {}

    return items


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")


def collect_org(session: requests.Session, org: str, out: Path) -> List[str]:
    manifest: List[str] = []

    org_obj = api_get(session, f"/orgs/{org}").json()
    write_json(out / "org.json", org_obj)
    manifest.append("org.json")

    repos = paginate_json(session, f"/orgs/{org}/repos", params={"per_page": 100, "type": "all"})
    write_json(out / "repos.json", repos)
    manifest.append("repos.json")

    members = paginate_json(session, f"/orgs/{org}/members", params={"per_page": 100}, optional=True)
    write_json(out / "members.json", members)
    manifest.append("members.json")

    outside = paginate_json(
        session,
        f"/orgs/{org}/outside_collaborators",
        params={"per_page": 100},
        optional=True,
    )
    write_json(out / "outside_collaborators.json", outside)
    manifest.append("outside_collaborators.json")

    audit_log = paginate_json(session, f"/orgs/{org}/audit-log", params={"per_page": 100}, optional=True)
    write_json(out / "audit_log.json", audit_log)
    manifest.append("audit_log.json")

    rulesets = paginate_json(session, f"/orgs/{org}/rulesets", params={"per_page": 100}, optional=True)
    write_json(out / "rulesets" / "org_rulesets.json", rulesets)
    manifest.append("rulesets/org_rulesets.json")

    sec_managers = api_get(session, f"/orgs/{org}/security-managers", optional=True)
    if sec_managers is not None:
        write_json(out / "security_managers.json", sec_managers.json())
        manifest.append("security_managers.json")

    return manifest


def collect_repo(
    session: requests.Session,
    org: str,
    repo_name: str,
    out: Path,
    include_code: bool,
    include_dep: bool,
) -> List[str]:
    repo_dir = out / "repos" / repo_name
    manifest: List[str] = []

    repo = api_get(session, f"/repos/{org}/{repo_name}").json()
    write_json(repo_dir / "repo.json", repo)
    manifest.append(f"repos/{repo_name}/repo.json")

    rulesets = paginate_json(session, f"/repos/{org}/{repo_name}/rulesets", params={"per_page": 100}, optional=True)
    write_json(repo_dir / "rulesets.json", rulesets)
    manifest.append(f"repos/{repo_name}/rulesets.json")

    secret_alerts = paginate_json(
        session,
        f"/repos/{org}/{repo_name}/secret-scanning/alerts",
        params={"per_page": 100},
        optional=True,
    )
    write_json(repo_dir / "secret_scanning_alerts.json", secret_alerts)
    manifest.append(f"repos/{repo_name}/secret_scanning_alerts.json")

    if include_code:
        code_alerts = paginate_json(
            session,
            f"/repos/{org}/{repo_name}/code-scanning/alerts",
            params={"per_page": 100},
            optional=True,
        )
        write_json(repo_dir / "code_scanning_alerts.json", code_alerts)
        manifest.append(f"repos/{repo_name}/code_scanning_alerts.json")

    if include_dep:
        dep_alerts = paginate_json(
            session,
            f"/repos/{org}/{repo_name}/dependabot/alerts",
            params={"per_page": 100},
            optional=True,
        )
        write_json(repo_dir / "dependabot_alerts.json", dep_alerts)
        manifest.append(f"repos/{repo_name}/dependabot_alerts.json")

    default_branch = repo.get("default_branch")
    if default_branch:
        bp = api_get(
            session,
            f"/repos/{org}/{repo_name}/branches/{default_branch}/protection",
            optional=True,
        )
        if bp is not None:
            write_json(repo_dir / "branch_protection.json", bp.json())
            manifest.append(f"repos/{repo_name}/branch_protection.json")

    return manifest


def build_readme(org: str, out: Path, repo_count: int) -> None:
    readme = f"""# GitHub FedRAMP Evidence Package

Organization: {org}
Collected: {time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
Repositories discovered: {repo_count}

Contents:
- org.json
- repos.json
- audit_log.json
- members.json
- outside_collaborators.json
- security_managers.json
- rulesets/org_rulesets.json
- repos/<repo>/repo.json
- repos/<repo>/rulesets.json
- repos/<repo>/secret_scanning_alerts.json
- repos/<repo>/code_scanning_alerts.json
- repos/<repo>/dependabot_alerts.json
- repos/<repo>/branch_protection.json

Notes:
- GitHub audit log access requires appropriate organization/enterprise privileges.
- Secret scanning and push protection settings are reflected in repository security controls.
- Use this package with the SSP SA-9 section, ATO letter, and POA&M.
"""
    write_text(out / "README.md", readme)


def build_manifest(out: Path, org_artifacts: List[str], repo_artifacts: List[str]) -> None:
    manifest = {
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "artifacts": org_artifacts + repo_artifacts,
    }
    write_json(out / "manifest.json", manifest)


def main() -> int:
    args = parse_args()

    if not args.org:
        print("ERROR: --org or GH_ORG is required", file=sys.stderr)
        return 2
    if not args.token:
        print("ERROR: --token or GH_TOKEN/GITHUB_TOKEN is required", file=sys.stderr)
        return 2

    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    session = make_session(args.token)

    org_artifacts = collect_org(session, args.org, out)

    repos = json.loads((out / "repos.json").read_text(encoding="utf-8"))
    repo_artifacts: List[str] = []

    for repo in repos:
        name = repo["name"]
        try:
            repo_artifacts.extend(
                collect_repo(
                    session=session,
                    org=args.org,
                    repo_name=name,
                    out=out,
                    include_code=args.include_code_scanning,
                    include_dep=args.include_dependabot,
                )
            )
        except GitHubAPIError as exc:
            err_dir = out / "repos" / name
            err_dir.mkdir(parents=True, exist_ok=True)
            write_text(err_dir / "error.txt", str(exc) + "\n")
            repo_artifacts.append(f"repos/{name}/error.txt")

    build_readme(args.org, out, len(repos))
    build_manifest(out, org_artifacts, repo_artifacts)

    print(f"Evidence package written to: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
