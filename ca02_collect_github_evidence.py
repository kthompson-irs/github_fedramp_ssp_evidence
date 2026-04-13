#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import zipfile
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


def request_json(session: requests.Session, url: str, params=None) -> Dict[str, Any]:
    r = session.get(url, params=params)
    try:
        return r.json()
    except Exception:
        return {"error": r.text}


def paged_get(session: requests.Session, url: str, params=None) -> List[Any]:
    results = []
    while url:
        r = session.get(url, params=params)
        if not r.ok:
            results.append({"error": r.text})
            break

        data = r.json()
        if isinstance(data, list):
            results.extend(data)
        else:
            results.append(data)

        url = r.links.get("next", {}).get("url")
        params = None

    return results


def write_json(path: Path, data: Any):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def write_jsonl(path: Path, data: List[Any]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for item in data:
            f.write(json.dumps(item) + "\n")


def create_zip(output_dir: Path):
    zip_path = output_dir.parent / "ca02-github-fedramp-evidence.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for file in output_dir.rglob("*"):
            if file.is_file():
                zf.write(file, file.relative_to(output_dir))
    return zip_path


def main():
    cfg = get_config()
    cfg.output_dir.mkdir(parents=True, exist_ok=True)

    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {cfg.token}",
        "Accept": "application/vnd.github+json",
    })

    manifest = {}

    # Org
    org = request_json(session, f"{API_BASE}/orgs/{cfg.org}")
    write_json(cfg.output_dir / "org.json", org)

    # Repos
    repos = paged_get(session, f"{API_BASE}/orgs/{cfg.org}/repos")
    write_json(cfg.output_dir / "repos.json", repos)

    # Audit log
    audit = paged_get(session, f"{API_BASE}/orgs/{cfg.org}/audit-log")
    write_jsonl(cfg.output_dir / "audit_log.jsonl", audit)

    repo_names = [r["name"] for r in repos if isinstance(r, dict) and "name" in r]

    for repo in repo_names:
        branch = request_json(session, f"{API_BASE}/repos/{cfg.org}/{repo}/branches/{cfg.branch}/protection")
        write_json(cfg.output_dir / "branches" / f"{repo}.json", branch)

        dep = request_json(session, f"{API_BASE}/repos/{cfg.org}/{repo}/dependabot/alerts")
        write_json(cfg.output_dir / "dependabot" / f"{repo}.json", dep)

        sec = request_json(session, f"{API_BASE}/repos/{cfg.org}/{repo}/secret-scanning/alerts")
        write_json(cfg.output_dir / "secret_scanning" / f"{repo}.json", sec)

    zip_path = create_zip(cfg.output_dir)

    print(json.dumps({
        "output_dir": str(cfg.output_dir),
        "zip_file": str(zip_path),
        "repos": len(repo_names)
    }, indent=2))


if __name__ == "__main__":
    main()
