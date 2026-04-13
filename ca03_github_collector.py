#!/usr/bin/env python3

import argparse
import csv
import json
import os
import sys
import zipfile
from collections import defaultdict
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
