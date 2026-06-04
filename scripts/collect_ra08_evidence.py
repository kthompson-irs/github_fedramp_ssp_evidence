#!/usr/bin/env python3

import base64
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path


API = "https://api.github.com"
OUT_DIR = Path("evidence/ra08")


RA08_AUDIT_KEYWORDS = [
    "audit_log",
    "business",
    "enterprise",
    "integration",
    "oauth",
    "org",
    "personal_access_token",
    "private_repository",
    "repo",
    "repository",
    "saml",
    "scim",
    "secret_scanning",
    "security",
    "sso",
    "team",
    "user",
]


PII_REVIEW_KEYWORDS = [
    "pii",
    "privacy",
    "pia",
    "pta",
    "privacy impact assessment",
    "privacy threshold analysis",
    "personally identifiable information",
    "sorn",
    "records notice",
]


CANDIDATE_PATHS = [
    "PRIVACY.md",
    "PIA.md",
    "PTA.md",
    "SECURITY.md",
    "CODEOWNERS",
    ".github/CODEOWNERS",
    ".github/ISSUE_TEMPLATE/privacy_review.md",
    ".github/PULL_REQUEST_TEMPLATE.md",
    "docs/privacy.md",
    "docs/pia.md",
    "docs/pta.md",
]


def required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        print(f"ERROR: Missing required environment variable: {name}", file=sys.stderr)
        sys.exit(1)
    return value


TOKEN = required_env("GH_TOKEN_RA08")
ENTERPRISE = required_env("GH_ENTERPRISE")
ORG = required_env("GH_ORG")
AUDIT_DAYS = int(os.getenv("AUDIT_DAYS", "90"))
AUDIT_SCOPE = os.getenv("AUDIT_SCOPE", "org").strip().lower()


def github_headers() -> dict:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {TOKEN}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "ra08-evidence-collector",
    }


def build_url(url: str, params: dict | None = None) -> str:
    if not params:
        return url
    query = urllib.parse.urlencode(params)
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{query}"


def parse_link_header(value: str | None) -> dict:
    links = {}
    if not value:
        return links

    for part in value.split(","):
        section = part.strip().split(";")
        if len(section) < 2:
            continue

        url = section[0].strip()
        if url.startswith("<") and url.endswith(">"):
            url = url[1:-1]

        rel = None
        for item in section[1:]:
            item = item.strip()
            if item.startswith("rel="):
                rel = item.split("=", 1)[1].strip('"')

        if rel:
            links[rel] = url

    return links


def request_json(url: str, params: dict | None = None):
    final_url = build_url(url, params)

    while True:
        request = urllib.request.Request(final_url, headers=github_headers(), method="GET")

        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                body = response.read().decode("utf-8")
                headers = dict(response.headers.items())

                if not body:
                    return None, headers

                return json.loads(body), headers

        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", errors="replace")
            headers = dict(error.headers.items())

            if error.code in (403, 429):
                remaining = headers.get("X-RateLimit-Remaining")
                reset = headers.get("X-RateLimit-Reset")
                if remaining == "0" and reset:
                    sleep_for = max(5, int(reset) - int(time.time()) + 5)
                    print(f"Rate limited. Sleeping {sleep_for} seconds.", file=sys.stderr)
                    time.sleep(sleep_for)
                    continue

            print(f"ERROR: HTTP {error.code} {final_url}", file=sys.stderr)
            print(body[:2000], file=sys.stderr)
            raise


def paginate(url: str, params: dict | None = None) -> list:
    items = []
    next_url = url
    next_params = params

    while next_url:
        data, headers = request_json(next_url, next_params)

        if isinstance(data, list):
            items.extend(data)
        elif data is not None:
            items.append(data)

        links = parse_link_header(headers.get("Link"))
        next_url = links.get("next")
        next_params = None

    return items


def write_json(name: str, data):
    path = OUT_DIR / name
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    return path


def write_csv(name: str, rows: list[dict]):
    path = OUT_DIR / name

    if not rows:
        path.write_text("", encoding="utf-8")
        return path

    keys = sorted({key for row in rows for key in row.keys()})

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=keys)
        writer.writeheader()
        writer.writerows(rows)

    return path


def flatten_repo(repo: dict) -> dict:
    return {
        "name": repo.get("name"),
        "full_name": repo.get("full_name"),
        "private": repo.get("private"),
        "visibility": repo.get("visibility"),
        "archived": repo.get("archived"),
        "disabled": repo.get("disabled"),
        "fork": repo.get("fork"),
        "description": repo.get("description"),
        "topics": ",".join(repo.get("topics") or []),
        "default_branch": repo.get("default_branch"),
        "created_at": repo.get("created_at"),
        "updated_at": repo.get("updated_at"),
        "pushed_at": repo.get("pushed_at"),
        "html_url": repo.get("html_url"),
    }


def get_file_if_exists(repo_full_name: str, path: str):
    url = f"{API}/repos/{repo_full_name}/contents/{urllib.parse.quote(path)}"
    request = urllib.request.Request(url, headers=github_headers(), method="GET")

    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            body = response.read().decode("utf-8")
            data = json.loads(body)

            return {
                "repo": repo_full_name,
                "path": path,
                "status": response.status,
                "name": data.get("name"),
                "sha": data.get("sha"),
                "size": data.get("size"),
                "html_url": data.get("html_url"),
            }

    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None

        body = error.read().decode("utf-8", errors="replace")
        return {
            "repo": repo_full_name,
            "path": path,
            "status": error.code,
            "error": body[:500],
        }


def build_audit_url() -> str:
    if AUDIT_SCOPE == "enterprise":
        return f"{API}/enterprises/{ENTERPRISE}/audit-log"

    if AUDIT_SCOPE == "org":
        return f"{API}/orgs/{ORG}/audit-log"

    print("ERROR: AUDIT_SCOPE must be either 'enterprise' or 'org'.", file=sys.stderr)
    sys.exit(1)


def collect_readme_candidate_hits(repo_full_name: str):
    url = f"{API}/repos/{repo_full_name}/readme"

    try:
        data, _headers = request_json(url)

        if not isinstance(data, dict):
            return None

        encoded_content = data.get("content")
        encoding = data.get("encoding")

        if not encoded_content or encoding != "base64":
            return None

        decoded = base64.b64decode(encoded_content).decode("utf-8", errors="replace").lower()
        matches = [keyword for keyword in PII_REVIEW_KEYWORDS if keyword in decoded]

        if not matches:
            return None

        return {
            "repo": repo_full_name,
            "path": data.get("path"),
            "html_url": data.get("html_url"),
            "matched_terms": ",".join(matches),
        }

    except urllib.error.HTTPError:
        return None


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    collected_at = datetime.now(timezone.utc)
    audit_start = collected_at - timedelta(days=AUDIT_DAYS)

    metadata = {
        "control": "RA-08",
        "control_name": "Privacy Impact Assessments",
        "enterprise": ENTERPRISE,
        "organization": ORG,
        "audit_scope": AUDIT_SCOPE,
        "collected_at_utc": collected_at.isoformat(),
        "audit_start_utc": audit_start.isoformat(),
        "audit_days": AUDIT_DAYS,
    }

    org, _org_headers = request_json(f"{API}/orgs/{ORG}")

    repos = paginate(
        f"{API}/orgs/{ORG}/repos",
        {
            "per_page": 100,
            "type": "all",
            "sort": "updated",
            "direction": "desc",
        },
    )

    members = paginate(f"{API}/orgs/{ORG}/members", {"per_page": 100})
    teams = paginate(f"{API}/orgs/{ORG}/teams", {"per_page": 100})

    audit_phrase = " OR ".join(RA08_AUDIT_KEYWORDS)
    audit_query = f"created:>={audit_start.strftime('%Y-%m-%d')} ({audit_phrase})"

    audit_logs = paginate(
        build_audit_url(),
        {
            "per_page": 100,
            "phrase": audit_query,
        },
    )

    repo_rows = [flatten_repo(repo) for repo in repos]

    privacy_candidate_repos = []
    readme_privacy_hits = []
    governance_files = []

    for repo in repo_rows:
        searchable = " ".join(
            [
                str(repo.get("name") or ""),
                str(repo.get("description") or ""),
                str(repo.get("topics") or ""),
            ]
        ).lower()

        matches = [keyword for keyword in PII_REVIEW_KEYWORDS if keyword in searchable]

        if matches:
            privacy_candidate_repos.append(
                {
                    "full_name": repo["full_name"],
                    "html_url": repo["html_url"],
                    "matched_terms": ",".join(matches),
                    "description": repo.get("description"),
                    "topics": repo.get("topics"),
                }
            )

    for repo in repos:
        full_name = repo.get("full_name")

        if not full_name:
            continue

        for path in CANDIDATE_PATHS:
            found = get_file_if_exists(full_name, path)

            if found:
                governance_files.append(found)

        readme_hit = collect_readme_candidate_hits(full_name)

        if readme_hit:
            readme_privacy_hits.append(readme_hit)

    audit_rows = []

    for item in audit_logs:
        audit_rows.append(
            {
                "created_at": item.get("@timestamp") or item.get("created_at"),
                "action": item.get("action"),
                "actor": item.get("actor"),
                "org": item.get("org"),
                "repo": item.get("repo"),
                "user": item.get("user"),
                "business": item.get("business"),
                "operation_type": item.get("operation_type"),
                "visibility": item.get("visibility"),
                "raw": json.dumps(item, sort_keys=True),
            }
        )

    member_rows = [
        {
            "login": member.get("login"),
            "type": member.get("type"),
            "site_admin": member.get("site_admin"),
            "html_url": member.get("html_url"),
        }
        for member in members
    ]

    team_rows = [
        {
            "name": team.get("name"),
            "slug": team.get("slug"),
            "privacy": team.get("privacy"),
            "permission": team.get("permission"),
            "members_count": team.get("members_count"),
            "repos_count": team.get("repos_count"),
            "html_url": team.get("html_url"),
        }
        for team in teams
    ]

    summary = {
        **metadata,
        "organization_profile": {
            "login": org.get("login") if isinstance(org, dict) else None,
            "id": org.get("id") if isinstance(org, dict) else None,
            "html_url": org.get("html_url") if isinstance(org, dict) else None,
            "description": org.get("description") if isinstance(org, dict) else None,
            "public_repos": org.get("public_repos") if isinstance(org, dict) else None,
            "owned_private_repos": org.get("owned_private_repos") if isinstance(org, dict) else None,
            "two_factor_requirement_enabled": (
                org.get("two_factor_requirement_enabled") if isinstance(org, dict) else None
            ),
        },
        "counts": {
            "repositories": len(repos),
            "members": len(members),
            "teams": len(teams),
            "audit_log_events": len(audit_logs),
            "privacy_candidate_repositories": len(privacy_candidate_repos),
            "governance_files_found": len(governance_files),
            "readme_privacy_hits": len(readme_privacy_hits),
        },
    }

    write_json("summary.json", summary)
    write_json("repositories.json", repos)
    write_json("members.json", members)
    write_json("teams.json", teams)
    write_json("audit_log_ra08_events.json", audit_logs)
    write_json("privacy_candidate_repositories.json", privacy_candidate_repos)
    write_json("governance_files.json", governance_files)
    write_json("readme_privacy_hits.json", readme_privacy_hits)

    write_csv("repositories.csv", repo_rows)
    write_csv("members.csv", member_rows)
    write_csv("teams.csv", team_rows)
    write_csv("audit_log_ra08_events.csv", audit_rows)
    write_csv("privacy_candidate_repositories.csv", privacy_candidate_repos)
    write_csv("governance_files.csv", governance_files)
    write_csv("readme_privacy_hits.csv", readme_privacy_hits)

    markdown = f"""# RA-08 Evidence Collection Summary

Control: RA-08 Privacy Impact Assessments

Enterprise: `{ENTERPRISE}`  
Organization: `{ORG}`  
Audit scope: `{AUDIT_SCOPE}`  
Collected UTC: `{collected_at.isoformat()}`  
Audit lookback days: `{AUDIT_DAYS}`

## Evidence Counts

| Evidence Area | Count |
|---|---:|
| Repositories | {len(repos)} |
| Members | {len(members)} |
| Teams | {len(teams)} |
| RA-08-relevant audit log events | {len(audit_logs)} |
| Privacy candidate repositories | {len(privacy_candidate_repos)} |
| Governance files found | {len(governance_files)} |
| README privacy hits | {len(readme_privacy_hits)} |

## RA-08 Use

This package supports RA-08 by identifying repositories, users, teams, governance files, README privacy indicators, and audit events that may indicate collection, processing, storage, transmission, or governance of PII.

## Required Human Review

The Privacy Officer, System Owner, and ISSO should review:

- `privacy_candidate_repositories.csv`
- `governance_files.csv`
- `readme_privacy_hits.csv`
- `audit_log_ra08_events.csv`

These files help determine whether a Privacy Threshold Analysis, Privacy Impact Assessment, or PIA update is required.

## Limitation

This collection does not itself prove that a PIA exists or that one is not required. It provides GitHub Enterprise Cloud evidence to support the RA-08 assessment.
"""

    (OUT_DIR / "RA-08-evidence-summary.md").write_text(markdown, encoding="utf-8")

    print(f"RA-08 evidence written to {OUT_DIR}")


if __name__ == "__main__":
    main()
