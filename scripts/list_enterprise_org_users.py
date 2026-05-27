#!/usr/bin/env python3
"""
List users across all GitHub.com organizations in an enterprise account.

This script:
  1) Uses GitHub GraphQL to enumerate organizations under an enterprise slug.
  2) Uses the REST API to list members for each organization.
  3) Writes:
       - JSON evidence artifact
       - CSV summary
       - Markdown summary
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import requests


GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"
GITHUB_REST_BASE = "https://api.github.com"


@dataclass
class OrgUserRecord:
    enterprise_slug: str
    enterprise_name: str
    org_login: str
    org_name: str
    user_login: str
    user_id: int
    user_type: str
    site_admin: bool


class GitHubAPIError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inventory users across organizations in a GitHub enterprise."
    )
    parser.add_argument(
        "--enterprise-slug",
        default=os.environ.get("ENTERPRISE_SLUG", "internal-revenue-service"),
        help="GitHub enterprise slug",
    )
    parser.add_argument(
        "--output-dir",
        default=os.environ.get("OUTPUT_DIR", "artifacts/enterprise-users"),
        help="Output directory for generated artifacts",
    )
    parser.add_argument(
        "--max-orgs",
        type=int,
        default=int(os.environ.get("MAX_ORGS", "0") or "0"),
        help="Optional cap on organizations to process; 0 means no cap",
    )
    return parser.parse_args()


def get_token() -> str:
    token = os.environ.get("GH_ENTERPRISE_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        raise GitHubAPIError(
            "Missing token. Set GH_ENTERPRISE_TOKEN to a PAT or GitHub App token."
        )
    return token


def build_session(token: str) -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        }
    )
    api_version = os.environ.get("GITHUB_API_VERSION", "").strip()
    if api_version:
        session.headers["X-GitHub-Api-Version"] = api_version
    return session


def graphql_query(
    session: requests.Session,
    query: str,
    variables: Dict[str, Any],
) -> Dict[str, Any]:
    response = session.post(
        GITHUB_GRAPHQL_URL,
        json={"query": query, "variables": variables},
        timeout=60,
    )
    if response.status_code >= 400:
        raise GitHubAPIError(
            f"GraphQL request failed ({response.status_code}): {response.text}"
        )

    payload = response.json()
    if payload.get("errors"):
        raise GitHubAPIError(f"GraphQL returned errors: {json.dumps(payload['errors'])}")
    return payload["data"]


def get_enterprise_orgs(
    session: requests.Session,
    enterprise_slug: str,
    max_orgs: int = 0,
) -> Tuple[str, List[Dict[str, Any]]]:
    query = """
    query($slug: String!, $after: String) {
      enterprise(slug: $slug) {
        name
        organizations(first: 100, after: $after) {
          pageInfo {
            hasNextPage
            endCursor
          }
          nodes {
            login
            name
          }
        }
      }
    }
    """

    orgs: List[Dict[str, Any]] = []
    after: Optional[str] = None
    enterprise_name = enterprise_slug

    while True:
        data = graphql_query(session, query, {"slug": enterprise_slug, "after": after})
        enterprise = data.get("enterprise")
        if enterprise is None:
            raise GitHubAPIError(
                f'Enterprise "{enterprise_slug}" was not found or is not accessible with the provided token.'
            )

        enterprise_name = enterprise.get("name") or enterprise_slug
        org_conn = enterprise.get("organizations") or {}
        nodes = org_conn.get("nodes") or []
        for node in nodes:
            if node and node.get("login"):
                orgs.append({"login": node["login"], "name": node.get("name") or node["login"]})
                if max_orgs and len(orgs) >= max_orgs:
                    return enterprise_name, orgs

        page_info = org_conn.get("pageInfo") or {}
        if not page_info.get("hasNextPage"):
            break
        after = page_info.get("endCursor")

    return enterprise_name, orgs


def rest_get(
    session: requests.Session,
    url: str,
    params: Optional[Dict[str, Any]] = None,
) -> requests.Response:
    response = session.get(url, params=params, timeout=60)
    if response.status_code >= 500:
        raise GitHubAPIError(f"GitHub REST error ({response.status_code}): {response.text}")
    return response


def list_org_members(session: requests.Session, org_login: str) -> List[Dict[str, Any]]:
    members: List[Dict[str, Any]] = []
    page = 1

    while True:
        response = rest_get(
            session,
            f"{GITHUB_REST_BASE}/orgs/{org_login}/members",
            params={"per_page": 100, "page": page},
        )

        if response.status_code == 404:
            raise GitHubAPIError(f'Organization "{org_login}" not found or inaccessible.')
        if response.status_code == 403:
            raise GitHubAPIError(
                f'Forbidden listing members for organization "{org_login}". '
                "The token likely lacks Members(read) on that organization."
            )
        if response.status_code >= 400:
            raise GitHubAPIError(
                f"Failed to list members for {org_login} ({response.status_code}): {response.text}"
            )

        batch = response.json()
        if not batch:
            break

        members.extend(batch)
        if len(batch) < 100:
            break
        page += 1

    return members


def write_csv(path: Path, records: Sequence[OrgUserRecord]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "enterprise_slug",
                "enterprise_name",
                "org_login",
                "org_name",
                "user_login",
                "user_id",
                "user_type",
                "site_admin",
            ],
        )
        writer.writeheader()
        for record in records:
            writer.writerow(asdict(record))


def write_markdown_summary(
    path: Path,
    enterprise_slug: str,
    enterprise_name: str,
    orgs: Sequence[Dict[str, Any]],
    records: Sequence[OrgUserRecord],
    errors: Sequence[Dict[str, str]],
) -> None:
    by_org: Dict[str, List[str]] = {}
    for record in records:
        by_org.setdefault(record.org_login, []).append(record.user_login)

    unique_users = sorted({r.user_login for r in records})

    lines: List[str] = []
    lines.append("# GitHub Enterprise user inventory")
    lines.append("")
    lines.append(f"- Enterprise slug: `{enterprise_slug}`")
    lines.append(f"- Enterprise name: `{enterprise_name}`")
    lines.append(f"- Organizations processed: `{len(orgs)}`")
    lines.append(f"- User rows collected: `{len(records)}`")
    lines.append(f"- Unique users across all orgs: `{len(unique_users)}`")
    lines.append("")

    if errors:
        lines.append("## Organization errors")
        lines.append("")
        for err in errors:
            lines.append(f"- `{err['org_login']}`: {err['message']}")
        lines.append("")

    lines.append("## Organization membership snapshot")
    lines.append("")
    for org in orgs:
        org_login = org["login"]
        users = sorted(set(by_org.get(org_login, [])))
        lines.append(f"### `{org_login}`")
        lines.append("")
        lines.append(f"- Display name: `{org.get('name') or org_login}`")
        lines.append(f"- Members captured: `{len(users)}`")
        if users:
            lines.append("")
            for user in users:
                lines.append(f"- `{user}`")
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    args = parse_args()
    token = get_token()
    session = build_session(token)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    started_at = dt.datetime.now(dt.timezone.utc).isoformat()
    enterprise_name, orgs = get_enterprise_orgs(
        session,
        args.enterprise_slug,
        max_orgs=args.max_orgs,
    )

    records: List[OrgUserRecord] = []
    errors: List[Dict[str, str]] = []

    for idx, org in enumerate(orgs, start=1):
        org_login = org["login"]
        org_name = org.get("name") or org_login

        try:
            members = list_org_members(session, org_login)
            for member in members:
                login = member.get("login")
                user_id = member.get("id")
                if login is None or user_id is None:
                    continue
                records.append(
                    OrgUserRecord(
                        enterprise_slug=args.enterprise_slug,
                        enterprise_name=enterprise_name,
                        org_login=org_login,
                        org_name=org_name,
                        user_login=login,
                        user_id=int(user_id),
                        user_type=member.get("type") or "User",
                        site_admin=bool(member.get("site_admin", False)),
                    )
                )
        except Exception as exc:  # noqa: BLE001
            errors.append({"org_login": org_login, "message": str(exc)})

        if idx % 10 == 0:
            time.sleep(0.5)

    unique_users = sorted({r.user_login for r in records})
    unique_orgs = sorted({org["login"] for org in orgs})

    payload = {
        "enterprise_slug": args.enterprise_slug,
        "enterprise_name": enterprise_name,
        "started_at": started_at,
        "completed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "organization_count": len(unique_orgs),
        "record_count": len(records),
        "unique_user_count": len(unique_users),
        "organizations": orgs,
        "users": [asdict(r) for r in records],
        "unique_users": unique_users,
        "errors": errors,
    }

    json_path = output_dir / "enterprise-org-users.json"
    csv_path = output_dir / "enterprise-org-users.csv"
    md_path = output_dir / "summary.md"

    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    write_csv(csv_path, records)
    write_markdown_summary(md_path, args.enterprise_slug, enterprise_name, orgs, records, errors)

    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GitHubAPIError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
