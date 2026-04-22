#!/usr/bin/env python3
"""
Fetch GitHub SCIM-derived evidence for Enterprise Managed Users.

This collector talks directly to GitHub's enterprise-scoped SCIM REST API:
    /scim/v2/enterprises/{enterprise}/Users

Authentication:
- classic PAT for the enterprise setup user with scim:enterprise
- User-Agent header required
- For GHE.com, set --api-base appropriately (default is https://api.github.com)

GitHub SCIM is the EMU lifecycle path; the enterprise audit log is a separate feed.
"""

from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import requests

DEFAULT_API_BASE = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"


def format_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def load_scim_targets(terminations: Path) -> List[Dict[str, str]]:
    with terminations.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    return [row for row in rows if (row.get("evidence_source") or "").strip() == "scim_log"]


def extract_resources(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        resources = payload.get("Resources")
        if isinstance(resources, list):
            return [item for item in resources if isinstance(item, dict)]
    return []


def build_users_url(api_base: str, enterprise: str) -> str:
    base = api_base.rstrip("/")
    return f"{base}/scim/v2/enterprises/{enterprise}/Users"


def fetch_scim_users(api_base: str, enterprise: str, token: str, user_name: str) -> List[Dict[str, Any]]:
    url = build_users_url(api_base, enterprise)
    headers = {
        "Accept": "application/scim+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "ps04-scim-collector/1.0",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }
    params = {
        "filter": f'userName eq "{user_name}"',
        "startIndex": 1,
        "count": 100,
    }

    resp = requests.get(url, headers=headers, params=params, timeout=60)

    if resp.status_code == 401:
        raise SystemExit(
            "GitHub SCIM authentication failed (401). "
            "Use a classic PAT for the enterprise setup user with scim:enterprise."
        )
    if resp.status_code == 403:
        raise SystemExit(
            "GitHub SCIM authorization failed (403). "
            "Confirm the token belongs to the enterprise setup user and has scim:enterprise."
        )
    if resp.status_code == 404:
        raise SystemExit(
            "GitHub SCIM endpoint not found (404). "
            "Check the enterprise slug and the API base. "
            "For Enterprise Managed Users, the URL must be /scim/v2/enterprises/{enterprise}/Users."
        )

    resp.raise_for_status()
    return extract_resources(resp.json())


def normalize_identity(row: Dict[str, str]) -> str:
    for key in ("github_identity", "github_username", "github_user", "user", "login", "email"):
        value = (row.get(key) or "").strip()
        if value:
            return value
    return ""


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch GitHub SCIM-derived evidence.")
    parser.add_argument("--terminations", required=True, type=Path)
    parser.add_argument("--enterprise", required=True, help="GitHub enterprise slug")
    parser.add_argument("--api-base", default=DEFAULT_API_BASE, help="GitHub API base URL")
    parser.add_argument("--token", required=True, help="Classic PAT with scim:enterprise")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    if not args.enterprise.strip():
        raise SystemExit("Missing --enterprise")
    if not args.api_base.strip():
        raise SystemExit("Missing --api-base")
    if not args.token.strip():
        raise SystemExit("Missing --token")

    targets = load_scim_targets(args.terminations)
    derived_events: List[Dict[str, Any]] = []

    for row in targets:
        identity = normalize_identity(row)
        if not identity:
            continue

        resources = fetch_scim_users(
            api_base=args.api_base,
            enterprise=args.enterprise,
            token=args.token,
            user_name=identity,
        )

        for resource in resources:
            active = bool(resource.get("active", True))
            if active:
                continue

            meta = resource.get("meta") if isinstance(resource.get("meta"), dict) else {}
            last_modified = meta.get("lastModified") or format_utc(datetime.now(timezone.utc))

            derived_events.append(
                {
                    "action": "external_identity.deprovision",
                    "user": resource.get("userName", identity),
                    "actor": "scim-service",
                    "created_at": last_modified,
                    "active": False,
                    "synthetic": False,
                    "scim_id": resource.get("id"),
                    "display_name": resource.get("displayName"),
                    "external_id": resource.get("externalId"),
                    "raw": resource,
                }
            )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(derived_events, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {len(derived_events)} SCIM-derived event(s) to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
