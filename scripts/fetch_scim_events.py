#!/usr/bin/env python3
"""
Fetch SCIM-derived evidence for terminated identities.

This treats deprovisioned SCIM state as evidence: for each termination row that
targets scim_log, it queries a SCIM Users endpoint and emits a deprovision event
when the user is inactive.

This is a state-to-evidence conversion for the pipeline; it is not a claim that
SCIM is itself a historical event log.
"""

from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import requests


def format_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def load_scim_targets(terminations: Path) -> List[str]:
    with terminations.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    return [row["github_identity"] for row in rows if row.get("evidence_source") == "scim_log"]


def extract_resources(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if isinstance(payload, dict):
        resources = payload.get("Resources")
        if isinstance(resources, list):
            return [x for x in resources if isinstance(x, dict)]
    return []


def fetch_user(base_url: str, token: str, user_name: str) -> List[Dict[str, Any]]:
    url = f"{base_url.rstrip('/')}/scim/v2/Users"
    headers = {
        "Accept": "application/scim+json",
        "Authorization": f"Bearer {token}",
    }
    resp = requests.get(url, headers=headers, params={"filter": f'userName eq "{user_name}"'}, timeout=60)
    resp.raise_for_status()
    return extract_resources(resp.json())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--terminations", required=True, type=Path)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--token", default=None)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    if not args.base_url:
        raise SystemExit("Missing --base-url")
    if not args.token:
        raise SystemExit("Missing --token")

    targets = load_scim_targets(args.terminations)
    now = format_utc(datetime.now(timezone.utc))

    events: List[Dict[str, Any]] = []
    for user_name in targets:
        resources = fetch_user(args.base_url, args.token, user_name)
        for resource in resources:
            active = resource.get("active", True)
            if active is False:
                events.append(
                    {
                        "action": "external_identity.deprovision",
                        "user": resource.get("userName", user_name),
                        "actor": "scim-service",
                        "created_at": resource.get("meta", {}).get("lastModified", now)
                        if isinstance(resource.get("meta"), dict)
                        else now,
                        "active": False,
                        "synthetic": False,
                    }
                )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(events, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(events)} SCIM-derived event(s) to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
