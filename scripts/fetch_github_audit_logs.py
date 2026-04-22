#!/usr/bin/env python3
"""
Fetch GitHub enterprise audit log evidence.

GitHub requires:
- an enterprise admin account
- classic PAT / OAuth token with read:audit_log
- or a fine-grained token with Enterprise administration (read)
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

import requests


def fetch_page(enterprise: str, token: str, page: int, per_page: int) -> List[Dict[str, Any]]:
    url = f"https://api.github.com/enterprises/{enterprise}/audit-log"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    resp = requests.get(url, headers=headers, params={"page": page, "per_page": per_page}, timeout=60)

    if resp.status_code == 401:
        raise SystemExit(
            "GitHub audit-log authentication failed (401). "
            "Use an enterprise-admin token with read:audit_log (classic PAT) "
            "or Enterprise administration (read) for fine-grained tokens."
        )

    if resp.status_code == 403:
        raise SystemExit(
            "GitHub audit-log authorization failed (403). "
            "The token is valid but not allowed for this enterprise audit log. "
            "Confirm the user is an enterprise admin and the token has the required permission."
        )

    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, list):
        raise RuntimeError("Unexpected response shape; expected a JSON array")
    return [item for item in data if isinstance(item, dict)]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--enterprise", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--per-page", type=int, default=100)
    parser.add_argument("--max-pages", type=int, default=10)
    args = parser.parse_args()

    events: List[Dict[str, Any]] = []
    for page in range(1, args.max_pages + 1):
        batch = fetch_page(args.enterprise, args.token, page=page, per_page=args.per_page)
        if not batch:
            break
        events.extend(batch)
        if len(batch) < args.per_page:
            break

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(events, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(events)} enterprise audit event(s) to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
