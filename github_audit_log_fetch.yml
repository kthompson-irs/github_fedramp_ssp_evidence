#!/usr/bin/env python3
"""Fetch GitHub audit log events with enterprise-first fallback to organization audit log."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _today_minus(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).date().isoformat()


def _request_session(token: str, api_version: str) -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": api_version,
            "User-Agent": "fedramp-poam-audit-fetcher/1.0",
        }
    )
    return session


def _paginate(
    session: requests.Session,
    url: str,
    params: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    next_url = url
    next_params = dict(params or {})
    first = True

    while next_url:
        resp = session.get(next_url, params=next_params if first else None, timeout=30)
        first = False

        if resp.status_code >= 400:
            raise RuntimeError(f"GET {resp.url} failed: {resp.status_code} {resp.text[:600]}")

        data = resp.json()
        if isinstance(data, list):
            events.extend(data)
        else:
            events.append(data)

        next_url = resp.links.get("next", {}).get("url")

    return events


def _fetch_with_fallback(
    session: requests.Session,
    attempts: List[Tuple[str, str]],
    query_params: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], List[str], str]:
    errors: List[str] = []

    for mode, url in attempts:
        try:
            return _paginate(session, url, query_params), errors, mode
        except Exception as exc:
            errors.append(f"{mode} audit log unavailable: {exc}")

    return [], errors, "none"


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch GitHub audit log events.")
    parser.add_argument(
        "--output",
        default=os.getenv("AUDIT_LOG_JSONL", "poam-output/audit.log.jsonl"),
        help="Path to JSONL output file",
    )
    parser.add_argument(
        "--errors-output",
        default=os.getenv("AUDIT_SOURCE_ERRORS_JSON", "poam-output/audit_source_errors.json"),
        help="Path to JSON output file containing source errors",
    )
    parser.add_argument("--owner", default=os.getenv("GH_OWNER") or os.getenv("GITHUB_OWNER") or "")
    parser.add_argument("--enterprise-slug", default=os.getenv("GH_ENTERPRISE_SLUG") or os.getenv("GITHUB_ENTERPRISE") or "")
    parser.add_argument("--token", default=os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN") or "")
    parser.add_argument("--api-version", default=os.getenv("GH_API_VERSION") or os.getenv("GITHUB_API_VERSION") or "2022-11-28")
    parser.add_argument("--days", type=int, default=int(os.getenv("AUDIT_DAYS", "90")))
    parser.add_argument("--use-enterprise", action="store_true", default=_env_bool("USE_ENTERPRISE_AUDIT_LOG", False))
    args = parser.parse_args()

    if not args.token:
        print("GH_TOKEN is required.", file=sys.stderr)
        return 2
    if not args.owner:
        print("GH_OWNER is required.", file=sys.stderr)
        return 2

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    errors_path = Path(args.errors_output)
    errors_path.parent.mkdir(parents=True, exist_ok=True)

    session = _request_session(args.token, args.api_version)
    cutoff = _today_minus(args.days)
    query_params = {"include": "all", "per_page": 100, "phrase": f"created:>={cutoff}"}

    attempts: List[Tuple[str, str]] = []
    if args.use_enterprise and args.enterprise_slug:
        attempts.append(("enterprise", f"https://api.github.com/enterprises/{args.enterprise_slug}/audit-log"))
    attempts.append(("org", f"https://api.github.com/orgs/{args.owner}/audit-log"))

    events, errors, mode = _fetch_with_fallback(session, attempts, query_params)

    with out_path.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event, ensure_ascii=False, default=str))
            f.write("\n")

    errors_path.write_text(json.dumps(errors, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Mode used: {mode}")
    print(f"Fetched events: {len(events)}")
    if errors:
        print("Source errors:")
        for err in errors:
            print(f"- {err}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
