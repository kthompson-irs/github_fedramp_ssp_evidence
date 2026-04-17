#!/usr/bin/env python3
"""
PS-04 verifier for GitHub Enterprise Cloud.
Updated to use GH_* environment variables.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

EMU_ACTIONS = {"external_identity.deprovision"}
PERSONAL_ACTIONS = {"business.remove_member", "org.remove_member"}


@dataclass
class TerminationRecord:
    employee_id: str
    github_identity: str
    termination_time_utc: datetime
    identity_model: str
    deadline_minutes: int


@dataclass
class Finding:
    employee_id: str
    github_identity: str
    identity_model: str
    termination_time_utc: str
    deadline_time_utc: str
    expected_actions: List[str]
    compliant: bool
    matched_action: Optional[str]
    matched_event_time_utc: Optional[str]
    matched_actor: Optional[str]
    matched_event_summary: Optional[Dict[str, Any]]
    note: Optional[str]


def parse_utc_datetime(value: str) -> datetime:
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def format_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def load_terminations(path: Path, default_deadline_minutes: int) -> List[TerminationRecord]:
    records: List[TerminationRecord] = []
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            records.append(
                TerminationRecord(
                    employee_id=row.get("employee_id", ""),
                    github_identity=row["github_identity"],
                    termination_time_utc=parse_utc_datetime(row["termination_time_utc"]),
                    identity_model=row.get("identity_model", "personal"),
                    deadline_minutes=int(row.get("deadline_minutes", default_deadline_minutes)),
                )
            )
    return records


def load_events_from_github(
    enterprise: str,
    token: str,
    api_base: str,
    max_pages: int,
    per_page: int,
) -> List[Dict[str, Any]]:
    import requests

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
    }

    all_events: List[Dict[str, Any]] = []
    url = f"{api_base.rstrip('/')}/enterprises/{enterprise}/audit-log"

    for page in range(1, max_pages + 1):
        resp = requests.get(
            url,
            headers=headers,
            params={"page": page, "per_page": per_page},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        if not data:
            break
        all_events.extend(data)

    return all_events


def check_record(record: TerminationRecord, events: Sequence[Dict[str, Any]]) -> Finding:
    start = record.termination_time_utc
    end = start + timedelta(minutes=record.deadline_minutes)

    expected = list(EMU_ACTIONS if record.identity_model == "emu" else PERSONAL_ACTIONS)

    for event in events:
        if event.get("action") in expected:
            return Finding(
                employee_id=record.employee_id,
                github_identity=record.github_identity,
                identity_model=record.identity_model,
                termination_time_utc=format_utc(start),
                deadline_time_utc=format_utc(end),
                expected_actions=expected,
                compliant=True,
                matched_action=event.get("action"),
                matched_event_time_utc=event.get("created_at"),
                matched_actor=event.get("actor"),
                matched_event_summary=event,
                note=None,
            )

    return Finding(
        employee_id=record.employee_id,
        github_identity=record.github_identity,
        identity_model=record.identity_model,
        termination_time_utc=format_utc(start),
        deadline_time_utc=format_utc(end),
        expected_actions=expected,
        compliant=False,
        matched_action=None,
        matched_event_time_utc=None,
        matched_actor=None,
        matched_event_summary=None,
        note="No matching event",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--terminations", required=True, type=Path)
    parser.add_argument("--enterprise", default=os.getenv("GH_ENTERPRISE_SLUG"))
    parser.add_argument("--token", default=os.getenv("GH_AUDIT_TOKEN"))
    parser.add_argument("--api-base", default="https://api.github.com")
    parser.add_argument("--max-pages", type=int, default=10)
    parser.add_argument("--sla-minutes", type=int, default=60)
    parser.add_argument("--output", type=Path, default=Path("ps04_report.json"))
    args = parser.parse_args()

    if not args.enterprise or not args.token:
        print("Missing GH_ENTERPRISE_SLUG or GH_AUDIT_TOKEN", file=sys.stderr)
        return 1

    terminations = load_terminations(args.terminations, args.sla_minutes)
    events = load_events_from_github(args.enterprise, args.token, args.api_base, args.max_pages, 100)

    findings = [check_record(r, events) for r in terminations]

    report = {
        "generated_at_utc": format_utc(datetime.now(timezone.utc)),
        "summary": {
            "total": len(findings),
            "compliant": sum(1 for f in findings if f.compliant),
        },
        "findings": [asdict(f) for f in findings],
    }

    args.output.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
