#!/usr/bin/env python3
"""
PS-04 verifier for GitHub Enterprise Cloud.

What it does:
- Reads a termination roster from CSV.
- Reads GitHub audit events from either:
  (a) a local JSON/JSONL export, or
  (b) the GitHub Enterprise audit-log API.
- Checks whether the expected offboarding event happened within the SLA window.
- Emits a JSON report and returns a non-zero exit code when gaps are found.

CSV input schema:
- employee_id               (optional but recommended)
- github_identity           (required; GitHub username, SCIM userName, or email)
- termination_time_utc      (required; ISO-8601 like 2026-04-17T18:30:00Z)
- identity_model           (optional; "emu" or "personal"; default: personal)
- deadline_minutes         (optional; overrides the global SLA for that row)
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
from typing import Any, Dict, Iterable, List, Optional, Sequence


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
    if not raw:
        raise ValueError("empty datetime")

    # Accept "Z" or explicit offsets.
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"

    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        # Treat naive timestamps as UTC to keep the script predictable.
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def format_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def event_time(event: Dict[str, Any]) -> Optional[datetime]:
    for key in ("created_at", "@timestamp"):
        if key not in event or event[key] in (None, ""):
            continue
        value = event[key]
        if isinstance(value, (int, float)):
            # GitHub audit-log API commonly returns milliseconds since epoch.
            seconds = value / 1000.0 if value > 1_000_000_000_000 else float(value)
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        if isinstance(value, str):
            try:
                return parse_utc_datetime(value)
            except ValueError:
                continue
    return None


def normalize_identity_model(value: str) -> str:
    v = (value or "").strip().lower()
    if v in {"emu", "managed", "managed_user", "managed-users", "manageduser"}:
        return "emu"
    return "personal"


def expected_actions(identity_model: str) -> List[str]:
    if identity_model == "emu":
        return sorted(EMU_ACTIONS)
    return sorted(PERSONAL_ACTIONS)


def row_get(row: Dict[str, str], *keys: str, default: str = "") -> str:
    for key in keys:
        if key in row and row[key].strip():
            return row[key].strip()
    return default


def load_terminations(path: Path, default_deadline_minutes: int) -> List[TerminationRecord]:
    records: List[TerminationRecord] = []
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for idx, row in enumerate(reader, start=2):
            github_identity = row_get(row, "github_identity", "github_username", "github_user", "user", "login", "email")
            if not github_identity:
                raise ValueError(f"{path}:{idx}: missing github_identity/github_username/user/login/email")

            ts_raw = row_get(row, "termination_time_utc", "terminated_at_utc", "termination_time")
            if not ts_raw:
                raise ValueError(f"{path}:{idx}: missing termination_time_utc")

            identity_model = normalize_identity_model(row_get(row, "identity_model", default="personal"))
            deadline_raw = row_get(row, "deadline_minutes", default=str(default_deadline_minutes))
            try:
                deadline_minutes = int(deadline_raw)
            except ValueError as exc:
                raise ValueError(f"{path}:{idx}: invalid deadline_minutes={deadline_raw!r}") from exc

            employee_id = row_get(row, "employee_id", "id", default="")

            records.append(
                TerminationRecord(
                    employee_id=employee_id,
                    github_identity=github_identity,
                    termination_time_utc=parse_utc_datetime(ts_raw),
                    identity_model=identity_model,
                    deadline_minutes=deadline_minutes,
                )
            )
    return records


def load_events_from_json_path(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(path)

    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return []

    # Support JSON array, JSON object per line, or a single JSON object.
    if raw.startswith("["):
        data = json.loads(raw)
        if not isinstance(data, list):
            raise ValueError(f"{path}: expected a JSON array")
        return [e for e in data if isinstance(e, dict)]

    events: List[Dict[str, Any]] = []
    for line_no, line in enumerate(raw.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        event = json.loads(line)
        if not isinstance(event, dict):
            raise ValueError(f"{path}:{line_no}: expected JSON object per line")
        events.append(event)
    return events


def load_events_from_github(
    enterprise: str,
    token: str,
    api_base: str,
    max_pages: int,
    per_page: int,
) -> List[Dict[str, Any]]:
    try:
        import requests
    except ImportError as exc:
        raise RuntimeError("requests is required for GitHub API mode: pip install requests") from exc

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2026-03-10",
    }

    all_events: List[Dict[str, Any]] = []
    url = f"{api_base.rstrip('/')}/enterprises/{enterprise}/audit-log"

    for page in range(1, max_pages + 1):
        resp = requests.get(
            url,
            headers=headers,
            params={
                "include": "web",
                "order": "desc",
                "page": page,
                "per_page": per_page,
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, list):
            raise RuntimeError("Unexpected GitHub audit-log response shape; expected a JSON array")
        if not data:
            break

        for item in data:
            if isinstance(item, dict):
                all_events.append(item)

        if len(data) < per_page:
            break

    return all_events


def matches_identity(event: Dict[str, Any], identity: str) -> bool:
    needle = identity.strip().lower()
    if not needle:
        return False

    preferred_keys = (
        "user",
        "actor",
        "name",
        "display_name",
        "username",
        "user_name",
        "scim_user_id",
        "externalId",
        "email",
    )

    for key in preferred_keys:
        value = event.get(key)
        if value is None:
            continue
        text = str(value).strip().lower()
        if not text:
            continue
        if text == needle or needle in text or text in needle:
            return True

    # Fall back to a broad search over the stringified event.
    blob = " ".join(str(v).lower() for v in event.values() if v is not None)
    return needle in blob


def summarize_event(event: Dict[str, Any]) -> Dict[str, Any]:
    keys = [
        "action",
        "actor",
        "user",
        "org",
        "repo",
        "team",
        "business",
        "external_group",
        "external_group_id",
        "scim_user_id",
        "request_method",
        "url_path",
        "status_code",
    ]
    return {k: event.get(k) for k in keys if k in event}


def check_record(record: TerminationRecord, events: Sequence[Dict[str, Any]]) -> Finding:
    start = record.termination_time_utc
    end = start + timedelta(minutes=record.deadline_minutes)
    expected = expected_actions(record.identity_model)

    best_event: Optional[Dict[str, Any]] = None
    best_event_time: Optional[datetime] = None

    for event in events:
        action = str(event.get("action", "")).strip()
        if action not in expected:
            continue

        et = event_time(event)
        if et is None:
            continue
        if et < start or et > end:
            continue
        if not matches_identity(event, record.github_identity):
            continue

        if best_event is None or et < best_event_time:
            best_event = event
            best_event_time = et

    compliant = best_event is not None
    note = None if compliant else "No matching GitHub offboarding event found inside the SLA window."

    return Finding(
        employee_id=record.employee_id,
        github_identity=record.github_identity,
        identity_model=record.identity_model,
        termination_time_utc=format_utc(record.termination_time_utc),
        deadline_time_utc=format_utc(end),
        expected_actions=expected,
        compliant=compliant,
        matched_action=str(best_event.get("action")) if best_event else None,
        matched_event_time_utc=format_utc(best_event_time) if best_event_time else None,
        matched_actor=str(best_event.get("actor")) if best_event else None,
        matched_event_summary=summarize_event(best_event) if best_event else None,
        note=note,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify GitHub PS-04 offboarding evidence.")
    parser.add_argument("--terminations", required=True, type=Path, help="CSV file of termination records")
    parser.add_argument("--audit-log", type=Path, help="Local GitHub audit log export (JSON, JSONL, or array)")
    parser.add_argument("--enterprise", help="GitHub enterprise slug (API mode)")
    parser.add_argument("--token", help="GitHub token (API mode)")
    parser.add_argument("--api-base", default=os.getenv("GITHUB_API_BASE", "https://api.github.com"), help="API base URL")
    parser.add_argument("--max-pages", type=int, default=10, help="Maximum audit-log pages to fetch in API mode")
    parser.add_argument("--per-page", type=int, default=100, help="Audit-log page size in API mode")
    parser.add_argument("--sla-minutes", type=int, default=60, help="Default PS-04 SLA in minutes")
    parser.add_argument("--output", type=Path, help="Write the JSON report to this file")
    parser.add_argument("--fail-on-gaps", action="store_true", help="Exit non-zero when any record is non-compliant")
    args = parser.parse_args()

    terminations = load_terminations(args.terminations, args.sla_minutes)

    if args.audit_log:
        events = load_events_from_json_path(args.audit_log)
    else:
        if not args.enterprise or not args.token:
            raise SystemExit("Provide either --audit-log or both --enterprise and --token")
        events = load_events_from_github(
            enterprise=args.enterprise,
            token=args.token,
            api_base=args.api_base,
            max_pages=args.max_pages,
            per_page=args.per_page,
        )

    # Sort oldest to newest for easier reading in the report.
    events_sorted = sorted(
        events,
        key=lambda e: event_time(e) or datetime.min.replace(tzinfo=timezone.utc),
    )

    findings = [check_record(record, events_sorted) for record in terminations]
    compliant_count = sum(1 for f in findings if f.compliant)
    gap_count = len(findings) - compliant_count

    report = {
        "generated_at_utc": format_utc(datetime.now(timezone.utc)),
        "summary": {
            "total_records": len(findings),
            "compliant_records": compliant_count,
            "gap_records": gap_count,
        },
        "findings": [asdict(f) for f in findings],
    }

    output_text = json.dumps(report, indent=2, sort_keys=True)
    print(output_text)

    if args.output:
        args.output.write_text(output_text + "\n", encoding="utf-8")

    if args.fail_on_gaps and gap_count:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
