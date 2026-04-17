#!/usr/bin/env python3
"""
PS-04 verifier for GitHub evidence feeds.

This version routes each termination record to the evidence source declared in
the CSV row:
- enterprise_audit_log
- security_log
- scim_log

It supports local JSON or JSONL evidence exports for each source.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


VALID_EVIDENCE_SOURCES = {
    "enterprise_audit_log",
    "security_log",
    "scim_log",
}


@dataclass
class TerminationRecord:
    employee_id: str
    github_identity: str
    termination_time_utc: datetime
    identity_model: str
    evidence_source: str
    expected_actions: List[str]
    deadline_minutes: int


@dataclass
class Finding:
    employee_id: str
    github_identity: str
    identity_model: str
    evidence_source: str
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
        raise ValueError("empty datetime value")
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def format_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def row_get(row: Dict[str, str], *keys: str, default: str = "") -> str:
    for key in keys:
        value = row.get(key, "")
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return default


def normalize_identity_model(value: str) -> str:
    v = (value or "").strip().lower()
    if v in {"emu", "managed", "managed_user", "managed-users", "manageduser"}:
        return "emu"
    return "personal"


def normalize_evidence_source(value: str) -> str:
    v = (value or "").strip().lower()
    if v not in VALID_EVIDENCE_SOURCES:
        raise ValueError(f"invalid evidence_source={value!r}")
    return v


def parse_actions(value: str) -> List[str]:
    parts = [p.strip() for p in (value or "").replace(",", "|").replace(";", "|").split("|")]
    return [p for p in parts if p]


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

            evidence_source = normalize_evidence_source(row_get(row, "evidence_source", default=""))
            actions = parse_actions(row_get(row, "expected_actions", default=""))
            if not actions:
                raise ValueError(f"{path}:{idx}: expected_actions is required")

            deadline_raw = row_get(row, "deadline_minutes", default=str(default_deadline_minutes))
            try:
                deadline_minutes = int(deadline_raw)
            except ValueError as exc:
                raise ValueError(f"{path}:{idx}: invalid deadline_minutes={deadline_raw!r}") from exc

            if deadline_minutes <= 0:
                raise ValueError(f"{path}:{idx}: deadline_minutes must be greater than 0")

            employee_id = row_get(row, "employee_id", "id", default="")
            identity_model = normalize_identity_model(row_get(row, "identity_model", default="personal"))

            records.append(
                TerminationRecord(
                    employee_id=employee_id,
                    github_identity=github_identity,
                    termination_time_utc=parse_utc_datetime(ts_raw),
                    identity_model=identity_model,
                    evidence_source=evidence_source,
                    expected_actions=actions,
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

    if raw.startswith("["):
        data = json.loads(raw)
        if not isinstance(data, list):
            raise ValueError(f"{path}: expected a JSON array")
        return [item for item in data if isinstance(item, dict)]

    events: List[Dict[str, Any]] = []
    for line_no, line in enumerate(raw.splitlines(), start=1):
        text = line.strip()
        if not text:
            continue
        item = json.loads(text)
        if not isinstance(item, dict):
            raise ValueError(f"{path}:{line_no}: expected a JSON object per line")
        events.append(item)
    return events


def event_time(event: Dict[str, Any]) -> Optional[datetime]:
    for key in ("created_at", "@timestamp"):
        value = event.get(key)
        if not value:
            continue
        if isinstance(value, (int, float)):
            seconds = value / 1000.0 if value > 1_000_000_000_000 else float(value)
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        if isinstance(value, str):
            try:
                return parse_utc_datetime(value)
            except ValueError:
                continue
    return None


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
        "login",
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

    best_event: Optional[Dict[str, Any]] = None
    best_event_time: Optional[datetime] = None

    for event in events:
        action = str(event.get("action", "")).strip()
        if action not in record.expected_actions:
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

    return Finding(
        employee_id=record.employee_id,
        github_identity=record.github_identity,
        identity_model=record.identity_model,
        evidence_source=record.evidence_source,
        termination_time_utc=format_utc(start),
        deadline_time_utc=format_utc(end),
        expected_actions=record.expected_actions,
        compliant=compliant,
        matched_action=str(best_event.get("action")) if best_event else None,
        matched_event_time_utc=format_utc(best_event_time) if best_event_time else None,
        matched_actor=str(best_event.get("actor")) if best_event else None,
        matched_event_summary=summarize_event(best_event) if best_event else None,
        note=None if compliant else "No matching evidence event found inside the SLA window.",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify GitHub PS-04 offboarding evidence.")
    parser.add_argument("--terminations", required=True, type=Path, help="CSV file of termination records")
    parser.add_argument("--enterprise-audit-log", type=Path, default=None, help="Enterprise/org audit log JSON or JSONL")
    parser.add_argument("--security-log", type=Path, default=None, help="Security log JSON or JSONL")
    parser.add_argument("--scim-log", type=Path, default=None, help="SCIM log JSON or JSONL")
    parser.add_argument("--sla-minutes", type=int, default=60)
    parser.add_argument("--output", type=Path, default=Path("ps04_report.json"))
    parser.add_argument("--fail-on-gaps", action="store_true")
    args = parser.parse_args()

    events_by_source: Dict[str, List[Dict[str, Any]]] = {}

    if args.enterprise_audit_log:
        events_by_source["enterprise_audit_log"] = load_events_from_json_path(args.enterprise_audit_log)
    if args.security_log:
        events_by_source["security_log"] = load_events_from_json_path(args.security_log)
    if args.scim_log:
        events_by_source["scim_log"] = load_events_from_json_path(args.scim_log)

    terminations = load_terminations(args.terminations, args.sla_minutes)

    missing_sources = sorted(
        {record.evidence_source for record in terminations if record.evidence_source not in events_by_source}
    )
    if missing_sources:
        print(
            "Missing evidence file(s) for source(s): " + ", ".join(missing_sources),
            file=sys.stderr,
        )
        return 1

    findings = [check_record(record, events_by_source[record.evidence_source]) for record in terminations]

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
    args.output.write_text(output_text + "\n", encoding="utf-8")

    if args.fail_on_gaps and gap_count:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
