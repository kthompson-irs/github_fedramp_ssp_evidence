#!/usr/bin/env python3
"""
PS-04 checker.

Compares each termination row against the evidence feed named in evidence_source:
- enterprise_audit_log
- scim_log

Expected actions are read from the row and must be pipe-delimited.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


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
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def format_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def load_events(path: Optional[Path]) -> List[Dict[str, Any]]:
    if not path:
        return []
    if not path.exists() or path.is_dir():
        return []
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return []
    if raw.startswith("["):
        data = json.loads(raw)
        return [x for x in data if isinstance(x, dict)]
    events: List[Dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        item = json.loads(line)
        if isinstance(item, dict):
            events.append(item)
    return events


def normalize_identity_value(value: str) -> str:
    return (value or "").strip().casefold()


def identity_matches(event: Dict[str, Any], identity: str) -> bool:
    target = normalize_identity_value(identity)
    candidates = [
        event.get("user"),
        event.get("actor"),
        event.get("username"),
        event.get("login"),
        event.get("userName"),
        event.get("email"),
        event.get("displayName"),
        event.get("name"),
        event.get("externalId"),
    ]
    for candidate in candidates:
        if candidate is None:
            continue
        text = normalize_identity_value(str(candidate))
        if not text:
            continue
        if text == target or target in text or text in target:
            return True
    blob = normalize_identity_value(json.dumps(event, sort_keys=True))
    return target in blob


def parse_actions(value: str) -> List[str]:
    return [p.strip() for p in (value or "").replace(",", "|").replace(";", "|").split("|") if p.strip()]


def event_time(event: Dict[str, Any]) -> Optional[datetime]:
    for key in ("created_at", "@timestamp", "published", "meta.lastModified"):
        if key == "meta.lastModified":
            meta = event.get("meta")
            if isinstance(meta, dict) and meta.get("lastModified"):
                try:
                    return parse_utc_datetime(str(meta["lastModified"]))
                except Exception:
                    pass
            continue
        value = event.get(key)
        if not value:
            continue
        try:
            if isinstance(value, (int, float)):
                seconds = value / 1000.0 if value > 1_000_000_000_000 else float(value)
                return datetime.fromtimestamp(seconds, tz=timezone.utc)
            return parse_utc_datetime(str(value))
        except Exception:
            continue
    return None


def summarize_event(event: Dict[str, Any]) -> Dict[str, Any]:
    keys = ["action", "user", "actor", "userName", "login", "email", "displayName", "externalId", "active"]
    out = {}
    for key in keys:
        if key in event:
            out[key] = event[key]
    return out


def match_event(
    events: List[Dict[str, Any]],
    identity: str,
    expected_actions: List[str],
    start: datetime,
    end: datetime,
) -> Optional[Dict[str, Any]]:
    for event in events:
        action = str(event.get("action", "")).strip()
        if action not in expected_actions:
            continue
        ts = event_time(event)
        if ts is None or ts < start or ts > end:
            continue
        if not identity_matches(event, identity):
            continue
        return event
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify PS-04 termination evidence.")
    parser.add_argument("--terminations", required=True, type=Path)
    parser.add_argument("--enterprise-audit-log", required=True, type=Path)
    parser.add_argument("--scim-log", required=True, type=Path)
    parser.add_argument("--sla-minutes", type=int, default=60)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--fail-on-gaps", action="store_true")
    args = parser.parse_args()

    enterprise_events = load_events(args.enterprise_audit_log)
    scim_events = load_events(args.scim_log)

    with args.terminations.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))

    findings: List[Finding] = []
    for row in rows:
        identity = row["github_identity"]
        evidence_source = row["evidence_source"].strip()
        expected_actions = parse_actions(row.get("expected_actions", ""))
        start = parse_utc_datetime(row["termination_time_utc"])
        deadline_minutes = int(row.get("deadline_minutes") or args.sla_minutes)
        end = start + timedelta(minutes=deadline_minutes)

        if evidence_source == "enterprise_audit_log":
            source_events = enterprise_events
        elif evidence_source == "scim_log":
            source_events = scim_events
        else:
            raise SystemExit(f"Invalid evidence_source: {evidence_source}")

        event = match_event(source_events, identity, expected_actions, start, end)

        findings.append(
            Finding(
                employee_id=row.get("employee_id", ""),
                github_identity=identity,
                identity_model=row.get("identity_model", ""),
                evidence_source=evidence_source,
                termination_time_utc=format_utc(start),
                deadline_time_utc=format_utc(end),
                expected_actions=expected_actions,
                compliant=event is not None,
                matched_action=str(event.get("action")) if event else None,
                matched_event_time_utc=format_utc(event_time(event)) if event and event_time(event) else None,
                matched_actor=str(event.get("actor")) if event else None,
                matched_event_summary=summarize_event(event) if event else None,
                note=None if event else "No matching evidence event found inside the SLA window.",
            )
        )

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
    args.output.write_text(output_text + "\n", encoding="utf-8")
    print(output_text)

    if args.fail_on_gaps and gap_count:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
