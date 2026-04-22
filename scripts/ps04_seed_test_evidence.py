#!/usr/bin/env python3
"""
Seed deterministic evidence for CI smoke tests only.

This creates synthetic events that match the termination rows so the pipeline
passes in test mode. Do not use this output as compliance evidence.
"""

from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List


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


def parse_actions(value: str, evidence_source: str) -> List[str]:
    raw = (value or "").strip()
    if raw:
        actions = [p.strip() for p in raw.replace(",", "|").replace(";", "|").split("|") if p.strip()]
        if actions:
            return actions
    if evidence_source == "enterprise_audit_log":
        return ["org.remove_member", "business.remove_member"]
    return ["external_identity.deprovision"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--terminations", required=True, type=Path)
    parser.add_argument("--enterprise-audit-log", required=True, type=Path)
    parser.add_argument("--scim-log", required=True, type=Path)
    args = parser.parse_args()

    with args.terminations.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))

    enterprise_events: List[Dict[str, Any]] = []
    scim_events: List[Dict[str, Any]] = []

    for row in rows:
        identity = row["github_identity"]
        evidence_source = row["evidence_source"]
        termination_time = parse_utc_datetime(row["termination_time_utc"])
        expected_actions = parse_actions(row.get("expected_actions", ""), evidence_source)

        if evidence_source == "enterprise_audit_log":
            enterprise_events.append(
                {
                    "action": expected_actions[0] if expected_actions else "org.remove_member",
                    "user": identity,
                    "actor": "ps04-test-admin",
                    "created_at": format_utc(termination_time + timedelta(minutes=15)),
                    "synthetic": True,
                }
            )

        if evidence_source == "scim_log":
            scim_events.append(
                {
                    "action": expected_actions[0] if expected_actions else "external_identity.deprovision",
                    "user": identity,
                    "actor": "ps04-test-idp",
                    "created_at": format_utc(termination_time + timedelta(minutes=10)),
                    "active": False,
                    "synthetic": True,
                }
            )

    args.enterprise_audit_log.parent.mkdir(parents=True, exist_ok=True)
    args.scim_log.parent.mkdir(parents=True, exist_ok=True)

    args.enterprise_audit_log.write_text(json.dumps(enterprise_events, indent=2) + "\n", encoding="utf-8")
    args.scim_log.write_text(json.dumps(scim_events, indent=2) + "\n", encoding="utf-8")

    print(f"Wrote {len(enterprise_events)} synthetic enterprise audit event(s)")
    print(f"Wrote {len(scim_events)} synthetic SCIM event(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
