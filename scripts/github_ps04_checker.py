#!/usr/bin/env python3
import argparse, csv, json, sys
from datetime import datetime, timedelta
from pathlib import Path

def load_events(path):
    p = Path(path)
    if not p.exists():
        return []
    raw = p.read_text().strip()
    return json.loads(raw) if raw else []

def parse(t):
    return datetime.fromisoformat(t.replace("Z","+00:00"))

def identity_match(event, identity):
    identity = identity.lower()
    fields = [
        event.get("user"),
        event.get("actor"),
        event.get("login"),
        event.get("email"),
    ]
    return any(f and identity in str(f).lower() for f in fields)

def match(events, identity, actions, start, end):
    for e in events:
        if e.get("action") not in actions:
            continue

        ts = e.get("created_at")
        if not ts:
            continue

        ts = parse(ts)

        if not (start <= ts <= end):
            continue

        if identity_match(e, identity):
            return e

    return None

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--terminations", required=True)
    p.add_argument("--enterprise-audit-log", required=True)
    p.add_argument("--sla-minutes", type=int, default=60)
    p.add_argument("--output", required=True)
    p.add_argument("--fail-on-gaps", action="store_true")
    args = p.parse_args()

    events = load_events(args.enterprise_audit_log)
    rows = list(csv.DictReader(open(args.terminations)))

    findings = []

    for r in rows:
        start = parse(r["termination_time_utc"])
        end = start + timedelta(minutes=int(r.get("deadline_minutes", 60)))

        ev = match(
            events,
            r["github_identity"],
            ["org.remove_member","business.remove_member"],
            start,
            end
        )

        findings.append({
            "user": r["github_identity"],
            "compliant": bool(ev)
        })

    gaps = [f for f in findings if not f["compliant"]]

    report = {
        "summary": {
            "total": len(findings),
            "gaps": len(gaps)
        },
        "findings": findings
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))

    if args.fail_on_gaps and gaps:
        sys.exit(2)

if __name__ == "__main__":
    main()
