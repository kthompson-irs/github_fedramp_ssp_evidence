#!/usr/bin/env python3
import argparse, csv, json, sys
from pathlib import Path
from datetime import datetime, timedelta

def load_json_file(path):
    if not path:
        return []
    p = Path(path)
    if not p.exists() or p.is_dir():
        return []
    raw = p.read_text().strip()
    if not raw:
        return []
    if raw.startswith("["):
        return json.loads(raw)
    return [json.loads(line) for line in raw.splitlines() if line.strip()]

def load_terminations(path):
    with open(path) as f:
        return list(csv.DictReader(f))

def parse_time(t):
    return datetime.fromisoformat(t.replace("Z","+00:00"))

def match(events, identity, actions, start, end):
    for e in events:
        if e.get("action") not in actions:
            continue
        et = e.get("created_at") or e.get("@timestamp")
        if not et:
            continue
        et = parse_time(et)
        if not (start <= et <= end):
            continue
        blob = json.dumps(e).lower()
        if identity.lower() in blob:
            return e
    return None

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--terminations")
    p.add_argument("--enterprise-audit-log")
    p.add_argument("--security-log")
    p.add_argument("--scim-log")
    p.add_argument("--sla-minutes", type=int, default=60)
    p.add_argument("--output")
    p.add_argument("--fail-on-gaps", action="store_true")
    args = p.parse_args()

    enterprise_events = load_json_file(args.enterprise_audit_log)
    security_events = load_json_file(args.security_log)
    scim_events = load_json_file(args.scim_log)

    terms = load_terminations(args.terminations)

    findings = []

    for t in terms:
        start = parse_time(t["termination_time_utc"])
        end = start + timedelta(minutes=int(t.get("deadline_minutes", args.sla_minutes)))

        source = t.get("evidence_source")
        identity = t["github_identity"]

        if source == "enterprise_audit_log":
            events = enterprise_events
            actions = ["business.remove_member","org.remove_member"]
        elif source == "scim_log":
            events = scim_events
            actions = ["external_identity.deprovision"]
        elif source == "security_log":
            events = security_events
            actions = t["expected_actions"].split("|")
        else:
            raise SystemExit(f"Invalid evidence_source: {source}")

        ev = match(events, identity, actions, start, end)

        findings.append({
            "user": identity,
            "source": source,
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
