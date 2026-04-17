#!/usr/bin/env python3
import argparse, csv, json, sys
from datetime import datetime, timedelta
from pathlib import Path

def load_json(path):
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
    return [json.loads(l) for l in raw.splitlines() if l.strip()]

def parse(t):
    return datetime.fromisoformat(t.replace("Z","+00:00"))

def match(events, identity, actions, start, end):
    for e in events:
        if e.get("action") not in actions:
            continue
        ts = e.get("created_at") or e.get("@timestamp")
        if not ts:
            continue
        ts = parse(ts)
        if not (start <= ts <= end):
            continue
        if identity.lower() in json.dumps(e).lower():
            return e
    return None

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--terminations")
    p.add_argument("--enterprise-audit-log")
    p.add_argument("--scim-log")
    p.add_argument("--sla-minutes", type=int, default=60)
    p.add_argument("--output")
    p.add_argument("--fail-on-gaps", action="store_true")
    args = p.parse_args()

    enterprise = load_json(args.enterprise_audit_log)
    scim = load_json(args.scim_log)

    rows = list(csv.DictReader(open(args.terminations)))

    findings = []

    for r in rows:
        start = parse(r["termination_time_utc"])
        end = start + timedelta(minutes=int(r.get("deadline_minutes", 60)))

        identity = r["github_identity"]
        source = r["evidence_source"]

        if source == "enterprise_audit_log":
            ev = match(enterprise, identity,
                ["org.remove_member","business.remove_member"], start, end)
        elif source == "scim_log":
            ev = match(scim, identity,
                ["external_identity.deprovision"], start, end)
        else:
            ev = None

        findings.append({
            "user": identity,
            "source": source,
            "compliant": bool(ev)
        })

    gaps = [f for f in findings if not f["compliant"]]

    report = {"summary": {"total": len(findings), "gaps": len(gaps)}, "findings": findings}

    json.dump(report, open(args.output, "w"), indent=2)
    print(json.dumps(report, indent=2))

    if args.fail_on_gaps and gaps:
        sys.exit(2)

if __name__ == "__main__":
    main()
