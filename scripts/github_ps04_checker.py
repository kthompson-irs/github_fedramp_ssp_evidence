#!/usr/bin/env python3
import argparse, csv, json, sys
from datetime import datetime, timedelta
from pathlib import Path

# ---------- Helpers ----------

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

def parse_time(t):
    return datetime.fromisoformat(t.replace("Z", "+00:00"))

# ---------- Improved Identity Matching ----------

def identity_matches(event, identity):
    identity = identity.lower()

    candidates = [
        str(event.get("user", "")).lower(),
        str(event.get("actor", "")).lower(),
        str(event.get("username", "")).lower(),
        str(event.get("login", "")).lower(),
        str(event.get("email", "")).lower(),
    ]

    return any(
        identity == c or identity in c or c in identity
        for c in candidates if c
    )

# ---------- Event Matching ----------

def match(events, identity, actions, start, end):
    for e in events:
        if e.get("action") not in actions:
            continue

        ts = e.get("created_at") or e.get("@timestamp")
        if not ts:
            continue

        ts = parse_time(ts)

        if not (start <= ts <= end):
            continue

        if not identity_matches(e, identity):
            continue

        return e

    return None

# ---------- Main ----------

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--terminations", required=True)
    p.add_argument("--enterprise-audit-log")
    p.add_argument("--scim-log")
    p.add_argument("--sla-minutes", type=int, default=60)
    p.add_argument("--output", required=True)
    p.add_argument("--fail-on-gaps", action="store_true")
    args = p.parse_args()

    enterprise_events = load_json(args.enterprise_audit_log)
    scim_events = load_json(args.scim_log)

    rows = list(csv.DictReader(open(args.terminations)))

    findings = []

    for r in rows:
        start = parse_time(r["termination_time_utc"])
        deadline = start + timedelta(minutes=int(r.get("deadline_minutes", args.sla_minutes)))

        identity = r["github_identity"]
        source = r["evidence_source"]

        if source == "enterprise_audit_log":
            ev = match(
                enterprise_events,
                identity,
                ["org.remove_member", "business.remove_member"],
                start,
                deadline
            )

        elif source == "scim_log":
            ev = match(
                scim_events,
                identity,
                ["external_identity.deprovision"],
                start,
                deadline
            )

        else:
            raise SystemExit(f"Invalid evidence_source: {source}")

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
