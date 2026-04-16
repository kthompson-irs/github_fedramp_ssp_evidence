#!/usr/bin/env python3

"""
IA-11 FedRAMP evidence collector for GitHub.com organizations.

Environment variables:
- GH_ORG
- GH_TOKEN
- GH_API_URL
- OUTPUT_DIR
- SINCE_DAYS
"""

import argparse
import datetime as dt
import json
import os
import sys
from collections import Counter
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.parse import urlencode


AUTH_RELATED_ACTIONS = {
    "user.login",
    "org.sso_response",
    "org.saml_authentication",
    "personal_access_token.create",
    "oauth_authorization.create",
}


def utc_now():
    return dt.datetime.now(dt.timezone.utc)


def api_get(url, token):
    req = Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
    )
    with urlopen(req) as resp:
        return json.loads(resp.read().decode())


def build_url(base, path, params=None):
    url = f"{base.rstrip('/')}/{path.lstrip('/')}"
    if params:
        url += "?" + urlencode(params)
    return url


def fetch_org(api, token, org):
    return api_get(build_url(api, f"orgs/{org}"), token)


def fetch_logs(api, token, org):
    return api_get(build_url(api, f"orgs/{org}/audit-log"), token)


def summarize(events):
    actions = [e.get("action") for e in events]
    counts = Counter(actions)

    return {
        "total_events": len(events),
        "login_events": counts.get("user.login", 0),
        "sso_events": counts.get("org.sso_response", 0),
    }


def evaluate(org_meta, summary):
    status = "PASS"
    notes = []

    if not org_meta.get("two_factor_requirement_enabled"):
        status = "FAIL"
        notes.append("MFA not enforced")

    if summary["login_events"] == 0:
        status = "WARN"
        notes.append("No login events detected")

    return status, notes


def write_report(outdir, org, org_meta, summary, status, notes):
    Path(outdir).mkdir(exist_ok=True)

    report = {
        "control": "IA-11",
        "org": org,
        "generated": utc_now().isoformat(),
        "status": status,
        "summary": summary,
        "notes": notes,
    }

    with open(f"{outdir}/ia11_report.json", "w") as f:
        json.dump(report, f, indent=2)

    with open(f"{outdir}/ia11_report.md", "w") as f:
        f.write(f"# IA-11 Report\n\nStatus: **{status}**\n\n")
        for n in notes:
            f.write(f"- {n}\n")


def main():
    org = os.getenv("GH_ORG")
    token = os.getenv("GH_TOKEN")
    api = os.getenv("GH_API_URL", "https://api.github.com")
    outdir = os.getenv("OUTPUT_DIR", "artifacts")

    if not org or not token:
        print("Missing GH_ORG or GH_TOKEN")
        sys.exit(1)

    org_meta = fetch_org(api, token, org)
    events = fetch_logs(api, token, org)

    summary = summarize(events)
    status, notes = evaluate(org_meta, summary)

    write_report(outdir, org, org_meta, summary, status, notes)

    print(f"Status: {status}")
    sys.exit(1 if status == "FAIL" else 0)


if __name__ == "__main__":
    main()
