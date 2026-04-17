#!/usr/bin/env python3

import os
import sys
import json
import datetime as dt
from urllib.request import Request, urlopen
from urllib.error import HTTPError

API = os.getenv("GH_API_URL", "https://api.github.com")
ENTERPRISE = os.getenv("GH_ENTERPRISE")
TOKEN = os.getenv("GH_ENTERPRISE_TOKEN")
OUTPUT = os.getenv("OUTPUT_DIR", "artifacts")

def call(path):
    req = Request(
        f"{API}{path}",
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urlopen(req) as r:
            body = r.read().decode()
            try:
                return r.status, json.loads(body)
            except Exception:
                return r.status, body
    except HTTPError as e:
        raw = e.read().decode(errors="replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw

def fail(msg):
    print(f"ERROR: {msg}")
    sys.exit(1)

def warn(msg):
    print(f"WARN: {msg}")

def preflight():
    print("\n=== PREFLIGHT CHECK ===")

    if not ENTERPRISE:
        fail("GH_ENTERPRISE not set")

    if not TOKEN:
        fail("GH_ENTERPRISE_TOKEN not set")

    status, user = call("/user")
    print("Authenticated user status:", status)

    if status != 200:
        fail(f"Unable to read authenticated user: {user}")

    login = user.get("login") if isinstance(user, dict) else None
    print("Authenticated login:", login)

    status, logs = call(f"/enterprises/{ENTERPRISE}/audit-log?per_page=1&include=all&order=desc")
    print("Audit log status:", status)

    if status == 200:
        print("Audit log access confirmed")
        return

    if status == 404:
        fail("Token cannot access this enterprise audit log, or the enterprise slug is wrong for this token.")
    if status == 403:
        fail("Token is missing audit_log permission or SSO authorization.")
    fail(f"Unexpected audit log response: {status} -> {logs}")

def validate_ia11():
    path = os.getenv("IDP_POLICY_FILE")

    if not path or not os.path.exists(path):
        warn("No IdP policy file found")
        return "WARN"

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    timeout = data.get("session_timeout_minutes")
    reauth = data.get("reauth_required")
    mfa = data.get("mfa_required")

    print("\n=== IA-11 POLICY ===")
    print(json.dumps(data, indent=2))

    if timeout is None or reauth is None or mfa is None:
        warn("Incomplete IdP policy")
        return "WARN"

    if timeout > 15:
        fail("IA-11 FAIL: session timeout > 15 minutes")

    if not reauth:
        fail("IA-11 FAIL: reauthentication not enforced")

    if not mfa:
        fail("IA-11 FAIL: MFA not enforced")

    return "PASS"

def write_report(status):
    os.makedirs(OUTPUT, exist_ok=True)
    report = {
        "enterprise": ENTERPRISE,
        "timestamp": dt.datetime.utcnow().isoformat(),
        "ia11_status": status
    }
    with open(f"{OUTPUT}/ia_enterprise_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    with open(f"{OUTPUT}/ia_enterprise_report.md", "w", encoding="utf-8") as f:
        f.write("# IA-11 Enterprise Report\n\n")
        f.write(f"Enterprise: `{ENTERPRISE}`\n\n")
        f.write(f"Status: **{status}**\n")

def main():
    preflight()
    ia11_status = validate_ia11()
    write_report(ia11_status)
    print("\n=== FINAL STATUS ===")
    print(ia11_status)

if __name__ == "__main__":
    main()
