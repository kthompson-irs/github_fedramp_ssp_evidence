#!/usr/bin/env python3

import os, sys, json, datetime as dt
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
        },
    )
    try:
        with urlopen(req) as r:
            return r.status, json.loads(r.read().decode())
    except HTTPError as e:
        return e.code, e.read().decode()

def fail(msg):
    print(f"ERROR: {msg}")
    sys.exit(1)

def warn(msg):
    print(f"WARN: {msg}")

def preflight():
    print("=== PREFLIGHT CHECK ===")

    if not ENTERPRISE:
        fail("GH_ENTERPRISE not set")

    if not TOKEN:
        fail("GH_ENTERPRISE_TOKEN not set")

    # 1. Enterprise metadata check
    status, data = call(f"/enterprises/{ENTERPRISE}")
    print("Enterprise metadata status:", status)

    if status == 404:
        fail("Enterprise slug invalid OR token cannot access enterprise")

    if status != 200:
        fail(f"Unexpected enterprise metadata response: {status}")

    print("Enterprise found:", data.get("slug"))

    # 2. Audit log check
    status, data = call(f"/enterprises/{ENTERPRISE}/audit-log?per_page=1")

    print("Audit log status:", status)

    if status == 404:
        fail("Token is NOT enterprise admin OR missing audit_log scope")

    if status == 403:
        fail("Token missing required permissions (audit_log)")

    if status != 200:
        fail(f"Unexpected audit log response: {status}")

    print("Audit log access confirmed")

def validate_ia11():
    path = os.getenv("IDP_POLICY_FILE")

    if not os.path.exists(path):
        warn("No IdP policy file found")
        return "WARN"

    data = json.load(open(path))

    timeout = data.get("session_timeout_minutes")
    reauth = data.get("reauth_required")
    mfa = data.get("mfa_required")

    print("IA-11 policy:", data)

    if timeout is None or reauth is None or mfa is None:
        warn("Incomplete IdP policy")
        return "WARN"

    if timeout > 15 or not reauth or not mfa:
        fail("IA-11 violation detected")

    return "PASS"

def main():
    preflight()

    status = validate_ia11()

    os.makedirs(OUTPUT, exist_ok=True)

    report = {
        "enterprise": ENTERPRISE,
        "timestamp": dt.datetime.utcnow().isoformat(),
        "ia11_status": status,
    }

    with open(f"{OUTPUT}/ia_enterprise_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print("FINAL STATUS:", status)

if __name__ == "__main__":
    main()
