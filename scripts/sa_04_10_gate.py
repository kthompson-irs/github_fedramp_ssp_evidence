#!/usr/bin/env python3

import os
import sys
import requests

GH_API = "https://api.github.com"

def get_headers():
    token = os.getenv("GH_TOKEN")
    if not token:
        print("ERROR: GH_TOKEN not set")
        sys.exit(1)

    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json"
    }

def get_repo():
    repo = os.getenv("GH_REPO")
    if not repo:
        print("ERROR: GH_REPO not set")
        sys.exit(1)
    return repo

def check_code_scanning(repo, headers):
    print("\nChecking Code Scanning Alerts (CodeQL)...")
    url = f"{GH_API}/repos/{repo}/code-scanning/alerts"
    params = {"state": "open"}

    resp = requests.get(url, headers=headers, params=params)
    resp.raise_for_status()

    alerts = resp.json()
    failures = 0

    for alert in alerts:
        severity = alert.get("rule", {}).get("severity", "").lower()
        if severity in ["high", "critical"]:
            print(f"FAIL: CodeQL alert - {alert.get('rule', {}).get('id')} ({severity})")
            failures += 1

    return failures

def check_dependabot(repo, headers):
    print("\nChecking Dependabot Alerts...")
    url = f"{GH_API}/repos/{repo}/dependabot/alerts"
    params = {"state": "open"}

    resp = requests.get(url, headers=headers, params=params)
    resp.raise_for_status()

    alerts = resp.json()
    failures = 0

    for alert in alerts:
        severity = alert.get("security_advisory", {}).get("severity", "").lower()
        if severity in ["high", "critical"]:
            print(f"FAIL: Dependabot alert - {alert.get('dependency', {}).get('package', {}).get('name')} ({severity})")
            failures += 1

    return failures

def check_secret_scanning(repo, headers):
    print("\nChecking Secret Scanning Alerts...")
    url = f"{GH_API}/repos/{repo}/secret-scanning/alerts"
    params = {"state": "open"}

    resp = requests.get(url, headers=headers, params=params)
    resp.raise_for_status()

    alerts = resp.json()

    if alerts:
        for alert in alerts:
            print(f"FAIL: Secret exposed - {alert.get('secret_type')}")
        return len(alerts)

    return 0

def main():
    headers = get_headers()
    repo = get_repo()

    total_failures = 0

    total_failures += check_code_scanning(repo, headers)
    total_failures += check_dependabot(repo, headers)
    total_failures += check_secret_scanning(repo, headers)

    print("\n============================")
    if total_failures > 0:
        print(f"SA-04(10) FAILED: {total_failures} issues found")
        sys.exit(1)
    else:
        print("SA-04(10) PASSED: No blocking security issues")
        sys.exit(0)

if __name__ == "__main__":
    main()
