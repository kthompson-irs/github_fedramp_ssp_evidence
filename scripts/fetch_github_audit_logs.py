#!/usr/bin/env python3
import requests, os, json, datetime

ENTERPRISE = os.environ["GH_ENTERPRISE_SLUG"]
TOKEN = os.environ["GH_AUDIT_TOKEN"]

def fetch():
    url = f"https://api.github.com/enterprises/{ENTERPRISE}/audit-log"
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/vnd.github+json"
    }

    params = {
        "per_page": 100
    }

    r = requests.get(url, headers=headers, params=params)
    r.raise_for_status()
    return r.json()

def main():
    events = fetch()

    with open("data/enterprise_audit_log.json", "w") as f:
        json.dump(events, f, indent=2)

    print(f"Fetched {len(events)} audit events")

if __name__ == "__main__":
    main()
