#!/usr/bin/env python3
import requests, os, json

ENTERPRISE = os.getenv("GH_ENTERPRISE_SLUG")
TOKEN = os.getenv("GH_AUDIT_TOKEN")

def main():
    if not ENTERPRISE or not TOKEN:
        raise SystemExit("Missing GitHub credentials")

    url = f"https://api.github.com/enterprises/{ENTERPRISE}/audit-log"

    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/vnd.github+json"
    }

    r = requests.get(url, headers=headers, params={"per_page": 100})
    r.raise_for_status()

    events = r.json()

    os.makedirs("data", exist_ok=True)

    with open("data/enterprise_audit_log.json", "w") as f:
        json.dump(events, f, indent=2)

    print(f"Fetched {len(events)} GitHub audit events")

if __name__ == "__main__":
    main()
