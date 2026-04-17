#!/usr/bin/env python3
import requests, os, json

OKTA_DOMAIN = os.getenv("OKTA_DOMAIN")
OKTA_TOKEN = os.getenv("OKTA_TOKEN")

def main():
    os.makedirs("data", exist_ok=True)

    if not OKTA_DOMAIN or not OKTA_TOKEN:
        print("OKTA not configured — writing empty SCIM log")
        with open("data/scim_log.json", "w") as f:
            json.dump([], f)
        return

    url = f"https://{OKTA_DOMAIN}/api/v1/logs"

    headers = {
        "Authorization": f"SSWS {OKTA_TOKEN}"
    }

    params = {
        "limit": 100,
        "filter": 'eventType eq "user.lifecycle.deactivate"'
    }

    r = requests.get(url, headers=headers, params=params)
    r.raise_for_status()

    events = r.json()

    normalized = []
    for e in events:
        normalized.append({
            "action": "external_identity.deprovision",
            "actor": e.get("actor", {}).get("alternateId"),
            "user": e.get("target", [{}])[0].get("alternateId"),
            "created_at": e.get("published")
        })

    with open("data/scim_log.json", "w") as f:
        json.dump(normalized, f, indent=2)

    print(f"Fetched {len(normalized)} SCIM events")

if __name__ == "__main__":
    main()
