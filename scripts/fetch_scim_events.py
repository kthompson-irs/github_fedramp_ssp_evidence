#!/usr/bin/env python3
import requests, os, json

OKTA_DOMAIN = os.environ["OKTA_DOMAIN"]
OKTA_TOKEN = os.environ["OKTA_TOKEN"]

def fetch():
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
    return r.json()

def main():
    events = fetch()

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
