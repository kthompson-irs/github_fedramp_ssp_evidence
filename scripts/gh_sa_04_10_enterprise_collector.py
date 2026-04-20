#!/usr/bin/env python3
"""
Enterprise SA-04(10) Collector
(New version — does not overwrite legacy script)
"""

import os
import json
import requests
from datetime import datetime
from pathlib import Path

API = "https://api.github.com"

def headers(token):
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json"
    }

def get_enterprise_dependabot(ent, token):
    url = f"{API}/enterprises/{ent}/dependabot/alerts"
    r = requests.get(url, headers=headers(token))
    if r.status_code != 200:
        return [], f"{r.status_code}: {r.text[:200]}"
    return r.json(), None

def write_history(output_dir, snapshot):
    hist_dir = Path(output_dir) / "history"
    hist_dir.mkdir(parents=True, exist_ok=True)

    with open(hist_dir / "history.jsonl", "a") as f:
        f.write(json.dumps(snapshot) + "\n")

    with open(hist_dir / f"{snapshot['date']}.json", "w") as f:
        json.dump(snapshot, f, indent=2)

def main():
    scope = os.getenv("GH_ALERT_SCOPE", "enterprise")
    repo = os.getenv("GH_REPOSITORY")
    enterprise = os.getenv("GH_ENTERPRISE_SLUG")
    token = os.getenv("GH_ENTERPRISE_TOKEN")

    now = datetime.utcnow().isoformat() + "Z"
    date = now[:10]

    dependabot, error = get_enterprise_dependabot(enterprise, token)

    results = {
        "dependabot": {
            "count": len(dependabot),
            "blocking_count": len(dependabot)
        }
    }

    snapshot = {
        "generated_at": now,
        "date": date,
        "scope": scope,
        "repository": repo,
        "enterprise": enterprise,
        "results": results,
        "blocking_findings": dependabot,
        "errors": [error] if error else [],
        "overall": {
            "blocking_count": len(dependabot),
            "error_count": 1 if error else 0,
            "status": "fail" if dependabot else "pass"
        }
    }

    Path("artifacts/sa-04-10").mkdir(parents=True, exist_ok=True)

    with open("artifacts/sa-04-10/summary.json", "w") as f:
        json.dump(snapshot, f, indent=2)

    write_history("artifacts/sa-04-10", snapshot)

    print("Enterprise snapshot complete")

if __name__ == "__main__":
    main()
