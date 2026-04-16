#!/usr/bin/env python3
"""
FedRAMP IA-2(8) Enterprise Audit Log Evidence Collector
"""

from __future__ import annotations
import requests, jwt, time, os, json, datetime as dt
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict

@dataclass
class Config:
    app_id: str
    private_key: str
    enterprise: str
    api: str = "https://api.github.com"
    version: str = "2022-11-28"
    days: int = 30

def now():
    return dt.datetime.now(dt.timezone.utc)

def jwt_token(cfg):
    payload = {"iat": int(time.time()) - 60, "exp": int(time.time()) + 600, "iss": cfg.app_id}
    return jwt.encode(payload, cfg.private_key, algorithm="RS256")

def gh_request(cfg, method, path, token=None, params=None):
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": cfg.version,
    }
    headers["Authorization"] = f"Bearer {token}" if token else f"Bearer {jwt_token(cfg)}"
    r = requests.request(method, cfg.api + path, headers=headers, params=params)
    return r

def get_installation_id(cfg):
    installs = gh_request(cfg, "GET", "/app/installations").json()
    for i in installs:
        if str(i.get("target_type","")).lower() == "enterprise":
            return i["id"]
    raise Exception("No enterprise installation found")

def get_installation_token(cfg, inst_id):
    r = gh_request(cfg, "POST", f"/app/installations/{inst_id}/access_tokens")
    return r.json()["token"]

def preflight(cfg, token):
    r = gh_request(cfg, "GET", f"/enterprises/{cfg.enterprise}/audit-log",
                   token, {"per_page":1})
    if r.status_code == 200:
        return
    raise Exception(f"Preflight failed: {r.text}")

def collect(cfg):
    inst = get_installation_id(cfg)
    token = get_installation_token(cfg, inst)

    preflight(cfg, token)

    events: List[Dict] = []
    today = now().date()

    for i in range(cfg.days):
        day = today - dt.timedelta(days=i)
        r = gh_request(
            cfg,
            "GET",
            f"/enterprises/{cfg.enterprise}/audit-log",
            token,
            {"phrase": f"created:{day}..{day}", "per_page": 100}
        )
        if r.status_code != 200:
            raise Exception(r.text)
        events.extend(r.json())

    out = Path("artifacts")
    out.mkdir(exist_ok=True)

    (out / "enterprise_audit_log.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events)
    )

    (out / "summary.json").write_text(json.dumps({
        "enterprise": cfg.enterprise,
        "count": len(events),
        "collected": now().isoformat()
    }, indent=2))

    return out

def main():
    cfg = Config(
        app_id=os.environ["GH_APP_ID"],
        private_key=os.environ["GH_APP_PRIVATE_KEY"],
        enterprise=os.environ["GH_ENTERPRISE"],
        days=int(os.environ.get("SINCE_DAYS", "30")),
    )
    out = collect(cfg)
    print(out)

if __name__ == "__main__":
    main()
