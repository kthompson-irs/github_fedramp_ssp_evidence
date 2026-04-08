#!/usr/bin/env python3
"""FedRAMP IA-2(8) Evidence Collector (timeout-safe version)"""

from __future__ import annotations

import datetime as dt
import json
import os
import random
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import jwt
import requests


# 🔥 NEW LIMITS (prevent timeout)
MAX_AUDIT_PAGES = int(os.environ.get("GH_MAX_AUDIT_PAGES", "25"))
MAX_AUDIT_EVENTS = int(os.environ.get("GH_MAX_AUDIT_EVENTS", "2000"))


@dataclass
class GitHubConfig:
    app_id: str
    private_key: str
    org: str
    api_url: str = "https://api.github.com"
    api_version: str = "2022-11-28"
    days: int = 90
    request_delay_seconds: float = 0.25


class GitHubAppAuthenticator:
    def __init__(self, cfg: GitHubConfig):
        self.cfg = cfg

    def _jwt(self):
        now = int(time.time())
        return jwt.encode(
            {"iat": now - 60, "exp": now + 540, "iss": self.cfg.app_id},
            self.cfg.private_key,
            algorithm="RS256",
        )

    def request(self, method, path):
        return requests.request(
            method,
            f"{self.cfg.api_url}{path}",
            headers={
                "Authorization": f"Bearer {self._jwt()}",
                "Accept": "application/vnd.github+json",
            },
        )

    def get_installation_token(self):
        inst = self.request("GET", f"/orgs/{self.cfg.org}/installation").json()
        token = self.request(
            "POST", f"/app/installations/{inst['id']}/access_tokens"
        ).json()
        return token["token"]


class GitHubClient:
    def __init__(self, cfg: GitHubConfig, token: str):
        self.cfg = cfg
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        })

    def get(self, path, params=None):
        time.sleep(self.cfg.request_delay_seconds)
        resp = self.session.get(f"{self.cfg.api_url}{path}", params=params)

        if resp.status_code != 200:
            print(f"\nDEBUG FAIL: {path}", file=sys.stderr)
            print("Status:", resp.status_code, file=sys.stderr)
            print("Permissions:",
                  resp.headers.get("X-Accepted-GitHub-Permissions"),
                  file=sys.stderr)
            print("Body:", resp.text[:300], file=sys.stderr)

        resp.raise_for_status()
        return resp


def iso_date(days):
    return (dt.datetime.utcnow() - dt.timedelta(days=days)).date().isoformat()


def collect(cfg: GitHubConfig) -> Path:
    auth = GitHubAppAuthenticator(cfg)
    token = auth.get_installation_token()
    client = GitHubClient(cfg, token)

    out = Path(f"github_ia208_evidence_{int(time.time())}")
    out.mkdir()

    # org
    org = client.get(f"/orgs/{cfg.org}").json()
    (out / "org.json").write_text(json.dumps(org, indent=2))

    # 🔥 audit log (LIMITED)
    audit_events = []
    page = 1

    while page <= MAX_AUDIT_PAGES:
        resp = client.get(
            f"/orgs/{cfg.org}/audit-log",
            params={
                "include": "all",
                "per_page": 50,  # 🔥 reduced from 100
                "page": page,
                "phrase": f"created:>={iso_date(cfg.days)}",
            },
        )

        data = resp.json()

        if not data:
            break

        audit_events.extend(data)

        print(f"Fetched page {page} ({len(data)} events)", file=sys.stderr)

        # 🔥 stop if too many events
        if len(audit_events) >= MAX_AUDIT_EVENTS:
            print("Stopping early (event cap reached)", file=sys.stderr)
            break

        if 'rel="next"' not in resp.headers.get("Link", ""):
            break

        page += 1

    # write output
    with open(out / "audit_log.jsonl", "w") as f:
        for e in audit_events:
            f.write(json.dumps(e) + "\n")

    return out


def main():
    cfg = GitHubConfig(
        app_id=os.environ["GH_APP_ID"],
        private_key=os.environ["GH_APP_PRIVATE_KEY"],
        org=os.environ["GH_ORG"],
        days=int(os.environ.get("GH_DAYS", "30")),  # 🔥 default reduced
    )

    out = collect(cfg)
    print(out)


if __name__ == "__main__":
    main()
