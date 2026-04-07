#!/usr/bin/env python3
"""FedRAMP IA-2(8) Evidence Collector with permission debugging"""

from __future__ import annotations

import csv
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


@dataclass
class GitHubConfig:
    app_id: str
    private_key: str
    org: str
    api_url: str = "https://api.github.com"
    api_version: str = "2022-11-28"
    enterprise: Optional[str] = None
    days: int = 90
    timeout: int = 30
    request_delay_seconds: float = 0.25
    max_retries: int = 5
    max_rate_limit_sleep_seconds: int = 3600


class GitHubAppAuthenticator:
    def __init__(self, cfg: GitHubConfig) -> None:
        self.cfg = cfg
        self.session = requests.Session()

    def _url(self, path: str) -> str:
        return self.cfg.api_url.rstrip("/") + "/" + path.lstrip("/")

    def _jwt_token(self) -> str:
        now = int(time.time())
        payload = {
            "iat": now - 60,
            "exp": now + 540,
            "iss": self.cfg.app_id,
        }
        return jwt.encode(payload, self.cfg.private_key, algorithm="RS256")

    def request(self, method: str, path: str) -> requests.Response:
        return self.session.request(
            method,
            self._url(path),
            headers={
                "Authorization": f"Bearer {self._jwt_token()}",
                "Accept": "application/vnd.github+json",
            },
            timeout=self.cfg.timeout,
        )

    def get_installation_id(self) -> int:
        resp = self.request("GET", f"/orgs/{self.cfg.org}/installation")
        if resp.status_code >= 400:
            raise RuntimeError(f"Installation lookup failed: {resp.text}")
        return resp.json()["id"]

    def get_installation_token(self, installation_id: int) -> str:
        resp = self.request("POST", f"/app/installations/{installation_id}/access_tokens")
        if resp.status_code >= 400:
            raise RuntimeError(f"Token creation failed: {resp.text}")
        return resp.json()["token"]


class GitHubClient:
    def __init__(self, cfg: GitHubConfig, token: str):
        self.cfg = cfg
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": cfg.api_version,
        })

    def _url(self, path: str) -> str:
        return self.cfg.api_url.rstrip("/") + "/" + path.lstrip("/")

    def _debug_headers(self, resp: requests.Response, path: str):
        print("\n=== DEBUG: API FAILURE ===", file=sys.stderr)
        print(f"Endpoint: {path}", file=sys.stderr)
        print(f"Status: {resp.status_code}", file=sys.stderr)

        print("X-Accepted-GitHub-Permissions:",
              resp.headers.get("X-Accepted-GitHub-Permissions"),
              file=sys.stderr)

        print("X-OAuth-Scopes:",
              resp.headers.get("X-OAuth-Scopes"),
              file=sys.stderr)

        print("Response:",
              resp.text[:500],
              file=sys.stderr)

        print("=== END DEBUG ===\n", file=sys.stderr)

    def request(self, path: str, params=None):
        for attempt in range(self.cfg.max_retries + 1):
            time.sleep(self.cfg.request_delay_seconds)
            resp = self.session.get(self._url(path), params=params)

            if resp.status_code == 200:
                return resp

            if resp.status_code in (403, 404):
                self._debug_headers(resp, path)

            if resp.status_code in (403, 429):
                reset = resp.headers.get("X-RateLimit-Reset")
                if reset:
                    sleep_time = max(int(reset) - int(time.time()), 60)
                else:
                    sleep_time = min((2**attempt) * 60, self.cfg.max_rate_limit_sleep_seconds)
                time.sleep(sleep_time)
                continue

            raise RuntimeError(f"{path} failed: {resp.status_code} {resp.text}")

        raise RuntimeError(f"{path} exceeded retries")

    def paginate(self, path: str, params=None):
        params = dict(params or {})
        params["per_page"] = 100
        page = 1

        while True:
            params["page"] = page
            resp = self.request(path, params=params)
            data = resp.json()

            if not data:
                break

            for item in data:
                yield item

            if 'rel="next"' not in resp.headers.get("Link", ""):
                break

            page += 1


def iso_date_days_ago(days: int) -> str:
    return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).date().isoformat()


def collect(cfg: GitHubConfig) -> Path:
    auth = GitHubAppAuthenticator(cfg)
    installation_id = auth.get_installation_id()
    token = auth.get_installation_token(installation_id)

    client = GitHubClient(cfg, token)

    stamp = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    out = Path(f"github_ia208_evidence_{stamp}")
    out.mkdir()

    org = client.request(f"/orgs/{cfg.org}").json()
    (out / "org.json").write_text(json.dumps(org, indent=2))

    # --- DEBUG TARGET ENDPOINTS ---
    print("Checking credential-authorizations...", file=sys.stderr)
    cred_auths = list(client.paginate(f"/orgs/{cfg.org}/credential-authorizations"))

    print("Checking installations...", file=sys.stderr)
    installations = list(client.paginate(f"/orgs/{cfg.org}/installations"))

    print("Checking audit-log...", file=sys.stderr)
    audit = list(
        client.paginate(
            f"/orgs/{cfg.org}/audit-log",
            params={"include": "all", "phrase": f"created:>={iso_date_days_ago(cfg.days)}"},
        )
    )

    with open(out / "audit_log.jsonl", "w") as f:
        for e in audit:
            f.write(json.dumps(e) + "\n")

    return out


def main():
    app_id = os.environ.get("GH_APP_ID")
    key = os.environ.get("GH_APP_PRIVATE_KEY")
    org = os.environ.get("GH_ORG")

    if not app_id or not key or not org:
        print("Set GH_APP_ID, GH_APP_PRIVATE_KEY, GH_ORG", file=sys.stderr)
        return 2

    cfg = GitHubConfig(
        app_id=app_id,
        private_key=key,
        org=org,
        api_url=os.environ.get("GH_API_URL", "https://api.github.com"),
        api_version=os.environ.get("GH_API_VERSION", "2022-11-28"),
        days=int(os.environ.get("GH_DAYS", "90")),
        request_delay_seconds=float(os.environ.get("GH_REQUEST_DELAY_SECONDS", "0.25")),
        max_retries=int(os.environ.get("GH_MAX_RETRIES", "5")),
        max_rate_limit_sleep_seconds=int(os.environ.get("GH_MAX_RATE_LIMIT_SLEEP_SECONDS", "3600")),
    )

    output = collect(cfg)
    print(output)


if __name__ == "__main__":
    sys.exit(main())
