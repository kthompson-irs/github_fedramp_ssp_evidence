#!/usr/bin/env python3
"""FedRAMP IA-2(8) Enterprise Audit Log Evidence Collector"""

from __future__ import annotations

import csv
import datetime as dt
import json
import os
import random
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import jwt
import requests


CONTROL_MAP: Dict[str, List[str]] = {
    "enterprise_installation.json": ["IA-2(8)", "AC-2"],
    "enterprise_audit_log.jsonl": ["IA-2(8)", "AU-2", "AU-6", "AU-12"],
    "enterprise_audit_log.csv": ["IA-2(8)", "AU-2", "AU-6", "AU-12"],
    "summary.json": ["IA-2(8)", "AC-2", "AU-2"],
    "control_map.json": ["IA-2(8)", "AC-2", "AU-2"],
    "manifest.md": ["IA-2(8)"],
}


@dataclass
class GitHubConfig:
    app_id: str
    private_key: str
    enterprise: str
    api_url: str = "https://api.github.com"
    api_version: str = "2022-11-28"
    days: int = 90


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def normalize_audit_event(event: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "created_at": event.get("created_at"),
        "action": event.get("action"),
        "actor": event.get("actor"),
        "org": event.get("org"),
        "repo": event.get("repo"),
        "raw": event,
    }


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    with path.open("w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        return
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


class GitHubAppAuthenticator:
    def __init__(self, cfg: GitHubConfig):
        self.cfg = cfg

    def jwt_token(self) -> str:
        now = int(time.time())
        payload = {"iat": now - 60, "exp": now + 600, "iss": self.cfg.app_id}
        return jwt.encode(payload, self.cfg.private_key, algorithm="RS256")

    def headers(self):
        return {
            "Authorization": f"Bearer {self.jwt_token()}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": self.cfg.api_version,
        }

    def get(self, path):
        return requests.get(self.cfg.api_url + path, headers=self.headers())

    def paginate(self, path):
        page = 1
        while True:
            r = requests.get(
                self.cfg.api_url + path,
                headers=self.headers(),
                params={"per_page": 100, "page": page},
            )
            if r.status_code >= 400:
                raise RuntimeError(r.text)
            data = r.json()
            if not data:
                break
            for item in data:
                yield item
            if 'rel="next"' not in r.headers.get("Link", ""):
                break
            page += 1

    def get_installation_id(self) -> int:
        installations = list(self.paginate("/app/installations"))

        enterprise_installs = [
            i for i in installations
            if str(i.get("target_type", "")).lower() == "enterprise"
        ]

        if len(enterprise_installs) == 1:
            return enterprise_installs[0]["id"]

        raise RuntimeError(f"No enterprise installation found. Visible: {installations}")

    def get_installation_token(self, installation_id: int) -> str:
        r = requests.post(
            f"{self.cfg.api_url}/app/installations/{installation_id}/access_tokens",
            headers=self.headers(),
        )
        if r.status_code >= 400:
            raise RuntimeError(r.text)
        return r.json()["token"]


class GitHubClient:
    def __init__(self, cfg: GitHubConfig, token: str):
        self.cfg = cfg
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        }

    def get(self, path, params=None):
        r = requests.get(self.cfg.api_url + path, headers=self.headers, params=params)
        if r.status_code >= 400:
            raise RuntimeError(r.text)
        return r.json()


def collect(cfg: GitHubConfig) -> Path:
    auth = GitHubAppAuthenticator(cfg)
    inst_id = auth.get_installation_id()
    token = auth.get_installation_token(inst_id)

    client = GitHubClient(cfg, token)

    output = Path(f"enterprise_evidence_{int(time.time())}")
    output.mkdir()

    events = []
    today = utc_now().date()

    for i in range(cfg.days):
        day = today - dt.timedelta(days=i)
        data = client.get(
            f"/enterprises/{cfg.enterprise}/audit-log",
            params={"phrase": f"created:{day}..{day}"},
        )
        for e in data:
            events.append(normalize_audit_event(e))

    write_jsonl(output / "enterprise_audit_log.jsonl", events)
    write_csv(output / "enterprise_audit_log.csv", events)

    write_json(output / "enterprise_installation.json", {"installation_id": inst_id})

    summary = {
        "enterprise": cfg.enterprise,
        "event_count": len(events),
        "collected_at": utc_now().isoformat(),
    }
    write_json(output / "summary.json", summary)

    return output


def main():
    cfg = GitHubConfig(
        app_id=os.environ["GH_APP_ID"],
        private_key=os.environ["GH_APP_PRIVATE_KEY"],
        enterprise=os.environ["GH_ENTERPRISE"],
        days=int(os.environ.get("GH_DAYS", "90")),
    )

    out = collect(cfg)
    print(out)


if __name__ == "__main__":
    main()
