#!/usr/bin/env python3
"""Collect FedRAMP evidence for GitHub.com IA-2(8) and adjacent controls.

This version is tuned to avoid hammering the API:
- Uses a GitHub App installation token end-to-end.
- Sends requests serially.
- Sleeps briefly before each request.
- Honors Retry-After and x-ratelimit-reset.
- Uses bounded retries with exponential backoff.
- Keeps the audit-log window narrow via GITHUB_DAYS.

Outputs a timestamped folder containing:
- org.json
- audit_log.jsonl
- audit_log.csv
- credential_authorizations.json
- installations.json
- summary.json
- manifest.md

Required env vars:
- GITHUB_APP_ID: GitHub App ID
- GITHUB_APP_PRIVATE_KEY: GitHub App private key in PEM format
- GITHUB_ORG: organization name

Optional env vars:
- GITHUB_API_URL: default https://api.github.com
- GITHUB_API_VERSION: default 2022-11-28
- GITHUB_DAYS: default 90
- GITHUB_REQUEST_DELAY_SECONDS: default 0.25
- GITHUB_MAX_RETRIES: default 5
- GITHUB_MAX_RATE_LIMIT_SLEEP_SECONDS: default 3600
"""
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
    days: int = 90
    timeout: int = 30
    request_delay_seconds: float = 0.25
    max_retries: int = 5
    max_rate_limit_sleep_seconds: int = 3600


class GitHubAppAuthenticator:
    def __init__(self, cfg: GitHubConfig) -> None:
        self.cfg = cfg
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": cfg.api_version,
                "User-Agent": "fedramp-ia208-evidence-collector/3.0",
            }
        )

    def _url(self, path_or_url: str) -> str:
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            return path_or_url
        return self.cfg.api_url.rstrip("/") + "/" + path_or_url.lstrip("/")

    def _jwt_token(self) -> str:
        now = int(time.time())
        payload = {
            "iat": now - 60,
            "exp": now + 540,
            "iss": self.cfg.app_id,
        }
        return jwt.encode(payload, self.cfg.private_key, algorithm="RS256")

    def request(
        self,
        method: str,
        path_or_url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> requests.Response:
        headers = dict(self.session.headers)
        headers["Authorization"] = f"Bearer {self._jwt_token()}"
        url = self._url(path_or_url)
        resp = self.session.request(
            method,
            url,
            headers=headers,
            params=params,
            json=json_body,
            timeout=self.cfg.timeout,
        )
        return resp

    def get_installation_id(self) -> int:
        resp = self.request("GET", f"/orgs/{self.cfg.org}/installation")
        if resp.status_code == 404:
            raise RuntimeError(
                f"Could not find a GitHub App installation for organization '{self.cfg.org}'. "
                f"Make sure the app is installed on that org. Response: {resp.text[:400]}"
            )
        if resp.status_code >= 400:
            raise RuntimeError(
                f"GET /orgs/{self.cfg.org}/installation failed: {resp.status_code} {resp.text[:400]}"
            )
        data = resp.json()
        installation_id = data.get("id")
        if not installation_id:
            raise RuntimeError(f"Installation lookup returned no id: {data}")
        return int(installation_id)

    def get_installation_token(self, installation_id: int) -> str:
        resp = self.request("POST", f"/app/installations/{installation_id}/access_tokens", json_body={})
        if resp.status_code >= 400:
            raise RuntimeError(
                f"POST /app/installations/{installation_id}/access_tokens failed: "
                f"{resp.status_code} {resp.text[:400]}"
            )
        data = resp.json()
        token = data.get("token")
        if not token:
            raise RuntimeError(f"Installation token response did not include token: {data}")
        return token


class GitHubClient:
    def __init__(self, cfg: GitHubConfig, token: str) -> None:
        self.cfg = cfg
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": cfg.api_version,
                "User-Agent": "fedramp-ia208-evidence-collector/3.0",
            }
        )

    def _url(self, path_or_url: str) -> str:
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            return path_or_url
        return self.cfg.api_url.rstrip("/") + "/" + path_or_url.lstrip("/")

    def _sleep_before_request(self) -> None:
        delay = self.cfg.request_delay_seconds
        if delay > 0:
            time.sleep(delay + random.uniform(0.0, min(0.25, delay)))

    def _is_rate_limit_response(self, resp: requests.Response) -> bool:
        if resp.status_code == 429:
            return True
        if resp.status_code != 403:
            return False
        text = (resp.text or "").lower()
        if "rate limit" in text:
            return True
        if resp.headers.get("Retry-After"):
            return True
        if resp.headers.get("X-RateLimit-Remaining") == "0":
            return True
        return False

    def _rate_limit_sleep_seconds(self, resp: requests.Response, attempt: int) -> int:
        retry_after = resp.headers.get("Retry-After")
        if retry_after:
            try:
                return max(1, min(int(retry_after), self.cfg.max_rate_limit_sleep_seconds))
            except ValueError:
                return min(60, self.cfg.max_rate_limit_sleep_seconds)

        remaining = resp.headers.get("X-RateLimit-Remaining")
        reset = resp.headers.get("X-RateLimit-Reset")
        if remaining == "0" and reset:
            try:
                reset_epoch = int(reset)
                now = int(time.time())
                return max(
                    60,
                    min(reset_epoch - now + 2, self.cfg.max_rate_limit_sleep_seconds),
                )
            except ValueError:
                pass

        # Secondary limit or ambiguous 403: exponential backoff with cap.
        return min((2**attempt) * 60, self.cfg.max_rate_limit_sleep_seconds)

    def request(
        self,
        method: str,
        path_or_url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
    ) -> requests.Response:
        url = self._url(path_or_url)
        last_resp: Optional[requests.Response] = None

        for attempt in range(self.cfg.max_retries + 1):
            self._sleep_before_request()
            resp = self.session.request(
                method,
                url,
                params=params,
                timeout=self.cfg.timeout,
            )
            last_resp = resp

            if not self._is_rate_limit_response(resp):
                return resp

            sleep_for = self._rate_limit_sleep_seconds(resp, attempt)
            if sleep_for > 0:
                time.sleep(sleep_for)

        return last_resp if last_resp is not None else resp

    def _auth_hint(self, resp: requests.Response) -> str:
        sso = resp.headers.get("X-GitHub-SSO")
        return f" X-GitHub-SSO={sso}" if sso else ""

    def get_json(self, path_or_url: str, *, params: Optional[Dict[str, Any]] = None) -> Any:
        resp = self.request("GET", path_or_url, params=params)

        if resp.status_code == 404:
            raise RuntimeError(
                f"GET {path_or_url} failed: 404 Not Found. "
                f"Verify the org login and that the app installation can see it. "
                f"Response: {resp.text[:400]}{self._auth_hint(resp)}"
            )
        if resp.status_code == 401:
            raise RuntimeError(
                f"GET {path_or_url} failed: 401 Unauthorized. "
                f"Check the app credentials and generated installation token. "
                f"Response: {resp.text[:400]}{self._auth_hint(resp)}"
            )
        if resp.status_code == 403:
            raise RuntimeError(
                f"GET {path_or_url} failed: 403 Forbidden. "
                f"Check the app's granted permissions and installation access. "
                f"Response: {resp.text[:400]}{self._auth_hint(resp)}"
            )
        if resp.status_code >= 400:
            raise RuntimeError(f"GET {path_or_url} failed: {resp.status_code} {resp.text[:400]}")

        return resp.json()

    def paginate(self, path_or_url: str, *, params: Optional[Dict[str, Any]] = None) -> Iterable[Any]:
        params = dict(params or {})
        params.setdefault("per_page", 100)
        page = 1

        while True:
            page_params = dict(params)
            page_params["page"] = page
            resp = self.request("GET", path_or_url, params=page_params)

            if resp.status_code == 404:
                raise RuntimeError(
                    f"GET {path_or_url} page {page} failed: 404 Not Found. "
                    f"Verify the org login and that the app installation can see it. "
                    f"Response: {resp.text[:400]}{self._auth_hint(resp)}"
                )
            if resp.status_code == 401:
                raise RuntimeError(
                    f"GET {path_or_url} page {page} failed: 401 Unauthorized. "
                    f"Check the app credentials and generated installation token. "
                    f"Response: {resp.text[:400]}{self._auth_hint(resp)}"
                )
            if resp.status_code == 403 and not self._is_rate_limit_response(resp):
                raise RuntimeError(
                    f"GET {path_or_url} page {page} failed: 403 Forbidden. "
                    f"Check the app's granted permissions and installation access. "
                    f"Response: {resp.text[:400]}{self._auth_hint(resp)}"
                )
            if resp.status_code >= 400 and not self._is_rate_limit_response(resp):
                raise RuntimeError(
                    f"GET {path_or_url} page {page} failed: {resp.status_code} {resp.text[:400]}"
                )

            data = resp.json()
            if isinstance(data, list):
                for item in data:
                    yield item
            else:
                yield data

            link = resp.headers.get("Link", "")
            if 'rel="next"' not in link:
                break
            page += 1


def iso_date_days_ago(days: int) -> str:
    return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).date().isoformat()


def normalize_audit_event(event: Dict[str, Any]) -> Dict[str, Any]:
    created_at = event.get("created_at")
    if isinstance(created_at, (int, float)):
        created_iso = dt.datetime.fromtimestamp(created_at / 1000.0, tz=dt.timezone.utc).isoformat()
    else:
        created_iso = created_at

    country_code = event.get("actor_location.country_code")
    if country_code is None and isinstance(event.get("actor_location"), dict):
        country_code = event["actor_location"].get("country_code")

    return {
        "created_at": created_iso,
        "action": event.get("action"),
        "actor": event.get("actor"),
        "user": event.get("user"),
        "org": event.get("org"),
        "repo": event.get("repo"),
        "team": event.get("team"),
        "visibility": event.get("visibility"),
        "ip": event.get("ip_address") or event.get("client_ip_address"),
        "country_code": country_code,
        "raw": event,
    }


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def build_manifest(output_dir: Path, files: List[Path]) -> None:
    lines = ["# Evidence Manifest", ""]
    lines.append(f"Generated: {dt.datetime.now(dt.timezone.utc).isoformat()}")
    lines.append("")
    for file_path in files:
        lines.append(f"- {file_path.relative_to(output_dir).as_posix()}")
    (output_dir / "manifest.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def collect(cfg: GitHubConfig) -> Path:
    auth = GitHubAppAuthenticator(cfg)
    installation_id = auth.get_installation_id()
    installation_token = auth.get_installation_token(installation_id)
    client = GitHubClient(cfg, installation_token)

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_dir = Path.cwd() / f"github_ia208_evidence_{stamp}"
    output_dir.mkdir(parents=True, exist_ok=True)

    files: List[Path] = []

    org = client.get_json(f"/orgs/{cfg.org}")
    org_path = output_dir / "org.json"
    write_json(org_path, org)
    files.append(org_path)

    try:
        cred_auths = list(client.paginate(f"/orgs/{cfg.org}/credential-authorizations"))
    except RuntimeError as exc:
        cred_auths = {"error": str(exc)}
    cred_path = output_dir / "credential_authorizations.json"
    write_json(cred_path, cred_auths)
    files.append(cred_path)

    try:
        installations = list(client.paginate(f"/orgs/{cfg.org}/installations"))
    except RuntimeError as exc:
        installations = {"error": str(exc)}
    inst_path = output_dir / "installations.json"
    write_json(inst_path, installations)
    files.append(inst_path)

    created_filter = f"created:>={iso_date_days_ago(cfg.days)}"
    audit_events: List[Dict[str, Any]] = []
    try:
        for event in client.paginate(
            f"/orgs/{cfg.org}/audit-log",
            params={
                "include": "all",
                "phrase": created_filter,
                "per_page": 100,
                "order": "desc",
            },
        ):
            audit_events.append(normalize_audit_event(event))
    except RuntimeError as exc:
        audit_events = [{"error": str(exc)}]

    audit_jsonl = output_dir / "audit_log.jsonl"
    with audit_jsonl.open("w", encoding="utf-8") as f:
        for event in audit_events:
            f.write(json.dumps(event, sort_keys=True))
            f.write("\n")
    files.append(audit_jsonl)

    rows_for_csv = [e for e in audit_events if "error" not in e]
    audit_csv = output_dir / "audit_log.csv"
    csv_fields = ["created_at", "action", "actor", "user", "org", "repo", "team", "visibility", "ip", "country_code"]
    write_csv(audit_csv, rows_for_csv, csv_fields)
    files.append(audit_csv)

    summary: Dict[str, Any] = {
        "org": cfg.org,
        "api_url": cfg.api_url,
        "days_collected": cfg.days,
        "collected_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "org_two_factor_requirement_enabled": org.get("two_factor_requirement_enabled"),
        "credential_authorization_count": len(cred_auths) if isinstance(cred_auths, list) else None,
        "installation_count": len(installations) if isinstance(installations, list) else None,
        "audit_event_count": len(rows_for_csv),
        "potential_gaps": [],
    }

    if not org.get("two_factor_requirement_enabled"):
        summary["potential_gaps"].append("Organization 2FA requirement is not enabled.")
    if isinstance(cred_auths, dict) and cred_auths.get("error"):
        summary["potential_gaps"].append(
            "Could not retrieve credential authorizations; verify the app permissions and that the app is installed on the org."
        )
    if isinstance(audit_events, list) and audit_events and "error" in audit_events[0]:
        summary["potential_gaps"].append(
            "Could not retrieve audit log; verify the app permissions and that the app is installed on the org."
        )

    auth_related = [
        e for e in rows_for_csv
        if any(
            token in str(e.get("action", "")).lower()
            for token in ("auth", "saml", "oauth", "token", "credential", "2fa", "mfa")
        )
    ]
    summary["auth_related_event_count"] = len(auth_related)

    summary_path = output_dir / "summary.json"
    write_json(summary_path, summary)
    files.append(summary_path)

    build_manifest(output_dir, files)
    return output_dir


def main() -> int:
    app_id = os.environ.get("GITHUB_APP_ID", "").strip()
    private_key = os.environ.get("GITHUB_APP_PRIVATE_KEY", "").strip()
    org = os.environ.get("GITHUB_ORG", "").strip()

    if not app_id or not private_key or not org:
        print("Set GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY, and GITHUB_ORG before running.", file=sys.stderr)
        return 2

    try:
        days = int(os.environ.get("GITHUB_DAYS", "90"))
    except ValueError:
        print("GITHUB_DAYS must be an integer.", file=sys.stderr)
        return 2

    try:
        request_delay_seconds = float(os.environ.get("GITHUB_REQUEST_DELAY_SECONDS", "0.25"))
    except ValueError:
        print("GITHUB_REQUEST_DELAY_SECONDS must be a number.", file=sys.stderr)
        return 2

    try:
        max_retries = int(os.environ.get("GITHUB_MAX_RETRIES", "5"))
    except ValueError:
        print("GITHUB_MAX_RETRIES must be an integer.", file=sys.stderr)
        return 2

    try:
        max_rate_limit_sleep_seconds = int(os.environ.get("GITHUB_MAX_RATE_LIMIT_SLEEP_SECONDS", "3600"))
    except ValueError:
        print("GITHUB_MAX_RATE_LIMIT_SLEEP_SECONDS must be an integer.", file=sys.stderr)
        return 2

    cfg = GitHubConfig(
        app_id=app_id,
        private_key=private_key,
        org=org,
        api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com").strip(),
        api_version=os.environ.get("GITHUB_API_VERSION", "2022-11-28").strip(),
        days=days,
        request_delay_seconds=request_delay_seconds,
        max_retries=max_retries,
        max_rate_limit_sleep_seconds=max_rate_limit_sleep_seconds,
    )

    try:
        output_dir = collect(cfg)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(str(output_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
