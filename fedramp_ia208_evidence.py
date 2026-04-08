#!/usr/bin/env python3
"""Collect FedRAMP evidence for GitHub.com IA-2(8) and adjacent controls.

This version is checkpointed so audit-log collection resumes from the last
successfully processed day instead of starting over.

It does that by:
- using GitHub App installation auth end-to-end
- collecting the audit log in 1-day windows by default
- saving a durable checkpoint after each completed day
- optionally pushing that checkpoint back to the repository after each day
- retrying transient server and rate-limit errors with backoff
- printing helpful debug headers on failures

Outputs a timestamped folder containing:
- org.json
- audit_log.jsonl
- audit_log.csv
- credential_authorizations.json
- installations.json
- summary.json
- manifest.md

Required env vars:
- GH_APP_ID
- GH_APP_PRIVATE_KEY
- GH_ORG

Optional env vars:
- GH_API_URL: default https://api.github.com
- GH_API_VERSION: default 2022-11-28
- GH_ENTERPRISE: retained for reporting only
- GH_DAYS: default 90
- GH_REQUEST_DELAY_SECONDS: default 0.25
- GH_MAX_RETRIES: default 5
- GH_MAX_RATE_LIMIT_SLEEP_SECONDS: default 3600
- GH_MAX_SERVER_SLEEP_SECONDS: default 300
- GH_AUDIT_WINDOW_DAYS: default 1
- GH_AUDIT_MAX_PAGES_PER_WINDOW: default 50
- GH_AUDIT_MAX_EVENTS: default 10000
- GH_MAX_WINDOWS_PER_RUN: default 7
- GH_CHECKPOINT_FILE: default .github/evidence_state/irsdigitalservice_audit_checkpoint.json
- GH_AUTO_PUSH_CHECKPOINT: default 1
"""
from __future__ import annotations

import csv
import datetime as dt
import json
import os
import random
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

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
    max_server_sleep_seconds: int = 300
    audit_window_days: int = 1
    audit_max_pages_per_window: int = 50
    audit_max_events: int = 10000
    max_windows_per_run: int = 7
    checkpoint_file: str = ".github/evidence_state/irsdigitalservice_audit_checkpoint.json"
    auto_push_checkpoint: bool = True


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_date_days_ago(days: int) -> dt.date:
    return (utc_now() - dt.timedelta(days=days)).date()


def parse_iso_date(value: str) -> dt.date:
    return dt.date.fromisoformat(value)


def date_windows(start: dt.date, end: dt.date, window_days: int) -> List[Tuple[dt.date, dt.date]]:
    if window_days < 1:
        window_days = 1

    windows: List[Tuple[dt.date, dt.date]] = []
    cursor = start
    step = dt.timedelta(days=window_days)

    while cursor <= end:
        window_end = min(cursor + step - dt.timedelta(days=1), end)
        windows.append((cursor, window_end))
        cursor = window_end + dt.timedelta(days=1)

    return windows


def normalize_audit_event(event: Dict[str, Any]) -> Dict[str, Any]:
    created_at = event.get("created_at")
    if isinstance(created_at, (int, float)):
        created_iso = dt.datetime.fromtimestamp(
            created_at / 1000.0, tz=dt.timezone.utc
        ).isoformat()
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
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def build_manifest(output_dir: Path, files: List[Path]) -> None:
    lines = ["# Evidence Manifest", ""]
    lines.append(f"Generated: {utc_now().isoformat()}")
    lines.append("")
    for file_path in files:
        lines.append(f"- {file_path.relative_to(output_dir).as_posix()}")
    (output_dir / "manifest.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def load_checkpoint(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def save_checkpoint(path: Path, data: Dict[str, Any]) -> None:
    write_json(path, data)


def maybe_git_push_checkpoint(checkpoint_path: Path, message: str) -> None:
    """
    Best-effort push of the checkpoint file back to the repo.
    This assumes the workflow has configured git auth for the checkout remote.
    """
    if os.environ.get("GH_AUTO_PUSH_CHECKPOINT", "1").strip().lower() in {"0", "false", "no"}:
        return

    if not (checkpoint_path.exists() or checkpoint_path.parent.exists()):
        return

    try:
        subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return

    try:
        status = subprocess.run(
            ["git", "status", "--porcelain", "--", str(checkpoint_path)],
            check=True,
            capture_output=True,
            text=True,
        )
        if not status.stdout.strip():
            return

        subprocess.run(["git", "add", str(checkpoint_path)], check=True)
        commit = subprocess.run(
            ["git", "commit", "-m", message],
            check=False,
            capture_output=True,
            text=True,
        )
        if commit.returncode != 0:
            # Nothing to commit or commit failed; keep going.
            return

        push = subprocess.run(["git", "push"], check=False, capture_output=True, text=True)
        if push.returncode != 0:
            print(
                f"WARNING: checkpoint push failed: {push.stderr.strip() or push.stdout.strip()}",
                file=sys.stderr,
            )
    except Exception as exc:
        print(f"WARNING: checkpoint push skipped: {exc}", file=sys.stderr)


class GitHubAppAuthenticator:
    def __init__(self, cfg: GitHubConfig) -> None:
        self.cfg = cfg
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": cfg.api_version,
                "User-Agent": "fedramp-ia208-evidence-collector/5.0",
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
        return self.session.request(
            method,
            self._url(path_or_url),
            headers=headers,
            params=params,
            json=json_body,
            timeout=self.cfg.timeout,
        )

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
                "User-Agent": "fedramp-ia208-evidence-collector/5.0",
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

    def _debug_failure(self, resp: requests.Response, path_or_url: str) -> None:
        print("\n=== DEBUG: API FAILURE ===", file=sys.stderr)
        print(f"Endpoint: {path_or_url}", file=sys.stderr)
        print(f"Status: {resp.status_code}", file=sys.stderr)
        print(
            "X-Accepted-GitHub-Permissions:",
            resp.headers.get("X-Accepted-GitHub-Permissions"),
            file=sys.stderr,
        )
        print("X-OAuth-Scopes:", resp.headers.get("X-OAuth-Scopes"), file=sys.stderr)
        print("Response:", resp.text[:500], file=sys.stderr)
        print("=== END DEBUG ===\n", file=sys.stderr)

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

    def _retry_sleep_seconds(self, resp: requests.Response, attempt: int) -> int:
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
                return max(60, min(reset_epoch - now + 2, self.cfg.max_rate_limit_sleep_seconds))
            except ValueError:
                pass

        return min((2**attempt) * 60, self.cfg.max_rate_limit_sleep_seconds)

    def _server_error_sleep_seconds(self, attempt: int) -> int:
        return min((2**attempt) * 5, self.cfg.max_rate_limit_sleep_seconds)

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

            if resp.status_code in (500, 502, 503, 504):
                self._debug_failure(resp, path_or_url)
                time.sleep(self._server_error_sleep_seconds(attempt))
                continue

            if not self._is_rate_limit_response(resp):
                return resp

            self._debug_failure(resp, path_or_url)
            time.sleep(self._retry_sleep_seconds(resp, attempt))

        return last_resp if last_resp is not None else resp

    def get_json(self, path_or_url: str, *, params: Optional[Dict[str, Any]] = None) -> Any:
        resp = self.request("GET", path_or_url, params=params)

        if resp.status_code == 404:
            raise RuntimeError(
                f"GET {path_or_url} failed: 404 Not Found. "
                f"Verify the org login and that the app installation can see it. "
                f"Response: {resp.text[:400]}"
            )
        if resp.status_code == 401:
            raise RuntimeError(
                f"GET {path_or_url} failed: 401 Unauthorized. "
                f"Check the app credentials and generated installation token. "
                f"Response: {resp.text[:400]}"
            )
        if resp.status_code == 403:
            raise RuntimeError(
                f"GET {path_or_url} failed: 403 Forbidden. "
                f"Check the app's granted permissions and installation access. "
                f"Response: {resp.text[:400]}"
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

            if resp.status_code in (500, 502, 503, 504):
                raise RuntimeError(
                    f"GET {path_or_url} page {page} failed: {resp.status_code} {resp.text[:400]}"
                )
            if resp.status_code == 404:
                raise RuntimeError(
                    f"GET {path_or_url} page {page} failed: 404 Not Found. "
                    f"Verify the org login and that the app installation can see it. "
                    f"Response: {resp.text[:400]}"
                )
            if resp.status_code == 401:
                raise RuntimeError(
                    f"GET {path_or_url} page {page} failed: 401 Unauthorized. "
                    f"Check the app credentials and generated installation token. "
                    f"Response: {resp.text[:400]}"
                )
            if resp.status_code == 403 and not self._is_rate_limit_response(resp):
                raise RuntimeError(
                    f"GET {path_or_url} page {page} failed: 403 Forbidden. "
                    f"Check the app's granted permissions and installation access. "
                    f"Response: {resp.text[:400]}"
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


def collect_audit_day(
    client: GitHubClient,
    org: str,
    day: dt.date,
    max_pages: int,
    max_events: int,
) -> List[Dict[str, Any]]:
    created_filter = f"created:{day.isoformat()}..{day.isoformat()}"
    collected: List[Dict[str, Any]] = []

    page = 1
    while page <= max_pages and len(collected) < max_events:
        params = {
            "include": "all",
            "phrase": created_filter,
            "per_page": 100,
            "order": "desc",
            "page": page,
        }

        resp = client.request("GET", f"/orgs/{org}/audit-log", params=params)

        if resp.status_code in (500, 502, 503, 504):
            raise RuntimeError(
                f"GET /orgs/{org}/audit-log window {created_filter} page {page} failed: "
                f"{resp.status_code} {resp.text[:400]}"
            )
        if resp.status_code == 404:
            raise RuntimeError(
                f"GET /orgs/{org}/audit-log window {created_filter} page {page} failed: "
                f"404 Not Found. Response: {resp.text[:400]}"
            )
        if resp.status_code == 401:
            raise RuntimeError(
                f"GET /orgs/{org}/audit-log window {created_filter} page {page} failed: "
                f"401 Unauthorized. Response: {resp.text[:400]}"
            )
        if resp.status_code == 403 and not client._is_rate_limit_response(resp):
            raise RuntimeError(
                f"GET /orgs/{org}/audit-log window {created_filter} page {page} failed: "
                f"403 Forbidden. Response: {resp.text[:400]}"
            )
        if resp.status_code >= 400 and not client._is_rate_limit_response(resp):
            raise RuntimeError(
                f"GET /orgs/{org}/audit-log window {created_filter} page {page} failed: "
                f"{resp.status_code} {resp.text[:400]}"
            )

        data = resp.json()
        if not isinstance(data, list) or not data:
            break

        for event in data:
            collected.append(normalize_audit_event(event))
            if len(collected) >= max_events:
                break

        if 'rel="next"' not in resp.headers.get("Link", ""):
            break

        page += 1

    if page > max_pages and collected:
        raise RuntimeError(
            f"GET /orgs/{org}/audit-log window {created_filter} exceeded max pages ({max_pages})."
        )

    return collected


def collect_audit_log(
    client: GitHubClient,
    org: str,
    days: int,
    window_days: int,
    max_pages_per_window: int,
    max_events: int,
    max_windows_per_run: int,
    checkpoint_path: Path,
    auto_push_checkpoint: bool,
) -> List[Dict[str, Any]]:
    checkpoint = load_checkpoint(checkpoint_path)
    today = utc_now().date()

    if checkpoint.get("last_processed_day"):
        start_date = parse_iso_date(str(checkpoint["last_processed_day"]))
    else:
        start_date = iso_date_days_ago(days)

    windows = date_windows(start_date, today, window_days)
    windows = windows[: max(1, max_windows_per_run)]

    collected: List[Dict[str, Any]] = []
    last_completed_day: Optional[dt.date] = None

    for window_start, window_end in windows:
        if len(collected) >= max_events:
            break

        # One-day windows by default. If window_days > 1, process each day inside.
        day = window_start
        while day <= window_end:
            day_events = collect_audit_day(
                client=client,
                org=org,
                day=day,
                max_pages=max_pages_per_window,
                max_events=max_events - len(collected),
            )
            collected.extend(day_events)
            last_completed_day = day

            checkpoint_data = {
                "org": org,
                "last_processed_day": day.isoformat(),
                "last_updated_at": utc_now().isoformat(),
                "window_days": window_days,
                "max_pages_per_window": max_pages_per_window,
                "max_events": max_events,
            }
            save_checkpoint(checkpoint_path, checkpoint_data)

            if auto_push_checkpoint:
                maybe_git_push_checkpoint(
                    checkpoint_path,
                    message=f"Update audit checkpoint for {org} through {day.isoformat()}",
                )

            if len(collected) >= max_events:
                break

            day += dt.timedelta(days=1)

    # If we processed nothing new but already had a checkpoint, preserve it.
    if last_completed_day is None and checkpoint:
        save_checkpoint(checkpoint_path, checkpoint)

    return collected


def collect(cfg: GitHubConfig) -> Path:
    auth = GitHubAppAuthenticator(cfg)
    installation_id = auth.get_installation_id()
    installation_token = auth.get_installation_token(installation_id)
    client = GitHubClient(cfg, installation_token)

    stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    output_dir = Path.cwd() / f"github_ia208_evidence_{stamp}"
    output_dir.mkdir(parents=True, exist_ok=True)

    checkpoint_path = Path(cfg.checkpoint_file)
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)

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

    try:
        audit_events = collect_audit_log(
            client=client,
            org=cfg.org,
            days=cfg.days,
            window_days=cfg.audit_window_days,
            max_pages_per_window=cfg.audit_max_pages_per_window,
            max_events=cfg.audit_max_events,
            max_windows_per_run=cfg.max_windows_per_run,
            checkpoint_path=checkpoint_path,
            auto_push_checkpoint=cfg.auto_push_checkpoint,
        )
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
    csv_fields = [
        "created_at",
        "action",
        "actor",
        "user",
        "org",
        "repo",
        "team",
        "visibility",
        "ip",
        "country_code",
    ]
    write_csv(audit_csv, rows_for_csv, csv_fields)
    files.append(audit_csv)

    checkpoint = load_checkpoint(checkpoint_path)

    summary: Dict[str, Any] = {
        "org": cfg.org,
        "api_url": cfg.api_url,
        "enterprise": cfg.enterprise,
        "days_collected": cfg.days,
        "audit_window_days": cfg.audit_window_days,
        "audit_max_pages_per_window": cfg.audit_max_pages_per_window,
        "audit_max_events": cfg.audit_max_events,
        "max_windows_per_run": cfg.max_windows_per_run,
        "collected_at": utc_now().isoformat(),
        "org_two_factor_requirement_enabled": org.get("two_factor_requirement_enabled"),
        "org_has_saml_sso_authorizations_endpoint": True,
        "credential_authorization_count": len(cred_auths) if isinstance(cred_auths, list) else None,
        "installation_count": len(installations) if isinstance(installations, list) else None,
        "audit_event_count": len(rows_for_csv),
        "checkpoint_file": str(checkpoint_path),
        "checkpoint_last_processed_day": checkpoint.get("last_processed_day"),
        "potential_gaps": [],
    }

    if not org.get("two_factor_requirement_enabled"):
        summary["potential_gaps"].append("Organization 2FA requirement is not enabled.")

    if isinstance(cred_auths, dict) and cred_auths.get("error"):
        summary["potential_gaps"].append(
            "Could not retrieve credential authorizations; verify org owner permissions and app installation."
        )

    if isinstance(audit_events, list) and audit_events and "error" in audit_events[0]:
        summary["potential_gaps"].append(
            "Could not retrieve audit log; verify org access, app permissions, and rate limits."
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
    app_id = os.environ.get("GH_APP_ID", "").strip()
    private_key = os.environ.get("GH_APP_PRIVATE_KEY", "").strip()
    org = os.environ.get("GH_ORG", "").strip()

    if not app_id or not private_key or not org:
        print("Set GH_APP_ID, GH_APP_PRIVATE_KEY, and GH_ORG before running.", file=sys.stderr)
        return 2

    try:
        days = int(os.environ.get("GH_DAYS", "90"))
    except ValueError:
        print("GH_DAYS must be an integer.", file=sys.stderr)
        return 2

    try:
        request_delay_seconds = float(os.environ.get("GH_REQUEST_DELAY_SECONDS", "0.25"))
    except ValueError:
        print("GH_REQUEST_DELAY_SECONDS must be a number.", file=sys.stderr)
        return 2

    try:
        max_retries = int(os.environ.get("GH_MAX_RETRIES", "5"))
    except ValueError:
        print("GH_MAX_RETRIES must be an integer.", file=sys.stderr)
        return 2

    try:
        max_rate_limit_sleep_seconds = int(os.environ.get("GH_MAX_RATE_LIMIT_SLEEP_SECONDS", "3600"))
    except ValueError:
        print("GH_MAX_RATE_LIMIT_SLEEP_SECONDS must be an integer.", file=sys.stderr)
        return 2

    try:
        max_server_sleep_seconds = int(os.environ.get("GH_MAX_SERVER_SLEEP_SECONDS", "300"))
    except ValueError:
        print("GH_MAX_SERVER_SLEEP_SECONDS must be an integer.", file=sys.stderr)
        return 2

    try:
        audit_window_days = int(os.environ.get("GH_AUDIT_WINDOW_DAYS", "1"))
    except ValueError:
        print("GH_AUDIT_WINDOW_DAYS must be an integer.", file=sys.stderr)
        return 2

    try:
        audit_max_pages_per_window = int(os.environ.get("GH_AUDIT_MAX_PAGES_PER_WINDOW", "50"))
    except ValueError:
        print("GH_AUDIT_MAX_PAGES_PER_WINDOW must be an integer.", file=sys.stderr)
        return 2

    try:
        audit_max_events = int(os.environ.get("GH_AUDIT_MAX_EVENTS", "10000"))
    except ValueError:
        print("GH_AUDIT_MAX_EVENTS must be an integer.", file=sys.stderr)
        return 2

    try:
        max_windows_per_run = int(os.environ.get("GH_MAX_WINDOWS_PER_RUN", "7"))
    except ValueError:
        print("GH_MAX_WINDOWS_PER_RUN must be an integer.", file=sys.stderr)
        return 2

    checkpoint_file = os.environ.get(
        "GH_CHECKPOINT_FILE",
        ".github/evidence_state/irsdigitalservice_audit_checkpoint.json",
    ).strip()

    auto_push_checkpoint = os.environ.get("GH_AUTO_PUSH_CHECKPOINT", "1").strip().lower() not in {
        "0",
        "false",
        "no",
    }

    cfg = GitHubConfig(
        app_id=app_id,
        private_key=private_key,
        org=org,
        api_url=os.environ.get("GH_API_URL", "https://api.github.com").strip(),
        api_version=os.environ.get("GH_API_VERSION", "2022-11-28").strip(),
        enterprise=os.environ.get("GH_ENTERPRISE") or None,
        days=days,
        request_delay_seconds=request_delay_seconds,
        max_retries=max_retries,
        max_rate_limit_sleep_seconds=max_rate_limit_sleep_seconds,
        max_server_sleep_seconds=max_server_sleep_seconds,
        audit_window_days=audit_window_days,
        audit_max_pages_per_window=audit_max_pages_per_window,
        audit_max_events=audit_max_events,
        max_windows_per_run=max_windows_per_run,
        checkpoint_file=checkpoint_file,
        auto_push_checkpoint=auto_push_checkpoint,
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
