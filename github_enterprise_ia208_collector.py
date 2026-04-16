#!/usr/bin/env python3
"""
FedRAMP IA-2(8) evidence collector for GitHub Enterprise Cloud.

Primary mode:
- Collect enterprise-wide audit log evidence from:
  GET /enterprises/{enterprise}/audit-log

Auth:
- GitHub App installation token
- Enterprise-level app installation must grant Enterprise administration: read
- The authenticated installation must be visible to the enterprise

Outputs:
- evidence_output/enterprise_audit_log.jsonl
- evidence_output/enterprise_audit_log.csv
- evidence_output/enterprise_installation.json
- evidence_output/summary.json
- evidence_output/control_map.json
- evidence_output/manifest.md
- evidence_output/errors.json

Optional:
- checkpointed incremental collection using a rolling date window
- archive slices under evidence/archive
- optional S3 sync for the archive slice
"""

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
    timeout: int = 30
    request_delay_seconds: float = 0.25
    max_retries: int = 5
    max_rate_limit_sleep_seconds: int = 3600
    max_server_sleep_seconds: int = 300
    days: int = 90
    audit_window_days: int = 1
    audit_max_pages_per_window: int = 50
    audit_max_events: int = 10000
    max_windows_per_run: int = 7
    checkpoint_file: str = ".github/evidence_state/checkpoints/enterprise_audit_checkpoint.json"
    archive_root: str = "evidence/archive"
    auto_push_checkpoint: bool = True
    archive_s3_bucket: Optional[str] = None
    archive_s3_prefix: str = "github-enterprise"
    aws_region: Optional[str] = None


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_date_days_ago(days: int) -> dt.date:
    return (utc_now() - dt.timedelta(days=days)).date()


def parse_iso_date(value: str) -> dt.date:
    return dt.date.fromisoformat(value)


def date_windows(start: dt.date, end: dt.date, window_days: int) -> List[Tuple[dt.date, dt.date]]:
    window_days = max(1, window_days)
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
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True, default=str))
            f.write("\n")


def write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def append_jsonl(path: Path, record: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True, default=str))
        f.write("\n")


def build_manifest(output_dir: Path, files: List[Path]) -> None:
    lines = ["# Enterprise Evidence Manifest", ""]
    lines.append(f"Generated: {utc_now().isoformat()}")
    lines.append("")
    lines.append("Files:")
    for file_path in files:
        lines.append(f"- {file_path.relative_to(output_dir).as_posix()}")
    (output_dir / "manifest.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def sync_directory_to_s3(directory: Path, bucket: str, prefix: str, region: Optional[str]) -> None:
    try:
        import boto3  # type: ignore
    except Exception as exc:
        raise RuntimeError("boto3 is required for GH_ARCHIVE_S3_BUCKET uploads") from exc

    client = boto3.client("s3", region_name=region or None)
    base_prefix = prefix.strip("/")
    for file_path in directory.rglob("*"):
        if not file_path.is_file():
            continue
        rel = file_path.relative_to(directory).as_posix()
        key = f"{base_prefix}/{rel}" if base_prefix else rel
        client.upload_file(str(file_path), bucket, key)


def maybe_git_push_checkpoint(checkpoint_path: Path, message: str) -> None:
    if os.environ.get("GH_AUTO_PUSH_CHECKPOINT", "1").strip().lower() in {"0", "false", "no"}:
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
            return

        push = subprocess.run(["git", "push"], check=False, capture_output=True, text=True)
        if push.returncode != 0:
            print(f"WARNING: checkpoint push failed: {push.stderr.strip() or push.stdout.strip()}", file=sys.stderr)
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
                "User-Agent": "fedramp-ia208-enterprise-evidence-collector/1.0",
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

    def get_json(self, path_or_url: str, *, params: Optional[Dict[str, Any]] = None) -> Any:
        resp = self.request("GET", path_or_url, params=params)
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

            if resp.status_code >= 400:
                raise RuntimeError(f"GET {path_or_url} page {page} failed: {resp.status_code} {resp.text[:400]}")

            data = resp.json()
            if isinstance(data, list):
                for item in data:
                    yield item
            else:
                yield data

            if 'rel="next"' not in resp.headers.get("Link", ""):
                break
            page += 1

    def get_installation_id(self) -> int:
        app = self.get_json("/app")
        installations = list(self.paginate("/app/installations"))
        target = self.cfg.enterprise.strip().lower()
        matches = []
        for inst in installations:
            account = inst.get("account") or {}
            login = str(account.get("login", "")).strip().lower()
            if login == target:
                matches.append(inst)

        if not matches:
            visible = [
                {
                    "installation_id": inst.get("id"),
                    "account_login": (inst.get("account") or {}).get("login"),
                    "target_type": inst.get("target_type"),
                }
                for inst in installations
            ]
            raise RuntimeError(
                f"GitHub App '{app.get('slug', '<unknown>')}' (id={app.get('id', '<unknown>')}) "
                f"has no visible installation for enterprise '{self.cfg.enterprise}'. "
                f"Visible installations: {visible}. "
                f"Install the app on the enterprise and ensure Enterprise administration: read is granted."
            )

        if len(matches) > 1:
            ids = [m.get("id") for m in matches]
            raise RuntimeError(
                f"Multiple matching enterprise installations found for '{self.cfg.enterprise}': {ids}. "
                f"Select one explicitly or tighten the lookup."
            )

        installation_id = matches[0].get("id")
        if not installation_id:
            raise RuntimeError(f"Matched installation record had no id: {matches[0]}")
        return int(installation_id)

    def get_installation_token(self, installation_id: int) -> str:
        resp = self.request("POST", f"/app/installations/{installation_id}/access_tokens", json_body={})
        if resp.status_code >= 400:
            raise RuntimeError(
                f"POST /app/installations/{installation_id}/access_tokens failed: {resp.status_code} {resp.text[:400]}"
            )
        data = resp.json()
        token = data.get("token")
        if not token:
            raise RuntimeError(f"Installation token response did not include token: {data}")
        return token


class GitHubEnterpriseClient:
    def __init__(self, cfg: GitHubConfig, token: str) -> None:
        self.cfg = cfg
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": cfg.api_version,
                "User-Agent": "fedramp-ia208-enterprise-evidence-collector/1.0",
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
        print("X-Accepted-GitHub-Permissions:", resp.headers.get("X-Accepted-GitHub-Permissions"), file=sys.stderr)
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

        return min((2 ** attempt) * 60, self.cfg.max_rate_limit_sleep_seconds)

    def _server_error_sleep_seconds(self, attempt: int) -> int:
        return min((2 ** attempt) * 5, self.cfg.max_server_sleep_seconds)

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
            raise RuntimeError(f"GET {path_or_url} failed: 404 Not Found. Response: {resp.text[:400]}")
        if resp.status_code == 401:
            raise RuntimeError(f"GET {path_or_url} failed: 401 Unauthorized. Response: {resp.text[:400]}")
        if resp.status_code == 403 and not self._is_rate_limit_response(resp):
            raise RuntimeError(
                f"GET {path_or_url} failed: 403 Forbidden. Response: {resp.text[:400]}. "
                f"Check enterprise installation and Enterprise administration: read permission."
            )
        if resp.status_code >= 400 and not self._is_rate_limit_response(resp):
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
                raise RuntimeError(f"GET {path_or_url} page {page} failed: 404 Not Found. Response: {resp.text[:400]}")
            if resp.status_code == 401:
                raise RuntimeError(f"GET {path_or_url} page {page} failed: 401 Unauthorized. Response: {resp.text[:400]}")
            if resp.status_code == 403 and not self._is_rate_limit_response(resp):
                raise RuntimeError(
                    f"GET {path_or_url} page {page} failed: 403 Forbidden. Response: {resp.text[:400]}. "
                    f"Check enterprise installation and Enterprise administration: read permission."
                )
            if resp.status_code >= 400 and not self._is_rate_limit_response(resp):
                raise RuntimeError(f"GET {path_or_url} page {page} failed: {resp.status_code} {resp.text[:400]}")

            data = resp.json()
            if isinstance(data, list):
                for item in data:
                    yield item
            else:
                yield data

            if 'rel="next"' not in resp.headers.get("Link", ""):
                break
            page += 1


def load_checkpoint(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_checkpoint(path: Path, data: Dict[str, Any]) -> None:
    write_json(path, data)


def collect_audit_day(
    client: GitHubEnterpriseClient,
    enterprise: str,
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
        resp = client.request("GET", f"/enterprises/{enterprise}/audit-log", params=params)

        if resp.status_code in (500, 502, 503, 504):
            client._debug_failure(resp, f"/enterprises/{enterprise}/audit-log window {created_filter} page {page}")
            raise RuntimeError(
                f"GET /enterprises/{enterprise}/audit-log window {created_filter} page {page} failed: "
                f"{resp.status_code} {resp.text[:400]}"
            )
        if resp.status_code == 404:
            client._debug_failure(resp, f"/enterprises/{enterprise}/audit-log window {created_filter} page {page}")
            raise RuntimeError(
                f"GET /enterprises/{enterprise}/audit-log window {created_filter} page {page} failed: "
                f"404 Not Found. Response: {resp.text[:400]}"
            )
        if resp.status_code == 401:
            client._debug_failure(resp, f"/enterprises/{enterprise}/audit-log window {created_filter} page {page}")
            raise RuntimeError(
                f"GET /enterprises/{enterprise}/audit-log window {created_filter} page {page} failed: "
                f"401 Unauthorized. Response: {resp.text[:400]}"
            )
        if resp.status_code == 403 and not client._is_rate_limit_response(resp):
            client._debug_failure(resp, f"/enterprises/{enterprise}/audit-log window {created_filter} page {page}")
            raise RuntimeError(
                f"GET /enterprises/{enterprise}/audit-log window {created_filter} page {page} failed: "
                f"403 Forbidden. Response: {resp.text[:400]}"
            )
        if resp.status_code >= 400 and not client._is_rate_limit_response(resp):
            client._debug_failure(resp, f"/enterprises/{enterprise}/audit-log window {created_filter} page {page}")
            raise RuntimeError(
                f"GET /enterprises/{enterprise}/audit-log window {created_filter} page {page} failed: "
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

    return collected


def collect_audit_log(
    client: GitHubEnterpriseClient,
    enterprise: str,
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
        start_date = parse_iso_date(str(checkpoint["last_processed_day"])) + dt.timedelta(days=1)
        collection_mode = "delta" if checkpoint.get("backfill_complete", False) else "backfill"
    else:
        start_date = iso_date_days_ago(days)
        collection_mode = "backfill"

    if start_date > today:
        return []

    windows = date_windows(start_date, today, window_days)
    windows = windows[: max(1, max_windows_per_run)]

    collected: List[Dict[str, Any]] = []
    for window_start, window_end in windows:
        if len(collected) >= max_events:
            break

        day = window_start
        while day <= window_end:
            day_events = collect_audit_day(
                client=client,
                enterprise=enterprise,
                day=day,
                max_pages=max_pages_per_window,
                max_events=max_events - len(collected),
            )
            collected.extend(day_events)

            checkpoint_data = {
                "enterprise": enterprise,
                "last_processed_day": day.isoformat(),
                "last_updated_at": utc_now().isoformat(),
                "window_days": window_days,
                "max_pages_per_window": max_pages_per_window,
                "max_events": max_events,
                "backfill_complete": day >= today,
                "collection_mode": collection_mode if day < today else "delta",
            }
            save_checkpoint(checkpoint_path, checkpoint_data)

            if auto_push_checkpoint:
                maybe_git_push_checkpoint(
                    checkpoint_path,
                    message=f"Update enterprise audit checkpoint for {enterprise} through {day.isoformat()}",
                )

            if len(collected) >= max_events:
                break

            day += dt.timedelta(days=1)

    return collected


def archive_run(
    run_dir: Path,
    archive_root: Path,
    run_stamp: str,
    files_to_archive: List[str],
    index_record: Dict[str, Any],
) -> Path:
    today = utc_now()
    rel_slice = Path(today.strftime("%Y")) / today.strftime("%m") / today.strftime("%d") / f"run-{run_stamp}"
    persistent_slice_dir = archive_root / rel_slice
    run_slice_dir = run_dir / "archive" / rel_slice

    for dest in (persistent_slice_dir, run_slice_dir):
        dest.mkdir(parents=True, exist_ok=True)
        for filename in files_to_archive:
            src = run_dir / filename
            if src.exists():
                shutil.copy2(src, dest / filename)

    append_jsonl(archive_root / "index.jsonl", index_record)
    append_jsonl(run_dir / "archive" / "index.jsonl", index_record)
    return persistent_slice_dir


def collect(cfg: GitHubConfig) -> Path:
    auth = GitHubAppAuthenticator(cfg)
    installation_id = auth.get_installation_id()
    installation_token = auth.get_installation_token(installation_id)
    client = GitHubEnterpriseClient(cfg, installation_token)

    run_stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    output_dir = Path.cwd() / f"github_enterprise_ia208_evidence_{run_stamp}"
    output_dir.mkdir(parents=True, exist_ok=True)

    checkpoint_path = Path(cfg.checkpoint_file)
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)

    archive_root = Path.cwd() / cfg.archive_root
    archive_root.mkdir(parents=True, exist_ok=True)

    files: List[Path] = []

    enterprise_install = {
        "enterprise": cfg.enterprise,
        "installation_id": installation_id,
        "collected_at": utc_now().isoformat(),
    }
    install_path = output_dir / "enterprise_installation.json"
    write_json(install_path, enterprise_install)
    files.append(install_path)

    try:
        audit_events = collect_audit_log(
            client=client,
            enterprise=cfg.enterprise,
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

    audit_jsonl = output_dir / "enterprise_audit_log.jsonl"
    write_jsonl(audit_jsonl, audit_events)
    files.append(audit_jsonl)

    rows_for_csv = [e for e in audit_events if "error" not in e]
    audit_csv = output_dir / "enterprise_audit_log.csv"
    write_csv(
        audit_csv,
        rows_for_csv,
        ["created_at", "action", "actor", "user", "org", "repo", "team", "visibility", "ip", "country_code"],
    )
    files.append(audit_csv)

    checkpoint = load_checkpoint(checkpoint_path)
    control_map = {name: CONTROL_MAP[name] for name in CONTROL_MAP}
    controls_covered = sorted({c for vals in control_map.values() for c in vals})

    summary: Dict[str, Any] = {
        "enterprise": cfg.enterprise,
        "api_url": cfg.api_url,
        "days_collected": cfg.days,
        "audit_window_days": cfg.audit_window_days,
        "audit_max_pages_per_window": cfg.audit_max_pages_per_window,
        "audit_max_events": cfg.audit_max_events,
        "max_windows_per_run": cfg.max_windows_per_run,
        "collection_mode": checkpoint.get("collection_mode", "backfill" if not checkpoint else "delta"),
        "collected_at": utc_now().isoformat(),
        "installation_id": installation_id,
        "audit_event_count": len(rows_for_csv),
        "checkpoint_file": str(checkpoint_path),
        "checkpoint_last_processed_day": checkpoint.get("last_processed_day"),
        "checkpoint_backfill_complete": bool(checkpoint.get("backfill_complete", False)),
        "archive_root": str(archive_root),
        "run_stamp": run_stamp,
        "run_dir": str(output_dir),
        "controls_covered": controls_covered,
        "control_map": control_map,
        "potential_gaps": [],
    }

    if isinstance(audit_events, list) and audit_events and "error" in audit_events[0]:
        summary["potential_gaps"].append(
            "Could not retrieve enterprise audit log; verify enterprise admin authorization and Enterprise administration: read permission."
        )

    auth_related = [
        e for e in rows_for_csv
        if any(token in str(e.get("action", "")).lower() for token in ("auth", "saml", "oauth", "token", "credential", "2fa", "mfa"))
    ]
    summary["auth_related_event_count"] = len(auth_related)

    summary_path = output_dir / "summary.json"
    write_json(summary_path, summary)
    files.append(summary_path)

    control_map_path = output_dir / "control_map.json"
    write_json(control_map_path, control_map)
    files.append(control_map_path)

    build_manifest(output_dir, files)

    archive_index_record = {
        "run_stamp": run_stamp,
        "enterprise": cfg.enterprise,
        "run_dir": str(output_dir),
        "archive_root": str(archive_root),
        "archive_slice_rel": f"{dt.datetime.now(dt.timezone.utc).strftime('%Y/%m/%d')}/run-{run_stamp}",
        "checkpoint_file": str(checkpoint_path),
        "checkpoint_last_processed_day": summary["checkpoint_last_processed_day"],
        "collection_mode": summary["collection_mode"],
        "controls_covered": controls_covered,
        "files": [p.name for p in files],
        "record_type": "evidence_slice",
        "created_at": utc_now().isoformat(),
    }

    persistent_slice_dir = archive_run(
        run_dir=output_dir,
        archive_root=archive_root,
        run_stamp=run_stamp,
        files_to_archive=[p.name for p in files],
        index_record=archive_index_record,
    )

    summary["archive_slice_dir"] = str(output_dir / "archive" / archive_index_record["archive_slice_rel"])
    summary["persistent_archive_slice_dir"] = str(persistent_slice_dir)
    write_json(summary_path, summary)
    shutil.copy2(summary_path, persistent_slice_dir / "summary.json")
    shutil.copy2(control_map_path, persistent_slice_dir / "control_map.json")
    build_manifest(output_dir, files)

    if cfg.archive_s3_bucket:
        s3_prefix = f"{cfg.archive_s3_prefix.strip('/')}/{archive_index_record['archive_slice_rel']}".strip("/")
        sync_directory_to_s3(persistent_slice_dir, cfg.archive_s3_bucket, s3_prefix, cfg.aws_region)

    return output_dir


def main() -> int:
    app_id = os.environ.get("GH_APP_ID", "").strip()
    private_key = os.environ.get("GH_APP_PRIVATE_KEY", "").strip()
    enterprise = os.environ.get("GH_ENTERPRISE", "").strip()

    if not app_id or not private_key or not enterprise:
        print("Set GH_APP_ID, GH_APP_PRIVATE_KEY, and GH_ENTERPRISE before running.", file=sys.stderr)
        return 2

    def read_int(name: str, default: str) -> int:
        value = os.environ.get(name, default)
        try:
            return int(value)
        except ValueError:
            print(f"{name} must be an integer.", file=sys.stderr)
            raise

    def read_float(name: str, default: str) -> float:
        value = os.environ.get(name, default)
        try:
            return float(value)
        except ValueError:
            print(f"{name} must be a number.", file=sys.stderr)
            raise

    try:
        cfg = GitHubConfig(
            app_id=app_id,
            private_key=private_key,
            enterprise=enterprise,
            api_url=os.environ.get("GH_API_URL", "https://api.github.com").strip(),
            api_version=os.environ.get("GH_API_VERSION", "2022-11-28").strip(),
            days=read_int("GH_DAYS", "90"),
            request_delay_seconds=read_float("GH_REQUEST_DELAY_SECONDS", "0.25"),
            max_retries=read_int("GH_MAX_RETRIES", "5"),
            max_rate_limit_sleep_seconds=read_int("GH_MAX_RATE_LIMIT_SLEEP_SECONDS", "3600"),
            max_server_sleep_seconds=read_int("GH_MAX_SERVER_SLEEP_SECONDS", "300"),
            audit_window_days=read_int("GH_AUDIT_WINDOW_DAYS", "1"),
            audit_max_pages_per_window=read_int("GH_AUDIT_MAX_PAGES_PER_WINDOW", "50"),
            audit_max_events=read_int("GH_AUDIT_MAX_EVENTS", "10000"),
            max_windows_per_run=read_int("GH_MAX_WINDOWS_PER_RUN", "7"),
            checkpoint_file=os.environ.get(
                "GH_CHECKPOINT_FILE",
                ".github/evidence_state/checkpoints/enterprise_audit_checkpoint.json",
            ).strip(),
            archive_root=os.environ.get("GH_ARCHIVE_ROOT", "evidence/archive").strip(),
            auto_push_checkpoint=os.environ.get("GH_AUTO_PUSH_CHECKPOINT", "1").strip().lower() not in {"0", "false", "no"},
            archive_s3_bucket=os.environ.get("GH_ARCHIVE_S3_BUCKET") or None,
            archive_s3_prefix=os.environ.get("GH_ARCHIVE_S3_PREFIX", "github-enterprise").strip(),
            aws_region=os.environ.get("GH_AWS_REGION") or None,
        )
    except Exception:
        return 2

    try:
        output_dir = collect(cfg)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(str(output_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
