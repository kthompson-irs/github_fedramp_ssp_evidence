#!/usr/bin/env python3
"""Collect FedRAMP evidence for GitHub.com IA-2(8) and adjacent controls.

Outputs a timestamped folder containing:
- org.json
- audit_log.jsonl
- audit_log.csv
- credential_authorizations.json
- installations.json
- summary.json
- manifest.md

Required env vars:
- GITHUB_TOKEN: GitHub PAT or App token with the required permissions
- GITHUB_ORG: organization name

Optional env vars:
- GITHUB_API_URL: default https://api.github.com
- GITHUB_API_VERSION: default 2022-11-28
- GITHUB_ENTERPRISE: enterprise slug (enables optional enterprise audit stream checks)
- GITHUB_DAYS: default 90; how many days of audit log to collect

Notes:
- The organization token must belong to an organization owner.
- Organization audit log access and SAML SSO authorization listing require owner privileges.
- Enterprise audit log streaming configuration checks are only attempted when GITHUB_ENTERPRISE is provided.
"""
from __future__ import annotations

import csv
import datetime as dt
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import requests


@dataclass
class GitHubConfig:
    token: str
    org: str
    api_url: str = "https://api.github.com"
    api_version: str = "2022-11-28"
    enterprise: Optional[str] = None
    days: int = 90
    timeout: int = 30


class GitHubClient:
    def __init__(self, cfg: GitHubConfig) -> None:
        self.cfg = cfg
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {cfg.token}",
                "X-GitHub-Api-Version": cfg.api_version,
                "User-Agent": "fedramp-ia208-evidence-collector/1.0",
            }
        )
        self._root_metadata: Optional[Dict[str, Any]] = None

    def _url(self, path_or_url: str) -> str:
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            return path_or_url
        return self.cfg.api_url.rstrip("/") + "/" + path_or_url.lstrip("/")

    def request(
        self,
        method: str,
        path_or_url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
    ) -> requests.Response:
        url = self._url(path_or_url)
        backoff = 2
        last_resp: Optional[requests.Response] = None

        for _attempt in range(6):
            resp = self.session.request(
                method,
                url,
                params=params,
                timeout=self.cfg.timeout,
            )
            last_resp = resp

            if resp.status_code not in (403, 429):
                return resp

            retry_after = resp.headers.get("Retry-After")
            if retry_after:
                try:
                    sleep_for = min(int(retry_after), 60)
                except ValueError:
                    sleep_for = min(backoff, 60)
                    backoff *= 2
            else:
                sleep_for = min(backoff, 60)
                backoff *= 2

            time.sleep(sleep_for)

        return last_resp if last_resp is not None else resp

    def _format_auth_hint(self, resp: requests.Response) -> str:
        sso = resp.headers.get("X-GitHub-SSO")
        parts = []
        if sso:
            parts.append(f"X-GitHub-SSO={sso}")
        if resp.headers.get("X-RateLimit-Remaining") is not None:
            parts.append(
                f"rate_limit_remaining={resp.headers.get('X-RateLimit-Remaining')}"
            )
        return f" ({'; '.join(parts)})" if parts else ""

    def get_json(self, path_or_url: str, *, params: Optional[Dict[str, Any]] = None) -> Any:
        resp = self.request("GET", path_or_url, params=params)

        if resp.status_code == 404:
            raise RuntimeError(
                f"GET {path_or_url} failed: 404 Not Found. "
                f"Verify the exact org login, token visibility, and API host. "
                f"Response: {resp.text[:400]}{self._format_auth_hint(resp)}"
            )

        if resp.status_code == 401:
            raise RuntimeError(
                f"GET {path_or_url} failed: 401 Unauthorized. "
                f"Check the token and whether it is valid for the target GitHub host. "
                f"Response: {resp.text[:400]}{self._format_auth_hint(resp)}"
            )

        if resp.status_code == 403:
            raise RuntimeError(
                f"GET {path_or_url} failed: 403 Forbidden. "
                f"Check token permissions and whether the token is authorized for SSO. "
                f"Response: {resp.text[:400]}{self._format_auth_hint(resp)}"
            )

        if resp.status_code >= 400:
            raise RuntimeError(
                f"GET {path_or_url} failed: {resp.status_code} {resp.text[:400]}"
            )

        return resp.json()

    def paginate(
        self,
        path_or_url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
    ) -> Iterable[Any]:
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
                    f"Verify the exact org login and API host. "
                    f"Response: {resp.text[:400]}{self._format_auth_hint(resp)}"
                )

            if resp.status_code == 401:
                raise RuntimeError(
                    f"GET {path_or_url} page {page} failed: 401 Unauthorized. "
                    f"Check token validity and host. Response: {resp.text[:400]}"
                )

            if resp.status_code == 403:
                raise RuntimeError(
                    f"GET {path_or_url} page {page} failed: 403 Forbidden. "
                    f"Check token permissions and SSO authorization. "
                    f"Response: {resp.text[:400]}{self._format_auth_hint(resp)}"
                )

            if resp.status_code >= 400:
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

    def root_metadata(self) -> Dict[str, Any]:
        if self._root_metadata is None:
            self._root_metadata = self.get_json("/")
        return self._root_metadata

    def org_url(self, org: str) -> str:
        root = self.root_metadata()
        template = root.get("organization_url", "/orgs/{org}")
        try:
            return template.format(org=org)
        except Exception:
            return f"/orgs/{org}"

    def current_user_url(self) -> str:
        root = self.root_metadata()
        return root.get("current_user_url", "/user")

    def user_orgs_url(self) -> str:
        root = self.root_metadata()
        return root.get("user_organizations_url", "/user/orgs")


def iso_date_days_ago(days: int) -> str:
    return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).date().isoformat()


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
        rel = file_path.relative_to(output_dir)
        lines.append(f"- {rel.as_posix()}")
    (output_dir / "manifest.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def visible_org_logins(client: GitHubClient) -> List[str]:
    try:
        return [
            item.get("login", "")
            for item in client.paginate(client.user_orgs_url())
            if isinstance(item, dict)
        ]
    except Exception:
        return []


def collect(cfg: GitHubConfig) -> Path:
    client = GitHubClient(cfg)

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_dir = Path.cwd() / f"github_ia208_evidence_{stamp}"
    output_dir.mkdir(parents=True, exist_ok=True)

    files: List[Path] = []

    if cfg.enterprise and "api.github.com" in cfg.api_url:
        print(
            f"WARNING: GITHUB_ENTERPRISE is set to '{cfg.enterprise}' but GITHUB_API_URL "
            f"is still '{cfg.api_url}'. If you are targeting GitHub Enterprise Server, "
            f"point GITHUB_API_URL at that host's API root.",
            file=sys.stderr,
        )

    root = client.root_metadata()
    org_url = client.org_url(cfg.org)

    try:
        org = client.get_json(org_url)
    except RuntimeError as exc:
        if "404 Not Found" in str(exc):
            visible_orgs = visible_org_logins(client)
            if visible_orgs:
                raise RuntimeError(
                    f"Organization '{cfg.org}' was not found or is not visible to this token. "
                    f"Visible orgs for the current token: {', '.join(sorted(set(visible_orgs)))}. "
                    f"Check the org login and whether the token is authorized for that org."
                ) from exc
            raise RuntimeError(
                f"Organization '{cfg.org}' was not found or is not visible to this token. "
                f"Check the org login, the token's access, and the API host."
            ) from exc
        raise

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

    audit_csv = output_dir / "audit_log.csv"
    rows_for_csv = [e for e in audit_events if "error" not in e]
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

    summary: Dict[str, Any] = {
        "org": cfg.org,
        "api_url": cfg.api_url,
        "enterprise": cfg.enterprise,
        "days_collected": cfg.days,
        "collected_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "root_organization_url_template": root.get("organization_url"),
        "root_user_organizations_url_template": root.get("user_organizations_url"),
        "org_two_factor_requirement_enabled": org.get("two_factor_requirement_enabled"),
        "org_has_saml_sso_authorizations_endpoint": True,
        "credential_authorization_count": len(cred_auths) if isinstance(cred_auths, list) else None,
        "installation_count": len(installations) if isinstance(installations, list) else None,
        "audit_event_count": len(rows_for_csv),
        "potential_gaps": [],
    }

    if not org.get("two_factor_requirement_enabled"):
        summary["potential_gaps"].append("Organization 2FA requirement is not enabled.")

    if isinstance(cred_auths, dict) and cred_auths.get("error"):
        summary["potential_gaps"].append(
            "Could not retrieve credential authorizations; verify org owner permissions and SAML SSO configuration."
        )

    if isinstance(audit_events, list) and audit_events and "error" in audit_events[0]:
        summary["potential_gaps"].append(
            "Could not retrieve audit log; verify owner permissions, token scope, and API host."
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
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    org = os.environ.get("GITHUB_ORG", "").strip()

    if not token or not org:
        print("Set GITHUB_TOKEN and GITHUB_ORG before running.", file=sys.stderr)
        return 2

    api_url = os.environ.get("GITHUB_API_URL", "https://api.github.com").strip()
    api_version = os.environ.get("GITHUB_API_VERSION", "2022-11-28").strip()
    enterprise = os.environ.get("GITHUB_ENTERPRISE") or None

    try:
        days = int(os.environ.get("GITHUB_DAYS", "90"))
    except ValueError:
        print("GITHUB_DAYS must be an integer.", file=sys.stderr)
        return 2

    cfg = GitHubConfig(
        token=token,
        org=org,
        api_url=api_url,
        api_version=api_version,
        enterprise=enterprise,
        days=days,
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
