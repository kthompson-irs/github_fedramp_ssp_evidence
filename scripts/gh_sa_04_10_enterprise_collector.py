#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

GH_API = "https://api.github.com"
PAGE_SIZE = 100
TIMEOUT_SECONDS = 30


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def fail(message: str, exit_code: int = 1) -> None:
    print(f"SA-04(10) COMPLIANCE FAILURE: {message}")
    sys.exit(exit_code)


def get_env(name: str, default: Optional[str] = None) -> str:
    value = os.getenv(name, default)
    if value is None or value == "":
        fail(f"required environment variable {name} is not set", exit_code=2)
    return value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Enterprise SA-04(10) alert collector.")
    parser.add_argument(
        "--scope",
        choices=["repository", "organization", "enterprise"],
        default=os.getenv("GH_ALERT_SCOPE", "enterprise"),
        help="Alert scope to inspect.",
    )
    parser.add_argument(
        "--enterprise",
        default=os.getenv("GH_ENTERPRISE_SLUG", ""),
        help="Enterprise slug, required when scope=enterprise.",
    )
    parser.add_argument(
        "--owner",
        default=os.getenv("GH_ORG_NAME", ""),
        help="Repository owner or organization name.",
    )
    parser.add_argument(
        "--repo",
        default="",
        help="Repository name. If omitted, parsed from GH_REPOSITORY.",
    )
    parser.add_argument(
        "--output-dir",
        default="artifacts/sa-04-10",
        help="Directory where evidence and summary files are written.",
    )
    parser.add_argument(
        "--soft-fail",
        action="store_true",
        help="Record collection errors and continue so the evidence package can still be built.",
    )
    return parser.parse_args()


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def repo_parts() -> Tuple[str, str]:
    repo_full = get_env("GH_REPOSITORY")
    if "/" not in repo_full:
        fail(f"GH_REPOSITORY is malformed: {repo_full}", exit_code=2)
    owner, repo = repo_full.split("/", 1)
    return owner, repo


def normalize_scope(scope: str) -> str:
    scope = (scope or "").strip().lower()
    if scope not in {"repository", "organization", "enterprise"}:
        fail(f"unsupported scope: {scope}", exit_code=2)
    return scope


def scope_base(scope: str, owner: str, repo: str, enterprise: str) -> str:
    if scope == "repository":
        if not owner or not repo:
            fail("repository scope requires owner and repo values", exit_code=2)
        return f"/repos/{owner}/{repo}"
    if scope == "organization":
        if not owner:
            fail("organization scope requires owner", exit_code=2)
        return f"/orgs/{owner}"
    if scope == "enterprise":
        if not enterprise:
            fail("enterprise scope requires enterprise slug", exit_code=2)
        return f"/enterprises/{enterprise}"
    fail(f"unsupported scope: {scope}", exit_code=2)
    return ""


def display_context(scope: str, owner: str, repo: str, enterprise: str) -> Dict[str, str]:
    if scope == "enterprise":
        return {
            "organization": "enterprise-wide",
            "repository": "enterprise-wide",
            "repository_full": f"enterprise/{enterprise}" if enterprise else "enterprise-wide",
        }
    return {
        "organization": owner,
        "repository": repo,
        "repository_full": f"{owner}/{repo}",
    }


def token_candidates(scope: str) -> List[Tuple[str, str]]:
    if scope == "enterprise":
        return [
            ("GH_ENTERPRISE_TOKEN", "enterprise_token"),
            ("GH_DEPENDABOT_TOKEN", "dependabot_token_fallback"),
            ("GH_AUTH_TOKEN", "auth_fallback"),
        ]
    return [
        ("GH_APP_TOKEN", "github_app_token"),
        ("GH_DEPENDABOT_TOKEN", "dependabot_token_fallback"),
        ("GH_AUTH_TOKEN", "auth_fallback"),
    ]


def make_headers(token: str, auth_kind: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "X-SA04-AUTH-KIND": auth_kind,
    }


def accepted_permissions(response: requests.Response) -> Optional[str]:
    return response.headers.get("X-Accepted-GitHub-Permissions")


def sso_header(response: requests.Response) -> Optional[str]:
    return response.headers.get("X-GitHub-SSO")


def response_excerpt(response: requests.Response, limit: int = 400) -> str:
    try:
        payload = response.json()
        if isinstance(payload, dict):
            message = payload.get("message")
            if message:
                return str(message)[:limit]
            return json.dumps(payload)[:limit]
        return response.text[:limit]
    except Exception:
        return response.text[:limit]


def request_one(url: str, headers: Dict[str, str], params: Optional[Dict[str, Any]] = None) -> requests.Response:
    return requests.get(url, headers=headers, params=params or {}, timeout=TIMEOUT_SECONDS)


def probe_identity(headers: Dict[str, str]) -> Dict[str, Any]:
    url = f"{GH_API}/user"
    try:
        response = requests.get(url, headers=headers, timeout=TIMEOUT_SECONDS)
        info: Dict[str, Any] = {
            "kind": "identity",
            "endpoint": "/user",
            "status_code": response.status_code,
            "accepted_permissions": accepted_permissions(response),
            "sso": sso_header(response),
            "message": response_excerpt(response),
        }
        if response.status_code == 200:
            try:
                payload = response.json()
                if isinstance(payload, dict):
                    info["login"] = payload.get("login")
                    info["id"] = payload.get("id")
                    info["type"] = payload.get("type")
                    info["name"] = payload.get("name")
            except Exception:
                pass
        return info
    except Exception as exc:
        return {
            "kind": "identity",
            "endpoint": "/user",
            "status_code": None,
            "accepted_permissions": None,
            "sso": None,
            "message": str(exc),
        }


def parse_next_link(link_header: Optional[str]) -> Optional[str]:
    if not link_header:
        return None

    parts = [p.strip() for p in link_header.split(",")]
    for part in parts:
        if 'rel="next"' not in part:
            continue
        start = part.find("<")
        end = part.find(">")
        if start != -1 and end != -1 and end > start + 1:
            return part[start + 1 : end]
    return None


def classify_error(response: requests.Response) -> str:
    msg = response_excerpt(response).lower()
    if response.status_code == 401:
        return "token_invalid_or_expired"
    if response.status_code == 403:
        if sso_header(response):
            return "sso_required"
        perm = accepted_permissions(response)
        if perm:
            return f"insufficient_permissions:{perm}"
        return "forbidden"
    if response.status_code == 404:
        return "not_found_or_not_authorized"
    if response.status_code == 400 and "pagination using the `page` parameter is not supported" in msg:
        return "request_shape_invalid_pagination"
    if response.status_code == 400:
        return "bad_request"
    return f"http_{response.status_code}"


def list_alerts_paginated(
    url: str,
    headers: Dict[str, str],
    params: Optional[Dict[str, Any]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Fetch a GitHub REST collection using cursor-style pagination via Link headers.
    This avoids sending `page`, which enterprise Dependabot alerts rejects.
    Returns (items, page_diagnostics).
    """
    items: List[Dict[str, Any]] = []
    diagnostics: List[Dict[str, Any]] = []

    next_url: Optional[str] = url
    query = dict(params or {})
    query.setdefault("per_page", PAGE_SIZE)

    while next_url:
        response = requests.get(next_url, headers=headers, params=query, timeout=TIMEOUT_SECONDS)
        diag = {
            "kind": "page",
            "url": next_url,
            "status_code": response.status_code,
            "accepted_permissions": accepted_permissions(response),
            "sso": sso_header(response),
            "message": response_excerpt(response),
        }
        diagnostics.append(diag)

        if response.status_code != 200:
            raise RuntimeError(
                f"GitHub API request failed for {next_url}: {classify_error(response)} | "
                f"accepted_permissions={accepted_permissions(response)!r} | "
                f"sso={sso_header(response)!r} | body={response_excerpt(response)}"
            )

        payload = response.json()
        if not isinstance(payload, list):
            raise RuntimeError(f"unexpected response shape from {next_url}")

        items.extend(payload)

        next_url = parse_next_link(response.headers.get("Link"))
        query = {}

    return items, diagnostics


def rank(severity: str) -> int:
    return {"low": 1, "medium": 2, "moderate": 2, "high": 3, "critical": 4}.get((severity or "").lower(), 0)


def blocking(severity: str, threshold: str) -> bool:
    return rank(severity) >= rank(threshold) > 0


def parse_repo_context(alert: Dict[str, Any], fallback_repository_full: str = "") -> Dict[str, str]:
    repository = alert.get("repository") or {}
    repo_full = ""
    organization = ""
    repo_name = ""

    if isinstance(repository, dict) and repository:
        repo_full = str(repository.get("full_name") or "").strip()
        repo_name = str(repository.get("name") or "").strip()
        owner = repository.get("owner") or {}
        if isinstance(owner, dict):
            organization = str(owner.get("login") or "").strip()

    if not repo_full:
        repo_url = str(alert.get("repository_url") or "").strip()
        if repo_url:
            parsed = urlparse(repo_url)
            parts = [p for p in parsed.path.split("/") if p]
            if len(parts) >= 3 and parts[0] == "repos":
                organization = organization or parts[1]
                repo_name = repo_name or parts[2]
                repo_full = f"{organization}/{repo_name}"

    if not repo_full and fallback_repository_full:
        repo_full = fallback_repository_full
        if "/" in fallback_repository_full:
            organization, repo_name = fallback_repository_full.split("/", 1)

    if not organization and repo_full and "/" in repo_full:
        organization = repo_full.split("/", 1)[0]
    if not repo_name and repo_full and "/" in repo_full:
        repo_name = repo_full.split("/", 1)[1]

    return {
        "organization": organization,
        "repository": repo_name,
        "repository_full": repo_full,
    }


def normalize_alert(alert: Dict[str, Any], fallback_repository_full: str = "") -> Dict[str, Any]:
    normalized = dict(alert)
    repo_ctx = parse_repo_context(normalized, fallback_repository_full=fallback_repository_full)
    normalized["organization"] = repo_ctx["organization"]
    normalized["repository"] = repo_ctx["repository"]
    normalized["repository_full"] = repo_ctx["repository_full"]
    return normalized


def codeql_findings(alerts: List[Dict[str, Any]], threshold: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for alert in alerts:
        rule = alert.get("rule") or {}
        severity = str(rule.get("severity") or "").lower()
        if not blocking(severity, threshold):
            continue
        loc = (alert.get("most_recent_instance") or {}).get("location") or {}
        findings.append(
            {
                "category": "code_scanning",
                "identifier": rule.get("id") or "unknown-rule",
                "title": rule.get("name") or "unknown-title",
                "severity": severity,
                "state": alert.get("state") or "open",
                "html_url": alert.get("html_url"),
                "organization": alert.get("organization") or "",
                "repository": alert.get("repository") or "",
                "repository_full": alert.get("repository_full") or "",
                "path": loc.get("path"),
                "start_line": loc.get("start_line"),
                "end_line": loc.get("end_line"),
            }
        )
    return findings


def dependabot_findings(alerts: List[Dict[str, Any]], threshold: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for alert in alerts:
        advisory = alert.get("security_advisory") or {}
        severity = str(advisory.get("severity") or "").lower()
        if not blocking(severity, threshold):
            continue
        dependency = (((alert.get("dependency") or {}).get("package") or {}).get("name")) or "unknown-package"
        findings.append(
            {
                "category": "dependabot",
                "identifier": advisory.get("ghsa_id") or advisory.get("cve_id") or "unknown-advisory",
                "title": advisory.get("summary") or "unknown-advisory",
                "severity": severity,
                "state": alert.get("state") or "open",
                "html_url": alert.get("html_url"),
                "organization": alert.get("organization") or "",
                "repository": alert.get("repository") or "",
                "repository_full": alert.get("repository_full") or "",
                "dependency": dependency,
                "manifest_path": ((alert.get("dependency") or {}).get("manifest_path")),
            }
        )
    return findings


def secret_findings(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for alert in alerts:
        findings.append(
            {
                "category": "secret_scanning",
                "identifier": alert.get("secret_type") or alert.get("secret_type_display_name") or "unknown-secret",
                "title": alert.get("secret_type_display_name") or alert.get("secret_type") or "unknown-secret",
                "severity": "open",
                "state": alert.get("state") or "open",
                "html_url": alert.get("html_url"),
                "organization": alert.get("organization") or "",
                "repository": alert.get("repository") or "",
                "repository_full": alert.get("repository_full") or "",
                "secret_type": alert.get("secret_type"),
            }
        )
    return findings


def probe(scope: str, base_path: str, headers: Dict[str, str]) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Self-diagnosing probe for candidate tokens.
    Uses per_page only and no page parameter.
    """
    diagnostics: List[Dict[str, Any]] = []

    identity = probe_identity(headers)
    diagnostics.append(identity)

    endpoints = [
        ("code_scanning", f"{GH_API}{base_path}/code-scanning/alerts"),
        ("dependabot", f"{GH_API}{base_path}/dependabot/alerts"),
        ("secret_scanning", f"{GH_API}{base_path}/secret-scanning/alerts"),
    ]

    for category, url in endpoints:
        response = request_one(url, headers, params={"state": "open", "per_page": 1})
        diagnostics.append(
            {
                "kind": "probe",
                "category": category,
                "url": url,
                "status_code": response.status_code,
                "accepted_permissions": accepted_permissions(response),
                "sso": sso_header(response),
                "message": response_excerpt(response),
            }
        )
        if response.status_code != 200:
            return False, diagnostics

    return True, diagnostics


def collect_category(
    base_path: str,
    headers: Dict[str, str],
    category: str,
    threshold: str,
    fallback_repository_full: str,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    endpoint_lookup = {
        "code_scanning": "code-scanning/alerts",
        "dependabot": "dependabot/alerts",
        "secret_scanning": "secret-scanning/alerts",
    }
    if category not in endpoint_lookup:
        fail(f"unsupported category: {category}", exit_code=2)

    url = f"{GH_API}{base_path}/{endpoint_lookup[category]}"
    alerts, page_diagnostics = list_alerts_paginated(
        url,
        headers,
        params={"state": "open", "per_page": PAGE_SIZE},
    )

    normalized_alerts = [normalize_alert(alert, fallback_repository_full=fallback_repository_full) for alert in alerts]

    if category == "code_scanning":
        blocking_items = codeql_findings(normalized_alerts, threshold)
    elif category == "dependabot":
        blocking_items = dependabot_findings(normalized_alerts, threshold)
    else:
        blocking_items = secret_findings(normalized_alerts)

    result = {
        "accessible": True,
        "skipped": False,
        "skip_reason": None,
        "count": len(normalized_alerts),
        "blocking_count": len(blocking_items),
        "alerts": normalized_alerts,
    }
    evidence_lines = [f"SSP-EVIDENCE: {category} alert polling completed successfully"]
    return result, blocking_items, page_diagnostics, evidence_lines


def append_history(output_dir: Path, snapshot: Dict[str, Any]) -> None:
    hist_dir = output_dir / "history"
    hist_dir.mkdir(parents=True, exist_ok=True)

    line = json.dumps(snapshot, sort_keys=True)
    with (hist_dir / "history.jsonl").open("a", encoding="utf-8") as f:
        f.write(line + "\n")

    write_json(hist_dir / f"{snapshot['date']}.json", snapshot)


def build_snapshot(
    scope: str,
    organization: str,
    repository: str,
    repository_full: str,
    enterprise: str,
    auth_kind: str,
    results: Dict[str, Any],
    blocking_findings: List[Dict[str, Any]],
    errors: List[str],
    repositories: List[str],
    evidence_lines: List[str],
) -> Dict[str, Any]:
    generated_at = utc_now()
    date = generated_at[:10]

    overall_status = "pass"
    if errors:
        overall_status = "error"
    elif blocking_findings:
        overall_status = "fail"

    return {
        "generated_at": generated_at,
        "date": date,
        "scope": scope,
        "organization": organization,
        "repository": repository,
        "repository_full": repository_full,
        "enterprise": enterprise,
        "repository_count": len(repositories),
        "repositories": repositories,
        "auth_kind": auth_kind,
        "results": results,
        "blocking_findings": blocking_findings,
        "errors": errors,
        "evidence_lines": evidence_lines,
        "overall": {
            "blocking_count": len(blocking_findings),
            "error_count": len(errors),
            "status": overall_status,
        },
    }


def write_summary_files(output_dir: Path, snapshot: Dict[str, Any], auth_attempts: List[Dict[str, Any]]) -> None:
    write_json(output_dir / "summary.json", snapshot)
    write_json(output_dir / "current_snapshot.json", snapshot)
    write_json(output_dir / "blocking_findings.json", snapshot.get("blocking_findings", []))
    write_json(output_dir / "auth_attempts.json", auth_attempts)
    write_text(output_dir / "evidence_lines.txt", "\n".join(snapshot.get("evidence_lines", [])) + "\n")
    write_text(
        output_dir / "repositories.txt",
        "\n".join(snapshot.get("repositories", [])) + ("\n" if snapshot.get("repositories") else ""),
    )


def render_summary_md(snapshot: Dict[str, Any], auth_attempts: List[Dict[str, Any]]) -> str:
    results = snapshot.get("results", {}) or {}
    overall = snapshot.get("overall", {}) or {}

    lines = [
        "# SA-04(10) Evidence Collection Summary",
        "",
        f"- Generated at: `{snapshot.get('generated_at', '')}`",
        f"- Scope: `{snapshot.get('scope', '')}`",
        f"- Organization: `{snapshot.get('organization', '')}`",
        f"- Repository: `{snapshot.get('repository', '')}`",
        f"- Repository full: `{snapshot.get('repository_full', '')}`",
        f"- Enterprise: `{snapshot.get('enterprise', '')}`",
        f"- Repository count: `{snapshot.get('repository_count', 0)}`",
        f"- Auth kind: `{snapshot.get('auth_kind', '')}`",
        f"- Blocking findings: `{overall.get('blocking_count', 0)}`",
        f"- Collection errors: `{overall.get('error_count', 0)}`",
        f"- Status: `{overall.get('status', '')}`",
        "",
        "## Authentication Attempts",
        "",
        "| Token Env | Auth Kind | Status |",
        "|---|---|---|",
    ]

    for attempt in auth_attempts:
        lines.append(f"| {attempt.get('token_env', '')} | {attempt.get('auth_kind', '')} | {attempt.get('status', '')} |")

    lines.extend(["", "## Covered Repositories", ""])
    for repo in snapshot.get("repositories", []) or []:
        lines.append(f"- {repo}")

    lines.extend(
        [
            "",
            "## Category Results",
            "",
            "| Category | Accessible | Skipped | Count | Blocking |",
            "|---|---:|---:|---:|---:|",
        ]
    )

    for category in ("code_scanning", "dependabot", "secret_scanning"):
        item = results.get(category, {}) or {}
        lines.append(
            f"| {category} | {str(item.get('accessible', False)).lower()} | "
            f"{str(item.get('skipped', False)).lower()} | {item.get('count', 0)} | "
            f"{item.get('blocking_count', 0)} |"
        )

    lines.extend(["", "## Evidence Lines", ""])
    for entry in snapshot.get("evidence_lines", []):
        lines.append(f"- {entry}")

    if snapshot.get("errors"):
        lines.extend(["", "## Collection Errors", ""])
        for entry in snapshot["errors"]:
            lines.append(f"- {entry}")

    return "\n".join(lines) + "\n"


def render_diagnostics_md(diagnostics: Dict[str, Any]) -> str:
    lines = [
        "# SA-04(10) Collector Diagnostics",
        "",
        f"- Generated at: `{diagnostics.get('generated_at', '')}`",
        f"- Scope: `{diagnostics.get('scope', '')}`",
        f"- Enterprise: `{diagnostics.get('enterprise', '')}`",
        f"- Organization: `{diagnostics.get('organization', '')}`",
        f"- Repository: `{diagnostics.get('repository', '')}`",
        f"- Repository full: `{diagnostics.get('repository_full', '')}`",
        f"- Selected auth kind: `{diagnostics.get('selected_auth_kind', '')}`",
        "",
        "## Token Attempts",
        "",
    ]

    for attempt in diagnostics.get("token_attempts", []) or []:
        lines.extend(
            [
                f"### {attempt.get('token_env', '')}",
                f"- Auth kind: `{attempt.get('auth_kind', '')}`",
                f"- Status: `{attempt.get('status', '')}`",
            ]
        )
        identity = attempt.get("identity") or {}
        if identity:
            lines.append(f"- Token login: `{identity.get('login', '')}`")
            lines.append(f"- Token type: `{identity.get('type', '')}`")
            lines.append(f"- Identity status: `{identity.get('status_code', '')}`")
            if identity.get("accepted_permissions"):
                lines.append(f"- Identity accepted permissions: `{identity.get('accepted_permissions', '')}`")
            if identity.get("sso"):
                lines.append(f"- Identity SSO: `{identity.get('sso', '')}`")
            if identity.get("message"):
                lines.append(f"- Identity message: `{identity.get('message', '')}`")

        probes = attempt.get("probe", []) or []
        if probes:
            lines.append("")
            lines.append("| Kind | Category | Status | Accepted Permissions | SSO | Message |")
            lines.append("|---|---|---:|---|---|---|")
            for probe_item in probes:
                lines.append(
                    f"| {probe_item.get('kind', '')} | {probe_item.get('category', '')} | "
                    f"{probe_item.get('status_code', '')} | {probe_item.get('accepted_permissions', '') or ''} | "
                    f"{probe_item.get('sso', '') or ''} | {probe_item.get('message', '')} |"
                )
        lines.append("")

    if diagnostics.get("notes"):
        lines.extend(["## Notes", ""])
        for note in diagnostics["notes"]:
            lines.append(f"- {note}")
        lines.append("")

    return "\n".join(lines) + "\n"


def collect_soft_failure_snapshot(
    scope: str,
    organization: str,
    repository: str,
    repository_full: str,
    enterprise: str,
    token_attempts: List[Dict[str, Any]],
    diagnostics_notes: List[str],
) -> Dict[str, Any]:
    return {
        "generated_at": utc_now(),
        "date": utc_now()[:10],
        "scope": scope,
        "organization": organization,
        "repository": repository,
        "repository_full": repository_full,
        "enterprise": enterprise,
        "repository_count": 0,
        "repositories": [],
        "auth_kind": "none",
        "results": {
            "code_scanning": {
                "accessible": False,
                "skipped": True,
                "skip_reason": "no usable token",
                "count": 0,
                "blocking_count": 0,
                "alerts": [],
            },
            "dependabot": {
                "accessible": False,
                "skipped": True,
                "skip_reason": "no usable token",
                "count": 0,
                "blocking_count": 0,
                "alerts": [],
            },
            "secret_scanning": {
                "accessible": False,
                "skipped": True,
                "skip_reason": "no usable token",
                "count": 0,
                "blocking_count": 0,
                "alerts": [],
            },
        },
        "blocking_findings": [],
        "errors": ["no usable token found for the selected scope"],
        "evidence_lines": ["SSP-EVIDENCE: no usable token found; collection was not performed."],
        "overall": {"blocking_count": 0, "error_count": 1, "status": "error"},
        "token_attempts": token_attempts,
        "notes": diagnostics_notes,
    }


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    owner_default, repo_default = repo_parts()

    organization = args.owner or owner_default
    repository = args.repo or repo_default
    enterprise = args.enterprise or os.getenv("GH_ENTERPRISE_SLUG", "")
    scope = normalize_scope(args.scope)
    threshold = os.getenv("FAIL_ON_SEVERITY", "high").strip().lower()
    soft_fail = args.soft_fail or os.getenv("SA04_SOFT_FAIL", "") == "1"

    if threshold not in {"low", "medium", "moderate", "high", "critical"}:
        fail(f"invalid FAIL_ON_SEVERITY value: {threshold}", exit_code=2)

    ctx = display_context(scope, organization, repository, enterprise)
    base_path = scope_base(scope, organization, repository, enterprise)

    print("SA-04(10) enterprise collector starting")
    print(f"Scope: {scope}")
    print(f"Organization: {ctx['organization']}")
    print(f"Repository: {ctx['repository']}")
    print(f"Repository full: {ctx['repository_full']}")
    print(f"Enterprise: {enterprise}")
    print(f"Blocking threshold: {threshold}")
    print(f"Soft fail: {soft_fail}")

    results: Dict[str, Any] = {}
    evidence_lines: List[str] = []
    errors: List[str] = []
    blocking_findings: List[Dict[str, Any]] = []
    repositories_seen: set[str] = set()
    token_attempts_diag: List[Dict[str, Any]] = []
    diagnostics_notes: List[str] = []

    selected_headers: Optional[Dict[str, str]] = None
    selected_auth_kind: str = "none"

    for env_name, auth_kind in token_candidates(scope):
        token = os.getenv(env_name)
        attempt: Dict[str, Any] = {
            "token_env": env_name,
            "auth_kind": auth_kind,
            "status": "missing",
            "identity": None,
            "probe": [],
        }

        if not token:
            token_attempts_diag.append(attempt)
            continue

        headers = make_headers(token, auth_kind)
        identity = probe_identity(headers)
        attempt["identity"] = identity

        try:
            ok, probe_diag = probe(scope, base_path, headers)
            attempt["probe"] = probe_diag
            attempt["status"] = "ok" if ok else "rejected"
            token_attempts_diag.append(attempt)
            if ok:
                selected_headers = headers
                selected_auth_kind = auth_kind
                diagnostics_notes.append(f"Selected token from {env_name} with auth kind {auth_kind}.")
                break
        except requests.RequestException as exc:
            attempt["status"] = "rejected"
            attempt["probe"] = [
                {
                    "kind": "probe_error",
                    "category": "unknown",
                    "status_code": None,
                    "accepted_permissions": None,
                    "sso": None,
                    "message": str(exc),
                }
            ]
            token_attempts_diag.append(attempt)

    if selected_headers is None:
        diagnostics = {
            "generated_at": utc_now(),
            "scope": scope,
            "enterprise": enterprise,
            "organization": ctx["organization"],
            "repository": ctx["repository"],
            "repository_full": ctx["repository_full"],
            "selected_auth_kind": "none",
            "token_attempts": token_attempts_diag,
            "notes": diagnostics_notes
            + [
                "No candidate token could access the required endpoints.",
                "Review the probe status, accepted permissions, SSO header, and token owner access.",
            ],
        }
        write_json(output_dir / "diagnostics.json", diagnostics)
        write_text(output_dir / "diagnostics.md", render_diagnostics_md(diagnostics))

        if soft_fail:
            snapshot = collect_soft_failure_snapshot(
                scope=scope,
                organization=ctx["organization"],
                repository=ctx["repository"],
                repository_full=ctx["repository_full"],
                enterprise=enterprise,
                token_attempts=token_attempts_diag,
                diagnostics_notes=diagnostics_notes,
            )
            append_history(output_dir, snapshot)
            write_summary_files(output_dir, snapshot, token_attempts_diag)
            write_text(output_dir / "summary.md", render_summary_md(snapshot, token_attempts_diag))
            print("SA-04(10) collection soft-failed; diagnostics were written for review.")
            return 0

        fail(
            "no usable token found for the selected scope. "
            "Check token scope, SSO authorization, enterprise membership, org role, or enterprise PAT policy.",
            exit_code=2,
        )

    print(f"Selected auth kind: {selected_auth_kind}")

    try:
        print("Phase 1: code scanning alert polling")
        code_result, code_blocking, code_pages, code_evidence = collect_category(
            base_path=base_path,
            headers=selected_headers,
            category="code_scanning",
            threshold=threshold,
            fallback_repository_full=ctx["repository_full"],
        )
        results["code_scanning"] = code_result
        blocking_findings.extend(code_blocking)
        evidence_lines.extend(code_evidence)
        write_json(output_dir / "code_scanning_alerts.json", code_result["alerts"])
        write_json(output_dir / "code_scanning_probe_diagnostics.json", code_pages)
    except Exception as exc:
        if soft_fail:
            results["code_scanning"] = {
                "accessible": False,
                "skipped": True,
                "skip_reason": str(exc),
                "count": 0,
                "blocking_count": 0,
                "alerts": [],
            }
            errors.append(str(exc))
            diagnostics_notes.append(f"code scanning collection error: {exc}")
            write_json(output_dir / "code_scanning_error.json", {"error": str(exc)})
        else:
            fail(str(exc), exit_code=2)

    try:
        print("Phase 2: Dependabot alert polling")
        dep_result, dep_blocking, dep_pages, dep_evidence = collect_category(
            base_path=base_path,
            headers=selected_headers,
            category="dependabot",
            threshold=threshold,
            fallback_repository_full=ctx["repository_full"],
        )
        results["dependabot"] = dep_result
        blocking_findings.extend(dep_blocking)
        evidence_lines.extend(dep_evidence)
        write_json(output_dir / "dependabot_alerts.json", dep_result["alerts"])
        write_json(output_dir / "dependabot_probe_diagnostics.json", dep_pages)
    except Exception as exc:
        if soft_fail:
            results["dependabot"] = {
                "accessible": False,
                "skipped": True,
                "skip_reason": str(exc),
                "count": 0,
                "blocking_count": 0,
                "alerts": [],
            }
            errors.append(str(exc))
            diagnostics_notes.append(f"dependabot collection error: {exc}")
            write_json(output_dir / "dependabot_error.json", {"error": str(exc)})
        else:
            fail(str(exc), exit_code=2)

    try:
        print("Phase 3: secret scanning alert polling")
        sec_result, sec_blocking, sec_pages, sec_evidence = collect_category(
            base_path=base_path,
            headers=selected_headers,
            category="secret_scanning",
            threshold=threshold,
            fallback_repository_full=ctx["repository_full"],
        )
        results["secret_scanning"] = sec_result
        blocking_findings.extend(sec_blocking)
        evidence_lines.extend(sec_evidence)
        write_json(output_dir / "secret_scanning_alerts.json", sec_result["alerts"])
        write_json(output_dir / "secret_scanning_probe_diagnostics.json", sec_pages)
    except Exception as exc:
        if soft_fail:
            results["secret_scanning"] = {
                "accessible": False,
                "skipped": True,
                "skip_reason": str(exc),
                "count": 0,
                "blocking_count": 0,
                "alerts": [],
            }
            errors.append(str(exc))
            diagnostics_notes.append(f"secret scanning collection error: {exc}")
            write_json(output_dir / "secret_scanning_error.json", {"error": str(exc)})
        else:
            fail(str(exc), exit_code=2)

    for category_name in ("code_scanning", "dependabot", "secret_scanning"):
        for alert in (results.get(category_name, {}) or {}).get("alerts", []) or []:
            repo_full = str(alert.get("repository_full") or "").strip()
            if repo_full:
                repositories_seen.add(repo_full)

    repositories = sorted(repositories_seen)

    snapshot = build_snapshot(
        scope=scope,
        organization=ctx["organization"],
        repository=ctx["repository"],
        repository_full=ctx["repository_full"],
        enterprise=enterprise,
        auth_kind=selected_auth_kind,
        results=results,
        blocking_findings=blocking_findings,
        errors=errors,
        repositories=repositories,
        evidence_lines=evidence_lines,
    )

    append_history(output_dir, snapshot)
    write_summary_files(output_dir, snapshot, token_attempts_diag)
    write_text(output_dir / "summary.md", render_summary_md(snapshot, token_attempts_diag))

    diagnostics = {
        "generated_at": utc_now(),
        "scope": scope,
        "enterprise": enterprise,
        "organization": ctx["organization"],
        "repository": ctx["repository"],
        "repository_full": ctx["repository_full"],
        "selected_auth_kind": selected_auth_kind,
        "token_attempts": token_attempts_diag,
        "notes": diagnostics_notes,
    }
    write_json(output_dir / "diagnostics.json", diagnostics)
    write_text(output_dir / "diagnostics.md", render_diagnostics_md(diagnostics))

    print("")
    print("SA-04(10) collection complete")
    print(f"Organization: {snapshot['organization']}")
    print(f"Repository: {snapshot['repository']}")
    print(f"Repository full: {snapshot['repository_full']}")
    print(f"Repository count: {snapshot['repository_count']}")
    print(f"Blocking findings: {snapshot['overall']['blocking_count']}")
    print(f"Collection errors: {snapshot['overall']['error_count']}")

    if soft_fail:
        print("SA-04(10) collection was soft-failed so the FedRAMP package could be built.")
        return 0

    if snapshot["overall"]["error_count"] > 0:
        return 2
    if snapshot["overall"]["blocking_count"] > 0:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
