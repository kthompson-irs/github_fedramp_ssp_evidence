#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlpars:contentReference[oaicite:0]{index=0}SECONDS = 30
DEFAULT_AUDIT_LOOKBACK_DAYS = 30


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def utc_date_days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).date().isoformat()


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
        "--audit-lookback-days",
        type=int,
        default=int(os.getenv("GH_AUDIT_LOOKBACK_DAYS", str(DEFAULT_AUDIT_LOOKBACK_DAYS))),
        help="Number of days to include in the enterprise audit log snapshot.",
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


def write_csv(path: Path, fieldnames: List[str], rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


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


def token_candidates_alerts(scope: str) -> List[Tuple[str, str]]:
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


def token_candidates_admin() -> List[Tuple[str, str]]:
    return [
        ("GH_AUDIT_TOKEN", "audit_token"),
        ("GH_ENTERPRISE_TOKEN", "enterprise_token"),
        ("GH_AUTH_TOKEN", "auth_fallback"),
        ("GH_DEPENDABOT_TOKEN", "dependabot_token_fallback"),
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


def page_get(
    url: str,
    headers: Dict[str, str],
    params: Optional[Dict[str, Any]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    results: List[Dict[str, Any]] = []
    diagnostics: List[Dict[str, Any]] = []
    page = 1

    while True:
        query = dict(params or {})
        query["per_page"] = PAGE_SIZE
        query["page"] = page

        response = requests.get(url, headers=headers, params=query, timeout=TIMEOUT_SECONDS)
        diag = {
            "kind": "page",
            "url": url,
            "page": page,
            "status_code": response.status_code,
            "accepted_permissions": accepted_permissions(response),
            "sso": sso_header(response),
            "message": response_excerpt(response),
        }
        diagnostics.append(diag)

        if response.status_code != 200:
            raise RuntimeError(
                f"GitHub API request failed for {url}: {classify_error(response)} | "
                f"accepted_permissions={accepted_permissions(response)!r} | "
                f"sso={sso_header(response)!r} | body={response_excerpt(response)}"
            )

        payload = response.json()
        if not isinstance(payload, list):
            raise RuntimeError(f"unexpected response shape from {url}")

        if not payload:
            break

        results.extend(payload)

        if len(payload) < PAGE_SIZE:
            break

        page += 1

    return results, diagnostics


def cursor_get(
    url: str,
    headers: Dict[str, str],
    params: Optional[Dict[str, Any]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    results: List[Dict[str, Any]] = []
    diagnostics: List[Dict[str, Any]] = []
    next_url: Optional[str] = url
    query = dict(params or {})
    query.setdefault("per_page", PAGE_SIZE)

    while next_url:
        response = requests.get(next_url, headers=headers, params=query, timeout=TIMEOUT_SECONDS)
        diag = {
            "kind": "cursor",
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

        results.extend(payload)
        next_url = parse_next_link(response.headers.get("Link"))
        query = {}

    return results, diagnostics


def probe_alert_access(scope: str, base_path: str, headers: Dict[str, str]) -> Tuple[bool, List[Dict[str, Any]]]:
    diagnostics: List[Dict[str, Any]] = [probe_identity(headers)]
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


def probe_admin_access(enterprise_slug: str, headers: Dict[str, str], lookback_days: int) -> Tuple[bool, List[Dict[str, Any]]]:
    diagnostics: List[Dict[str, Any]] = [probe_identity(headers)]
    url = f"{GH_API}/enterprises/{enterprise_slug}/audit-log"
    response = request_one(
        url,
        headers,
        params={
            "phrase": f"created:>={utc_date_days_ago(lookback_days)}",
            "include": "all",
            "per_page": 1,
            "page": 1,
        },
    )
    diagnostics.append(
        {
            "kind": "probe",
            "category": "enterprise_audit_log",
            "url": url,
            "status_code": response.status_code,
            "accepted_permissions": accepted_permissions(response),
            "sso": sso_header(response),
            "message": response_excerpt(response),
        }
    )
    return response.status_code == 200, diagnostics


def choose_alert_token(scope: str, base_path: str) -> Tuple[Optional[Dict[str, str]], List[Dict[str, Any]], str]:
    attempts: List[Dict[str, Any]] = []

    for env_name, auth_kind in token_candidates_alerts(scope):
        token = os.getenv(env_name)
        if not token:
            attempts.append(
                {
                    "token_env": env_name,
                    "auth_kind": auth_kind,
                    "status": "missing",
                    "identity": None,
                    "probe": [],
                }
            )
            continue

        headers = make_headers(token, auth_kind)
        ok, diag = probe_alert_access(scope, base_path, headers)
        attempts.append(
            {
                "token_env": env_name,
                "auth_kind": auth_kind,
                "status": "ok" if ok else "rejected",
                "identity": diag[0] if diag else None,
                "probe": diag,
            }
        )
        if ok:
            return headers, attempts, auth_kind

    return None, attempts, "none"


def choose_admin_token(enterprise_slug: str, lookback_days: int) -> Tuple[Optional[Dict[str, str]], List[Dict[str, Any]], str]:
    attempts: List[Dict[str, Any]] = []

    for env_name, auth_kind in token_candidates_admin():
        token = os.getenv(env_name)
        if not token:
            attempts.append(
                {
                    "token_env": env_name,
                    "auth_kind": auth_kind,
                    "status": "missing",
                    "identity": None,
                    "probe": [],
                }
            )
            continue

        headers = make_headers(token, auth_kind)
        ok, diag = probe_admin_access(enterprise_slug, headers, lookback_days)
        attempts.append(
            {
                "token_env": env_name,
                "auth_kind": auth_kind,
                "status": "ok" if ok else "rejected",
                "identity": diag[0] if diag else None,
                "probe": diag,
            }
        )
        if ok:
            return headers, attempts, auth_kind

    return None, attempts, "none"


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


def rank(severity: str) -> int:
    return {"low": 1, "medium": 2, "moderate": 2, "high": 3, "critical": 4}.get((severity or "").lower(), 0)


def blocking(severity: str, threshold: str) -> bool:
    return rank(severity) >= rank(threshold) > 0


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
    alerts, page_diagnostics = cursor_get(url, headers, params={"state": "open", "per_page": PAGE_SIZE})

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


def collect_enterprise_org_inventory(
    enterprise_slug: str,
    headers: Dict[str, str],
) -> Dict[str, Any]:
    query = """
    query($slug: String!, $after: String) {
      enterprise(slug: $slug) {
        name
        organizations(first: 100, after: $after) {
          nodes {
            name
          }
          pageInfo {
            hasNextPage
            endCursor
          }
        }
      }
    }
    """

    def graphql_post(query_text: str, variables: Dict[str, Any]) -> Dict[str, Any]:
        resp = requests.post(
            "https://api.github.com/graphql",
            headers={**headers, "Content-Type": "application/json"},
            json={"query": query_text, "variables": variables},
            timeout=TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
        payload = resp.json()
        if "errors" in payload:
            raise RuntimeError(json.dumps(payload["errors"], indent=2))
        return payload["data"]

    def rest_get(url: str) -> Dict[str, Any]:
        resp = requests.get(url, headers=headers, timeout=TIMEOUT_SECONDS)
        resp.raise_for_status()
        return resp.json()

    orgs: List[Dict[str, Any]] = []
    after: str | None = None
    enterprise_name = enterprise_slug

    while True:
        data = graphql_post(query, {"slug": enterprise_slug, "after": after})
        enterprise = data.get("enterprise") or {}
        if not enterprise:
            raise RuntimeError(f"enterprise slug not found or inaccessible: {enterprise_slug}")
        enterprise_name = enterprise.get("name") or enterprise_name

        org_conn = enterprise.get("organizations") or {}
        nodes = org_conn.get("nodes") or []
        for node in nodes:
            name = str(node.get("name") or "").strip()
            if not name:
                continue

            item: Dict[str, Any] = {
                "slug": name,
                "display_name": name,
                "role": "Owner",
                "status": "active",
                "single_sign_on": None,
                "two_factor_required": None,
                "source": "graphql-enterprise",
            }

            try:
                org_detail = rest_get(f"{GH_API}/orgs/{name}")
                item["two_factor_required"] = org_detail.get("two_factor_requirement_enabled")
                item["public_repos"] = org_detail.get("public_repos")
                item["total_private_repos"] = org_detail.get("total_private_repos")
                item["public_repo_count"] = org_detail.get("public_repos")
                item["html_url"] = org_detail.get("html_url")
            except Exception as exc:
                item["detail_error"] = str(exc)

            orgs.append(item)

        page_info = org_conn.get("pageInfo") or {}
        if not page_info.get("hasNextPage"):
            break
        after = page_info.get("endCursor")

    return {
        "enterprise": enterprise_name,
        "generated_at": utc_now(),
        "organizations": orgs,
        "notes": [
            "Organizations were pulled live from the GitHub Enterprise Accounts GraphQL API.",
            "Where possible, organization REST details were used to augment the inventory with 2FA and repository counts.",
        ],
    }


def collect_org_members_for_org(
    org_name: str,
    headers: Dict[str, str],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    url = f"{GH_API}/orgs/{org_name}/members"
    members, page_diagnostics = page_get(url, headers, params={})
    return members, page_diagnostics


def collect_enterprise_audit_log(
    enterprise_slug: str,
    headers: Dict[str, str],
    lookback_days: int,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    url = f"{GH_API}/enterprises/{enterprise_slug}/audit-log"
    events, page_diagnostics = page_get(
        url,
        headers,
        params={
            "phrase": f"created:>={utc_date_days_ago(lookback_days)}",
            "include": "all",
        },
    )
    return events, page_diagnostics


def member_row(org_name: str, member: Dict[str, Any]) -> Dict[str, str]:
    return {
        "organization": org_name,
        "member_login": str(member.get("login") or ""),
        "member_id": str(member.get("id") or ""),
        "member_type": str(member.get("type") or ""),
        "site_admin": str(bool(member.get("site_admin", False))).lower(),
        "html_url": str(member.get("html_url") or ""),
        "node_id": str(member.get("node_id") or ""),
        "collected_at": utc_now(),
    }


def audit_event_row(event: Dict[str, Any]) -> Dict[str, str]:
    created_at = str(
        event.get("created_at")
        or event.get("@timestamp")
        or event.get("created")
        or event.get("createdAt")
        or ""
    )
    actor = str(event.get("actor") or event.get("user") or event.get("actor_login") or "")
    action = str(event.get("action") or event.get("event") or "")
    enterprise = str(event.get("enterprise") or event.get("org") or event.get("organization") or "")
    repo = str(event.get("repository") or event.get("repo") or "")
    user = str(event.get("user") or event.get("target_login") or event.get("member") or "")
    team = str(event.get("team") or "")
    ip = str(event.get("oauth_app_name") or event.get("ip") or event.get("actor_ip") or "")
    country = str(event.get("country") or "")
    reason = str(event.get("reason") or event.get("note") or "")
    raw = json.dumps(event, sort_keys=True, separators=(",", ":"))
    return {
        "created_at": created_at,
        "action": action,
        "actor": actor,
        "enterprise": enterprise,
        "repository": repo,
        "user": user,
        "team": team,
        "ip": ip,
        "country": country,
        "reason": reason,
        "raw_json": raw,
    }


def write_audit_exports(output_dir: Path, events: List[Dict[str, Any]]) -> None:
    rows = [audit_event_row(event) for event in events]
    write_json(output_dir / "enterprise_audit_log.json", events)
    write_csv(
        output_dir / "enterprise_audit_log.csv",
        [
            "created_at",
            "action",
            "actor",
            "enterprise",
            "repository",
            "user",
            "team",
            "ip",
            "country",
            "reason",
            "raw_json",
        ],
        rows,
    )

    md_lines = [
        "# Enterprise Audit Log",
        "",
        f"- Event count: {len(events)}",
        "",
        "| Created At | Action | Actor | Repository | User | Team |",
        "|---|---|---|---|---|---|",
    ]
    for row in rows[:500]:
        md_lines.append(
            f"| {row['created_at']} | {row['action']} | {row['actor']} | {row['repository']} | {row['user']} | {row['team']} |"
        )
    write_text(output_dir / "enterprise_audit_log.md", "\n".join(md_lines) + "\n")


def write_org_member_exports(output_dir: Path, org_members: List[Dict[str, Any]]) -> None:
    write_json(output_dir / "enterprise_org_members.json", org_members)

    flat_rows: List[Dict[str, str]] = []
    for org in org_members:
        org_name = str(org.get("organization") or "")
        for member in org.get("members", []) or []:
            flat_rows.append(member_row(org_name, member))

    write_csv(
        output_dir / "enterprise_org_members.csv",
        [
            "organization",
            "member_login",
            "member_id",
            "member_type",
            "site_admin",
            "html_url",
            "node_id",
            "collected_at",
        ],
        flat_rows,
    )

    md_lines = [
        "# Enterprise Organization Membership Evidence",
        "",
        f"- Organizations with membership snapshots: {len(org_members)}",
        f"- Member rows: {len(flat_rows)}",
        "",
        "| Organization | Member Count | Sample Members |",
        "|---|---:|---|",
    ]
    for org in org_members:
        members = org.get("members", []) or []
        sample = ", ".join(str(m.get("login") or "") for m in members[:10])
        md_lines.append(f"| {org.get('organization', '')} | {len(members)} | {sample} |")
    write_text(output_dir / "enterprise_org_members.md", "\n".join(md_lines) + "\n")


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
    alert_auth_kind: str,
    admin_auth_kind: str,
    results: Dict[str, Any],
    blocking_findings: List[Dict[str, Any]],
    errors: List[str],
    repositories: List[str],
    evidence_lines: List[str],
    audit_event_count: int,
    org_member_total: int,
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
        "alert_auth_kind": alert_auth_kind,
        "admin_auth_kind": admin_auth_kind,
        "results": results,
        "blocking_findings": blocking_findings,
        "errors": errors,
        "evidence_lines": evidence_lines,
        "enterprise_audit_event_count": audit_event_count,
        "enterprise_org_member_count": org_member_total,
        "overall": {
            "blocking_count": len(blocking_findings),
            "error_count": len(errors),
            "status": overall_status,
        },
    }


def write_summary_files(output_dir: Path, snapshot: Dict[str, Any], auth_attempts: Dict[str, Any]) -> None:
    write_json(output_dir / "summary.json", snapshot)
    write_json(output_dir / "current_snapshot.json", snapshot)
    write_json(output_dir / "blocking_findings.json", snapshot.get("blocking_findings", []))
    write_json(output_dir / "auth_attempts.json", auth_attempts)
    write_text(output_dir / "evidence_lines.txt", "\n".join(snapshot.get("evidence_lines", [])) + "\n")
    write_text(
        output_dir / "repositories.txt",
        "\n".join(snapshot.get("repositories", [])) + ("\n" if snapshot.get("repositories") else ""),
    )


def render_summary_md(snapshot: Dict[str, Any], auth_attempts: Dict[str, Any]) -> str:
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
        f"- Alert auth kind: `{snapshot.get('alert_auth_kind', '')}`",
        f"- Admin auth kind: `{snapshot.get('admin_auth_kind', '')}`",
        f"- Enterprise audit events: `{snapshot.get('enterprise_audit_event_count', 0)}`",
        f"- Enterprise org member rows: `{snapshot.get('enterprise_org_member_count', 0)}`",
        f"- Blocking findings: `{overall.get('blocking_count', 0)}`",
        f"- Collection errors: `{overall.get('error_count', 0)}`",
        f"- Status: `{overall.get('status', '')}`",
        "",
        "## Authentication Attempts",
        "",
        "| Channel | Token Env | Auth Kind | Status |",
        "|---|---|---|---|",
    ]

    for channel in ("alerts", "admin"):
        for attempt in auth_attempts.get(channel, []) or []:
            lines.append(
                f"| {channel} | {attempt.get('token_env', '')} | {attempt.get('auth_kind', '')} | {attempt.get('status', '')} |"
            )

    lines.extend(
        [
            "",
            "## Covered Repositories",
            "",
        ]
    )
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
        f"- Selected alert auth kind: `{diagnostics.get('selected_alert_auth_kind', '')}`",
        f"- Selected admin auth kind: `{diagnostics.get('selected_admin_auth_kind', '')}`",
        "",
        "## Alert Token Attempts",
        "",
    ]

    for attempt in diagnostics.get("alert_token_attempts", []) or []:
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

    lines.extend(["## Admin Token Attempts", ""])
    for attempt in diagnostics.get("admin_token_attempts", []) or []:
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
    alert_attempts: List[Dict[str, Any]],
    admin_attempts: List[Dict[str, Any]],
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
        "alert_auth_kind": "none",
        "admin_auth_kind": "none",
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
        "enterprise_audit_event_count": 0,
        "enterprise_org_member_count": 0,
        "overall": {"blocking_count": 0, "error_count": 1, "status": "error"},
        "alert_token_attempts": alert_attempts,
        "admin_token_attempts": admin_attempts,
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
    audit_lookback_days = max(1, args.audit_lookback_days)

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
    print(f"Audit lookback days: {audit_lookback_days}")

    results: Dict[str, Any] = {}
    evidence_lines: List[str] = []
    errors: List[str] = []
    blocking_findings: List[Dict[str, Any]] = []
    repositories_seen: set[str] = set()

    alert_token_attempts: List[Dict[str, Any]] = []
    admin_token_attempts: List[Dict[str, Any]] = []
    diagnostics_notes: List[str] = []

    selected_alert_headers, alert_token_attempts, selected_alert_auth_kind = choose_alert_token(scope, base_path)
    selected_admin_headers, admin_token_attempts, selected_admin_auth_kind = choose_admin_token(enterprise, audit_lookback_days)

    if selected_alert_headers is None:
        diagnostics = {
            "generated_at": utc_now(),
            "scope": scope,
            "enterprise": enterprise,
            "organization": ctx["organization"],
            "repository": ctx["repository"],
            "repository_full": ctx["repository_full"],
            "selected_alert_auth_kind": "none",
            "selected_admin_auth_kind": "none",
            "alert_token_attempts": alert_token_attempts,
            "admin_token_attempts": admin_token_attempts,
            "notes": diagnostics_notes
            + [
                "No alert token could access the required alert endpoints.",
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
                alert_attempts=alert_token_attempts,
                admin_attempts=admin_token_attempts,
                diagnostics_notes=diagnostics_notes,
            )
            append_history(output_dir, snapshot)
            write_summary_files(
                output_dir,
                snapshot,
                {"alerts": alert_token_attempts, "admin": admin_token_attempts},
            )
            write_text(output_dir / "summary.md", render_summary_md(snapshot, {"alerts": alert_token_attempts, "admin": admin_token_attempts}))
            print("SA-04(10) collection soft-failed; diagnostics were written for review.")
            return 0

        fail(
            "no usable token found for the selected scope. "
            "Check token scope, SSO authorization, enterprise membership, org role, or enterprise PAT policy.",
            exit_code=2,
        )

    print(f"Selected alert auth kind: {selected_alert_auth_kind}")
    print(f"Selected admin auth kind: {selected_admin_auth_kind}")

    # Live enterprise org inventory
    org_inventory: Dict[str, Any] = {
        "enterprise": enterprise,
        "generated_at": utc_now(),
        "organizations": [],
        "notes": [],
    }
    inventory_headers = selected_admin_headers or selected_alert_headers

    try:
        if inventory_headers is None:
            raise RuntimeError("no usable token for enterprise organization inventory")
        org_inventory = collect_enterprise_org_inventory(enterprise, inventory_headers)
        evidence_lines.append("SSP-EVIDENCE: enterprise organization inventory captured successfully")
        write_json(output_dir / "enterprise_organizations.json", org_inventory)
    except Exception as exc:
        if soft_fail:
            errors.append(f"enterprise organization inventory collection error: {exc}")
            diagnostics_notes.append(f"enterprise organization inventory collection error: {exc}")
            write_json(output_dir / "enterprise_organizations_error.json", {"error": str(exc)})
        else:
            fail(str(exc), exit_code=2)

    # Live enterprise audit log
    audit_events: List[Dict[str, Any]] = []
    try:
        if selected_admin_headers is None:
            raise RuntimeError(
                "no usable admin token found for enterprise audit log. "
                "The enterprise audit log endpoint requires an enterprise admin token with read:audit_log."
            )
        audit_events, audit_pages = collect_enterprise_audit_log(enterprise, selected_admin_headers, audit_lookback_days)
        write_audit_exports(output_dir, audit_events)
        write_json(output_dir / "enterprise_audit_log_probe_diagnostics.json", audit_pages)
        evidence_lines.append("SSP-EVIDENCE: enterprise audit log captured successfully")
    except Exception as exc:
        if soft_fail:
            errors.append(f"enterprise audit log collection error: {exc}")
            diagnostics_notes.append(f"enterprise audit log collection error: {exc}")
            write_json(output_dir / "enterprise_audit_log_error.json", {"error": str(exc)})
            write_json(output_dir / "enterprise_audit_log.json", audit_events)
            write_csv(
                output_dir / "enterprise_audit_log.csv",
                [
                    "created_at",
                    "action",
                    "actor",
                    "enterprise",
                    "repository",
                    "user",
                    "team",
                    "ip",
                    "country",
                    "reason",
                    "raw_json",
                ],
                [],
            )
            write_text(
                output_dir / "enterprise_audit_log.md",
                "# Enterprise Audit Log\n\n- Event count: 0\n\nNo audit log data was captured.\n",
            )
        else:
            fail(str(exc), exit_code=2)

    # Live org membership evidence
    org_member_records: List[Dict[str, Any]] = []
    try:
        member_headers = selected_admin_headers or selected_alert_headers
        if member_headers is None:
            raise RuntimeError("no usable token for organization membership evidence")
        for org in org_inventory.get("organizations", []) or []:
            org_name = str(org.get("slug") or org.get("display_name") or "").strip()
            if not org_name:
                continue
            try:
                members, member_pages = collect_org_members_for_org(org_name, member_headers)
                org_member_records.append(
                    {
                        "organization": org_name,
                        "member_count": len(members),
                        "members": members,
                        "page_diagnostics": member_pages,
                    }
                )
            except Exception as exc:
                if soft_fail:
                    diagnostics_notes.append(f"membership evidence collection error for {org_name}: {exc}")
                    org_member_records.append(
                        {
                            "organization": org_name,
                            "member_count": 0,
                            "members": [],
                            "page_diagnostics": [],
                            "error": str(exc),
                        }
                    )
                else:
                    raise

        write_org_member_exports(output_dir, org_member_records)
        write_json(output_dir / "enterprise_org_members_probe_diagnostics.json", org_member_records)
        evidence_lines.append("SSP-EVIDENCE: enterprise organization membership evidence captured successfully")
    except Exception as exc:
        if soft_fail:
            errors.append(f"enterprise organization membership collection error: {exc}")
            diagnostics_notes.append(f"enterprise organization membership collection error: {exc}")
            write_json(output_dir / "enterprise_org_members_error.json", {"error": str(exc)})
            write_json(output_dir / "enterprise_org_members.json", org_member_records)
            write_csv(
                output_dir / "enterprise_org_members.csv",
                [
                    "organization",
                    "member_login",
                    "member_id",
                    "member_type",
                    "site_admin",
                    "html_url",
                    "node_id",
                    "collected_at",
                ],
                [],
            )
            write_text(
                output_dir / "enterprise_org_members.md",
                "# Enterprise Organization Membership Evidence\n\n- Organizations with membership snapshots: 0\n- Member rows: 0\n",
            )
        else:
            fail(str(exc), exit_code=2)

    # Alerts
    try:
        print("Phase 1: code scanning alert polling")
        code_result, code_blocking, code_pages, code_evidence = collect_category(
            base_path=base_path,
            headers=selected_alert_headers,
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
            headers=selected_alert_headers,
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
            headers=selected_alert_headers,
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

    # Repositories touched by alert streams
    for category_name in ("code_scanning", "dependabot", "secret_scanning"):
        for alert in (results.get(category_name, {}) or {}).get("alerts", []) or []:
            repo_full = str(alert.get("repository_full") or "").strip()
            if repo_full:
                repositories_seen.add(repo_full)

    repositories = sorted(repositories_seen)
    total_member_rows = sum(int(org.get("member_count", 0) or 0) for org in org_member_records)

    snapshot = build_snapshot(
        scope=scope,
        organization=ctx["organization"],
        repository=ctx["repository"],
        repository_full=ctx["repository_full"],
        enterprise=enterprise,
        alert_auth_kind=selected_alert_auth_kind,
        admin_auth_kind=selected_admin_auth_kind,
        results=results,
        blocking_findings=blocking_findings,
        errors=errors,
        repositories=repositories,
        evidence_lines=evidence_lines,
        audit_event_count=len(audit_events),
        org_member_total=total_member_rows,
    )

    append_history(output_dir, snapshot)
    write_summary_files(
        output_dir,
        snapshot,
        {"alerts": alert_token_attempts, "admin": admin_token_attempts},
    )
    write_text(output_dir / "summary.md", render_summary_md(snapshot, {"alerts": alert_token_attempts, "admin": admin_token_attempts}))

    diagnostics = {
        "generated_at": utc_now(),
        "scope": scope,
        "enterprise": enterprise,
        "organization": ctx["organization"],
        "repository": ctx["repository"],
        "repository_full": ctx["repository_full"],
        "selected_alert_auth_kind": selected_alert_auth_kind,
        "selected_admin_auth_kind": selected_admin_auth_kind,
        "alert_token_attempts": alert_token_attempts,
        "admin_token_attempts": admin_token_attempts,
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
    print(f"Enterprise audit events: {snapshot['enterprise_audit_event_count']}")
    print(f"Enterprise org member rows: {snapshot['enterprise_org_member_count']}")
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
