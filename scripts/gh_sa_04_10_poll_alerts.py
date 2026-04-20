#!/usr/bin/env python3
"""
SA-04(10) alert polling and evidence collection for GitHub.com.

Scope support:
- repository
- organization
- enterprise

Auth support:
- repository / organization:
    * GH_DEPENDABOT_TOKEN (fine-grained PAT or classic PAT)
    * GH_APP_TOKEN (GitHub App token)
    * GH_AUTH_TOKEN (optional fallback)
- enterprise:
    * GH_ENTERPRISE_TOKEN (classic PAT or OAuth app token)
    * GH_AUTH_TOKEN (optional fallback)

Behavior:
- Selects a token that GitHub actually accepts for the selected scope.
- If GitHub returns 403/404, logs X-Accepted-GitHub-Permissions when present.
- Collects JSON evidence files for each category.
- Records structured SSP evidence lines.
- Supports soft-fail collection so the evidence binder can still be built.

Exit codes:
- 0 = compliant or soft-fail collection completed
- 1 = blocking findings detected (when not soft-failing)
- 2 = configuration/runtime failure
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, NoReturn, Tuple

import requests

GH_API = "https://api.github.com"
PAGE_SIZE = 100
TIMEOUT_SECONDS = 30


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def fail(message: str, exit_code: int = 1) -> NoReturn:
    print(f"SA-04(10) COMPLIANCE FAILURE: {message}")
    sys.exit(exit_code)


def get_env(name: str, default: Optional[str] = None) -> str:
    value = os.getenv(name, default)
    if value is None or value == "":
        fail(f"required environment variable {name} is not set", exit_code=2)
    return value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Poll GitHub security alerts and collect SA-04(10) evidence.")
    parser.add_argument(
        "--scope",
        choices=["repository", "organization", "enterprise"],
        default=os.getenv("GH_ALERT_SCOPE", "repository"),
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


def scope_base(scope: str, owner: str, repo: str, enterprise: str) -> str:
    if scope == "repository":
        if not owner or not repo:
            fail("repository scope requires owner and repo values", exit_code=2)
        return f"/repos/{owner}/{repo}"
    if scope == "organization":
        if not owner:
            fail("organization scope requires GH_ORG_NAME or --owner", exit_code=2)
        return f"/orgs/{owner}"
    if scope == "enterprise":
        if not enterprise:
            fail("enterprise scope requires GH_ENTERPRISE_SLUG or --enterprise", exit_code=2)
        return f"/enterprises/{enterprise}"
    fail(f"unsupported scope: {scope}", exit_code=2)


def token_candidates(scope: str) -> List[Tuple[str, str]]:
    """
    Returns (env_var_name, auth_kind).
    """
    if scope == "enterprise":
        return [
            ("GH_ENTERPRISE_TOKEN", "enterprise_classic_pat_or_oauth"),
            ("GH_AUTH_TOKEN", "enterprise_fallback"),
        ]

    return [
        ("GH_APP_TOKEN", "github_app_token"),
        ("GH_DEPENDABOT_TOKEN", "fine_grained_pat_or_classic_pat"),
        ("GH_AUTH_TOKEN", "fallback_token"),
    ]


def make_headers(token: str, auth_kind: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "X-SA04-AUTH-KIND": auth_kind,
    }


def endpoint_map(base_path: str, scope: str) -> Dict[str, Optional[str]]:
    if scope == "enterprise":
        return {
            "code_scanning": None,
            "dependabot": f"{base_path}/dependabot/alerts",
            "secret_scanning": None,
        }
    return {
        "code_scanning": f"{base_path}/code-scanning/alerts",
        "dependabot": f"{base_path}/dependabot/alerts",
        "secret_scanning": f"{base_path}/secret-scanning/alerts",
    }


def request_one(url: str, headers: Dict[str, str]) -> requests.Response:
    return requests.get(
        url,
        headers=headers,
        params={"state": "open", "per_page": 1, "page": 1},
        timeout=TIMEOUT_SECONDS,
    )


def accepted_permissions(response: requests.Response) -> Optional[str]:
    return response.headers.get("X-Accepted-GitHub-Permissions")


def probe_token_for_scope(
    base_path: str,
    scope: str,
    headers: Dict[str, str],
) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Probe all endpoints required for the selected scope.
    Returns (ok, diagnostics).
    """
    diagnostics: List[Dict[str, Any]] = []
    endpoints = endpoint_map(base_path, scope)

    for category, url in endpoints.items():
        if url is None:
            continue

        response = request_one(f"{GH_API}{url}", headers)
        if response.status_code == 200:
            diagnostics.append(
                {
                    "category": category,
                    "status_code": 200,
                    "message": "accessible",
                    "accepted_permissions": accepted_permissions(response),
                }
            )
            continue

        diag = {
            "category": category,
            "status_code": response.status_code,
            "message": "",
            "accepted_permissions": accepted_permissions(response),
        }
        try:
            payload = response.json()
            if isinstance(payload, dict):
                diag["message"] = payload.get("message") or response.text[:300]
            else:
                diag["message"] = response.text[:300]
        except Exception:
            diag["message"] = response.text[:300]

        diagnostics.append(diag)
        return False, diagnostics

    return True, diagnostics


def select_auth(
    scope: str,
    base_path: str,
) -> Tuple[Optional[Dict[str, str]], List[Dict[str, Any]]]:
    """
    Returns headers for the first token that can access the required endpoints.
    """
    diagnostics: List[Dict[str, Any]] = []

    for env_name, auth_kind in token_candidates(scope):
        token = os.getenv(env_name)
        if not token:
            diagnostics.append(
                {
                    "token_env": env_name,
                    "status": "missing",
                    "message": "token not set",
                }
            )
            continue

        headers = make_headers(token, auth_kind)
        ok, token_diagnostics = probe_token_for_scope(base_path, scope, headers)
        diagnostics.append(
            {
                "token_env": env_name,
                "auth_kind": auth_kind,
                "status": "ok" if ok else "rejected",
                "probe": token_diagnostics,
            }
        )
        if ok:
            return headers, diagnostics

    return None, diagnostics


def severity_rank(value: str) -> int:
    mapping = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    return mapping.get(value.lower(), 0)


def severity_is_blocking(severity: str, threshold: str) -> bool:
    return severity_rank(severity) >= severity_rank(threshold) > 0


def paged_get(
    url: str,
    headers: Dict[str, str],
    params: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    page = 1

    while True:
        query = dict(params or {})
        query["per_page"] = PAGE_SIZE
        query["page"] = page

        response = requests.get(url, headers=headers, params=query, timeout=TIMEOUT_SECONDS)
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            perm = accepted_permissions(response)
            raise RuntimeError(
                f"GitHub API request failed for {url}: {exc} | "
                f"accepted_permissions={perm!r} | body={response.text[:300]}"
            ) from exc

        payload = response.json()
        if not isinstance(payload, list):
            raise RuntimeError(f"unexpected response shape from {url}")

        if not payload:
            break

        results.extend(payload)

        if len(payload) < PAGE_SIZE:
            break

        page += 1

    return results


def extract_code_scanning_finding(alert: Dict[str, Any]) -> Dict[str, Any]:
    rule = alert.get("rule") or {}
    instance = (alert.get("most_recent_instance") or {}).get("location") or {}
    return {
        "category": "code_scanning",
        "identifier": rule.get("id") or "unknown-rule",
        "title": rule.get("name") or alert.get("rule", {}).get("id") or "unknown-title",
        "severity": str(rule.get("severity") or "").lower(),
        "state": alert.get("state") or "open",
        "html_url": alert.get("html_url"),
        "path": instance.get("path"),
        "start_line": instance.get("start_line"),
        "end_line": instance.get("end_line"),
    }


def extract_dependabot_finding(alert: Dict[str, Any]) -> Dict[str, Any]:
    advisory = alert.get("security_advisory") or {}
    dependency = (((alert.get("dependency") or {}).get("package") or {}).get("name")) or "unknown-package"
    return {
        "category": "dependabot",
        "identifier": advisory.get("ghsa_id") or advisory.get("cve_id") or "unknown-advisory",
        "title": advisory.get("summary") or "unknown-advisory",
        "severity": str(advisory.get("severity") or "").lower(),
        "state": alert.get("state") or "open",
        "html_url": alert.get("html_url"),
        "dependency": dependency,
        "manifest_path": (((alert.get("dependency") or {}).get("manifest_path"))),
    }


def extract_secret_scanning_finding(alert: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "category": "secret_scanning",
        "identifier": alert.get("secret_type") or alert.get("secret_type_display_name") or "unknown-secret",
        "title": alert.get("secret_type_display_name") or alert.get("secret_type") or "unknown-secret",
        "severity": "open",
        "state": alert.get("state") or "open",
        "html_url": alert.get("html_url"),
        "secret_type": alert.get("secret_type"),
    }


def collect_code_scanning(base_path: str, headers: Dict[str, str], threshold: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[str]]:
    url = f"{GH_API}{base_path}/code-scanning/alerts"
    alerts = paged_get(url, headers, params={"state": "open"})

    blocking_findings: List[Dict[str, Any]] = []
    evidence_lines = ["SSP-EVIDENCE: code scanning alert polling completed successfully"]

    for alert in alerts:
        rule = alert.get("rule") or {}
        severity = str(rule.get("severity") or "").lower()
        if severity_is_blocking(severity, threshold):
            blocking_findings.append(extract_code_scanning_finding(alert))

    result = {
        "accessible": True,
        "skipped": False,
        "skip_reason": None,
        "count": len(alerts),
        "blocking_count": len(blocking_findings),
        "alerts": alerts,
    }
    return result, blocking_findings, evidence_lines


def collect_dependabot(base_path: str, headers: Dict[str, str], threshold: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[str]]:
    url = f"{GH_API}{base_path}/dependabot/alerts"
    alerts = paged_get(url, headers, params={"state": "open"})

    blocking_findings: List[Dict[str, Any]] = []
    evidence_lines = ["SSP-EVIDENCE: dependabot alert polling completed successfully"]

    for alert in alerts:
        advisory = alert.get("security_advisory") or {}
        severity = str(advisory.get("severity") or "").lower()
        if severity_is_blocking(severity, threshold):
            blocking_findings.append(extract_dependabot_finding(alert))

    result = {
        "accessible": True,
        "skipped": False,
        "skip_reason": None,
        "count": len(alerts),
        "blocking_count": len(blocking_findings),
        "alerts": alerts,
    }
    return result, blocking_findings, evidence_lines


def collect_secret_scanning(base_path: str, headers: Dict[str, str]) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[str]]:
    url = f"{GH_API}{base_path}/secret-scanning/alerts"
    alerts = paged_get(url, headers, params={"state": "open"})

    blocking_findings: List[Dict[str, Any]] = []
    evidence_lines = ["SSP-EVIDENCE: secret scanning alert polling completed successfully"]

    for alert in alerts:
        if alert.get("state") == "open" or not alert.get("state"):
            blocking_findings.append(extract_secret_scanning_finding(alert))

    result = {
        "accessible": True,
        "skipped": False,
        "skip_reason": None,
        "count": len(alerts),
        "blocking_count": len(blocking_findings),
        "alerts": alerts,
    }
    return result, blocking_findings, evidence_lines


def render_summary_md(summary: Dict[str, Any]) -> str:
    overall = summary["overall"]
    results = summary["results"]

    lines = [
        "# SA-04(10) Evidence Collection Summary",
        "",
        f"- Scope: `{summary['scope']}`",
        f"- Repository: `{summary['repository']}`",
        f"- Organization: `{summary['organization']}`",
        f"- Enterprise: `{summary['enterprise']}`",
        f"- Threshold: `{summary['threshold']}`",
        f"- Generated: `{summary['generated_at']}`",
        f"- Status: `{overall['status']}`",
        f"- Blocking findings: `{overall['blocking_count']}`",
        f"- Collection errors: `{overall['error_count']}`",
        "",
        "## Authentication Selection",
        "",
        f"- Auth kind: `{summary.get('auth_kind', 'unknown')}`",
        "",
        "| Token Source | Status |",
        "|---|---|",
    ]

    for attempt in summary.get("auth_attempts", []):
        lines.append(f"| {attempt.get('token_env', 'unknown')} | {attempt.get('status', 'unknown')} |")

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
        item = results.get(category, {})
        lines.append(
            f"| {category} | {str(item.get('accessible', False)).lower()} | "
            f"{str(item.get('skipped', False)).lower()} | {item.get('count', 0)} | "
            f"{item.get('blocking_count', 0)} |"
        )

    lines.extend(["", "## Evidence Lines", ""])
    for entry in summary.get("evidence_lines", []):
        lines.append(f"- {entry}")

    if summary.get("errors"):
        lines.extend(["", "## Collection Errors", ""])
        for entry in summary["errors"]:
            lines.append(f"- {entry}")

    return "\n".join(lines) + "\n"


def build_summary(
    scope: str,
    repo: str,
    owner: str,
    org: str,
    enterprise: str,
    threshold: str,
    soft_fail: bool,
    auth_kind: str,
    auth_attempts: List[Dict[str, Any]],
    results: Dict[str, Any],
    blocking_findings: List[Dict[str, Any]],
    errors: List[str],
    evidence_lines: List[str],
) -> Dict[str, Any]:
    blocking_count = len(blocking_findings)
    error_count = len(errors)
    status = "pass"
    if error_count > 0:
        status = "error"
    elif blocking_count > 0:
        status = "fail"

    return {
        "generated_at": utc_now(),
        "scope": scope,
        "repository": repo,
        "owner": owner,
        "organization": org,
        "enterprise": enterprise,
        "threshold": threshold,
        "soft_fail": soft_fail,
        "auth_kind": auth_kind,
        "auth_attempts": auth_attempts,
        "results": results,
        "blocking_findings": blocking_findings,
        "overall": {
            "status": status,
            "blocking_count": blocking_count,
            "error_count": error_count,
        },
        "errors": errors,
        "evidence_lines": evidence_lines,
    }


def write_placeholder_skips_for_enterprise() -> Dict[str, Any]:
    return {
        "accessible": False,
        "skipped": True,
        "skip_reason": "not applicable to enterprise scope",
        "count": 0,
        "blocking_count": 0,
        "alerts": [],
    }


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    owner_default, repo_default = repo_parts()

    owner = args.owner or owner_default
    repo = args.repo or repo_default
    org = owner
    enterprise = args.enterprise or os.getenv("GH_ENTERPRISE_SLUG", "")
    scope = args.scope.strip().lower()

    threshold = os.getenv("FAIL_ON_SEVERITY", "high").strip().lower()
    soft_fail = args.soft_fail or os.getenv("SA04_SOFT_FAIL", "") == "1"

    if threshold not in {"low", "medium", "high", "critical"}:
        fail(f"invalid FAIL_ON_SEVERITY value: {threshold}", exit_code=2)

    base_path = scope_base(scope, owner=owner, repo=repo, enterprise=enterprise)

    headers, auth_attempts = select_auth(scope, base_path)
    if headers is None:
        if soft_fail:
            summary = build_summary(
                scope=scope,
                repo=f"{owner}/{repo}",
                owner=owner,
                org=org,
                enterprise=enterprise,
                threshold=threshold,
                soft_fail=soft_fail,
                auth_kind="none",
                auth_attempts=auth_attempts,
                results={
                    "code_scanning": write_placeholder_skips_for_enterprise() if scope == "enterprise" else {
                        "accessible": False,
                        "skipped": True,
                        "skip_reason": "no usable token found",
                        "count": 0,
                        "blocking_count": 0,
                        "alerts": [],
                    },
                    "dependabot": {
                        "accessible": False,
                        "skipped": True,
                        "skip_reason": "no usable token found",
                        "count": 0,
                        "blocking_count": 0,
                        "alerts": [],
                    },
                    "secret_scanning": write_placeholder_skips_for_enterprise() if scope == "enterprise" else {
                        "accessible": False,
                        "skipped": True,
                        "skip_reason": "no usable token found",
                        "count": 0,
                        "blocking_count": 0,
                        "alerts": [],
                    },
                },
                blocking_findings=[],
                errors=[],
                evidence_lines=["SSP-EVIDENCE: no usable token found; collection was not performed."],
            )
            write_json(output_dir / "summary.json", summary)
            write_text(output_dir / "summary.md", render_summary_md(summary))
            write_text(output_dir / "evidence_lines.txt", "\n".join(summary["evidence_lines"]) + "\n")
            write_json(output_dir / "blocking_findings.json", [])
            return 0
        fail(
            "no usable token was able to access the required alerts endpoints. "
            "Check token scope, org approval, repository selection, or use a classic PAT for enterprise alerts.",
            exit_code=2,
        )

    print("SA-04(10) security gate starting")
    print(f"Scope: {scope}")
    print(f"Repository: {repo}")
    print(f"Blocking threshold: {threshold}")
    print(f"Soft fail: {soft_fail}")
    print(f"Auth kind: {headers.get('X-SA04-AUTH-KIND')}")

    results: Dict[str, Any] = {}
    evidence_lines: List[str] = []
    errors: List[str] = []
    blocking_findings: List[Dict[str, Any]] = []

    try:
        if scope == "enterprise":
            results["code_scanning"] = write_placeholder_skips_for_enterprise()
            results["secret_scanning"] = write_placeholder_skips_for_enterprise()

            print("Phase 1: Dependabot alert polling (enterprise)")
            dependabot_result, dependabot_blocking, dependabot_evidence = collect_dependabot(base_path, headers, threshold)
            results["dependabot"] = dependabot_result
            blocking_findings.extend(dependabot_blocking)
            evidence_lines.extend(dependabot_evidence)
            write_json(output_dir / "dependabot_alerts.json", dependabot_result["alerts"])

        else:
            print("Phase 1: code scanning alert polling")
            code_scanning_result, code_scanning_blocking, code_scanning_evidence = collect_code_scanning(
                base_path, headers, threshold
            )
            results["code_scanning"] = code_scanning_result
            blocking_findings.extend(code_scanning_blocking)
            evidence_lines.extend(code_scanning_evidence)
            write_json(output_dir / "code_scanning_alerts.json", code_scanning_result["alerts"])

            print("Phase 2: Dependabot alert polling")
            dependabot_result, dependabot_blocking, dependabot_evidence = collect_dependabot(base_path, headers, threshold)
            results["dependabot"] = dependabot_result
            blocking_findings.extend(dependabot_blocking)
            evidence_lines.extend(dependabot_evidence)
            write_json(output_dir / "dependabot_alerts.json", dependabot_result["alerts"])

            print("Phase 3: secret scanning alert polling")
            secret_result, secret_blocking, secret_evidence = collect_secret_scanning(base_path, headers)
            results["secret_scanning"] = secret_result
            blocking_findings.extend(secret_blocking)
            evidence_lines.extend(secret_evidence)
            write_json(output_dir / "secret_scanning_alerts.json", secret_result["alerts"])

    except Exception as exc:
        if soft_fail:
            errors.append(str(exc))
            if scope == "enterprise":
                results.setdefault("dependabot", {
                    "accessible": False,
                    "skipped": True,
                    "skip_reason": str(exc),
                    "count": 0,
                    "blocking_count": 0,
                    "alerts": [],
                })
            else:
                results.setdefault("code_scanning", {
                    "accessible": False,
                    "skipped": True,
                    "skip_reason": str(exc),
                    "count": 0,
                    "blocking_count": 0,
                    "alerts": [],
                })
                results.setdefault("dependabot", {
                    "accessible": False,
                    "skipped": True,
                    "skip_reason": str(exc),
                    "count": 0,
                    "blocking_count": 0,
                    "alerts": [],
                })
                results.setdefault("secret_scanning", {
                    "accessible": False,
                    "skipped": True,
                    "skip_reason": str(exc),
                    "count": 0,
                    "blocking_count": 0,
                    "alerts": [],
                })
            evidence_lines.append(f"SSP-EVIDENCE: collection error recorded for review: {exc}")
        else:
            fail(str(exc), exit_code=2)

    overall = {
        "status": "pass",
        "blocking_count": len(blocking_findings),
        "error_count": len(errors),
    }
    if overall["error_count"] > 0:
        overall["status"] = "error"
    elif overall["blocking_count"] > 0:
        overall["status"] = "fail"

    summary = build_summary(
        scope=scope,
        repo=f"{owner}/{repo}",
        owner=owner,
        org=org,
        enterprise=enterprise,
        threshold=threshold,
        soft_fail=soft_fail,
        auth_kind=headers.get("X-SA04-AUTH-KIND", "unknown"),
        auth_attempts=auth_attempts,
        results=results,
        blocking_findings=blocking_findings,
        errors=errors,
        evidence_lines=evidence_lines,
    )
    summary["overall"] = overall

    write_json(output_dir / "summary.json", summary)
    write_text(output_dir / "summary.md", render_summary_md(summary))
    write_text(output_dir / "evidence_lines.txt", "\n".join(evidence_lines) + "\n")
    write_json(output_dir / "blocking_findings.json", blocking_findings)
    write_json(output_dir / "auth_attempts.json", auth_attempts)

    print("")
    print("SA-04(10) collection complete")
    print(f"Blocking findings: {overall['blocking_count']}")
    print(f"Collection errors: {overall['error_count']}")

    if soft_fail:
        print("SA-04(10) collection was soft-failed so the FedRAMP package could be built.")
        return 0

    if overall["error_count"] > 0:
        return 2
    if overall["blocking_count"] > 0:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
