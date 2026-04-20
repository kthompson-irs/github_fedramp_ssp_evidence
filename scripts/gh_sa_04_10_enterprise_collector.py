#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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


def token_candidates(scope: str) -> List[Tuple[str, str]]:
    """
    Returns (env_var_name, auth_kind).
    The collector tries these in order.
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


def accepted_permissions(response: requests.Response) -> Optional[str]:
    return response.headers.get("X-Accepted-GitHub-Permissions")


def request_one(url: str, headers: Dict[str, str]) -> requests.Response:
    return requests.get(
        url,
        headers=headers,
        params={"state": "open", "per_page": 1, "page": 1},
        timeout=TIMEOUT_SECONDS,
    )


def probe(scope: str, base_path: str, headers: Dict[str, str]) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Probe all endpoints required for the selected scope.
    Returns (ok, diagnostics).
    """
    diagnostics: List[Dict[str, Any]] = []

    if scope == "enterprise":
        endpoints = [("dependabot", f"{GH_API}{base_path}/dependabot/alerts")]
    else:
        endpoints = [
            ("code_scanning", f"{GH_API}{base_path}/code-scanning/alerts"),
            ("dependabot", f"{GH_API}{base_path}/dependabot/alerts"),
            ("secret_scanning", f"{GH_API}{base_path}/secret-scanning/alerts"),
        ]

    for category, url in endpoints:
        response = request_one(url, headers)
        diag = {
            "category": category,
            "status_code": response.status_code,
            "accepted_permissions": accepted_permissions(response),
            "message": "",
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

        if response.status_code != 200:
            return False, diagnostics

    return True, diagnostics


def choose_token(scope: str, base_path: str) -> Tuple[Dict[str, str], List[Dict[str, Any]], str]:
    """
    Returns (headers, attempts, auth_kind).
    """
    attempts: List[Dict[str, Any]] = []

    for env_name, auth_kind in token_candidates(scope):
        token = os.getenv(env_name)
        if not token:
            attempts.append(
                {
                    "token_env": env_name,
                    "auth_kind": auth_kind,
                    "status": "missing",
                    "probe": [],
                }
            )
            continue

        headers = make_headers(token, auth_kind)
        ok, diag = probe(scope, base_path, headers)
        attempts.append(
            {
                "token_env": env_name,
                "auth_kind": auth_kind,
                "status": "ok" if ok else "rejected",
                "probe": diag,
            }
        )
        if ok:
            return headers, attempts, auth_kind

    fail(
        "no usable token found for the selected scope. "
        "Check token scope, org approval, repository selection, or enterprise PAT policy.",
        exit_code=2,
    )
    raise SystemExit(2)


def paged_get(url: str, headers: Dict[str, str], params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
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


def rank(severity: str) -> int:
    return {"low": 1, "medium": 2, "moderate": 2, "high": 3, "critical": 4}.get((severity or "").lower(), 0)


def blocking(severity: str, threshold: str) -> bool:
    return rank(severity) >= rank(threshold) > 0


def codeql_findings(alerts: List[Dict[str, Any]], threshold: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for alert in alerts:
        rule = alert.get("rule") or {}
        severity = str(rule.get("severity") or "").lower()
        if blocking(severity, threshold):
            loc = (alert.get("most_recent_instance") or {}).get("location") or {}
            findings.append(
                {
                    "category": "code_scanning",
                    "identifier": rule.get("id") or "unknown-rule",
                    "title": rule.get("name") or "unknown-title",
                    "severity": severity,
                    "state": alert.get("state") or "open",
                    "html_url": alert.get("html_url"),
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
        if blocking(severity, threshold):
            dependency = (((alert.get("dependency") or {}).get("package") or {}).get("name")) or "unknown-package"
            findings.append(
                {
                    "category": "dependabot",
                    "identifier": advisory.get("ghsa_id") or advisory.get("cve_id") or "unknown-advisory",
                    "title": advisory.get("summary") or "unknown-advisory",
                    "severity": severity,
                    "state": alert.get("state") or "open",
                    "html_url": alert.get("html_url"),
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
                "secret_type": alert.get("secret_type"),
            }
        )
    return findings


def list_alerts(base_path: str, headers: Dict[str, str], endpoint: str) -> List[Dict[str, Any]]:
    return paged_get(f"{GH_API}{base_path}/{endpoint}", headers, params={"state": "open"})


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
) -> Dict[str, Any]:
    generated_at = utc_now()
    date = generated_at[:10]

    overall_status = "pass"
    if errors:
        overall_status = "error"
    elif blocking_findings:
        overall_status = "fail"

    snapshot = {
        "generated_at": generated_at,
        "date": date,
        "scope": scope,
        "organization": organization,
        "repository": repository,
        "repository_full": repository_full,
        "enterprise": enterprise,
        "auth_kind": auth_kind,
        "results": results,
        "blocking_findings": blocking_findings,
        "errors": errors,
        "overall": {
            "blocking_count": len(blocking_findings),
            "error_count": len(errors),
            "status": overall_status,
        },
    }
    return snapshot


def append_history(output_dir: Path, snapshot: Dict[str, Any]) -> None:
    hist_dir = output_dir / "history"
    hist_dir.mkdir(parents=True, exist_ok=True)

    line = json.dumps(snapshot, sort_keys=True)
    with (hist_dir / "history.jsonl").open("a", encoding="utf-8") as f:
        f.write(line + "\n")

    write_json(hist_dir / f"{snapshot['date']}.json", snapshot)


def write_summary_files(output_dir: Path, snapshot: Dict[str, Any], auth_attempts: List[Dict[str, Any]], evidence_lines: List[str]) -> None:
    write_json(output_dir / "summary.json", snapshot)
    write_json(output_dir / "current_snapshot.json", snapshot)
    write_json(output_dir / "blocking_findings.json", snapshot.get("blocking_findings", []))
    write_json(output_dir / "auth_attempts.json", auth_attempts)
    write_text(output_dir / "evidence_lines.txt", "\n".join(evidence_lines) + "\n")


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
        lines.append(
            f"| {attempt.get('token_env', '')} | {attempt.get('auth_kind', '')} | {attempt.get('status', '')} |"
        )

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


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    owner_default, repo_default = repo_parts()

    # Prefer explicit arguments, then env, then GH_REPOSITORY-derived defaults.
    organization = args.owner or owner_default
    repository = args.repo or repo_default
    repository_full = f"{organization}/{repository}" if organization and repository else os.getenv("GH_REPOSITORY", f"{organization}/{repository}")
    enterprise = args.enterprise or os.getenv("GH_ENTERPRISE_SLUG", "")
    scope = normalize_scope(args.scope)

    threshold = os.getenv("FAIL_ON_SEVERITY", "high").strip().lower()
    soft_fail = args.soft_fail or os.getenv("SA04_SOFT_FAIL", "") == "1"

    if threshold not in {"low", "medium", "moderate", "high", "critical"}:
        fail(f"invalid FAIL_ON_SEVERITY value: {threshold}", exit_code=2)

    base_path = scope_base(scope, organization, repository, enterprise)
    headers, auth_attempts, auth_kind = choose_token(scope, base_path)

    print("SA-04(10) enterprise collector starting")
    print(f"Scope: {scope}")
    print(f"Organization: {organization}")
    print(f"Repository: {repository}")
    print(f"Repository full: {repository_full}")
    print(f"Enterprise: {enterprise}")
    print(f"Blocking threshold: {threshold}")
    print(f"Soft fail: {soft_fail}")
    print(f"Auth kind: {auth_kind}")

    results: Dict[str, Any] = {}
    evidence_lines: List[str] = []
    errors: List[str] = []
    blocking_findings: List[Dict[str, Any]] = []

    # Enterprise scope only exposes Dependabot here; repo/org scope includes all three streams.
    if scope == "enterprise":
        try:
            print("Phase 1: Dependabot alert polling (enterprise)")
            alerts = list_alerts(base_path, headers, "dependabot/alerts")
            results["dependabot"] = {
                "accessible": True,
                "skipped": False,
                "skip_reason": None,
                "count": len(alerts),
                "blocking_count": len(dependabot_findings(alerts, threshold)),
                "alerts": alerts,
            }
            blocking_findings.extend(dependabot_findings(alerts, threshold))
            evidence_lines.append("SSP-EVIDENCE: enterprise Dependabot alert polling completed successfully")
            write_json(output_dir / "dependabot_alerts.json", alerts)
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
                evidence_lines.append(f"SSP-EVIDENCE: enterprise Dependabot polling issue recorded: {exc}")
                write_json(output_dir / "dependabot_skip.json", results["dependabot"])
            else:
                fail(str(exc), exit_code=2)

        # Keep fields present and consistent for downstream spreadsheets.
        results["code_scanning"] = {
            "accessible": False,
            "skipped": True,
            "skip_reason": "enterprise scope does not expose code scanning alerts in this collector path",
            "count": 0,
            "blocking_count": 0,
            "alerts": [],
        }
        results["secret_scanning"] = {
            "accessible": False,
            "skipped": True,
            "skip_reason": "enterprise scope does not expose secret scanning alerts in this collector path",
            "count": 0,
            "blocking_count": 0,
            "alerts": [],
        }
    else:
        try:
            print("Phase 1: code scanning alert polling")
            alerts = list_alerts(base_path, headers, "code-scanning/alerts")
            results["code_scanning"] = {
                "accessible": True,
                "skipped": False,
                "skip_reason": None,
                "count": len(alerts),
                "blocking_count": len(codeql_findings(alerts, threshold)),
                "alerts": alerts,
            }
            blocking_findings.extend(codeql_findings(alerts, threshold))
            evidence_lines.append("SSP-EVIDENCE: code scanning alert polling completed successfully")
            write_json(output_dir / "code_scanning_alerts.json", alerts)
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
                evidence_lines.append(f"SSP-EVIDENCE: code scanning collection error recorded for review: {exc}")
                write_json(output_dir / "code_scanning_error.json", {"error": str(exc)})
            else:
                fail(str(exc), exit_code=2)

        try:
            print("Phase 2: Dependabot alert polling")
            alerts = list_alerts(base_path, headers, "dependabot/alerts")
            results["dependabot"] = {
                "accessible": True,
                "skipped": False,
                "skip_reason": None,
                "count": len(alerts),
                "blocking_count": len(dependabot_findings(alerts, threshold)),
                "alerts": alerts,
            }
            blocking_findings.extend(dependabot_findings(alerts, threshold))
            evidence_lines.append("SSP-EVIDENCE: dependabot alert polling completed successfully")
            write_json(output_dir / "dependabot_alerts.json", alerts)
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
                evidence_lines.append(f"SSP-EVIDENCE: Dependabot polling issue recorded: {exc}")
                write_json(output_dir / "dependabot_skip.json", results["dependabot"])
            else:
                fail(str(exc), exit_code=2)

        try:
            print("Phase 3: secret scanning alert polling")
            alerts = list_alerts(base_path, headers, "secret-scanning/alerts")
            results["secret_scanning"] = {
                "accessible": True,
                "skipped": False,
                "skip_reason": None,
                "count": len(alerts),
                "blocking_count": len(secret_findings(alerts)),
                "alerts": alerts,
            }
            blocking_findings.extend(secret_findings(alerts))
            evidence_lines.append("SSP-EVIDENCE: secret scanning alert polling completed successfully")
            write_json(output_dir / "secret_scanning_alerts.json", alerts)
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
                evidence_lines.append(f"SSP-EVIDENCE: secret scanning polling issue recorded: {exc}")
                write_json(output_dir / "secret_scanning_skip.json", results["secret_scanning"])
            else:
                fail(str(exc), exit_code=2)

    snapshot = build_snapshot(
        scope=scope,
        organization=organization,
        repository=repository,
        repository_full=repository_full,
        enterprise=enterprise,
        auth_kind=auth_kind,
        results=results,
        blocking_findings=blocking_findings,
        errors=errors,
    )

    append_history(output_dir, snapshot)
    write_summary_files(output_dir, snapshot, auth_attempts, evidence_lines)
    write_text(output_dir / "summary.md", render_summary_md(snapshot, auth_attempts))

    print("")
    print("SA-04(10) collection complete")
    print(f"Organization: {snapshot['organization']}")
    print(f"Repository: {snapshot['repository']}")
    print(f"Repository full: {snapshot['repository_full']}")
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
