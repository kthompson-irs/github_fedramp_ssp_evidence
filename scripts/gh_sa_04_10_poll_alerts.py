#!/usr/bin/env python3
"""
SA-04(10) alert polling and evidence collection for GitHub.com.

Checks:
- Code scanning alerts (CodeQL): fail on open alerts at or above threshold
- Dependabot alerts: fail on open alerts at or above threshold
- Secret scanning alerts: fail on any open alert

Behavior:
- Collects JSON evidence files for each category.
- Gracefully logs and records skipped Dependabot or Secret Scanning access when
  GitHub denies access with 403/404 while SA04_SOFT_FAIL is enabled.
- Writes summary.json, summary.md, evidence_lines.txt, blocking_findings.json,
  and category-specific evidence files under the output directory.

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


def make_headers() -> Dict[str, str]:
    token = get_env("GH_DEPENDABOT_TOKEN")
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


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
            raise RuntimeError(
                f"GitHub API request failed for {url}: {exc} | body={response.text[:300]}"
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


def probe_optional_endpoint(
    url: str,
    headers: Dict[str, str],
    label: str,
) -> Tuple[bool, Dict[str, Any], Optional[str]]:
    response = requests.get(
        url,
        headers=headers,
        params={"state": "open", "per_page": 1, "page": 1},
        timeout=TIMEOUT_SECONDS,
    )

    if response.status_code == 200:
        return True, {"status_code": 200, "message": "accessible"}, None

    if response.status_code in {403, 404}:
        try:
            body = response.json()
            message = body.get("message") if isinstance(body, dict) else None
        except Exception:
            message = None
        if not message:
            message = response.text[:300]
        return False, {"status_code": response.status_code, "message": message}, (
            f"GitHub returned {response.status_code} for {label}; access is not available to the token or endpoint."
        )

    if response.status_code == 401:
        fail(f"{label} endpoint returned 401 Unauthorized. Check GH_DEPENDABOT_TOKEN.", exit_code=2)

    fail(
        f"unexpected response from {label} endpoint: {response.status_code} {response.text[:300]}",
        exit_code=2,
    )


def collect_code_scanning(repo: str, headers: Dict[str, str], threshold: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[str]]:
    url = f"{GH_API}/repos/{repo}/code-scanning/alerts"
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
        "count": len(alerts),
        "blocking_count": len(blocking_findings),
        "alerts": alerts,
    }
    return result, blocking_findings, evidence_lines


def collect_optional_alerts(
    repo: str,
    headers: Dict[str, str],
    label: str,
    endpoint: str,
    soft_fail: bool,
    threshold: str,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[str], List[str]]:
    url = f"{GH_API}/repos/{repo}/{endpoint}"
    accessible, access_info, skip_reason = probe_optional_endpoint(url, headers, label)

    if not accessible:
        result = {
            "accessible": False,
            "skipped": True,
            "skip_reason": access_info.get("message"),
            "status_code": access_info.get("status_code"),
            "count": 0,
            "blocking_count": 0,
            "alerts": [],
        }
        evidence_line = (
            f"SSP-EVIDENCE: {label} alert polling skipped because GitHub returned "
            f"{access_info.get('status_code')} for the alerts endpoint; documented for SA-04(10) review."
        )
        if soft_fail:
            return result, [], [evidence_line], [skip_reason or evidence_line]
        fail(evidence_line, exit_code=2)

    alerts = paged_get(url, headers, params={"state": "open"})
    blocking_findings: List[Dict[str, Any]] = []

    if label == "dependabot":
        for alert in alerts:
            advisory = alert.get("security_advisory") or {}
            severity = str(advisory.get("severity") or "").lower()
            if severity_is_blocking(severity, threshold):
                blocking_findings.append(extract_dependabot_finding(alert))
    elif label == "secret_scanning":
        for alert in alerts:
            if alert.get("state") == "open" or not alert.get("state"):
                blocking_findings.append(extract_secret_scanning_finding(alert))
    else:
        fail(f"unsupported optional alert label: {label}", exit_code=2)

    result = {
        "accessible": True,
        "skipped": False,
        "count": len(alerts),
        "blocking_count": len(blocking_findings),
        "alerts": alerts,
    }
    evidence_line = f"SSP-EVIDENCE: {label} alert polling completed successfully"
    return result, blocking_findings, [evidence_line], []


def build_summary(
    repo: str,
    threshold: str,
    soft_fail: bool,
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
        "repository": repo,
        "threshold": threshold,
        "soft_fail": soft_fail,
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


def render_summary_md(summary: Dict[str, Any]) -> str:
    repo = summary["repository"]
    threshold = summary["threshold"]
    overall = summary["overall"]
    results = summary["results"]

    lines = [
        "# SA-04(10) Evidence Collection Summary",
        "",
        f"- Repository: `{repo}`",
        f"- Threshold: `{threshold}`",
        f"- Generated: `{summary['generated_at']}`",
        f"- Status: `{overall['status']}`",
        f"- Blocking findings: `{overall['blocking_count']}`",
        f"- Collection errors: `{overall['error_count']}`",
        "",
        "## Category Results",
        "",
        "| Category | Accessible | Skipped | Count | Blocking |",
        "|---|---:|---:|---:|---:|",
    ]

    for category in ("code_scanning", "dependabot", "secret_scanning"):
        item = results.get(category, {})
        lines.append(
            f"| {category} | {str(item.get('accessible', False)).lower()} | "
            f"{str(item.get('skipped', False)).lower()} | {item.get('count', 0)} | "
            f"{item.get('blocking_count', 0)} |"
        )

    lines.extend(
        [
            "",
            "## Evidence Lines",
            "",
        ]
    )

    for entry in summary.get("evidence_lines", []):
        lines.append(f"- {entry}")

    if summary.get("errors"):
        lines.extend(["", "## Collection Errors", ""])
        for entry in summary["errors"]:
            lines.append(f"- {entry}")

    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    repo = get_env("GH_REPO")
    threshold = os.getenv("FAIL_ON_SEVERITY", "high").strip().lower()
    soft_fail = args.soft_fail or os.getenv("SA04_SOFT_FAIL", "") == "1"

    if threshold not in {"low", "medium", "high", "critical"}:
        fail(f"invalid FAIL_ON_SEVERITY value: {threshold}", exit_code=2)

    headers = make_headers()

    print("SA-04(10) security gate starting")
    print(f"Repository: {repo}")
    print(f"Blocking threshold: {threshold}")
    print(f"Soft fail: {soft_fail}")

    results: Dict[str, Any] = {}
    evidence_lines: List[str] = []
    errors: List[str] = []
    blocking_findings: List[Dict[str, Any]] = []

    # Code scanning is treated as required. If the endpoint is inaccessible in soft-fail mode,
    # the condition is still captured for evidence and the workflow can finish building the binder.
    try:
        print("Phase 1: code scanning alert polling")
        code_scanning_result, code_scanning_blocking, code_scanning_evidence = collect_code_scanning(
            repo, headers, threshold
        )
        results["code_scanning"] = code_scanning_result
        blocking_findings.extend(code_scanning_blocking)
        evidence_lines.extend(code_scanning_evidence)
        write_json(output_dir / "code_scanning_alerts.json", code_scanning_result["alerts"])
    except Exception as exc:
        message = f"code scanning collection error: {exc}"
        if soft_fail:
            errors.append(message)
            results["code_scanning"] = {
                "accessible": False,
                "skipped": True,
                "skip_reason": str(exc),
                "count": 0,
                "blocking_count": 0,
                "alerts": [],
            }
            evidence_lines.append(f"SSP-EVIDENCE: code scanning collection error recorded for review: {exc}")
            write_json(output_dir / "code_scanning_error.json", {"error": str(exc)})
        else:
            fail(message, exit_code=2)

    # Dependabot is optionally skipped when access is not available.
    try:
        print("Phase 2: Dependabot alert polling")
        dependabot_result, dependabot_blocking, dependabot_evidence, dependabot_errors = collect_optional_alerts(
            repo=repo,
            headers=headers,
            label="dependabot",
            endpoint="dependabot/alerts",
            soft_fail=soft_fail,
            threshold=threshold,
        )
        results["dependabot"] = dependabot_result
        blocking_findings.extend(dependabot_blocking)
        evidence_lines.extend(dependabot_evidence)
        errors.extend(dependabot_errors)
        if dependabot_result.get("accessible"):
            write_json(output_dir / "dependabot_alerts.json", dependabot_result["alerts"])
        else:
            write_json(output_dir / "dependabot_skip.json", dependabot_result)
    except Exception as exc:
        message = f"dependabot collection error: {exc}"
        if soft_fail:
            errors.append(message)
            results["dependabot"] = {
                "accessible": False,
                "skipped": True,
                "skip_reason": str(exc),
                "count": 0,
                "blocking_count": 0,
                "alerts": [],
            }
            evidence_lines.append(f"SSP-EVIDENCE: Dependabot collection error recorded for review: {exc}")
            write_json(output_dir / "dependabot_error.json", {"error": str(exc)})
        else:
            fail(message, exit_code=2)

    # Secret scanning is also captured and can be skipped with evidence if the endpoint is unavailable.
    try:
        print("Phase 3: secret scanning alert polling")
        secret_result, secret_blocking, secret_evidence, secret_errors = collect_optional_alerts(
            repo=repo,
            headers=headers,
            label="secret_scanning",
            endpoint="secret-scanning/alerts",
            soft_fail=soft_fail,
            threshold=threshold,
        )
        results["secret_scanning"] = secret_result
        blocking_findings.extend(secret_blocking)
        evidence_lines.extend(secret_evidence)
        errors.extend(secret_errors)
        if secret_result.get("accessible"):
            write_json(output_dir / "secret_scanning_alerts.json", secret_result["alerts"])
        else:
            write_json(output_dir / "secret_scanning_skip.json", secret_result)
    except Exception as exc:
        message = f"secret scanning collection error: {exc}"
        if soft_fail:
            errors.append(message)
            results["secret_scanning"] = {
                "accessible": False,
                "skipped": True,
                "skip_reason": str(exc),
                "count": 0,
                "blocking_count": 0,
                "alerts": [],
            }
            evidence_lines.append(f"SSP-EVIDENCE: secret scanning collection error recorded for review: {exc}")
            write_json(output_dir / "secret_scanning_error.json", {"error": str(exc)})
        else:
            fail(message, exit_code=2)

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
        repo=repo,
        threshold=threshold,
        soft_fail=soft_fail,
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
