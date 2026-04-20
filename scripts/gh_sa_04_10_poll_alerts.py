#!/usr/bin/env python3
"""
SA-04(10) alert polling gate for GitHub.com.

Checks:
- Code scanning alerts (CodeQL): fail on open alerts at or above threshold
- Dependabot alerts: fail on open alerts at or above threshold
- Secret scanning alerts: fail on any open alert

Exit codes:
- 0 = compliant
- 1 = compliance failure
- 2 = configuration/runtime failure
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Optional, NoReturn

import requests

GH_API = "https://api.github.com"
PAGE_SIZE = 100
TIMEOUT_SECONDS = 30


def fail(message: str, exit_code: int = 1) -> NoReturn:
    print(f"SA-04(10) COMPLIANCE FAILURE: {message}")
    sys.exit(exit_code)


def get_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        fail(f"required environment variable {name} is not set", exit_code=2)
    return value


def make_headers() -> Dict[str, str]:
    token = get_env("GH_TOKEN")
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


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
            fail(f"GitHub API request failed for {url}: {exc}", exit_code=2)

        payload = response.json()
        if not isinstance(payload, list):
            fail(f"unexpected response shape from {url}", exit_code=2)

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


def check_code_scanning(repo: str, headers: Dict[str, str], threshold: str) -> int:
    url = f"{GH_API}/repos/{repo}/code-scanning/alerts"
    alerts = paged_get(url, headers, params={"state": "open"})

    failures = 0
    for alert in alerts:
        rule = alert.get("rule") or {}
        severity = str(rule.get("severity") or "").lower()
        if severity_is_blocking(severity, threshold):
            alert_id = rule.get("id") or "unknown-rule"
            print(f"BLOCK: code scanning alert {alert_id} severity={severity}")
            failures += 1

    print(f"Code scanning alerts checked: {len(alerts)}")
    return failures


def check_dependabot(repo: str, headers: Dict[str, str], threshold: str) -> int:
    url = f"{GH_API}/repos/{repo}/dependabot/alerts"
    alerts = paged_get(url, headers, params={"state": "open"})

    failures = 0
    for alert in alerts:
        advisory = alert.get("security_advisory") or {}
        severity = str(advisory.get("severity") or "").lower()
        if severity_is_blocking(severity, threshold):
            dependency = (((alert.get("dependency") or {}).get("package") or {}).get("name")) or "unknown-package"
            advisory_id = advisory.get("ghsa_id") or advisory.get("cve_id") or "unknown-advisory"
            print(f"BLOCK: dependabot alert {advisory_id} dependency={dependency} severity={severity}")
            failures += 1

    print(f"Dependabot alerts checked: {len(alerts)}")
    return failures


def check_secret_scanning(repo: str, headers: Dict[str, str]) -> int:
    url = f"{GH_API}/repos/{repo}/secret-scanning/alerts"
    alerts = paged_get(url, headers, params={"state": "open"})

    for alert in alerts:
        secret_type = alert.get("secret_type") or alert.get("secret_type_display_name") or "unknown-secret"
        resolution = alert.get("resolution") or "open"
        print(f"BLOCK: secret scanning alert secret_type={secret_type} state={resolution}")

    print(f"Secret scanning alerts checked: {len(alerts)}")
    return len(alerts)


def main() -> int:
    repo = get_env("GH_REPO")
    threshold = os.getenv("FAIL_ON_SEVERITY", "high").strip().lower()
    headers = make_headers()

    if threshold not in {"low", "medium", "high", "critical"}:
        fail(f"invalid FAIL_ON_SEVERITY value: {threshold}", exit_code=2)

    print("SA-04(10) security gate starting")
    print(f"Repository: {repo}")
    print(f"Blocking threshold: {threshold}")

    print("Phase 1: code scanning alert polling")
    code_scanning_failures = check_code_scanning(repo, headers, threshold)

    print("Phase 2: Dependabot alert polling")
    dependabot_failures = check_dependabot(repo, headers, threshold)

    print("Phase 3: secret scanning alert polling")
    secret_failures = check_secret_scanning(repo, headers)

    total_failures = code_scanning_failures + dependabot_failures + secret_failures

    if total_failures > 0:
        fail(
            f"{total_failures} blocking security finding(s) detected. "
            "No deployment may proceed until findings are remediated or formally accepted.",
            exit_code=1,
        )

    print(
        "SA-04(10) COMPLIANCE PASS: no blocking open code scanning, Dependabot, "
        "or secret scanning findings were detected."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
