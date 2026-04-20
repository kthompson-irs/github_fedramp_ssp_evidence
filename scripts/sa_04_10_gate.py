#!/usr/bin/env python3
"""SA-04(10) compliance gate for GitHub.com.

This script queries GitHub's REST APIs for:
  - code scanning alerts
  - Dependabot alerts
  - secret scanning alerts

It fails the run if it finds:
  - any open secret scanning alerts
  - any open code scanning alerts at or above the configured severity threshold
  - any open Dependabot alerts at or above the configured severity threshold

Environment:
  GITHUB_TOKEN (required)
  GITHUB_REPOSITORY (required, e.g. org/repo)
  GITHUB_API_URL (optional, default https://api.github.com)
  CODE_SCAN_FAIL_SEVERITIES (optional, default critical,high)
  DEPENDABOT_FAIL_SEVERITIES (optional, default critical,high)
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlparse, parse_qs
from urllib.request import Request, urlopen


SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "moderate": 2,
    "medium": 2,
    "low": 1,
    "unknown": 0,
    None: 0,
}


@dataclass
class FindingSummary:
    category: str
    count: int
    failing: int
    samples: List[str]


def _require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value


def _api_get_all(base_url: str, token: str, path: str, params: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    params = dict(params or {})
    params.setdefault("per_page", "100")
    url = f"{base_url.rstrip('/')}{path}?{urlencode(params)}"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "sa-04-10-compliance-gate",
    }

    items: List[Dict[str, Any]] = []
    while url:
        req = Request(url, headers=headers)
        try:
            with urlopen(req, timeout=60) as resp:
                raw = resp.read().decode("utf-8")
                page = json.loads(raw) if raw else []
                if isinstance(page, dict):
                    page = [page]
                items.extend(page)
                url = _next_link(resp.headers.get("Link"))
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace") if hasattr(exc, "read") else ""
            raise SystemExit(f"GitHub API error for {path}: {exc.code} {exc.reason}\n{body}") from exc
        except URLError as exc:
            raise SystemExit(f"Network error calling GitHub API for {path}: {exc}") from exc

    return items


def _next_link(link_header: Optional[str]) -> Optional[str]:
    if not link_header:
        return None
    for part in link_header.split(","):
        if 'rel="next"' in part:
            match = re.search(r"<([^>]+)>", part)
            if match:
                return match.group(1)
    return None


def _severity_value(raw: Optional[str]) -> int:
    return SEVERITY_ORDER.get((raw or "unknown").lower(), 0)


def _code_alert_severity(alert: Dict[str, Any]) -> str:
    rule = alert.get("rule") or {}
    return (rule.get("security_severity_level") or alert.get("security_severity_level") or "unknown").lower()


def _dependabot_alert_severity(alert: Dict[str, Any]) -> str:
    advisory = alert.get("security_advisory") or {}
    return (advisory.get("severity") or alert.get("severity") or "unknown").lower()


def _slug(alert: Dict[str, Any], keys: Sequence[str]) -> str:
    for key in keys:
        value = alert.get(key)
        if value:
            return str(value)
    return "unknown"


def _top_samples(alerts: Sequence[Dict[str, Any]], formatter, limit: int = 5) -> List[str]:
    samples: List[str] = []
    for alert in alerts[:limit]:
        samples.append(formatter(alert))
    return samples


def _format_code_alert(alert: Dict[str, Any]) -> str:
    severity = _code_alert_severity(alert)
    rule = alert.get("rule") or {}
    location = (alert.get("most_recent_instance") or {}).get("location") or {}
    path = location.get("path") or "unknown path"
    start_line = location.get("start_line")
    label = rule.get("name") or rule.get("id") or "code-scanning-alert"
    line = f":{start_line}" if start_line else ""
    return f"- [{severity}] {label} @ {path}{line}"


def _format_dependabot_alert(alert: Dict[str, Any]) -> str:
    severity = _dependabot_alert_severity(alert)
    dep = alert.get("dependency") or {}
    pkg = dep.get("package") or {}
    manifest = dep.get("manifest_path") or "unknown manifest"
    name = pkg.get("name") or "unknown package"
    return f"- [{severity}] {name} in {manifest}"


def _format_secret_alert(alert: Dict[str, Any]) -> str:
    secret_type = alert.get("secret_type") or alert.get("secret_type_display_name") or "secret"
    location = (alert.get("location") or {}).get("path") or "unknown path"
    return f"- [open] {secret_type} @ {location}"


def _summarize_code_scan(alerts: Sequence[Dict[str, Any]], threshold_severities: Sequence[str]) -> FindingSummary:
    threshold = max((_severity_value(s) for s in threshold_severities), default=0)
    failing = [a for a in alerts if _severity_value(_code_alert_severity(a)) >= threshold and threshold > 0]
    return FindingSummary(
        category="Code scanning",
        count=len(alerts),
        failing=len(failing),
        samples=_top_samples(failing or alerts, _format_code_alert),
    )


def _summarize_dependabot(alerts: Sequence[Dict[str, Any]], threshold_severities: Sequence[str]) -> FindingSummary:
    threshold = max((_severity_value(s) for s in threshold_severities), default=0)
    failing = [a for a in alerts if _severity_value(_dependabot_alert_severity(a)) >= threshold and threshold > 0]
    return FindingSummary(
        category="Dependabot",
        count=len(alerts),
        failing=len(failing),
        samples=_top_samples(failing or alerts, _format_dependabot_alert),
    )


def _summarize_secrets(alerts: Sequence[Dict[str, Any]]) -> FindingSummary:
    return FindingSummary(
        category="Secret scanning",
        count=len(alerts),
        failing=len(alerts),
        samples=_top_samples(alerts, _format_secret_alert),
    )


def _write_summary_block(summary_path: Optional[str], content: str) -> None:
    if not summary_path:
        return
    with open(summary_path, "a", encoding="utf-8") as fh:
        fh.write(content)
        if not content.endswith("\n"):
            fh.write("\n")


def main() -> int:
    token = _require_env("GITHUB_TOKEN")
    repo = _require_env("GITHUB_REPOSITORY")
    base_url = os.getenv("GITHUB_API_URL", "https://api.github.com")
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")

    owner, name = repo.split("/", 1)
    repo_path = f"/repos/{owner}/{name}"

    code_thresholds = [s.strip().lower() for s in os.getenv("CODE_SCAN_FAIL_SEVERITIES", "critical,high").split(",") if s.strip()]
    dep_thresholds = [s.strip().lower() for s in os.getenv("DEPENDABOT_FAIL_SEVERITIES", "critical,high").split(",") if s.strip()]

    code_alerts = _api_get_all(base_url, token, f"{repo_path}/code-scanning/alerts", {"state": "open"})
    dep_alerts = _api_get_all(base_url, token, f"{repo_path}/dependabot/alerts", {"state": "open"})
    secret_alerts = _api_get_all(base_url, token, f"{repo_path}/secret-scanning/alerts", {"state": "open"})

    code_summary = _summarize_code_scan(code_alerts, code_thresholds)
    dep_summary = _summarize_dependabot(dep_alerts, dep_thresholds)
    secret_summary = _summarize_secrets(secret_alerts)

    report_lines = [
        "# SA-04(10) compliance gate",
        "",
        f"Repository: `{repo}`",
        f"Code scanning open alerts: `{code_summary.count}` (failing: `{code_summary.failing}`)",
        f"Dependabot open alerts: `{dep_summary.count}` (failing: `{dep_summary.failing}`)",
        f"Secret scanning open alerts: `{secret_summary.count}` (failing: `{secret_summary.failing}`)",
        "",
    ]

    for block in (code_summary, dep_summary, secret_summary):
        report_lines.append(f"## {block.category}")
        if block.samples:
            report_lines.extend(block.samples)
        else:
            report_lines.append("- No open alerts found.")
        report_lines.append("")

    report = "\n".join(report_lines)
    print(report)
    _write_summary_block(summary_path, report + "\n")

    failures: List[str] = []
    if code_summary.failing:
        failures.append(f"{code_summary.failing} code scanning alert(s) at/above threshold")
    if dep_summary.failing:
        failures.append(f"{dep_summary.failing} Dependabot alert(s) at/above threshold")
    if secret_summary.failing:
        failures.append(f"{secret_summary.failing} secret scanning alert(s)")

    if failures:
        print("SA-04(10) gate failed: " + "; ".join(failures), file=sys.stderr)
        return 1

    print("SA-04(10) gate passed: no blocking alerts found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
