#!/usr/bin/env python3
"""
IA-11 FedRAMP evidence collector for GitHub.com organizations.

What it does:
- Pulls GitHub org metadata and audit log events
- Summarizes authentication-related evidence for IA-11
- Produces JSON + Markdown reports for auditor review
- Flags missing manual evidence items that a screenshot package should provide

Environment variables:
- GITHUB_ORG: GitHub organization name (required)
- GITHUB_TOKEN: GitHub token with read:org and audit log permissions (required)
- GITHUB_API_URL: defaults to https://api.github.com
- OUTPUT_DIR: defaults to artifacts
- SINCE_DAYS: default 30
- PAGE_SIZE: default 100
- MAX_PAGES: default 10
"""

import argparse
import datetime as dt
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


AUTH_RELATED_ACTIONS = {
    "user.login",
    "org.sso_response",
    "org.saml_authentication",
    "oauth_authorization.create",
    "personal_access_token.create",
    "oauth_authorization.destroy",
    "personal_access_token.destroy",
    "repo.access",
}

MANUAL_EVIDENCE_ITEMS = [
    "SAML SSO enforcement screenshot",
    "MFA enforcement screenshot",
    "Session timeout / re-authentication policy screenshot",
    "Audit log UI screenshot with filtered auth event",
    "Org settings screenshot showing security posture",
]


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_iso8601(value: str) -> Optional[dt.datetime]:
    if not value:
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return dt.datetime.fromisoformat(value)
    except ValueError:
        return None


def api_get(url: str, token: str, timeout: int = 30) -> Any:
    req = Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ia11-fedramp-evidence-collector",
        },
        method="GET",
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            if not body:
                return None
            return json.loads(body)
    except HTTPError as exc:
        raise RuntimeError(
            f"GitHub API error {exc.code} for {url}: "
            f"{exc.read().decode('utf-8', errors='replace')}"
        ) from exc
    except URLError as exc:
        raise RuntimeError(f"Network error calling {url}: {exc}") from exc


def build_url(api_base: str, path: str, params: Optional[Dict[str, Any]] = None) -> str:
    api_base = api_base.rstrip("/")
    path = path if path.startswith("/") else f"/{path}"
    url = f"{api_base}{path}"
    if params:
        filtered = {k: v for k, v in params.items() if v is not None and v != ""}
        if filtered:
            url = f"{url}?{urlencode(filtered)}"
    return url


def fetch_org_metadata(api_base: str, token: str, org: str) -> Dict[str, Any]:
    return api_get(build_url(api_base, f"/orgs/{org}"), token)


def fetch_audit_log_events(
    api_base: str,
    token: str,
    org: str,
    since_days: int,
    page_size: int,
    max_pages: int,
) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    cutoff = utc_now() - dt.timedelta(days=since_days)

    for page in range(1, max_pages + 1):
        url = build_url(
            api_base,
            f"/orgs/{org}/audit-log",
            {"per_page": page_size, "page": page},
        )
        data = api_get(url, token)

        if not data:
            break
        if not isinstance(data, list):
            raise RuntimeError(f"Unexpected audit log response type: {type(data)}")

        stop = False
        for event in data:
            created = parse_iso8601(str(event.get("@timestamp", "")))
            if created and created < cutoff:
                stop = True
                continue
            events.append(event)

        if stop or len(data) < page_size:
            break

    return events


def summarize_events(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    actions = [str(e.get("action", "unknown")) for e in events]
    counts = Counter(actions)

    auth_events = [e for e in events if str(e.get("action", "")) in AUTH_RELATED_ACTIONS]
    login_events = [e for e in events if str(e.get("action", "")) == "user.login"]
    sso_events = [
        e for e in events
        if str(e.get("action", "")) in {"org.sso_response", "org.saml_authentication"}
    ]
    pat_events = [e for e in events if str(e.get("action", "")) == "personal_access_token.create"]
    oauth_events = [e for e in events if str(e.get("action", "")) == "oauth_authorization.create"]

    return {
        "total_events": len(events),
        "event_counts": dict(counts),
        "auth_related_events": len(auth_events),
        "login_events": len(login_events),
        "sso_events": len(sso_events),
        "pat_creation_events": len(pat_events),
        "oauth_authorization_events": len(oauth_events),
    }


def detect_manual_evidence(root: Path) -> Dict[str, bool]:
    evidence_dir = root / "evidence" / "manual"
    present = evidence_dir.exists() and any(p.is_file() for p in evidence_dir.rglob("*"))
    return {item: present for item in MANUAL_EVIDENCE_ITEMS}


def compute_status(org_meta: Dict[str, Any], summary: Dict[str, Any], manual_evidence_present: bool) -> Tuple[str, List[str]]:
    notes: List[str] = []
    status = "PASS"

    if not org_meta:
        return "FAIL", ["Unable to retrieve organization metadata."]

    if org_meta.get("two_factor_requirement_enabled") is not True:
        status = "FAIL"
        notes.append("GitHub organization does not require 2FA according to org metadata.")

    if summary["login_events"] == 0:
        if status == "PASS":
            status = "WARN"
        notes.append("No user.login events were found in the selected lookback window.")

    if summary["sso_events"] == 0:
        if status == "PASS":
            status = "WARN"
        notes.append("No org.sso_response / org.saml_authentication events were found in the selected lookback window.")

    if not manual_evidence_present:
        if status == "PASS":
            status = "WARN"
        notes.append("Manual evidence package not detected. Add screenshots for SAML, MFA, session timeout, and audit log views.")

    return status, notes


def write_reports(
    output_dir: Path,
    org: str,
    org_meta: Dict[str, Any],
    events: List[Dict[str, Any]],
    summary: Dict[str, Any],
    status: str,
    notes: List[str],
    manual_evidence: Dict[str, bool],
    since_days: int,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    raw_path = output_dir / "github_audit_log_raw.json"
    raw_path.write_text(json.dumps(events, indent=2))

    report = {
        "control": "IA-11",
        "organization": org,
        "lookback_days": since_days,
        "generated_at_utc": utc_now().isoformat(),
        "status": status,
        "notes": notes,
        "organization_metadata": {
            "two_factor_requirement_enabled": org_meta.get("two_factor_requirement_enabled"),
            "default_repository_permission": org_meta.get("default_repository_permission"),
            "members_can_create_repositories": org_meta.get("members_can_create_repositories"),
        },
        "summary": summary,
        "manual_evidence": manual_evidence,
        "required_manual_evidence": MANUAL_EVIDENCE_ITEMS,
        "artifacts": {
            "raw_audit_log": raw_path.name,
            "markdown_report": "ia11_report.md",
        },
    }

    (output_dir / "ia11_report.json").write_text(json.dumps(report, indent=2))

    md_lines = [
        "# IA-11 FedRAMP Evidence Report",
        "",
        f"Organization: `{org}`",
        f"Lookback window: `{since_days}` days",
        f"Generated at (UTC): `{report['generated_at_utc']}`",
        f"Status: **{status}**",
        "",
        "## Organization Signals",
        f"- 2FA requirement enabled: `{org_meta.get('two_factor_requirement_enabled')}`",
        f"- Default repository permission: `{org_meta.get('default_repository_permission')}`",
        f"- Members can create repositories: `{org_meta.get('members_can_create_repositories')}`",
        "",
        "## Audit Log Summary",
        f"- Total events collected: `{summary['total_events']}`",
        f"- Authentication-related events: `{summary['auth_related_events']}`",
        f"- user.login events: `{summary['login_events']}`",
        f"- org.sso_response / org.saml_authentication events: `{summary['sso_events']}`",
        f"- personal_access_token.create events: `{summary['pat_creation_events']}`",
        f"- oauth_authorization.create events: `{summary['oauth_authorization_events']}`",
        "",
        "## Manual Evidence Check",
    ]
    for item, present in manual_evidence.items():
        md_lines.append(f"- {item}: {'present' if present else 'missing'}")

    if notes:
        md_lines.extend(["", "## Notes"])
        for note in notes:
            md_lines.append(f"- {note}")

    md_lines.extend([
        "",
        "## Auditor Guidance",
        "This report is supporting evidence only. It should be paired with screenshots and configuration exports that demonstrate:",
        "- SAML SSO enforcement",
        "- MFA enforcement",
        "- Session re-authentication policy",
        "- Audit log retention and review",
    ])

    (output_dir / "ia11_report.md").write_text("\n".join(md_lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect IA-11 FedRAMP evidence from GitHub audit logs.")
    parser.add_argument("--org", default=os.getenv("GITHUB_ORG"))
    parser.add_argument("--token", default=os.getenv("GITHUB_TOKEN"))
    parser.add_argument("--api-url", default=os.getenv("GITHUB_API_URL", "https://api.github.com"))
    parser.add_argument("--output-dir", default=os.getenv("OUTPUT_DIR", "artifacts"))
    parser.add_argument("--since-days", type=int, default=int(os.getenv("SINCE_DAYS", "30")))
    parser.add_argument("--page-size", type=int, default=int(os.getenv("PAGE_SIZE", "100")))
    parser.add_argument("--max-pages", type=int, default=int(os.getenv("MAX_PAGES", "10")))
    args = parser.parse_args()

    if not args.org:
        print("ERROR: GITHUB_ORG is required.", file=sys.stderr)
        return 2
    if not args.token:
        print("ERROR: GITHUB_TOKEN is required.", file=sys.stderr)
        return 2

    try:
        org_meta = fetch_org_metadata(args.api_url, args.token, args.org)
        events = fetch_audit_log_events(
            api_base=args.api_url,
            token=args.token,
            org=args.org,
            since_days=args.since_days,
            page_size=args.page_size,
            max_pages=args.max_pages,
        )
        summary = summarize_events(events)
        manual_evidence = detect_manual_evidence(Path.cwd())
        manual_present = any(manual_evidence.values())
        status, notes = compute_status(org_meta, summary, manual_present)
        write_reports(
            output_dir=Path(args.output_dir),
            org=args.org,
            org_meta=org_meta,
            events=events,
            summary=summary,
            status=status,
            notes=notes,
            manual_evidence=manual_evidence,
            since_days=args.since_days,
        )

        print(f"IA-11 report written to {args.output_dir}/ia11_report.md")
        print(f"Status: {status}")
        return 1 if status == "FAIL" else 0

    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
