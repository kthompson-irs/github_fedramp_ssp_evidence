#!/usr/bin/env python3
"""
Enterprise-scoped FedRAMP IA control collector for GitHub Enterprise Cloud.

What this script does:
- Pulls enterprise audit log events
- Validates IA controls using enterprise evidence and optional IdP policy exports
- Produces JSON + Markdown reports
- Fails only on hard IA violations; warnings remain non-fatal

Required environment variables:
- GH_ENTERPRISE
- GH_TOKEN

Optional environment variables:
- GH_API_URL (default: https://api.github.com)
- OUTPUT_DIR (default: artifacts)
- SINCE_DAYS (default: 30)
- PAGE_SIZE (default: 100)
- MAX_PAGES (default: 10)
- IDP_POLICY_FILE (path to JSON export of session/reauth policy)
- ENTERPRISE_SECURITY_FILE (path to JSON export of enterprise security settings)
- MANUAL_EVIDENCE_DIR (path to screenshot package)
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from collections import Counter
from dataclasses import dataclass
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
    "personal_access_token.destroy",
    "repo.access",
}

@dataclass
class ControlResult:
    control_id: str
    status: str
    summary: str
    evidence: List[str]
    notes: List[str]


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


def load_json_file(path: Optional[str]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    if not path:
        return None, None
    p = Path(path)
    if not p.exists():
        return None, f"File not found: {path}"
    try:
        return json.loads(p.read_text()), None
    except Exception as exc:
        return None, f"Unable to parse JSON from {path}: {exc}"


def api_get(url: str, token: str, timeout: int = 30) -> Any:
    req = Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
            "User-Agent": "ia-enterprise-fedramp-collector",
        },
        method="GET",
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body) if body else None
    except HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub API error {exc.code} for {url}: {payload}") from exc
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


def fetch_enterprise_metadata(api_base: str, token: str, enterprise: str) -> Dict[str, Any]:
    return api_get(build_url(api_base, f"/enterprises/{enterprise}"), token)


def fetch_enterprise_audit_events(api_base: str, token: str, enterprise: str, since_days: int, page_size: int, max_pages: int) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    cutoff = utc_now() - dt.timedelta(days=since_days)

    for page in range(1, max_pages + 1):
        url = build_url(api_base, f"/enterprises/{enterprise}/audit-log", {"per_page": page_size, "page": page, "order": "desc", "include": "all"})
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
    return {
        "total_events": len(events),
        "event_counts": dict(counts),
        "auth_related_events": len(auth_events),
        "login_events": counts.get("user.login", 0),
        "sso_events": counts.get("org.sso_response", 0) + counts.get("org.saml_authentication", 0),
        "pat_creation_events": counts.get("personal_access_token.create", 0),
        "oauth_authorization_events": counts.get("oauth_authorization.create", 0),
    }


def detect_manual_evidence(manual_dir: Path) -> Dict[str, bool]:
    expected = {
        "saml_sso_enabled.png": False,
        "mfa_policy.png": False,
        "session_timeout.png": False,
        "reauth_validation.png": False,
        "audit_log_filtered.png": False,
        "enterprise_security_settings.png": False,
    }
    if not manual_dir.exists():
        return expected
    existing = {p.name.lower() for p in manual_dir.rglob("*") if p.is_file()}
    for name in expected:
        expected[name] = name.lower() in existing
    return expected


def validate_idp_policy(policy: Optional[Dict[str, Any]]) -> Tuple[str, List[str], List[str]]:
    notes: List[str] = []
    evidence: List[str] = []
    if not policy:
        return "WARN", ["No IdP policy file provided or it could not be loaded."], evidence

    provider = str(policy.get("provider", "unknown"))
    timeout = policy.get("session_timeout_minutes")
    reauth_required = policy.get("reauth_required")
    mfa_required = policy.get("mfa_required")

    evidence.append(f"IdP provider: {provider}")
    evidence.append(f"Session timeout minutes: {timeout}")
    evidence.append(f"Re-authentication required: {reauth_required}")
    evidence.append(f"MFA required: {mfa_required}")

    if timeout is None or reauth_required is None or mfa_required is None:
        return "FAIL", ["IdP policy file is missing one or more required fields."], evidence
    if not isinstance(timeout, int):
        return "FAIL", ["IdP session_timeout_minutes must be an integer."], evidence

    if timeout > 15:
        notes.append(f"Session timeout is {timeout} minutes, which exceeds the 15 minute IA-11 threshold.")
    if reauth_required is not True:
        notes.append("IdP policy does not require re-authentication.")
    if mfa_required is not True:
        notes.append("IdP policy does not require MFA.")

    if notes:
        return "FAIL", notes, evidence

    return "PASS", ["IdP policy satisfies the IA-11 re-authentication threshold."], evidence


def assess_controls(enterprise_meta: Dict[str, Any], summary: Dict[str, Any], idp_policy: Optional[Dict[str, Any]], enterprise_security: Optional[Dict[str, Any]], manual_evidence: Dict[str, bool]) -> List[ControlResult]:
    results: List[ControlResult] = []

    ia2_evidence: List[str] = []
    ia2_notes: List[str] = []
    ia2_status = "WARN"
    if enterprise_security is not None:
        ia2_evidence.append("Enterprise security settings export loaded.")
        if enterprise_security.get("two_factor_requirement_enabled") is True:
            ia2_status = "PASS"
            ia2_notes.append("Enterprise security export shows 2FA requirement enabled.")
        elif enterprise_security.get("two_factor_requirement_enabled") is False:
            ia2_status = "FAIL"
            ia2_notes.append("Enterprise security export shows 2FA requirement disabled.")
        else:
            ia2_notes.append("Enterprise security export does not contain two_factor_requirement_enabled.")
    else:
        ia2_notes.append("No enterprise security export supplied.")
    if manual_evidence.get("mfa_policy.png"):
        ia2_evidence.append("MFA policy screenshot present.")
        if ia2_status == "WARN":
            ia2_status = "PASS"
    results.append(ControlResult("IA-2", ia2_status, "Organizational user identification and authentication", ia2_evidence, ia2_notes))

    ia4_evidence: List[str] = []
    ia4_notes: List[str] = []
    ia4_status = "WARN"
    if summary["login_events"] > 0:
        ia4_evidence.append(f"{summary['login_events']} login-related events observed in the lookback window.")
        ia4_notes.append("Identity activity observed in enterprise audit log.")
    if enterprise_security and enterprise_security.get("scim_enabled") is True:
        ia4_status = "PASS"
        ia4_evidence.append("SCIM enabled in enterprise export.")
    elif enterprise_security and enterprise_security.get("scim_enabled") is False:
        ia4_notes.append("SCIM is not enabled in enterprise export.")
    results.append(ControlResult("IA-4", ia4_status, "Identifier management", ia4_evidence, ia4_notes))

    ia5_evidence: List[str] = []
    ia5_notes: List[str] = []
    ia5_status = "WARN"
    if summary["pat_creation_events"] > 0:
        ia5_notes.append(f"{summary['pat_creation_events']} PAT creation events found; verify token policies and expiration controls.")
        ia5_evidence.append("PAT creation audit events found.")
    if enterprise_security and enterprise_security.get("pat_expiration_required") is True:
        ia5_status = "PASS"
        ia5_notes.append("Enterprise export indicates PAT expiration is required.")
        ia5_evidence.append("PAT expiration requirement present.")
    results.append(ControlResult("IA-5", ia5_status, "Authenticator management", ia5_evidence, ia5_notes))

    ia7_evidence: List[str] = []
    ia7_notes: List[str] = []
    ia7_status = "WARN"
    if enterprise_security and enterprise_security.get("fips_endpoints_required") is True:
        ia7_status = "PASS"
        ia7_notes.append("Enterprise export requires FIPS endpoints for GovCloud integration.")
        ia7_evidence.append("FIPS endpoint requirement present.")
    else:
        ia7_notes.append("No explicit FIPS endpoint requirement export provided.")
    results.append(ControlResult("IA-7", ia7_status, "Cryptographic module authentication", ia7_evidence, ia7_notes))

    ia8_evidence: List[str] = []
    ia8_notes: List[str] = []
    ia8_status = "WARN"
    if enterprise_security and enterprise_security.get("outside_collaborators_count") is not None:
        count = enterprise_security.get("outside_collaborators_count")
        ia8_evidence.append(f"Outside collaborator count: {count}")
        if isinstance(count, int) and count == 0:
            ia8_status = "PASS"
            ia8_notes.append("No outside collaborators reported.")
        else:
            ia8_notes.append("Outside collaborators exist; ensure access review and least privilege evidence.")
    results.append(ControlResult("IA-8", ia8_status, "Non-organizational user authentication", ia8_evidence, ia8_notes))

    ia11_status, ia11_notes, ia11_evidence = validate_idp_policy(idp_policy)
    if manual_evidence.get("session_timeout.png"):
        ia11_evidence.append("Session timeout screenshot present.")
    if manual_evidence.get("reauth_validation.png"):
        ia11_evidence.append("Re-authentication validation screenshot present.")
    if manual_evidence.get("audit_log_filtered.png"):
        ia11_evidence.append("Filtered audit log screenshot present.")
    results.append(ControlResult("IA-11", ia11_status, "Re-authentication", ia11_evidence, ia11_notes))

    return results


def write_reports(output_dir: Path, enterprise: str, enterprise_meta: Dict[str, Any], events: List[Dict[str, Any]], summary: Dict[str, Any], controls: List[ControlResult], manual_evidence: Dict[str, bool], since_days: int) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    status_rank = {"PASS": 0, "WARN": 1, "FAIL": 2}
    overall = "PASS"
    for c in controls:
        if status_rank[c.status] > status_rank[overall]:
            overall = c.status

    raw_path = output_dir / "enterprise_audit_log_raw.json"
    raw_path.write_text(json.dumps(events, indent=2))

    report = {
        "scope": "GitHub Enterprise Cloud",
        "control_family": "IA",
        "enterprise": enterprise,
        "lookback_days": since_days,
        "generated_at_utc": utc_now().isoformat(),
        "overall_status": overall,
        "enterprise_metadata": enterprise_meta,
        "summary": summary,
        "controls": [
            {
                "control_id": c.control_id,
                "status": c.status,
                "summary": c.summary,
                "evidence": c.evidence,
                "notes": c.notes,
            }
            for c in controls
        ],
        "manual_evidence": manual_evidence,
        "artifacts": {
            "raw_audit_log": raw_path.name,
            "markdown_report": "ia_enterprise_report.md",
        },
    }

    (output_dir / "ia_enterprise_report.json").write_text(json.dumps(report, indent=2))

    md = [
        "# IA FedRAMP Enterprise Evidence Report",
        "",
        f"Enterprise: `{enterprise}`",
        f"Lookback window: `{since_days}` days",
        f"Generated at (UTC): `{report['generated_at_utc']}`",
        f"Overall status: **{overall}**",
        "",
        "## Enterprise Signals",
        f"- Enterprise name: `{enterprise_meta.get('name')}`",
        f"- Enterprise slug: `{enterprise_meta.get('slug')}`",
        "",
        "## Audit Log Summary",
        f"- Total events collected: `{summary['total_events']}`",
        f"- Authentication-related events: `{summary['auth_related_events']}`",
        f"- user.login events: `{summary['login_events']}`",
        f"- org.sso_response / org.saml_authentication events: `{summary['sso_events']}`",
        f"- personal_access_token.create events: `{summary['pat_creation_events']}`",
        f"- oauth_authorization.create events: `{summary['oauth_authorization_events']}`",
        "",
        "## Control Results",
    ]
    for c in controls:
        md.append(f"### {c.control_id} — {c.status}")
        md.append(c.summary)
        if c.evidence:
            md.append("Evidence:")
            for item in c.evidence:
                md.append(f"- {item}")
        if c.notes:
            md.append("Notes:")
            for item in c.notes:
                md.append(f"- {item}")
        md.append("")

    md.append("## Manual Evidence Presence")
    for name, present in manual_evidence.items():
        md.append(f"- {name}: {'present' if present else 'missing'}")

    md.extend([
        "",
        "## Auditor Guidance",
        "This report is supporting evidence only. Pair it with screenshots and exports for SAML, MFA, session timeout, re-authentication, and audit log review.",
    ])

    (output_dir / "ia_enterprise_report.md").write_text("\n".join(md) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect enterprise-scoped IA FedRAMP evidence from GitHub Enterprise Cloud.")
    parser.add_argument("--enterprise", default=os.getenv("GH_ENTERPRISE"))
    parser.add_argument("--token", default=os.getenv("GH_TOKEN"))
    parser.add_argument("--api-url", default=os.getenv("GH_API_URL", "https://api.github.com"))
    parser.add_argument("--output-dir", default=os.getenv("OUTPUT_DIR", "artifacts"))
    parser.add_argument("--since-days", type=int, default=int(os.getenv("SINCE_DAYS", "30")))
    parser.add_argument("--page-size", type=int, default=int(os.getenv("PAGE_SIZE", "100")))
    parser.add_argument("--max-pages", type=int, default=int(os.getenv("MAX_PAGES", "10")))
    parser.add_argument("--idp-policy-file", default=os.getenv("IDP_POLICY_FILE"))
    parser.add_argument("--enterprise-security-file", default=os.getenv("ENTERPRISE_SECURITY_FILE"))
    parser.add_argument("--manual-evidence-dir", default=os.getenv("MANUAL_EVIDENCE_DIR", "evidence/manual"))
    args = parser.parse_args()

    if not args.enterprise:
        print("ERROR: GH_ENTERPRISE is required.", file=sys.stderr)
        return 2
    if not args.token:
        print("ERROR: GH_TOKEN is required.", file=sys.stderr)
        return 2

    try:
        enterprise_meta = fetch_enterprise_metadata(args.api_url, args.token, args.enterprise)
        events = fetch_enterprise_audit_events(args.api_url, args.token, args.enterprise, args.since_days, args.page_size, args.max_pages)
        summary = summarize_events(events)
        idp_policy, idp_err = load_json_file(args.idp_policy_file)
        enterprise_security, sec_err = load_json_file(args.enterprise_security_file)
        manual_evidence = detect_manual_evidence(Path(args.manual_evidence_dir))
        controls = assess_controls(enterprise_meta, summary, idp_policy, enterprise_security, manual_evidence)

        write_reports(Path(args.output_dir), args.enterprise, enterprise_meta, events, summary, controls, manual_evidence, args.since_days)

        status_rank = {"PASS": 0, "WARN": 1, "FAIL": 2}
        overall = max(controls, key=lambda c: status_rank[c.status]).status if controls else "UNKNOWN"
        print(f"IA enterprise report written to {args.output_dir}/ia_enterprise_report.md")
        print(f"Overall status: {overall}")

        hard_failures = [c for c in controls if c.status == "FAIL"]
        if hard_failures:
            for c in hard_failures:
                print(f"FAIL {c.control_id}: {c.notes}", file=sys.stderr)
            return 1

        if idp_err:
            print(f"WARN: {idp_err}", file=sys.stderr)
        if sec_err:
            print(f"WARN: {sec_err}", file=sys.stderr)

        return 0

    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
