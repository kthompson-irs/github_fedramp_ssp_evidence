#!/usr/bin/env python3
"""IA-5(6) enterprise compliance evidence collector for GitHub.com.

This script can operate in three scopes:
- repo: one repository
- org: all repositories in one or more organizations
- enterprise: all repositories in all organizations under a GitHub Enterprise slug

It gathers evidence for FedRAMP IA-5(6) and related supporting controls:
- secret scanning
- push protection
- branch protection
- workflow OIDC usage
- best-effort org MFA requirement
- workflow-file inspection for obvious secret patterns

It also generates:
- JSON evidence
- CSV manifest
- PDF report for assessor review

This script does not certify compliance. It collects evidence and highlights gaps.
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import json
import os
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, landscape
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        PageBreak,
    )
except Exception as exc:  # pragma: no cover
    raise SystemExit(
        "reportlab is required to generate the PDF report. "
        "Install it with: python -m pip install reportlab"
    ) from exc


API_BASE = "https://api.github.com"

SUSPICIOUS_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key ID pattern"),
    (re.compile(r"ASIA[0-9A-Z]{16}"), "AWS temporary access key ID pattern"),
    (re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{20,}"), "AWS secret access key assignment"),
    (re.compile(r"(?i)password\s*[:=]\s*['\"].+['\"]"), "Password assignment"),
    (re.compile(r"(?i)client_secret\s*[:=]\s*['\"].+['\"]"), "Client secret assignment"),
    (re.compile(r"(?i)private_key\s*[:=]\s*['\"].+['\"]"), "Private key assignment"),
    (re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Private key block"),
]


@dataclasses.dataclass
class CheckResult:
    scope: str
    owner: str
    repo: str
    control: str
    item: str
    status: str  # PASS / WARN / FAIL / NA / ERROR
    evidence: str
    details: Dict[str, Any]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def github_headers(token: str) -> Dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "ia-5-6-enterprise-compliance/1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def api_get(path: str, token: str, params: Optional[Dict[str, Any]] = None) -> Tuple[int, Any]:
    url = f"{API_BASE}{path}"
    resp = requests.get(url, headers=github_headers(token), params=params, timeout=45)
    try:
        payload = resp.json()
    except Exception:
        payload = resp.text
    return resp.status_code, payload


def paginated_get(path: str, token: str, params: Optional[Dict[str, Any]] = None) -> List[Any]:
    params = dict(params or {})
    params.setdefault("per_page", 100)
    out: List[Any] = []
    page = 1
    while True:
        params["page"] = page
        status, payload = api_get(path, token, params=params)
        if status != 200:
            raise RuntimeError(f"GET {path} failed with HTTP {status}: {payload}")
        if not isinstance(payload, list):
            raise RuntimeError(f"GET {path} returned non-list payload: {type(payload)}")
        out.extend(payload)
        if len(payload) < params["per_page"]:
            break
        page += 1
    return out


def parse_csv_list(value: str) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def repo_default_branch(repo: Dict[str, Any], fallback: str) -> str:
    return repo.get("default_branch") or fallback or "main"


def fetch_repository(owner: str, repo: str, token: str) -> Dict[str, Any]:
    status, payload = api_get(f"/repos/{owner}/{repo}", token)
    if status == 404:
        raise SystemExit(f"Repository not found or inaccessible: {owner}/{repo}. Check name and token permissions.")
    if status != 200 or not isinstance(payload, dict):
        raise SystemExit(f"Failed to load repository metadata for {owner}/{repo}: HTTP {status} {payload}")
    return payload


def fetch_org_repos(org: str, token: str) -> List[Dict[str, Any]]:
    return paginated_get(f"/orgs/{org}/repos", token, params={"type": "all", "sort": "full_name", "direction": "asc"})


def fetch_enterprise_orgs(slug: str, token: str) -> List[Dict[str, Any]]:
    status, payload = api_get(f"/enterprises/{slug}/orgs", token)
    if status == 404:
        raise SystemExit(
            f"Enterprise not found or inaccessible: {slug}. "
            "Check the enterprise slug and token permissions."
        )
    if status != 200 or not isinstance(payload, list):
        raise SystemExit(f"Failed to load enterprise org list for {slug}: HTTP {status} {payload}")
    return payload


def fetch_branch_protection(owner: str, repo: str, branch: str, token: str) -> Tuple[int, Any]:
    return api_get(f"/repos/{owner}/{repo}/branches/{branch}/protection", token)


def fetch_org_metadata(org: str, token: str) -> Tuple[int, Any]:
    return api_get(f"/orgs/{org}", token)


def fetch_workflow_files(owner: str, repo: str, default_branch: str, token: str) -> List[Dict[str, Any]]:
    status, payload = api_get(f"/repos/{owner}/{repo}/contents/.github/workflows", token, params={"ref": default_branch})
    if status == 404:
        return []
    if status != 200:
        return []

    files: List[Dict[str, Any]] = []
    if isinstance(payload, dict) and payload.get("type") == "file":
        files.append(payload)
    elif isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict) and item.get("type") == "file":
                files.append(item)
    return files


def fetch_raw_file(url: str, token: str) -> str:
    resp = requests.get(url, headers=github_headers(token), timeout=45)
    resp.raise_for_status()
    return resp.text


def scan_workflow_text_for_oidc(text: str) -> bool:
    return ("token.actions.githubusercontent.com" in text) or ("id-token: write" in text)


def scan_workflow_text_for_secrets(text: str) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    for rx, label in SUSPICIOUS_PATTERNS:
        for m in rx.finditer(text):
            snippet = text[max(0, m.start() - 60): min(len(text), m.end() + 60)].replace("\n", " ")
            findings.append({"pattern": label, "match": m.group(0)[:120], "snippet": snippet[:240]})
    return findings


def collect_repo_evidence(owner: str, repo_name: str, token: str, scope_label: str, branch_override: str = "") -> List[CheckResult]:
    repo = fetch_repository(owner, repo_name, token)
    default_branch = repo_default_branch(repo, branch_override)

    security = repo.get("security_and_analysis") or {}
    secret_scanning = security.get("secret_scanning") or {}
    push_protection = security.get("secret_scanning_push_protection") or {}

    results: List[CheckResult] = []

    results.append(
        CheckResult(
            scope=scope_label,
            owner=owner,
            repo=repo_name,
            control="IA-5(6)",
            item="Secret scanning enabled",
            status="PASS" if str(secret_scanning.get("status", "")).lower() == "enabled" else "FAIL",
            evidence=f"/repos/{owner}/{repo_name}.security_and_analysis.secret_scanning",
            details={"status": secret_scanning.get("status"), "raw": secret_scanning},
        )
    )

    results.append(
        CheckResult(
            scope=scope_label,
            owner=owner,
            repo=repo_name,
            control="IA-5(6)",
            item="Push protection enabled",
            status="PASS" if str(push_protection.get("status", "")).lower() == "enabled" else "WARN",
            evidence=f"/repos/{owner}/{repo_name}.security_and_analysis.secret_scanning_push_protection",
            details={"status": push_protection.get("status"), "raw": push_protection},
        )
    )

    bp_status, bp = fetch_branch_protection(owner, repo_name, default_branch, token)
    bp_state = "PASS" if bp_status == 200 else "WARN"
    results.append(
        CheckResult(
            scope=scope_label,
            owner=owner,
            repo=repo_name,
            control="AC/CM",
            item=f"Branch protection on {default_branch}",
            status=bp_state,
            evidence=f"/repos/{owner}/{repo_name}/branches/{default_branch}/protection",
            details={"http_status": bp_status, "raw": bp if bp_status == 200 else None},
        )
    )

    workflow_findings: List[Dict[str, Any]] = []
    oidc_hits: List[Dict[str, Any]] = []
    workflow_files = fetch_workflow_files(owner, repo_name, default_branch, token)
    for wf in workflow_files:
        download_url = wf.get("download_url")
        wf_name = wf.get("name") or wf.get("path") or "workflow"
        if not download_url:
            continue
        try:
            text = fetch_raw_file(download_url, token)
        except Exception as exc:
            workflow_findings.append({"file": wf_name, "error": str(exc)})
            continue

        if scan_workflow_text_for_oidc(text):
            oidc_hits.append({"file": wf_name, "oidc": "present"})
        workflow_findings.extend(
            [{"file": wf_name, **finding} for finding in scan_workflow_text_for_secrets(text)]
        )

    results.append(
        CheckResult(
            scope=scope_label,
            owner=owner,
            repo=repo_name,
            control="IA-5(6)",
            item="OIDC federation used in workflows",
            status="PASS" if oidc_hits else "WARN",
            evidence=f"/repos/{owner}/{repo_name}/contents/.github/workflows",
            details={"hits": oidc_hits},
        )
    )

    results.append(
        CheckResult(
            scope=scope_label,
            owner=owner,
            repo=repo_name,
            control="IA-5(6)",
            item="No obvious plaintext secrets in workflow files",
            status="PASS" if not workflow_findings else "FAIL",
            evidence=f"/repos/{owner}/{repo_name}/contents/.github/workflows",
            details={"findings": workflow_findings},
        )
    )

    return results


def collect_scope(scope: str, enterprise_slug: str, orgs: List[str], repo: str, branch: str, token: str) -> List[CheckResult]:
    results: List[CheckResult] = []

    if scope == "repo":
        owner = orgs[0] if orgs else None
        if not owner:
            raise SystemExit("For repo scope, pass --orgs with one owner/org value or set ORGS in the workflow.")
        results.extend(collect_repo_evidence(owner, repo, token, scope_label="repo", branch_override=branch))
        return results

    if scope == "org":
        if not orgs:
            raise SystemExit("For org scope, pass --orgs with one or more comma-separated org names.")
        for org in orgs:
            org_status, org_meta = fetch_org_metadata(org, token)
            if org_status == 200 and isinstance(org_meta, dict):
                two_factor = org_meta.get("two_factor_requirement_enabled")
                results.append(
                    CheckResult(
                        scope="org",
                        owner=org,
                        repo="*",
                        control="IA-2",
                        item="Org two-factor requirement (best-effort)",
                        status="PASS" if two_factor is True else ("WARN" if two_factor is False else "NA"),
                        evidence=f"/orgs/{org}",
                        details={"two_factor_requirement_enabled": two_factor},
                    )
                )
            else:
                results.append(
                    CheckResult(
                        scope="org",
                        owner=org,
                        repo="*",
                        control="IA-2",
                        item="Org two-factor requirement (best-effort)",
                        status="NA",
                        evidence=f"/orgs/{org}",
                        details={"http_status": org_status},
                    )
                )

            repos = fetch_org_repos(org, token)
            for r in repos:
                if not isinstance(r, dict) or not r.get("name"):
                    continue
                results.extend(collect_repo_evidence(org, r["name"], token, scope_label="org", branch_override=branch))
        return results

    if scope == "enterprise":
        if not enterprise_slug:
            raise SystemExit("For enterprise scope, pass --enterprise-slug or set ENTERPRISE_SLUG in the workflow.")
        enterprise_orgs = fetch_enterprise_orgs(enterprise_slug, token)
        for org_item in enterprise_orgs:
            org_login = org_item.get("login") if isinstance(org_item, dict) else None
            if not org_login:
                continue

            org_status, org_meta = fetch_org_metadata(org_login, token)
            if org_status == 200 and isinstance(org_meta, dict):
                two_factor = org_meta.get("two_factor_requirement_enabled")
                results.append(
                    CheckResult(
                        scope="enterprise",
                        owner=org_login,
                        repo="*",
                        control="IA-2",
                        item="Org two-factor requirement (best-effort)",
                        status="PASS" if two_factor is True else ("WARN" if two_factor is False else "NA"),
                        evidence=f"/orgs/{org_login}",
                        details={"two_factor_requirement_enabled": two_factor},
                    )
                )
            else:
                results.append(
                    CheckResult(
                        scope="enterprise",
                        owner=org_login,
                        repo="*",
                        control="IA-2",
                        item="Org two-factor requirement (best-effort)",
                        status="NA",
                        evidence=f"/orgs/{org_login}",
                        details={"http_status": org_status},
                    )
                )

            repos = fetch_org_repos(org_login, token)
            for r in repos:
                if not isinstance(r, dict) or not r.get("name"):
                    continue
                results.extend(collect_repo_evidence(org_login, r["name"], token, scope_label="enterprise", branch_override=branch))
        return results

    raise SystemExit(f"Unsupported scope: {scope}")


def write_json(output_dir: Path, data: Dict[str, Any]) -> Path:
    path = output_dir / "ia_5_6_evidence.json"
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def write_csv(output_dir: Path, results: List[CheckResult]) -> Path:
    path = output_dir / "ia_5_6_evidence_manifest.csv"
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["scope", "owner", "repo", "control", "item", "status", "evidence"])
        for r in results:
            writer.writerow([r.scope, r.owner, r.repo, r.control, r.item, r.status, r.evidence])
    return path


def status_counts(results: List[CheckResult]) -> Dict[str, int]:
    counts = defaultdict(int)
    for r in results:
        counts[r.status] += 1
    return dict(counts)


def make_pdf_report(output_dir: Path, meta: Dict[str, Any], results: List[CheckResult]) -> Path:
    pdf_path = output_dir / "ia_5_6_enterprise_evidence_report.pdf"

    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    header_style = styles["Heading2"]
    normal = styles["BodyText"]
    small = ParagraphStyle(
        name="Small",
        parent=styles["BodyText"],
        fontSize=8,
        leading=10,
    )

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=landscape(letter),
        rightMargin=28,
        leftMargin=28,
        topMargin=28,
        bottomMargin=28,
    )

    story: List[Any] = []

    story.append(Paragraph("FedRAMP IA-5(6) Enterprise Evidence Report", title_style))
    story.append(Spacer(1, 0.15 * inch))
    story.append(Paragraph(f"Generated: {meta['generated_at']}", normal))
    story.append(Paragraph(f"Scope: {meta['scope']}", normal))
    if meta.get("enterprise_slug"):
        story.append(Paragraph(f"Enterprise: {meta['enterprise_slug']}", normal))
    if meta.get("orgs"):
        story.append(Paragraph(f"Target orgs: {', '.join(meta['orgs'])}", normal))
    story.append(Paragraph(f"Repository filter: {meta.get('repo') or 'N/A'}", normal))
    story.append(Spacer(1, 0.15 * inch))

    counts = status_counts(results)
    summary_data = [
        ["Status", "Count"],
        ["PASS", str(counts.get("PASS", 0))],
        ["WARN", str(counts.get("WARN", 0))],
        ["FAIL", str(counts.get("FAIL", 0))],
        ["NA", str(counts.get("NA", 0))],
        ["ERROR", str(counts.get("ERROR", 0))],
    ]
    summary_table = Table(summary_data, colWidths=[1.5 * inch, 1.0 * inch])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#D9EAF7")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(Paragraph("Executive Summary", header_style))
    story.append(summary_table)
    story.append(Spacer(1, 0.2 * inch))

    grouped: Dict[Tuple[str, str], List[CheckResult]] = defaultdict(list)
    for r in results:
        grouped[(r.owner, r.repo)].append(r)

    for (owner, repo), group in sorted(grouped.items()):
        story.append(Paragraph(f"{owner} / {repo}", header_style))
        table_data = [["Control", "Item", "Status", "Evidence"]]
        for r in group:
            table_data.append(
                [
                    Paragraph(r.control, small),
                    Paragraph(r.item, small),
                    Paragraph(r.status, small),
                    Paragraph(r.evidence, small),
                ]
            )

        tbl = Table(table_data, colWidths=[1.0 * inch, 2.75 * inch, 0.75 * inch, 4.5 * inch], repeatRows=1)
        tbl.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8EEF7")),
                    ("GRID", (0, 0), (-1, -1), 0.35, colors.grey),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                ]
            )
        )
        story.append(tbl)
        story.append(Spacer(1, 0.15 * inch))

    story.append(PageBreak())
    story.append(Paragraph("Assessment Notes", header_style))
    notes = [
        "GitHub.com is treated as a code repository and workflow orchestrator, not as the cryptographic boundary for authenticator storage.",
        "Any secrets detected in workflows or tracked files should be remediated immediately and moved to FIPS-validated external secret stores.",
        "For assessor use, accompany this PDF with screenshots, exported JSON, and repository evidence that corroborate the API outputs.",
    ]
    for note in notes:
        story.append(Paragraph(f"• {note}", normal))
        story.append(Spacer(1, 0.08 * inch))

    doc.build(story)
    return pdf_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect IA-5(6) compliance evidence for GitHub.com.")
    parser.add_argument("--scope", choices=["repo", "org", "enterprise"], required=True)
    parser.add_argument("--enterprise-slug", default=os.getenv("ENTERPRISE_SLUG", ""))
    parser.add_argument("--orgs", default=os.getenv("ORGS", ""))
    parser.add_argument("--repo", default=os.getenv("REPO", ""))
    parser.add_argument("--branch", default=os.getenv("BRANCH", "main"))
    parser.add_argument("--output-dir", default="compliance-output")
    parser.add_argument("--token", default=os.getenv("GH_TOKEN", ""))
    args = parser.parse_args()

    token = args.token
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    orgs = parse_csv_list(args.orgs)
    results = collect_scope(args.scope, args.enterprise_slug, orgs, args.repo, args.branch, token)

    meta = {
        "generated_at": utc_now(),
        "scope": args.scope,
        "enterprise_slug": args.enterprise_slug,
        "orgs": orgs,
        "repo": args.repo,
        "branch": args.branch,
    }

    evidence = {
        **meta,
        "checks": [dataclasses.asdict(r) for r in results],
        "summary": status_counts(results),
    }

    json_path = write_json(output_dir, evidence)
    csv_path = write_csv(output_dir, results)
    pdf_path = make_pdf_report(output_dir, meta, results)

    print("IA-5(6) Enterprise Compliance Evidence Report")
    print(f"Generated: {meta['generated_at']}")
    print(f"Scope: {args.scope}")
    if args.enterprise_slug:
        print(f"Enterprise: {args.enterprise_slug}")
    if orgs:
        print(f"Orgs: {', '.join(orgs)}")
    if args.repo:
        print(f"Repo filter: {args.repo}")
    print()
    for status in ["PASS", "WARN", "FAIL", "NA", "ERROR"]:
        if evidence["summary"].get(status):
            print(f"{status}: {evidence['summary'][status]}")
    print()
    print(f"Wrote: {json_path}")
    print(f"Wrote: {csv_path}")
    print(f"Wrote: {pdf_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
