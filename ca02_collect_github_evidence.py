#!/usr/bin/env python3
"""
CA-02 GitHub FedRAMP audit automation.

What this script does:
- Pulls GitHub org, repo, audit log, branch protection, Dependabot, and secret-scanning data
- Writes normalized raw evidence into ./evidence/raw/
- Derives a CA-02 / CA-03 finding set
- Generates:
  - SAR_GitHub_Integration.md
  - POAM_GitHub_Integration.xlsx
  - CA02_CA03_Traceability.md
  - manifest.json
- Creates ca02-github-fedramp-evidence.zip at repository root

Environment variables:
- GH_TOKEN: required
- GH_ORG: required
- GH_REPOS: optional, comma-separated repo list
- GH_BRANCH: optional, default main
- GH_AUDIT_LOG_PHRASE: optional
- OUTPUT_DIR: optional, default ./evidence

Notes:
- GitHub org audit log and some security endpoints may require elevated org/repo permissions.
- The script captures permission failures as evidence instead of hard-failing.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from openpyxl import Workbook
from openpyxl.styles import Font


API_BASE = "https://api.github.com"
ZIP_NAME = "ca02-github-fedramp-evidence.zip"


@dataclass
class Config:
    token: str
    org: str
    repos: Optional[List[str]]
    branch: str
    output_dir: Path
    audit_log_phrase: Optional[str]


def env(name: str, default: Optional[str] = None, required: bool = False) -> str:
    value = os.getenv(name, default)
    if required and not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value or ""


def get_config() -> Config:
    repos_raw = env("GH_REPOS", "")
    repos = [r.strip() for r in repos_raw.split(",") if r.strip()] if repos_raw else None
    return Config(
        token=env("GH_TOKEN", required=True),
        org=env("GH_ORG", required=True),
        repos=repos,
        branch=env("GH_BRANCH", "main"),
        output_dir=Path(env("OUTPUT_DIR", "./evidence")).resolve(),
        audit_log_phrase=env("GH_AUDIT_LOG_PHRASE", "") or None,
    )


def today_utc() -> dt.date:
    return dt.datetime.now(dt.timezone.utc).date()


def add_days(days: int) -> str:
    return (today_utc() + dt.timedelta(days=days)).isoformat()


def slug(text: str) -> str:
    safe = []
    for ch in text.lower():
        if ch.isalnum():
            safe.append(ch)
        else:
            safe.append("-")
    out = "".join(safe)
    while "--" in out:
        out = out.replace("--", "-")
    return out.strip("-") or "item"


def build_session(token: str) -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "CA02-GitHub-FedRAMP-Audit-Automation",
        }
    )
    return session


def request_json(
    session: requests.Session,
    url: str,
    *,
    params: Optional[dict] = None,
) -> Dict[str, Any]:
    response = session.get(url, params=params, timeout=60)
    try:
        payload = response.json()
    except Exception:
        payload = {"text": response.text}

    return {
        "url": response.url,
        "status_code": response.status_code,
        "ok": response.ok,
        "data": payload if response.ok else None,
        "error": None if response.ok else payload,
    }


def paged_get(
    session: requests.Session,
    url: str,
    *,
    params: Optional[dict] = None,
    max_pages: int = 20,
) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    page_url = url
    page_params = dict(params or {})
    page_params.setdefault("per_page", 100)

    for _ in range(max_pages):
        response = session.get(page_url, params=page_params, timeout=60)
        try:
            payload = response.json()
        except Exception:
            payload = {"text": response.text}

        if not response.ok:
            items.append(
                {
                    "url": response.url,
                    "status_code": response.status_code,
                    "ok": False,
                    "error": payload,
                }
            )
            break

        if isinstance(payload, list):
            items.extend(payload)
        else:
            items.append(payload)
            break

        next_url = response.links.get("next", {}).get("url")
        if not next_url:
            break

        page_url = next_url
        page_params = None

    return items


def ensure_clean_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, data: Any) -> None:
    ensure_clean_dir(path.parent)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def write_jsonl(path: Path, rows: List[Any]) -> None:
    ensure_clean_dir(path.parent)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True))
            f.write("\n")


def write_text(path: Path, text: str) -> None:
    ensure_clean_dir(path.parent)
    path.write_text(text, encoding="utf-8")


def count_dependabot_severity(alerts: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for alert in alerts:
        sev = (
            alert.get("security_advisory", {}).get("severity")
            or alert.get("security_vulnerability", {}).get("severity")
            or "unknown"
        ).lower()
        if sev not in counts:
            sev = "unknown"
        counts[sev] += 1
    return counts


def open_secret_count(alerts: List[Dict[str, Any]]) -> int:
    return sum(1 for a in alerts if str(a.get("state", "")).lower() in {"open", "active"})


def repo_public(repo_payload: Dict[str, Any]) -> bool:
    if "private" in repo_payload:
        return not bool(repo_payload.get("private"))
    return bool(repo_payload.get("visibility") == "public")


def has_branch_protection(branch_payload: Dict[str, Any]) -> bool:
    if not branch_payload.get("ok", True):
        return False
    data = branch_payload.get("data") or {}
    if not isinstance(data, dict):
        return False
    if not data:
        return False
    if data.get("required_status_checks") is None and data.get("required_pull_request_reviews") is None:
        return False
    return True


def build_findings(
    repos: List[Dict[str, Any]],
    branch_results: Dict[str, Dict[str, Any]],
    dependabot_results: Dict[str, Dict[str, Any]],
    secret_results: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    for repo in repos:
        repo_name = repo.get("name", "unknown-repo")

        if repo_public(repo):
            findings.append(
                {
                    "id": f"CA03-{slug(repo_name)}-PUBLIC",
                    "control": "CA-03",
                    "title": "Repository is public",
                    "severity": "Medium",
                    "status": "Needs Review",
                    "weakness": f"Repository {repo_name} is public and should be confirmed as approved for non-sensitive content only.",
                    "remediation": "Confirm approval for public exposure or convert to private if not intended.",
                    "owner": "GitHub Admin",
                    "source": f"Repo inventory: {repo_name}",
                }
            )

        bp = branch_results.get(repo_name, {})
        if not has_branch_protection(bp):
            findings.append(
                {
                    "id": f"CA02-{slug(repo_name)}-BRANCH",
                    "control": "CA-02",
                    "title": "Branch protection evidence missing or incomplete",
                    "severity": "High",
                    "status": "Open",
                    "weakness": f"Branch protection could not be confirmed for {repo_name} on branch {bp.get('branch', 'main')}.",
                    "remediation": "Enable and document branch protection for the protected branch and re-run evidence capture.",
                    "owner": "GitHub Admin",
                    "source": f"Branch protection API: {repo_name}",
                }
            )
        else:
            data = bp.get("data") or {}
            if isinstance(data, dict):
                pr_reviews = data.get("required_pull_request_reviews") or {}
                enforce_admins = data.get("enforce_admins") or {}
                allow_force_pushes = data.get("allow_force_pushes") or {}
                allow_deletions = data.get("allow_deletions") or {}

                if not pr_reviews:
                    findings.append(
                        {
                            "id": f"CA02-{slug(repo_name)}-NO-PR-REVIEW",
                            "control": "CA-02",
                            "title": "Pull request review gate not confirmed",
                            "severity": "Medium",
                            "status": "Open",
                            "weakness": f"Required pull request reviews were not confirmed for {repo_name}.",
                            "remediation": "Require pull request reviews for protected branches.",
                            "owner": "GitHub Admin",
                            "source": f"Branch protection API: {repo_name}",
                        }
                    )

                if isinstance(enforce_admins, dict) and not enforce_admins.get("enabled", False):
                    findings.append(
                        {
                            "id": f"CA02-{slug(repo_name)}-ADMIN-BYPASS",
                            "control": "CA-02",
                            "title": "Admin bypass not disabled",
                            "severity": "Medium",
                            "status": "Open",
                            "weakness": f"Admin enforcement was not confirmed for {repo_name}.",
                            "remediation": "Enable branch protection for administrators where policy requires it.",
                            "owner": "GitHub Admin",
                            "source": f"Branch protection API: {repo_name}",
                        }
                    )

                if isinstance(allow_force_pushes, dict) and allow_force_pushes.get("enabled", False):
                    findings.append(
                        {
                            "id": f"CA02-{slug(repo_name)}-FORCE-PUSH",
                            "control": "CA-02",
                            "title": "Force pushes allowed",
                            "severity": "High",
                            "status": "Open",
                            "weakness": f"Force pushes are permitted on {repo_name}.",
                            "remediation": "Disable force pushes on protected branches unless a documented exception exists.",
                            "owner": "GitHub Admin",
                            "source": f"Branch protection API: {repo_name}",
                        }
                    )

                if isinstance(allow_deletions, dict) and allow_deletions.get("enabled", False):
                    findings.append(
                        {
                            "id": f"CA02-{slug(repo_name)}-DELETIONS",
                            "control": "CA-02",
                            "title": "Branch deletions allowed",
                            "severity": "Medium",
                            "status": "Open",
                            "weakness": f"Branch deletions are permitted on {repo_name}.",
                            "remediation": "Disable branch deletions for protected branches unless explicitly approved.",
                            "owner": "GitHub Admin",
                            "source": f"Branch protection API: {repo_name}",
                        }
                    )

        dep = dependabot_results.get(repo_name, {})
        dep_alerts = dep.get("alerts") if isinstance(dep.get("alerts"), list) else []
        dep_counts = count_dependabot_severity(dep_alerts)

        if dep_counts["critical"] or dep_counts["high"] or dep_counts["medium"] or dep_counts["low"]:
            top = "Low"
            if dep_counts["critical"]:
                top = "Critical"
            elif dep_counts["high"]:
                top = "High"
            elif dep_counts["medium"]:
                top = "Medium"

            findings.append(
                {
                    "id": f"RA05-{slug(repo_name)}-DEPENDABOT",
                    "control": "RA-05",
                    "title": "Dependabot alerts present",
                    "severity": top,
                    "status": "Open",
                    "weakness": f"{sum(dep_counts.values())} Dependabot alert(s) present for {repo_name}.",
                    "remediation": "Triage Dependabot alerts, patch vulnerable dependencies, and close resolved alerts.",
                    "owner": "Development Team",
                    "source": f"Dependabot alerts API: {repo_name}",
                }
            )

        sec = secret_results.get(repo_name, {})
        sec_alerts = sec.get("alerts") if isinstance(sec.get("alerts"), list) else []
        open_secrets = open_secret_count(sec_alerts)

        if open_secrets:
            findings.append(
                {
                    "id": f"SI07-{slug(repo_name)}-SECRETS",
                    "control": "SI-07",
                    "title": "Open secret-scanning alerts",
                    "severity": "High",
                    "status": "Open",
                    "weakness": f"{open_secrets} open secret-scanning alert(s) present for {repo_name}.",
                    "remediation": "Rotate exposed secrets, remove them from code, and close the alert after verification.",
                    "owner": "Development Team",
                    "source": f"Secret-scanning alerts API: {repo_name}",
                }
            )

    if not findings:
        findings.append(
            {
                "id": "INFO-NO-FINDINGS",
                "control": "CA-02",
                "title": "No actionable findings",
                "severity": "Informational",
                "status": "Closed",
                "weakness": "No actionable CA-02 / CA-03 issues were identified during this collection run.",
                "remediation": "None required.",
                "owner": "Security Team",
                "source": "Automated collection run",
            }
        )

    return findings


def build_sar(
    cfg: Config,
    org_data: Dict[str, Any],
    repos: List[Dict[str, Any]],
    audit_log: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    branch_results: Dict[str, Dict[str, Any]],
    dependabot_results: Dict[str, Dict[str, Any]],
    secret_results: Dict[str, Dict[str, Any]],
) -> str:
    repo_count = len([r for r in repos if isinstance(r, dict) and r.get("name")])
    open_findings = [f for f in findings if f.get("status") not in {"Closed", "Accepted Risk"}]

    lines = []
    lines.append("# Security Assessment Report (SAR) – GitHub.com Integration")
    lines.append("")
    lines.append("## 1. Assessment Summary")
    lines.append(f"- Organization: {cfg.org}")
    lines.append(f"- Branch Reviewed: {cfg.branch}")
    lines.append(f"- Repository Count: {repo_count}")
    lines.append(f"- Audit Log Events Captured: {len(audit_log)}")
    lines.append(f"- Open Findings: {len(open_findings)}")
    lines.append("")

    lines.append("## 2. Scope")
    lines.append("- GitHub organization settings")
    lines.append("- Repositories in scope")
    lines.append("- Branch protection configurations")
    lines.append("- Audit log review")
    lines.append("- Dependabot alerts")
    lines.append("- Secret-scanning alerts")
    lines.append("")

    lines.append("## 3. Methodology")
    lines.append("Assessment artifacts were collected using GitHub REST APIs and reviewed for configuration, vulnerability, and exposure indicators. Results were normalized into raw evidence files and summarized into this SAR.")
    lines.append("")

    lines.append("## 4. Findings")
    lines.append("| Finding ID | Control | Severity | Status | Weakness | Remediation |")
    lines.append("|---|---|---:|---|---|---|")
    for f in findings:
        lines.append(
            f"| {f['id']} | {f['control']} | {f['severity']} | {f['status']} | {f['weakness']} | {f['remediation']} |"
        )
    lines.append("")

    lines.append("## 5. Evidence Notes")
    lines.append(f"- Raw evidence directory: `raw/`")
    lines.append(f"- Traceability matrix: `CA02_CA03_Traceability.md`")
    lines.append(f"- POA&M workbook: `POAM_GitHub_Integration.xlsx`")
    lines.append("")

    lines.append("## 6. Conclusion")
    if open_findings:
        lines.append("The GitHub.com integration requires continued remediation and monitoring for the open findings listed above.")
    else:
        lines.append("The GitHub.com integration did not produce any open actionable findings in this assessment run.")

    return "\n".join(lines)


def build_traceability(findings: List[Dict[str, Any]]) -> str:
    rows = []
    rows.append("# CA-02 / CA-03 Traceability Matrix")
    rows.append("")
    rows.append("| Control | Requirement | Implementation | Evidence Artifact |")
    rows.append("|---|---|---|---|")
    rows.append("| CA-02 | Security assessments performed | Quarterly GitHub assessment automation and SAR generation | `SAR_GitHub_Integration.md` |")
    rows.append("| CA-02 | Findings documented and tracked | POA&M workbook generated from findings | `POAM_GitHub_Integration.xlsx` |")
    rows.append("| CA-03 | Interconnections identified | GitHub SaaS usage and data-handling scope documented | `SSP_GitHub_Integration.md` |")
    rows.append("| CA-03 | External service risk reviewed | Vendor-risk summary captured | `vendor_risk_assessment.md` |")
    rows.append("| RA-05 | Vulnerability monitoring | Dependabot alerts collected and summarized | `raw/dependabot/` |")
    rows.append("| SI-07 | Integrity / secrets exposure monitoring | Secret-scanning alerts collected and summarized | `raw/secret_scanning/` |")
    rows.append("")
    rows.append("## Findings Mapped to POA&M")
    rows.append("")
    rows.append("| Finding ID | Control | POA&M Status |")
    rows.append("|---|---|---|")
    for f in findings:
        rows.append(f"| {f['id']} | {f['control']} | {f['status']} |")
    return "\n".join(rows)


def build_poam_workbook(findings: List[Dict[str, Any]]) -> Workbook:
    wb = Workbook()
    ws = wb.active
    ws.title = "POAM"

    headers = [
        "POA&M ID",
        "Control ID",
        "Weakness Description",
        "Source",
        "Risk Level",
        "Planned Remediation",
        "Responsible Party",
        "Milestone Date",
        "Status",
        "Comments",
    ]
    ws.append(headers)
    for cell in ws[1]:
        cell.font = Font(bold=True)

    for idx, finding in enumerate(findings, start=1):
        risk = finding.get("severity", "Low")
        if risk not in {"Critical", "High", "Medium", "Low"}:
            risk = "Low"

        if risk == "Critical":
            date = add_days(14)
        elif risk == "High":
            date = add_days(30)
        elif risk == "Medium":
            date = add_days(60)
        else:
            date = add_days(90)

        ws.append(
            [
                f"POAM-{idx:03d}",
                finding.get("control", ""),
                finding.get("weakness", ""),
                finding.get("source", ""),
                risk,
                finding.get("remediation", ""),
                finding.get("owner", ""),
                date,
                finding.get("status", "Open"),
                finding.get("title", ""),
            ]
        )

    return wb


def create_zip(output_dir: Path) -> Path:
    zip_path = output_dir.parent / ZIP_NAME
    if zip_path.exists():
        zip_path.unlink()

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file in output_dir.rglob("*"):
            if file.is_file():
                zf.write(file, arcname=file.relative_to(output_dir.parent))
    return zip_path


def collect() -> Tuple[Config, Dict[str, Any]]:
    cfg = get_config()
    ensure_clean_dir(cfg.output_dir)

    raw_dir = cfg.output_dir / "raw"
    ensure_clean_dir(raw_dir)
    ensure_clean_dir(raw_dir / "branches")
    ensure_clean_dir(raw_dir / "dependabot")
    ensure_clean_dir(raw_dir / "secret_scanning")

    session = build_session(cfg.token)

    org_data = request_json(session, f"{API_BASE}/orgs/{cfg.org}")
    write_json(raw_dir / "org.json", org_data)

    repos_payload = paged_get(session, f"{API_BASE}/orgs/{cfg.org}/repos", params={"type": "all"}) if not cfg.repos else []
    if cfg.repos:
        for repo_name in cfg.repos:
            repos_payload.append(request_json(session, f"{API_BASE}/repos/{cfg.org}/{repo_name}"))
    write_json(raw_dir / "repos.json", repos_payload)

    audit_log_payload = paged_get(session, f"{API_BASE}/orgs/{cfg.org}/audit-log", params={"phrase": cfg.audit_log_phrase} if cfg.audit_log_phrase else None, max_pages=10)
    write_jsonl(raw_dir / "audit_log.jsonl", audit_log_payload)

    repos: List[Dict[str, Any]] = []
    for repo in repos_payload:
        if isinstance(repo, dict) and repo.get("name"):
            repos.append(repo)

    branch_results: Dict[str, Dict[str, Any]] = {}
    dependabot_results: Dict[str, Dict[str, Any]] = {}
    secret_results: Dict[str, Dict[str, Any]] = {}

    for repo in repos:
        repo_name = repo["name"]

        branch = request_json(session, f"{API_BASE}/repos/{cfg.org}/{repo_name}/branches/{cfg.branch}/protection")
        branch_results[repo_name] = branch
        write_json(raw_dir / "branches" / f"{slug(repo_name)}_{slug(cfg.branch)}_protection.json", branch)

        dep = request_json(session, f"{API_BASE}/repos/{cfg.org}/{repo_name}/dependabot/alerts")
        if isinstance(dep.get("data"), list):
            dep["alerts"] = dep["data"]
        else:
            dep["alerts"] = []
        dependabot_results[repo_name] = dep
        write_json(raw_dir / "dependabot" / f"{slug(repo_name)}_alerts.json", dep)

        sec = request_json(session, f"{API_BASE}/repos/{cfg.org}/{repo_name}/secret-scanning/alerts")
        if isinstance(sec.get("data"), list):
            sec["alerts"] = sec["data"]
        else:
            sec["alerts"] = []
        secret_results[repo_name] = sec
        write_json(raw_dir / "secret_scanning" / f"{slug(repo_name)}_alerts.json", sec)

    findings = build_findings(repos, branch_results, dependabot_results, secret_results)

    sar_md = build_sar(cfg, org_data, repos, audit_log_payload, findings, branch_results, dependabot_results, secret_results)
    traceability_md = build_traceability(findings)
    poam_wb = build_poam_workbook(findings)

    write_text(cfg.output_dir / "SAR_GitHub_Integration.md", sar_md)
    write_text(cfg.output_dir / "CA02_CA03_Traceability.md", traceability_md)

    poam_path = cfg.output_dir / "POAM_GitHub_Integration.xlsx"
    poam_wb.save(poam_path)

    manifest = {
        "org": cfg.org,
        "branch": cfg.branch,
        "repo_count": len(repos),
        "finding_count": len(findings),
        "files": sorted(str(p.relative_to(cfg.output_dir.parent)) for p in cfg.output_dir.parent.rglob("*") if p.is_file()),
    }
    write_json(cfg.output_dir / "manifest.json", manifest)

    zip_path = create_zip(cfg.output_dir)

    return cfg, {
        "org_data": org_data,
        "repos": repos,
        "audit_log": audit_log_payload,
        "findings": findings,
        "zip_path": str(zip_path),
    }


def main() -> int:
    cfg, result = collect()

    print(
        json.dumps(
            {
                "org": cfg.org,
                "branch": cfg.branch,
                "zip_file": result["zip_path"],
                "finding_count": len(result["findings"]),
                "repo_count": len(result["repos"]),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
