#!/usr/bin/env python3
"""IA-5(6) GitHub compliance evidence collector.

This script is designed to support FedRAMP IA-5(6) evidence collection for a
GitHub.com-based workflow. It does not certify compliance; it gathers evidence,
flags gaps, and produces artifacts for assessor review.

Checks performed:
- repository secret-scanning status
- repository push-protection status
- branch protection on the target branch
- workflow OIDC usage
- obvious plaintext secret patterns in tracked files
- best-effort org-level 2FA requirement
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests


API_BASE = "https://api.github.com"

SUSPICIOUS_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key ID pattern"),
    (re.compile(r"ASIA[0-9A-Z]{16}"), "AWS temporary access key ID pattern"),
    (
        re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{20,}"),
        "AWS secret access key assignment",
    ),
    (re.compile(r"(?i)password\s*[:=]\s*['\"].+['\"]"), "Password assignment"),
    (re.compile(r"(?i)client_secret\s*[:=]\s*['\"].+['\"]"), "Client secret assignment"),
    (re.compile(r"(?i)private_key\s*[:=]\s*['\"].+['\"]"), "Private key assignment"),
    (re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Private key block"),
]


@dataclasses.dataclass
class CheckResult:
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
        "User-Agent": "ia-5-6-compliance-check/1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def api_get(path: str, token: str, params: Optional[Dict[str, Any]] = None) -> Tuple[int, Any]:
    url = f"{API_BASE}{path}"
    resp = requests.get(url, headers=github_headers(token), params=params, timeout=30)
    try:
        payload = resp.json()
    except Exception:
        payload = resp.text
    return resp.status_code, payload


def scan_repository_files(root: Path, limit: int = 50) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    patterns = [
        "**/*.yml",
        "**/*.yaml",
        "**/*.py",
        "**/*.sh",
        "**/*.json",
        "**/*.toml",
        "**/*.ini",
        "**/*.env",
        "**/*.txt",
    ]
    seen = set()

    for glob_pattern in patterns:
        for path in root.glob(glob_pattern):
            if not path.is_file() or ".git" in path.parts:
                continue
            if path in seen:
                continue
            seen.add(path)

            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            for rx, label in SUSPICIOUS_PATTERNS:
                for match in rx.finditer(text):
                    start = max(0, match.start() - 60)
                    end = min(len(text), match.end() + 60)
                    snippet = text[start:end].replace("\n", " ")
                    findings.append(
                        {
                            "file": str(path),
                            "pattern": label,
                            "match": match.group(0)[:120],
                            "snippet": snippet[:240],
                        }
                    )
                    if len(findings) >= limit:
                        return findings
    return findings


def scan_oidc_usage(root: Path) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    workflows = list(root.glob(".github/workflows/**/*.yml")) + list(root.glob(".github/workflows/**/*.yaml"))

    for path in workflows:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        if "token.actions.githubusercontent.com" in text or "id-token: write" in text:
            hits.append({"file": str(path), "oidc": "present"})
    return hits


def write_outputs(output_dir: Path, evidence: Dict[str, Any], results: List[CheckResult]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    (output_dir / "ia_5_6_evidence.json").write_text(
        json.dumps(evidence, indent=2),
        encoding="utf-8",
    )

    md_lines = [
        "# IA-5(6) GitHub Compliance Evidence Report",
        "",
        f"Generated: {evidence['generated_at']}",
        f"Repository: {evidence['owner']}/{evidence['repo']}",
        f"Branch evaluated: {evidence['branch']}",
        "",
        "| Control | Item | Status | Evidence |",
        "|---|---|---:|---|",
    ]

    for r in results:
        md_lines.append(f"| {r.control} | {r.item} | {r.status} | {r.evidence} |")

    md_lines.extend(
        [
            "",
            "## Notes",
            "- GitHub.com is treated as a code repository and workflow orchestrator, not as the cryptographic boundary for authenticator storage.",
            "- Any secrets found in the repository should be remediated immediately and moved to FIPS-validated external secret stores.",
            "- For FedRAMP evidence, attach screenshots or exports that corroborate the API outputs captured here.",
        ]
    )

    (output_dir / "ia_5_6_evidence_report.md").write_text("\n".join(md_lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect IA-5(6) compliance evidence for GitHub.com.")
    parser.add_argument("--owner", required=True, help="GitHub organization or owner")
    parser.add_argument("--repo", required=True, help="Repository name")
    parser.add_argument("--branch", default="main", help="Branch to evaluate")
    parser.add_argument(
        "--output-dir",
        default="compliance-output",
        help="Output directory for evidence artifacts",
    )
    parser.add_argument(
        "--token",
        default=os.getenv("GITHUB_TOKEN", ""),
        help="GitHub token (or GITHUB_TOKEN env var)",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)

    # Repository metadata is required for the rest of the evidence collection.
    status, repo = api_get(f"/repos/{args.owner}/{args.repo}", args.token)
    if status == 404:
        raise SystemExit(
            f"Repository not found or inaccessible: {args.owner}/{args.repo}. "
            "Check the owner/repo name and token permissions."
        )
    if status != 200:
        raise SystemExit(f"Failed to load repository metadata: HTTP {status} {repo}")

    default_branch = repo.get("default_branch", args.branch)
    security = repo.get("security_and_analysis") or {}
    secret_scanning = security.get("secret_scanning") or {}
    push_protection = security.get("secret_scanning_push_protection") or {}

    results: List[CheckResult] = []

    results.append(
        CheckResult(
            control="IA-5(6)",
            item="Secret scanning enabled",
            status="PASS" if str(secret_scanning.get("status", "")).lower() == "enabled" else "FAIL",
            evidence=f"/repos/{args.owner}/{args.repo}.security_and_analysis.secret_scanning",
            details={"status": secret_scanning.get("status"), "raw": secret_scanning},
        )
    )

    results.append(
        CheckResult(
            control="IA-5(6)",
            item="Push protection enabled",
            status="PASS" if str(push_protection.get("status", "")).lower() == "enabled" else "WARN",
            evidence=f"/repos/{args.owner}/{args.repo}.security_and_analysis.secret_scanning_push_protection",
            details={"status": push_protection.get("status"), "raw": push_protection},
        )
    )

    bp_status, bp = api_get(
        f"/repos/{args.owner}/{args.repo}/branches/{default_branch}/protection",
        args.token,
    )

    if bp_status == 200:
        bp_status_text = "PASS"
    elif bp_status == 404:
        bp_status_text = "WARN"
    else:
        bp_status_text = "WARN"

    results.append(
        CheckResult(
            control="AC/CM",
            item=f"Branch protection on {default_branch}",
            status=bp_status_text,
            evidence=f"/repos/{args.owner}/{args.repo}/branches/{default_branch}/protection",
            details={"http_status": bp_status, "raw": bp if bp_status == 200 else None},
        )
    )

    root = Path.cwd()
    oidc_hits = scan_oidc_usage(root)
    results.append(
        CheckResult(
            control="IA-5(6)",
            item="OIDC federation used in workflows",
            status="PASS" if oidc_hits else "WARN",
            evidence=".github/workflows/*.yml|yaml",
            details={"hits": oidc_hits},
        )
    )

    secret_findings = scan_repository_files(root)
    results.append(
        CheckResult(
            control="IA-5(6)",
            item="No obvious plaintext secrets in tracked files",
            status="PASS" if not secret_findings else "FAIL",
            evidence="Repository file scan",
            details={"findings": secret_findings},
        )
    )

    org_status, org = api_get(f"/orgs/{args.owner}", args.token)
    if org_status == 200 and isinstance(org, dict):
        two_factor = org.get("two_factor_requirement_enabled")
        status_text = "PASS" if two_factor is True else ("WARN" if two_factor is False else "NA")
        results.append(
            CheckResult(
                control="IA-2",
                item="Org two-factor requirement (best-effort)",
                status=status_text,
                evidence=f"/orgs/{args.owner}",
                details={"two_factor_requirement_enabled": two_factor},
            )
        )
    elif org_status == 404:
        results.append(
            CheckResult(
                control="IA-2",
                item="Org two-factor requirement (best-effort)",
                status="NA",
                evidence=f"/orgs/{args.owner}",
                details={"note": "Organization metadata not accessible or not found.", "http_status": org_status},
            )
        )
    else:
        results.append(
            CheckResult(
                control="IA-2",
                item="Org two-factor requirement (best-effort)",
                status="NA",
                evidence=f"/orgs/{args.owner}",
                details={"http_status": org_status},
            )
        )

    evidence = {
        "generated_at": utc_now(),
        "owner": args.owner,
        "repo": args.repo,
        "branch": default_branch,
        "repository": {
            "full_name": repo.get("full_name"),
            "visibility": repo.get("visibility"),
            "private": repo.get("private"),
            "archived": repo.get("archived"),
            "security_and_analysis": security,
        },
        "checks": [dataclasses.asdict(r) for r in results],
    }

    write_outputs(output_dir, evidence, results)

    print("IA-5(6) GitHub Compliance Evidence Report")
    print(f"Generated: {evidence['generated_at']}")
    print(f"Repo: {args.owner}/{args.repo} @ {default_branch}")
    print()
    for r in results:
        print(f"[{r.status}] {r.control} - {r.item}")
    print()
    print(f"Artifacts written to: {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
