#!/usr/bin/env python3
"""Repository-level risk assessment helper for FedRAMP/NIST RA-03.

This script is intentionally dependency-free so it can run in GitHub Actions
without installing third-party packages.

It performs heuristic checks over repository files and GitHub Actions workflows
and produces:
  - JSON report (machine-readable)
  - Markdown summary (human-readable)
  - optional non-zero exit code when critical issues are found

The intent is to support RA-03 evidence collection and periodic review, not to
assert compliance by itself.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import List, Optional


WORKFLOW_GLOBS = (".github/workflows/*.yml", ".github/workflows/*.yaml")
TEXT_FILE_NAMES = {
    "CODEOWNERS",
    "SECURITY.md",
    "dependabot.yml",
    "dependabot.yaml",
}

SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}


@dataclasses.dataclass
class Finding:
    id: str
    title: str
    severity: str
    file: str
    details: str
    recommendation: str


@dataclasses.dataclass
class FileStat:
    path: str
    exists: bool
    reason: str


@dataclasses.dataclass
class Report:
    repository: str
    ref: str
    sha: str
    generated_at_utc: str
    score: int
    status: str
    findings: List[Finding]
    evidence: List[FileStat]


DANGEROUS_RUN_PATTERNS = [
    (re.compile(r"curl\s+[^\n|]+\|\s*(sh|bash)"), "Pipe-to-shell command detected."),
    (re.compile(r"wget\s+[^\n|]+\|\s*(sh|bash)"), "Pipe-to-shell command detected."),
    (re.compile(r"sudo\s+"), "Use of sudo in workflow step."),
]

ACTION_USE_RE = re.compile(r"^\s*uses:\s*([^\s#]+)\s*$", re.MULTILINE)
WRITE_PERMISSION_RE = re.compile(r"permissions:\s*\n(?P<body>(?:\s+[A-Za-z0-9_-]+:\s*[A-Za-z_-]+\s*\n?)+)", re.MULTILINE)
WRITE_ALL_RE = re.compile(r"permissions:\s*\bwrite-all\b")
SHA_RE = re.compile(r"@[0-9a-fA-F]{40}$")
LOCAL_ACTION_RE = re.compile(r"^\./")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def short_sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:12]


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def discover_files(repo_root: Path) -> List[Path]:
    files: List[Path] = []
    for pattern in WORKFLOW_GLOBS:
        files.extend(sorted(repo_root.glob(pattern)))
    for name in TEXT_FILE_NAMES:
        files.extend(sorted(repo_root.rglob(name)))
    seen = set()
    deduped = []
    for path in files:
        if path in seen:
            continue
        seen.add(path)
        deduped.append(path)
    return deduped


def workflow_files(repo_root: Path) -> List[Path]:
    wf = []
    for pattern in WORKFLOW_GLOBS:
        wf.extend(sorted(repo_root.glob(pattern)))
    return wf


def classify_permissions(text: str) -> Optional[str]:
    if WRITE_ALL_RE.search(text):
        return "write-all"
    m = WRITE_PERMISSION_RE.search(text)
    if not m:
        return None
    body = m.group("body")
    write_scopes = []
    for line in body.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        scope, value = [part.strip() for part in line.split(":", 1)]
        if value in {"write", "read-all", "write-all"}:
            write_scopes.append(f"{scope}={value}")
    return ", ".join(write_scopes) if write_scopes else None


def is_pinned_action(value: str) -> bool:
    value = value.strip()
    return bool(LOCAL_ACTION_RE.match(value) or SHA_RE.search(value))


def analyze_workflow(path: Path) -> List[Finding]:
    text = read_text(path)
    findings: List[Finding] = []
    rel = str(path)

    if "pull_request_target" in text:
        findings.append(
            Finding(
                id=f"wf-{short_sha(path.as_posix().encode())}-prtarget",
                title="Workflow uses pull_request_target",
                severity="medium",
                file=rel,
                details="pull_request_target runs with elevated token context and should be used carefully.",
                recommendation="Prefer pull_request when possible; if pull_request_target is necessary, avoid checking out or executing untrusted PR code.",
            )
        )

    perms = classify_permissions(text)
    if perms:
        severity = "high" if "write-all" in perms else "medium"
        findings.append(
            Finding(
                id=f"wf-{short_sha((path.as_posix() + perms).encode())}-perms",
                title="Workflow grants write permissions",
                severity=severity,
                file=rel,
                details=f"Detected broad permissions: {perms}.",
                recommendation="Reduce workflow permissions to the minimum required scope, and use read-only permissions where possible.",
            )
        )

    for match in ACTION_USE_RE.finditer(text):
        uses = match.group(1).strip()
        if uses.startswith("./"):
            continue
        if uses.startswith("docker://"):
            continue
        if not is_pinned_action(uses):
            findings.append(
                Finding(
                    id=f"wf-{short_sha((path.as_posix() + uses).encode())}-unpinned",
                    title="Action is not pinned to a commit SHA",
                    severity="medium",
                    file=rel,
                    details=f"Action reference '{uses}' is not pinned to a 40-character commit SHA.",
                    recommendation="Pin third-party actions to a full commit SHA and review pinned versions on a regular cadence.",
                )
            )

    for pattern, message in DANGEROUS_RUN_PATTERNS:
        for m in pattern.finditer(text):
            snippet = text[max(0, m.start() - 40): m.end() + 40].replace("\n", " ")
            findings.append(
                Finding(
                    id=f"wf-{short_sha((path.as_posix() + snippet).encode())}-shell",
                    title=message,
                    severity="high" if "Pipe-to-shell" in message else "medium",
                    file=rel,
                    details=f"Potentially risky command snippet: {snippet.strip()}",
                    recommendation="Replace pipe-to-shell installs with checked-in scripts, version-locked package installs, or vendor-supplied actions.",
                )
            )
            break

    if "codeql" in path.name.lower() or "codeql" in text.lower():
        findings.append(
            Finding(
                id=f"wf-{short_sha((path.as_posix() + 'codeql').encode())}-codeql",
                title="Code scanning workflow detected",
                severity="info",
                file=rel,
                details="A CodeQL or code-scanning workflow appears to be present.",
                recommendation="Keep code scanning enabled on push and schedule so new vulnerabilities and regressions are reviewed continuously.",
            )
        )

    if "schedule:" in text:
        findings.append(
            Finding(
                id=f"wf-{short_sha((path.as_posix() + 'schedule').encode())}-schedule",
                title="Scheduled execution configured",
                severity="info",
                file=rel,
                details="Workflow contains a schedule trigger.",
                recommendation="Use scheduled runs to refresh the assessment periodically, even when code is quiet.",
            )
        )

    return findings


def analyze_repo(repo_root: Path) -> Report:
    findings: List[Finding] = []
    evidence: List[FileStat] = []

    wf_files = workflow_files(repo_root)
    evidence.append(FileStat(path=".github/workflows", exists=bool(wf_files), reason="Workflow directory present" if wf_files else "No workflow directory found"))

    for path in discover_files(repo_root):
        evidence.append(FileStat(path=str(path.relative_to(repo_root)), exists=True, reason="Found"))

    if not wf_files:
        findings.append(
            Finding(
                id="repo-no-workflows",
                title="No GitHub Actions workflows found",
                severity="medium",
                file=".github/workflows",
                details="No workflow files were detected in .github/workflows.",
                recommendation="Add a scheduled RA-03 assessment workflow so risk reviews are repeatable and auditable.",
            )
        )

    if not any("codeql" in p.name.lower() for p in wf_files):
        findings.append(
            Finding(
                id="repo-no-codeql",
                title="No code scanning workflow detected",
                severity="medium",
                file=".github/workflows",
                details="No workflow named like a CodeQL or code-scanning workflow was found.",
                recommendation="Enable GitHub code scanning or another scanner so code vulnerabilities are part of the risk assessment evidence set.",
            )
        )

    if not any(p.name.lower() in {"dependabot.yml", "dependabot.yaml"} for p in discover_files(repo_root)):
        findings.append(
            Finding(
                id="repo-no-dependabot",
                title="Dependabot configuration not found",
                severity="low",
                file=".github/dependabot.yml",
                details="No Dependabot configuration file was found.",
                recommendation="Add Dependabot to keep dependency risk visible and reviewable.",
            )
        )

    if not any(p.name == "CODEOWNERS" for p in discover_files(repo_root)):
        findings.append(
            Finding(
                id="repo-no-codeowners",
                title="CODEOWNERS file not found",
                severity="low",
                file="CODEOWNERS",
                details="No CODEOWNERS file was found.",
                recommendation="Use CODEOWNERS so the right reviewers are included in risk-relevant changes.",
            )
        )

    for wf in wf_files:
        findings.extend(analyze_workflow(wf))

    unique: List[Finding] = []
    seen = set()
    for f in findings:
        key = (f.title, f.file, f.details)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    findings = unique

    score = 100
    for f in findings:
        score -= SEVERITY_WEIGHTS.get(f.severity, 0)
    score = max(0, min(100, score))

    if score >= 90:
        status = "pass"
    elif score >= 70:
        status = "attention"
    else:
        status = "fail"

    repo = os.getenv("GH_REPOSITORY", os.getenv("GITHUB_REPOSITORY", repo_root.name))
    ref = os.getenv("GH_REF_NAME", os.getenv("GITHUB_REF_NAME", os.getenv("GITHUB_REF", "local")))
    sha = os.getenv("GH_SHA", os.getenv("GITHUB_SHA", "local"))

    return Report(
        repository=repo,
        ref=ref,
        sha=sha,
        generated_at_utc=utc_now(),
        score=score,
        status=status,
        findings=findings,
        evidence=evidence,
    )


def render_markdown(report: Report) -> str:
    lines = [
        "# RA-03 Repository Risk Assessment",
        "",
        f"Repository: `{report.repository}`",
        f"Ref: `{report.ref}`",
        f"Commit: `{report.sha}`",
        f"Generated (UTC): `{report.generated_at_utc}`",
        f"Score: **{report.score}/100**",
        f"Status: **{report.status.upper()}**",
        "",
        "## Findings",
    ]

    if not report.findings:
        lines.append("No findings.")
    else:
        for finding in report.findings:
            lines.extend([
                f"- **[{finding.severity.upper()}] {finding.title}** ({finding.file})",
                f"  - {finding.details}",
                f"  - Recommendation: {finding.recommendation}",
            ])

    lines.extend([
        "",
        "## Evidence Collected",
    ])

    for item in report.evidence:
        if item.exists:
            lines.append(f"- `{item.path}` — {item.reason}")

    lines.extend([
        "",
        "## Notes",
        "This report is a control-support artifact. It is meant to document repository-level risk signals, not to certify compliance on its own.",
    ])
    return "\n".join(lines) + "\n"


def write_outputs(report: Report, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / "ra-03-report.json"
    md_path = output_dir / "ra-03-report.md"

    payload = {
        "repository": report.repository,
        "ref": report.ref,
        "sha": report.sha,
        "generated_at_utc": report.generated_at_utc,
        "score": report.score,
        "status": report.status,
        "findings": [dataclasses.asdict(f) for f in report.findings],
        "evidence": [dataclasses.asdict(e) for e in report.evidence],
    }

    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")

    step_summary = os.getenv("GITHUB_STEP_SUMMARY")
    if step_summary:
        Path(step_summary).write_text(render_markdown(report), encoding="utf-8")

    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    print(f"Score: {report.score} Status: {report.status}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run a repository risk assessment for RA-03 evidence.")
    parser.add_argument("--repo-root", default=".", help="Repository root to scan.")
    parser.add_argument("--output-dir", default="ra03-artifacts", help="Directory for generated artifacts.")
    parser.add_argument("--fail-below", type=int, default=70, help="Exit non-zero when score is below this threshold.")
    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    report = analyze_repo(repo_root)
    write_outputs(report, Path(args.output_dir).resolve())

    if report.score < args.fail_below:
        print(
            f"Risk score {report.score} is below threshold {args.fail_below}; failing the job to force review.",
            file=sys.stderr,
        )
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
