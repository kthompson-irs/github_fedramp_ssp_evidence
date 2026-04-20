#!/usr/bin/env python3
"""
Builds a FedRAMP submission package from the SA-04(10) evidence collection output.

Outputs:
- SSP/sa-04-10-control-response.md
- OSCAL/ssp.json
- Evidence/CI_CD/*
- Evidence/GitHub/*
- Evidence/AWS/*
- Evidence/Policies/*
- POAM/*
- README.md
- manifest.json
- fedramp_ato_package.zip

This script intentionally builds a submission-ready package structure that can be
expanded into a broader FedRAMP package.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build FedRAMP submission package.")
    parser.add_argument(
        "--input-dir",
        default="artifacts/sa-04-10",
        help="Directory created by gh_sa_04_10_poll_alerts.py",
    )
    parser.add_argument(
        "--output-dir",
        default="fedramp_ato_package",
        help="Directory where the FedRAMP package is built.",
    )
    return parser.parse_args()


def read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def copy_if_exists(src: Path, dst: Path) -> bool:
    if not src.exists():
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return True


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_manifest(root: Path) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            continue
        if path.name == "fedramp_ato_package.zip":
            continue
        entries.append(
            {
                "path": str(path.relative_to(root)),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return entries


def markdown_table(rows: List[List[str]]) -> str:
    if not rows:
        return ""
    header = rows[0]
    body = rows[1:]
    lines = [
        "| " + " | ".join(header) + " |",
        "| " + " | ".join(["---"] * len(header)) + " |",
    ]
    for row in body:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def build_ssp_markdown(summary: Dict[str, Any], run_context: Dict[str, Any]) -> str:
    results = summary.get("results", {})
    overall = summary.get("overall", {})
    repo = summary.get("repository", "unknown")
    generated_at = summary.get("generated_at", utc_now())
    threshold = summary.get("threshold", "high")

    rows = [
        ["Category", "Accessible", "Skipped", "Count", "Blocking"],
        [
            "Code Scanning",
            str(results.get("code_scanning", {}).get("accessible", False)).lower(),
            str(results.get("code_scanning", {}).get("skipped", False)).lower(),
            str(results.get("code_scanning", {}).get("count", 0)),
            str(results.get("code_scanning", {}).get("blocking_count", 0)),
        ],
        [
            "Dependabot",
            str(results.get("dependabot", {}).get("accessible", False)).lower(),
            str(results.get("dependabot", {}).get("skipped", False)).lower(),
            str(results.get("dependabot", {}).get("count", 0)),
            str(results.get("dependabot", {}).get("blocking_count", 0)),
        ],
        [
            "Secret Scanning",
            str(results.get("secret_scanning", {}).get("accessible", False)).lower(),
            str(results.get("secret_scanning", {}).get("skipped", False)).lower(),
            str(results.get("secret_scanning", {}).get("count", 0)),
            str(results.get("secret_scanning", {}).get("blocking_count", 0)),
        ],
    ]

    evidence_lines = summary.get("evidence_lines", [])
    blocking_findings = summary.get("blocking_findings", [])
    errors = summary.get("errors", [])

    lines = [
        "# SA-04(10) Control Implementation Statement",
        "",
        f"- Repository: `{repo}`",
        f"- Generated: `{generated_at}`",
        f"- Threshold: `{threshold}`",
        f"- Status: `{overall.get('status', 'unknown')}`",
        f"- Blocking findings: `{overall.get('blocking_count', 0)}`",
        f"- Collection errors: `{overall.get('error_count', 0)}`",
        "",
        "## Execution Summary",
        "",
        markdown_table(rows),
        "",
        "## Implementation Narrative",
        "",
        "The Treasury Cloud environment implements SA-04(10) as a layered shared-control design across AWS GovCloud (US), GitHub.com, and Treasury-managed application code.",
        "",
        "AWS GovCloud (US) provides inherited infrastructure and platform security testing evidence through its FedRAMP authorization package and continuous monitoring artifacts.",
        "",
        "GitHub.com provides developer security tooling that supports the control, including CodeQL for static analysis, Dependabot for dependency risk visibility, and secret scanning for leaked credential detection.",
        "",
        "Treasury enforces developer security testing through GitHub Actions, a Python compliance gate, and a generated evidence binder. The gate records structured SSP evidence lines and exports the results into a submission-ready package.",
        "",
        "## Evidence Lines",
        "",
    ]

    for item in evidence_lines:
        lines.append(f"- {item}")

    if errors:
        lines.extend(["", "## Collection Errors", ""])
        for item in errors:
            lines.append(f"- {item}")

    if blocking_findings:
        lines.extend(["", "## Blocking Findings Snapshot", ""])
        for finding in blocking_findings[:20]:
            lines.append(
                f"- {finding.get('category')} | {finding.get('identifier')} | "
                f"{finding.get('severity')} | {finding.get('html_url') or 'n/a'}"
            )

    lines.extend(
        [
            "",
            "## Assessor Notes",
            "",
            "The package includes the workflow, Python evidence collector, OSCAL SSP, POA&M candidate data, and a manifest of generated artifacts.",
            "",
        ]
    )

    return "\n".join(lines)


def build_oscal_ssp(summary: Dict[str, Any], run_context: Dict[str, Any]) -> Dict[str, Any]:
    repo = summary.get("repository", "unknown")
    generated_at = summary.get("generated_at", utc_now())
    threshold = summary.get("threshold", "high")
    results = summary.get("results", {})
    overall = summary.get("overall", {})
    blocking_findings = summary.get("blocking_findings", [])

    aws_uuid = str(uuid.uuid4())
    github_uuid = str(uuid.uuid4())
    treasury_uuid = str(uuid.uuid4())
    sa410_uuid = str(uuid.uuid4())

    back_matter_resources = []

    def add_resource(title: str, href: str) -> None:
        back_matter_resources.append(
            {
                "uuid": str(uuid.uuid4()),
                "title": title,
                "rlinks": [{"href": href}],
            }
        )

    add_resource("Workflow YAML", "../.github/workflows/sa-04-10-security-gate.yml")
    add_resource("Evidence Polling Script", "../scripts/gh_sa_04_10_poll_alerts.py")
    add_resource("Package Builder Script", "../scripts/build_fedramp_submission_package.py")
    add_resource("Evidence Summary", "../Evidence/CI_CD/summary.md")
    add_resource("Evidence Summary JSON", "../Evidence/CI_CD/summary.json")

    if run_context.get("codeql_sarif_exists"):
        add_resource("CodeQL SARIF", "../Evidence/CI_CD/codeql_results/python.sarif")

    return {
        "system-security-plan": {
            "uuid": str(uuid.uuid4()),
            "metadata": {
                "title": "Treasury Cloud SSP",
                "version": "1.0",
                "oscal-version": "1.0.4",
                "last-modified": generated_at,
                "remarks": "Generated automatically from SA-04(10) evidence collection.",
                "roles": [
                    {"id": "system-owner", "title": "System Owner"},
                    {"id": "isso", "title": "Information System Security Officer"},
                    {"id": "devsecops", "title": "DevSecOps Engineer"},
                ],
                "parties": [
                    {"uuid": str(uuid.uuid4()), "type": "person", "name": "Treasury Cloud Team"},
                ],
            },
            "system-characteristics": {
                "system-name": "Treasury Cloud",
                "authorization-boundary": "Treasury Cloud deployment using AWS GovCloud (US) and GitHub.com.",
                "security-sensitivity-level": "low",
                "system-description": {
                    "text": "Treasury Cloud uses AWS GovCloud (US) for runtime infrastructure and GitHub.com for source code management and security scanning workflows."
                },
                "information-types": [
                    {
                        "uuid": str(uuid.uuid4()),
                        "information-type-id": "fips-199-low",
                        "title": "Low Impact Information",
                        "confidentiality-impact": "low",
                        "integrity-impact": "low",
                        "availability-impact": "low",
                    }
                ],
            },
            "system-implementation": {
                "users": [
                    {"uuid": str(uuid.uuid4()), "title": "Authorized Treasury Developers", "role-ids": ["devsecops"]},
                    {"uuid": str(uuid.uuid4()), "title": "System Owners and ISSOs", "role-ids": ["system-owner", "isso"]},
                ],
                "components": [
                    {
                        "uuid": aws_uuid,
                        "type": "service",
                        "title": "AWS GovCloud (US)",
                        "description": "FedRAMP-authorized cloud infrastructure and platform services inherited by Treasury Cloud.",
                    },
                    {
                        "uuid": github_uuid,
                        "type": "service",
                        "title": "GitHub.com",
                        "description": "FedRAMP-authorized development platform providing CodeQL, Dependabot, and Secret Scanning.",
                    },
                    {
                        "uuid": treasury_uuid,
                        "type": "software",
                        "title": "Treasury CI/CD and Compliance Gate",
                        "description": "Treasury-owned workflow and Python compliance gate that enforces SA-04(10) evidence collection.",
                    },
                ],
            },
            "control-implementation": {
                "implemented-requirements": [
                    {
                        "uuid": sa410_uuid,
                        "control-id": "sa-4.10",
                        "props": [
                            {"name": "control-origination", "value": "shared"},
                            {"name": "threshold", "value": threshold},
                            {"name": "blocking-count", "value": str(overall.get("blocking_count", 0))},
                            {"name": "error-count", "value": str(overall.get("error_count", 0))},
                        ],
                        "by-components": [
                            {
                                "component-uuid": aws_uuid,
                                "description": "AWS GovCloud (US) provides inherited infrastructure-layer security testing evidence through its FedRAMP authorization package and continuous monitoring.",
                                "responsible-roles": [{"role-id": "system-owner"}],
                                "implemented-requirements": [
                                    {
                                        "control-id": "sa-4.10",
                                        "description": "Inherited infrastructure security testing and validation.",
                                    }
                                ],
                            },
                            {
                                "component-uuid": github_uuid,
                                "description": "GitHub.com provides developer security tooling and repository-level security scanning support.",
                                "responsible-roles": [{"role-id": "devsecops"}],
                                "implemented-requirements": [
                                    {
                                        "control-id": "sa-4.10",
                                        "description": "Shared platform-level developer security testing and evaluation.",
                                    }
                                ],
                            },
                            {
                                "component-uuid": treasury_uuid,
                                "description": "Treasury enforces security gates, collects evidence, and publishes the submission package.",
                                "responsible-roles": [{"role-id": "isso"}, {"role-id": "devsecops"}],
                                "implemented-requirements": [
                                    {
                                        "control-id": "sa-4.10",
                                        "description": "Customer-enforced application-layer developer security testing and evidence collection.",
                                    }
                                ],
                            },
                        ],
                        "statements": [
                            {
                                "uuid": str(uuid.uuid4()),
                                "statement-id": "sa-4.10_smt",
                                "description": (
                                    "SA-04(10) is implemented as a layered shared control across AWS GovCloud (US), "
                                    "GitHub.com, and Treasury-managed code. The control is enforced by CodeQL, "
                                    "Dependabot, Secret Scanning, and a Python compliance gate that exports a "
                                    "submission-ready evidence binder and OSCAL SSP package."
                                ),
                            }
                        ],
                        "remarks": (
                            f"Generated from {len(blocking_findings)} blocking findings and "
                            f"{overall.get('error_count', 0)} collection errors recorded during evidence collection."
                        ),
                    }
                ]
            },
            "back-matter": {
                "resources": back_matter_resources,
            },
        }
    }


def build_poam_candidate_csv(blocking_findings: List[Dict[str, Any]]) -> str:
    output = [
        ["id", "category", "identifier", "severity", "title", "source_url", "status", "recommended_due_date"],
    ]
    for idx, finding in enumerate(blocking_findings, start=1):
        output.append(
            [
                f"POAM-{idx:03d}",
                str(finding.get("category", "")),
                str(finding.get("identifier", "")),
                str(finding.get("severity", "")),
                str(finding.get("title", "")),
                str(finding.get("html_url", "")),
                "open",
                "30 days" if str(finding.get("severity", "")).lower() in {"high", "critical"} else "90 days",
            ]
        )
    lines: List[str] = []
    for row in output:
        lines.append(",".join(csv_quote(cell) for cell in row))
    return "\n".join(lines) + "\n"


def csv_quote(value: str) -> str:
    value = value or ""
    if any(ch in value for ch in [",", "\"", "\n"]):
        return '"' + value.replace('"', '""') + '"'
    return value


def build_readme(summary: Dict[str, Any]) -> str:
    repo = summary.get("repository", "unknown")
    generated_at = summary.get("generated_at", utc_now())
    overall = summary.get("overall", {})
    results = summary.get("results", {})

    return f"""# FedRAMP Submission Package

## System
Treasury Cloud (AWS GovCloud + GitHub.com)

## Control Focus
SA-04(10) – Developer Security Testing and Evaluation

## Generated
{generated_at}

## Repository
{repo}

## Package Status
- Overall status: {overall.get("status", "unknown")}
- Blocking findings: {overall.get("blocking_count", 0)}
- Collection errors: {overall.get("error_count", 0)}

## Contents
- SSP/sa-04-10-control-response.md
- OSCAL/ssp.json
- Evidence/CI_CD
- Evidence/GitHub
- Evidence/AWS
- Evidence/Policies
- POAM
- manifest.json
- fedramp_ato_package.zip

## Evidence Summary
- Code Scanning: {results.get("code_scanning", {}).get("count", 0)} alert(s)
- Dependabot: {results.get("dependabot", {}).get("count", 0)} alert(s)
- Secret Scanning: {results.get("secret_scanning", {}).get("count", 0)} alert(s)

## Review Notes
- The workflow and scripts are copied into the binder for traceability.
- The evidence binder includes the generated summary, blocking findings, and package manifest.
- The OSCAL SSP is generated as a submission-ready scaffold for SA-04(10) and can be extended with broader control content as needed.
"""


def build_placeholder_readme(folder_name: str, purpose: str) -> str:
    return f"""# {folder_name}

{purpose}

This folder is created automatically so the evidence binder is submission-ready.
Replace or supplement these notes with exported PDFs, screenshots, and agency-specific artifacts as needed.
"""


def copy_repo_source_files(output_dir: Path) -> None:
    source_targets = [
        (Path(".github/workflows/sa-04-10-security-gate.yml"), output_dir / "Evidence" / "CI_CD" / "source" / "sa-04-10-security-gate.yml"),
        (Path("scripts/gh_sa_04_10_poll_alerts.py"), output_dir / "Evidence" / "CI_CD" / "source" / "gh_sa_04_10_poll_alerts.py"),
        (Path("scripts/build_fedramp_submission_package.py"), output_dir / "Evidence" / "CI_CD" / "source" / "build_fedramp_submission_package.py"),
    ]
    for src, dst in source_targets:
        copy_if_exists(src, dst)


def copy_codeql_sarif(output_dir: Path) -> bool:
    candidates = [
        Path("../results/python.sarif"),
        Path("results/python.sarif"),
    ]
    for candidate in candidates:
        if candidate.exists():
            dst = output_dir / "Evidence" / "CI_CD" / "codeql_results" / "python.sarif"
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(candidate, dst)
            return True
    return False


def make_manifest_json(root: Path) -> Dict[str, Any]:
    files: List[Dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            continue
        if path.name == "fedramp_ato_package.zip":
            continue
        files.append(
            {
                "path": str(path.relative_to(root)),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return {
        "generated_at": utc_now(),
        "file_count": len(files),
        "files": files,
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def zip_directory(source_dir: Path, zip_path: Path) -> None:
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(source_dir.rglob("*")):
            if path.is_dir():
                continue
            if path == zip_path:
                continue
            zf.write(path, arcname=str(path.relative_to(source_dir)))


def main() -> int:
    args = parse_args()
    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)

    summary = read_json(input_dir / "summary.json")
    if not summary:
        raise SystemExit(f"summary.json not found in {input_dir}")

    run_context = {
        "repository": os.getenv("GITHUB_REPOSITORY", summary.get("repository")),
        "workflow": os.getenv("GITHUB_WORKFLOW"),
        "run_id": os.getenv("GITHUB_RUN_ID"),
        "run_attempt": os.getenv("GITHUB_RUN_ATTEMPT"),
        "sha": os.getenv("GITHUB_SHA"),
        "ref": os.getenv("GITHUB_REF"),
    }

    clean_dir(output_dir)

    for folder in [
        output_dir / "SSP",
        output_dir / "OSCAL",
        output_dir / "Evidence" / "CI_CD",
        output_dir / "Evidence" / "CI_CD" / "source",
        output_dir / "Evidence" / "GitHub",
        output_dir / "Evidence" / "AWS",
        output_dir / "Evidence" / "Policies",
        output_dir / "POAM",
    ]:
        folder.mkdir(parents=True, exist_ok=True)

    # Core evidence copies
    copy_if_exists(input_dir / "summary.json", output_dir / "Evidence" / "CI_CD" / "summary.json")
    copy_if_exists(input_dir / "summary.md", output_dir / "Evidence" / "CI_CD" / "summary.md")
    copy_if_exists(input_dir / "evidence_lines.txt", output_dir / "Evidence" / "CI_CD" / "evidence_lines.txt")
    copy_if_exists(input_dir / "blocking_findings.json", output_dir / "Evidence" / "CI_CD" / "blocking_findings.json")

    for name in [
        "code_scanning_alerts.json",
        "dependabot_alerts.json",
        "dependabot_skip.json",
        "dependabot_error.json",
        "secret_scanning_alerts.json",
        "secret_scanning_skip.json",
        "secret_scanning_error.json",
        "code_scanning_error.json",
    ]:
        copy_if_exists(input_dir / name, output_dir / "Evidence" / "CI_CD" / name)

    # Run context
    run_context["codeql_sarif_exists"] = copy_codeql_sarif(output_dir)
    write_json(output_dir / "Evidence" / "CI_CD" / "run_context.json", run_context)

    # Copy source files for traceability
    copy_repo_source_files(output_dir)

    # SSP control response
    ssp_md = build_ssp_markdown(summary, run_context)
    write_text(output_dir / "SSP" / "sa-04-10-control-response.md", ssp_md)

    # OSCAL SSP
    oscal = build_oscal_ssp(summary, run_context)
    write_json(output_dir / "OSCAL" / "ssp.json", oscal)

    # POA&M artifacts
    blocking_findings = summary.get("blocking_findings", [])
    write_text(output_dir / "POAM" / "poam_candidate.csv", build_poam_candidate_csv(blocking_findings))
    write_text(
        output_dir / "POAM" / "poam_template.csv",
        "id,category,identifier,severity,title,source_url,status,recommended_due_date\n",
    )
    write_text(
        output_dir / "POAM" / "README.md",
        build_placeholder_readme(
            "POAM",
            "Candidate POA&M entries derived from blocking findings are generated here.",
        ),
    )

    # Placeholder folders for human review / additional agency artifacts
    write_text(
        output_dir / "Evidence" / "GitHub" / "README.md",
        build_placeholder_readme(
            "Evidence/GitHub",
            "Place GitHub screenshots, authorization package excerpts, and review evidence here.",
        ),
    )
    write_text(
        output_dir / "Evidence" / "AWS" / "README.md",
        build_placeholder_readme(
            "Evidence/AWS",
            "Place AWS GovCloud SSP excerpts, SAR summaries, and continuous monitoring evidence here.",
        ),
    )
    write_text(
        output_dir / "Evidence" / "Policies" / "README.md",
        build_placeholder_readme(
            "Evidence/Policies",
            "Place SSDLC, vulnerability management, and supply chain policy artifacts here.",
        ),
    )

    # Root README
    write_text(output_dir / "README.md", build_readme(summary))

    # Manifest
    manifest = make_manifest_json(output_dir)
    write_json(output_dir / "manifest.json", manifest)

    # Zip archive
    zip_directory(output_dir, output_dir / "fedramp_ato_package.zip")

    print(f"FedRAMP submission package built at: {output_dir}")
    print(f"Archive created at: {output_dir / 'fedramp_ato_package.zip'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
