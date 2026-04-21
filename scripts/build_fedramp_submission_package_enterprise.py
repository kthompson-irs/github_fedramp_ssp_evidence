#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the FedRAMP submission package.")

    parser.add_argument("--input-dir", dest="input_dir", default=None)
    parser.add_argument("--spreadsheets-dir", dest="spreadsheets_dir", default=None)
    parser.add_argument("--poam-dir", dest="poam_dir", default=None)
    parser.add_argument("--controls-manifest", dest="controls_manifest", default=None)
    parser.add_argument("--enterprise-orgs-file", dest="enterprise_orgs_file", default=None)
    parser.add_argument("--output-dir", dest="output_dir", default=None)

    parser.add_argument("--input", dest="input_legacy", default=None)
    parser.add_argument("--spreadsheets", dest="spreadsheets_legacy", default=None)
    parser.add_argument("--poam", dest="poam_legacy", default=None)
    parser.add_argument("--manifest", dest="manifest_legacy", default=None)
    parser.add_argument("--enterprise-orgs", dest="enterprise_orgs_legacy", default=None)
    parser.add_argument("--output", dest="output_legacy", default=None)

    args = parser.parse_args()

    args.input_dir = args.input_dir or args.input_legacy or "artifacts/sa-04-10"
    args.spreadsheets_dir = args.spreadsheets_dir or args.spreadsheets_legacy or "spreadsheets"
    args.poam_dir = args.poam_dir or args.poam_legacy or "poam"
    args.controls_manifest = args.controls_manifest or args.manifest_legacy or "controls_manifest.json"
    args.enterprise_orgs_file = args.enterprise_orgs_file or args.enterprise_orgs_legacy or "enterprise_organizations.json"
    args.output_dir = args.output_dir or args.output_legacy or "fedramp_ato_package"

    return args


def read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def copy_tree(src: Path, dst: Path) -> None:
    if src.exists():
        shutil.copytree(src, dst, dirs_exist_ok=True)


def csv_quote(value: str) -> str:
    if any(ch in value for ch in [",", '"', "\n"]):
        return '"' + value.replace('"', '""') + '"'
    return value


def default_controls_manifest() -> Dict[str, Any]:
    return {
        "profile_name": "Default SA-04(10) Control Inventory",
        "description": "Fallback manifest used when controls_manifest.json is missing or invalid.",
        "controls": [
            {
                "control_id": "sa-4.10",
                "origination": "shared",
                "implementation": (
                    "SA-04(10) is implemented across AWS GovCloud, GitHub.com, and Treasury automation "
                    "through security scanning, alert polling, evidence generation, POA&M creation, and "
                    "submission-package assembly."
                ),
            }
        ],
    }


def load_controls_manifest(path: Path) -> Dict[str, Any]:
    manifest = read_json(path, default=None)
    if isinstance(manifest, dict):
        controls = manifest.get("controls", [])
        if isinstance(controls, list) and controls:
            return manifest

    print(
        f"WARNING: {path} is missing or invalid. Using a default SA-04(10) controls manifest "
        "so the package build can continue."
    )
    return default_controls_manifest()


def default_enterprise_orgs() -> Dict[str, Any]:
    return {
        "enterprise": "internal-revenue-service",
        "generated_at": utc_now(),
        "organizations": [
            {
                "slug": "AD-DIRECTFILE",
                "display_name": "AD-DIRECTFILE",
                "role": "Owner",
                "status": "archived_owner",
                "single_sign_on": False,
                "two_factor_required": False,
            },
            {
                "slug": "IRS-Codespaces-testing",
                "display_name": "IRS-Codespaces-testing",
                "role": "Owner",
                "status": "active",
                "single_sign_on": False,
                "two_factor_required": True,
            },
            {
                "slug": "IRS-CoPilot-Testing",
                "display_name": "IRS-CoPilot-Testing",
                "role": "Owner",
                "status": "active",
                "single_sign_on": False,
                "two_factor_required": True,
            },
            {
                "slug": "IRS-Public",
                "display_name": "IRS-Public",
                "role": "Owner",
                "status": "active",
                "single_sign_on": False,
                "two_factor_required": True,
            },
            {
                "slug": "IRS-ShareIT",
                "display_name": "IRS-ShareIT",
                "role": "Owner",
                "status": "active",
                "single_sign_on": False,
                "two_factor_required": True,
            },
            {
                "slug": "IRSDigitalService",
                "display_name": "IRSDigitalService",
                "role": "Owner",
                "status": "active",
                "single_sign_on": False,
                "two_factor_required": True,
            },
            {
                "slug": "sds-sbx",
                "display_name": "sds-sbx",
                "role": "Owner",
                "status": "active",
                "single_sign_on": True,
                "two_factor_required": True,
            },
            {
                "slug": "Taxpayer-Services-and-Online-Accounts",
                "display_name": "Taxpayer-Services-and-Online-Accounts",
                "role": "Owner",
                "status": "active",
                "single_sign_on": True,
                "two_factor_required": True,
            },
        ],
        "notes": [
            "Captured from the enterprise organization inventory provided by the user.",
        ],
    }


def load_enterprise_orgs(path: Path) -> Dict[str, Any]:
    data = read_json(path, default=None)
    if isinstance(data, dict):
        orgs = data.get("organizations", [])
        if isinstance(orgs, list) and orgs:
            return data

    print(
        f"WARNING: {path} is missing or invalid. Using the provided enterprise organization inventory fallback."
    )
    return default_enterprise_orgs()


def repo_from_env_or_summary(summary: Dict[str, Any]) -> Dict[str, str]:
    full = os.getenv("GH_REPOSITORY") or summary.get("repository") or ""
    owner = os.getenv("GH_ORG_NAME") or summary.get("organization") or summary.get("owner") or ""
    return {
        "repository": full,
        "organization": owner,
        "workflow": os.getenv("GH_WORKFLOW", ""),
        "run_id": os.getenv("GH_RUN_ID", ""),
        "run_attempt": os.getenv("GH_RUN_ATTEMPT", ""),
        "sha": os.getenv("GH_SHA", ""),
        "ref": os.getenv("GH_REF", ""),
    }


def build_poam_csv(findings: List[Dict[str, Any]]) -> str:
    rows = [
        [
            "id",
            "category",
            "organization",
            "repository",
            "repository_full",
            "identifier",
            "severity",
            "title",
            "source_url",
            "status",
            "recommended_due_date",
        ]
    ]
    for idx, finding in enumerate(findings, start=1):
        severity = str(finding.get("severity", "")).lower()
        due = "30 days" if severity in {"high", "critical"} else "90 days"
        rows.append(
            [
                f"POAM-{idx:03d}",
                str(finding.get("category", "")),
                str(finding.get("organization", "")),
                str(finding.get("repository", "")),
                str(finding.get("repository_full", "")),
                str(finding.get("identifier", "")),
                severity,
                str(finding.get("title", "")),
                str(finding.get("html_url", "")),
                "open",
                due,
            ]
        )
    return "\n".join(",".join(csv_quote(cell) for cell in row) for row in rows) + "\n"


def build_ssp_markdown(summary: Dict[str, Any], controls: List[Dict[str, Any]], run_context: Dict[str, str]) -> str:
    scope = summary.get("scope", "unknown")
    repository = summary.get("repository", "unknown")
    repo_count = summary.get("repository_count", 0)

    lines = [
        "# Treasury Cloud SSP",
        "",
        f"- Generated: `{summary.get('generated_at', utc_now())}`",
        f"- Scope: `{scope}`",
        f"- Organization: `{summary.get('organization', '')}`",
        f"- Repository: `{repository}`",
        f"- Repository count: `{repo_count}`",
        f"- Workflow: `{run_context.get('workflow', '')}`",
        f"- Run ID: `{run_context.get('run_id', '')}`",
        "",
        "## Control Coverage",
        "",
    ]

    for control in controls:
        lines.append(f"- {control.get('control_id', 'unknown')}: {control.get('origination', 'shared')}")

    lines.extend(
        [
            "",
            "## SA-04(10) Evidence Statement",
            "",
            "The system implements SA-04(10) through AWS GovCloud, GitHub security services, and Treasury automation.",
            "",
        ]
    )

    if scope == "enterprise":
        lines.extend(
            [
                "## Enterprise Coverage",
                "",
                f"- Enterprise slug: `{summary.get('enterprise', '')}`",
                f"- Covered repositories: `{repo_count}`",
                "",
            ]
        )

    return "\n".join(lines)


def build_oscal_ssp(
    summary: Dict[str, Any],
    controls: List[Dict[str, Any]],
    run_context: Dict[str, str],
    has_sarif: bool,
) -> Dict[str, Any]:
    sys_uuid = str(uuid.uuid4())
    aws_uuid = str(uuid.uuid4())
    github_uuid = str(uuid.uuid4())
    treasury_uuid = str(uuid.uuid4())

    components = [
        {
            "uuid": aws_uuid,
            "type": "service",
            "title": "AWS GovCloud (US)",
            "description": "FedRAMP-authorized infrastructure and platform services.",
        },
        {
            "uuid": github_uuid,
            "type": "service",
            "title": "GitHub.com",
            "description": "Development platform providing CodeQL, Dependabot, and secret scanning.",
        },
        {
            "uuid": treasury_uuid,
            "type": "software",
            "title": "Treasury CI/CD and Evidence Automation",
            "description": "Workflow and Python automation that collects evidence and builds the package.",
        },
    ]

    implemented_requirements = []
    for control in controls:
        control_id = control.get("control_id", "unknown")
        implemented_requirements.append(
            {
                "uuid": str(uuid.uuid4()),
                "control-id": control_id,
                "props": [
                    {"name": "control-origination", "value": control.get("origination", "shared")},
                ],
                "statements": [
                    {
                        "uuid": str(uuid.uuid4()),
                        "statement-id": f"{control_id}_smt",
                        "description": control.get(
                            "implementation",
                            "Implementation defined in the control manifest.",
                        ),
                    }
                ],
            }
        )

    back_matter_resources = [
        {
            "uuid": str(uuid.uuid4()),
            "title": "Workflow YAML",
            "rlinks": [{"href": "../.github/workflows/sa-04-10-enterprise-fedramp-evidence.yml"}],
        },
        {
            "uuid": str(uuid.uuid4()),
            "title": "Alert Collector",
            "rlinks": [{"href": "../scripts/gh_sa_04_10_enterprise_collector.py"}],
        },
        {
            "uuid": str(uuid.uuid4()),
            "title": "Spreadsheet Builder",
            "rlinks": [{"href": "../scripts/build_sa04_30_day_spreadsheets_enterprise.py"}],
        },
        {
            "uuid": str(uuid.uuid4()),
            "title": "POA&M Builder",
            "rlinks": [{"href": "../scripts/build_poam_from_findings.py"}],
        },
        {
            "uuid": str(uuid.uuid4()),
            "title": "Package Builder",
            "rlinks": [{"href": "../scripts/build_fedramp_submission_package_enterprise.py"}],
        },
        {
            "uuid": str(uuid.uuid4()),
            "title": "Controls Manifest",
            "rlinks": [{"href": "../controls_manifest.json"}],
        },
        {
            "uuid": str(uuid.uuid4()),
            "title": "Enterprise Organization Inventory",
            "rlinks": [{"href": "../Evidence/Enterprise/enterprise_organizations.json"}],
        },
    ]

    if has_sarif:
        back_matter_resources.append(
            {
                "uuid": str(uuid.uuid4()),
                "title": "CodeQL SARIF",
                "rlinks": [{"href": "../Evidence/CI_CD/codeql_results/python.sarif"}],
            }
        )

    return {
        "system-security-plan": {
            "uuid": sys_uuid,
            "metadata": {
                "title": "Treasury Cloud SSP",
                "version": "1.0",
                "oscal-version": "1.0.4",
                "last-modified": summary.get("generated_at", utc_now()),
                "remarks": "Generated automatically from enterprise SA-04(10) evidence collection.",
            },
            "system-characteristics": {
                "system-name": "Treasury Cloud",
                "security-sensitivity-level": "low",
                "authorization-boundary": "Treasury Cloud environment using AWS GovCloud and GitHub.com.",
                "system-description": {
                    "text": "Treasury Cloud uses AWS GovCloud (US) and GitHub.com with CI/CD security gates, historical logs, and evidence automation."
                },
            },
            "system-implementation": {
                "components": components,
            },
            "control-implementation": {
                "implemented-requirements": implemented_requirements,
            },
            "back-matter": {
                "resources": back_matter_resources,
            },
        }
    }


def build_readme(summary: Dict[str, Any], controls: List[Dict[str, Any]], run_context: Dict[str, str], org_inventory: Dict[str, Any]) -> str:
    scope = summary.get("scope", "unknown")
    repository = summary.get("repository", "unknown")
    repo_count = summary.get("repository_count", 0)
    org_count = len(org_inventory.get("organizations", []) or [])

    return "\n".join(
        [
            "# FedRAMP Submission Package",
            "",
            "## System",
            "Treasury Cloud (AWS GovCloud + GitHub.com)",
            "",
            "## Control Focus",
            "SA-04(10) – Developer Security Testing and Evaluation",
            "",
            f"Generated: {summary.get('generated_at', utc_now())}",
            f"Repository: {repository}",
            f"Organization: {summary.get('organization', '')}",
            f"Scope: {scope}",
            f"Repository count: {repo_count}",
            f"Enterprise organizations captured: {org_count}",
            f"Workflow: {run_context.get('workflow', '')}",
            f"Run ID: {run_context.get('run_id', '')}",
            "",
            "## Package Contents",
            "- SSP/sa-04-10-control-response.md",
            "- OSCAL/ssp.json",
            "- Evidence/CI_CD",
            "- Evidence/Enterprise",
            "- Evidence/GitHub",
            "- Evidence/AWS",
            "- Evidence/Policies",
            "- POAM",
            "- Spreadsheets",
            "- manifest.json",
            "- fedramp_ato_package.zip",
            "",
            "## Controls Included",
            "",
        ]
        + [f"- {c.get('control_id', 'unknown')} ({c.get('origination', 'shared')})" for c in controls]
        + [
            "",
            "## Evidence Summary",
            f"- Code Scanning: {summary.get('results', {}).get('code_scanning', {}).get('count', 0)} alert(s)",
            f"- Dependabot: {summary.get('results', {}).get('dependabot', {}).get('count', 0)} alert(s)",
            f"- Secret Scanning: {summary.get('results', {}).get('secret_scanning', {}).get('count', 0)} alert(s)",
            "",
            "## Enterprise Organizations",
            "",
            f"- Inventory file: `Evidence/Enterprise/enterprise_organizations.json`",
            f"- Inventory count: `{org_count}`",
            "",
        ]
    )


def copy_source_files(output_dir: Path, controls_manifest: Path, enterprise_orgs_file: Path) -> None:
    source_files = [
        Path(".github/workflows/sa-04-10-enterprise-fedramp-evidence.yml"),
        Path("scripts/gh_sa_04_10_enterprise_collector.py"),
        Path("scripts/build_sa04_30_day_spreadsheets_enterprise.py"),
        Path("scripts/build_poam_from_findings.py"),
        Path("scripts/build_fedramp_submission_package_enterprise.py"),
        controls_manifest,
        enterprise_orgs_file,
    ]

    for src in source_files:
        if src.exists():
            dst = output_dir / "Evidence" / "CI_CD" / "source" / src.name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)


def copy_spreadsheets(spreadsheets_dir: Path, output_dir: Path) -> List[str]:
    copied: List[str] = []
    if not spreadsheets_dir.exists():
        return copied

    wanted = [
        "dependabot_30_day_log.xlsx",
        "codeql_30_day_log.xlsx",
        "security_30_day_log.xlsx",
        "enterprise_coverage.txt",
    ]
    for name in wanted:
        src = spreadsheets_dir / name
        if src.exists():
            dst = output_dir / "Spreadsheets" / name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            copied.append(name)

    for src in sorted(spreadsheets_dir.iterdir()):
        if src.is_file() and src.suffix.lower() in {".xlsx", ".zip", ".txt"} and src.name not in copied:
            dst = output_dir / "Spreadsheets" / src.name
            shutil.copy2(src, dst)
            copied.append(src.name)

    return copied


def copy_enterprise_org_inventory(org_inventory: Dict[str, Any], output_dir: Path) -> None:
    enterprise_dir = output_dir / "Evidence" / "Enterprise"
    enterprise_dir.mkdir(parents=True, exist_ok=True)

    orgs = org_inventory.get("organizations", []) or []
    write_json(enterprise_dir / "enterprise_organizations.json", org_inventory)

    csv_lines = [
        "slug,display_name,role,status,single_sign_on,two_factor_required"
    ]
    for org in orgs:
        csv_lines.append(
            ",".join(
                csv_quote(str(org.get(field, "")))
                for field in [
                    "slug",
                    "display_name",
                    "role",
                    "status",
                    "single_sign_on",
                    "two_factor_required",
                ]
            )
        )
    write_text(enterprise_dir / "enterprise_organizations.csv", "\n".join(csv_lines) + "\n")

    md_lines = [
        "# Enterprise Organization Inventory",
        "",
        f"- Inventory count: {len(orgs)}",
        "",
        "| Slug | Display Name | Role | Status | SSO | 2FA |",
        "|---|---|---|---|---:|---:|",
    ]
    for org in orgs:
        md_lines.append(
            f"| {org.get('slug', '')} | {org.get('display_name', '')} | {org.get('role', '')} | "
            f"{org.get('status', '')} | {str(bool(org.get('single_sign_on', False))).lower()} | "
            f"{str(bool(org.get('two_factor_required', False))).lower()} |"
        )
    write_text(enterprise_dir / "enterprise_organizations.md", "\n".join(md_lines) + "\n")


def zip_directory(source_dir: Path, zip_path: Path) -> None:
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(source_dir.rglob("*")):
            if path.is_dir():
                continue
            if path == zip_path:
                continue
            zf.write(path, arcname=str(path.relative_to(source_dir)))


def make_manifest(root: Path) -> Dict[str, Any]:
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


def main() -> int:
    args = parse_args()

    input_dir = Path(args.input_dir)
    spreadsheets_dir = Path(args.spreadsheets_dir)
    poam_dir = Path(args.poam_dir)
    controls_manifest = Path(args.controls_manifest)
    enterprise_orgs_file = Path(args.enterprise_orgs_file)
    output_dir = Path(args.output_dir)

    summary = read_json(input_dir / "summary.json")
    if not summary:
        raise SystemExit(f"summary.json not found in {input_dir}")

    controls_doc = load_controls_manifest(controls_manifest)
    controls = controls_doc.get("controls", [])
    if not isinstance(controls, list) or not controls:
        controls = default_controls_manifest()["controls"]

    org_inventory = load_enterprise_orgs(enterprise_orgs_file)

    clean_dir(output_dir)

    for folder in [
        output_dir / "SSP",
        output_dir / "OSCAL",
        output_dir / "Evidence" / "CI_CD",
        output_dir / "Evidence" / "CI_CD" / "source",
        output_dir / "Evidence" / "Enterprise",
        output_dir / "Evidence" / "GitHub",
        output_dir / "Evidence" / "AWS",
        output_dir / "Evidence" / "Policies",
        output_dir / "POAM",
        output_dir / "Spreadsheets",
    ]:
        folder.mkdir(parents=True, exist_ok=True)

    copy_tree(input_dir, output_dir / "Evidence" / "CI_CD")
    copy_tree(poam_dir, output_dir / "POAM")
    copied_spreadsheets = copy_spreadsheets(spreadsheets_dir, output_dir)
    copy_source_files(output_dir, controls_manifest, enterprise_orgs_file)
    copy_enterprise_org_inventory(org_inventory, output_dir)

    findings = read_json(input_dir / "blocking_findings.json", []) or []
    write_text(output_dir / "POAM" / "poam.csv", build_poam_csv(findings))

    run_context = repo_from_env_or_summary(summary)
    has_sarif = (output_dir / "Evidence" / "CI_CD" / "codeql_results" / "python.sarif").exists()

    if summary.get("scope") == "enterprise" and summary.get("repositories"):
        write_text(
            output_dir / "Evidence" / "CI_CD" / "enterprise_repositories.txt",
            "\n".join(summary.get("repositories", [])) + "\n",
        )

    if copied_spreadsheets:
        write_text(
            output_dir / "Evidence" / "CI_CD" / "spreadsheets_manifest.txt",
            "\n".join(copied_spreadsheets) + "\n",
        )

    write_text(output_dir / "SSP" / "sa-04-10-control-response.md", build_ssp_markdown(summary, controls, run_context))
    write_json(output_dir / "OSCAL" / "ssp.json", build_oscal_ssp(summary, controls, run_context, has_sarif))
    write_json(output_dir / "manifest.json", make_manifest(output_dir))
    write_text(output_dir / "README.md", build_readme(summary, controls, run_context, org_inventory))

    zip_directory(output_dir, output_dir / "fedramp_ato_package.zip")

    print(f"FedRAMP package built at {output_dir}")
    print(f"Archive created at {output_dir / 'fedramp_ato_package.zip'}")
    print(f"Copied spreadsheets: {', '.join(copied_spreadsheets) if copied_spreadsheets else 'none'}")
    print(f"Enterprise organizations captured: {len(org_inventory.get('organizations', []) or [])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
