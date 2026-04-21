#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import requests


GH_API = "https://api.github.com"
TIMEOUT_SECONDS = 30


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the FedRAMP submission package.")

    parser.add_argument("--input-dir", dest="input_dir", default=None)
    parser.add_argument("--spreadsheets-dir", dest="spreadsheets_dir", default=None)
    parser.add_argument("--poam-dir", dest="poam_dir", default=None)
    parser.add_argument("--controls-manifest", dest="controls_manifest", default=None)
    parser.add_argument("--output-dir", dest="output_dir", default=None)

    parser.add_argument("--input", dest="input_legacy", default=None)
    parser.add_argument("--spreadsheets", dest="spreadsheets_legacy", default=None)
    parser.add_argument("--poam", dest="poam_legacy", default=None)
    parser.add_argument("--manifest", dest="manifest_legacy", default=None)
    parser.add_argument("--output", dest="output_legacy", default=None)

    args = parser.parse_args()

    args.input_dir = args.input_dir or args.input_legacy or "artifacts/sa-04-10"
    args.spreadsheets_dir = args.spreadsheets_dir or args.spreadsheets_legacy or "spreadsheets"
    args.poam_dir = args.poam_dir or args.poam_legacy or "poam"
    args.controls_manifest = args.controls_manifest or args.manifest_legacy or "controls_manifest.json"
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

    print(f"WARNING: {path} is missing or invalid. Using a default SA-04(10) controls manifest.")
    return default_controls_manifest()


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


def csv_rows_from_org_inventory(org_inventory: Dict[str, Any]) -> str:
    orgs = org_inventory.get("organizations", []) or []
    lines = [
        "slug,display_name,role,status,single_sign_on,two_factor_required,public_repo_count,public_repos,total_private_repos,html_url"
    ]
    for org in orgs:
        lines.append(
            ",".join(
                csv_quote(str(org.get(field, "")))
                for field in [
                    "slug",
                    "display_name",
                    "role",
                    "status",
                    "single_sign_on",
                    "two_factor_required",
                    "public_repo_count",
                    "public_repos",
                    "total_private_repos",
                    "html_url",
                ]
            )
        )
    return "\n".join(lines) + "\n"


def default_enterprise_slug(summary: Dict[str, Any]) -> str:
    return str(summary.get("enterprise") or os.getenv("GH_ENTERPRISE_SLUG") or "").strip()


def gh_token_candidates() -> List[Tuple[str, str]]:
    return [
        ("GH_ENTERPRISE_TOKEN", "enterprise_token"),
        ("GH_AUTH_TOKEN", "auth_fallback"),
        ("GH_DEPENDABOT_TOKEN", "dependabot_token_fallback"),
    ]


def auth_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
    }


def graphql_post(query: str, variables: Dict[str, Any], token: str) -> Dict[str, Any]:
    resp = requests.post(
        "https://api.github.com/graphql",
        headers={**auth_headers(token), "Content-Type": "application/json"},
        json={"query": query, "variables": variables},
        timeout=TIMEOUT_SECONDS,
    )
    resp.raise_for_status()
    payload = resp.json()
    if "errors" in payload:
        raise RuntimeError(json.dumps(payload["errors"], indent=2))
    return payload["data"]


def rest_get(url: str, token: str) -> Dict[str, Any]:
    resp = requests.get(url, headers=auth_headers(token), timeout=TIMEOUT_SECONDS)
    resp.raise_for_status()
    return resp.json()


def fetch_live_enterprise_org_inventory(enterprise_slug: str, token: str) -> Dict[str, Any]:
    query = """
    query($slug: String!, $after: String) {
      enterprise(slug: $slug) {
        name
        organizations(first: 100, after: $after) {
          nodes {
            name
          }
          pageInfo {
            hasNextPage
            endCursor
          }
        }
      }
    }
    """

    orgs: List[Dict[str, Any]] = []
    after: str | None = None
    enterprise_name = enterprise_slug

    while True:
        data = graphql_post(query, {"slug": enterprise_slug, "after": after}, token)
        enterprise = data.get("enterprise") or {}
        if not enterprise:
            raise RuntimeError(f"enterprise slug not found or inaccessible: {enterprise_slug}")
        enterprise_name = enterprise.get("name") or enterprise_name

        org_conn = enterprise.get("organizations") or {}
        nodes = org_conn.get("nodes") or []
        for node in nodes:
            name = str(node.get("name") or "").strip()
            if not name:
                continue

            item: Dict[str, Any] = {
                "slug": name,
                "display_name": name,
                "role": "Owner",
                "status": "active",
                "single_sign_on": None,
                "two_factor_required": None,
                "source": "graphql-enterprise",
            }

            try:
                org_detail = rest_get(f"{GH_API}/orgs/{name}", token)
                item["two_factor_required"] = org_detail.get("two_factor_requirement_enabled")
                item["public_repos"] = org_detail.get("public_repos")
                item["total_private_repos"] = org_detail.get("total_private_repos")
                item["public_repo_count"] = org_detail.get("public_repos")
                item["html_url"] = org_detail.get("html_url")
            except Exception as exc:
                item["detail_error"] = str(exc)

            orgs.append(item)

        page_info = org_conn.get("pageInfo") or {}
        if not page_info.get("hasNextPage"):
            break
        after = page_info.get("endCursor")

    return {
        "enterprise": enterprise_name,
        "generated_at": utc_now(),
        "organizations": orgs,
        "notes": [
            "Organizations were pulled live from the GitHub Enterprise Accounts GraphQL API.",
            "Where possible, organization REST details were used to augment the inventory with 2FA and repository counts.",
        ],
    }


def load_enterprise_org_inventory(summary: Dict[str, Any], input_dir: Path) -> Dict[str, Any]:
    enterprise_slug = default_enterprise_slug(summary)
    if enterprise_slug:
        last_error: Exception | None = None
        for env_name, _kind in gh_token_candidates():
            token = os.getenv(env_name)
            if not token:
                continue
            try:
                return fetch_live_enterprise_org_inventory(enterprise_slug, token)
            except Exception as exc:
                last_error = exc
                continue

        fallback = read_json(input_dir / "enterprise_organizations.json", default=None)
        if isinstance(fallback, dict) and fallback.get("organizations"):
            fallback["live_fetch_error"] = str(last_error) if last_error else "live fetch unavailable"
            return fallback

        raise SystemExit(f"Unable to fetch live enterprise org inventory: {last_error}")

    fallback = read_json(input_dir / "enterprise_organizations.json", default=None)
    if isinstance(fallback, dict) and fallback.get("organizations"):
        return fallback

    return {
        "enterprise": "unknown",
        "generated_at": utc_now(),
        "organizations": [],
        "notes": ["No live enterprise slug was available; inventory was not fetched."],
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


def build_ssp_markdown(summary: Dict[str, Any], controls: List[Dict[str, Any]], run_context: Dict[str, str], org_inventory: Dict[str, Any]) -> str:
    scope = summary.get("scope", "unknown")
    repo = summary.get("repository", "unknown")
    repo_count = summary.get("repository_count", 0)
    org_count = len(org_inventory.get("organizations", []) or [])

    lines = [
        "# Treasury Cloud SSP",
        "",
        f"- Generated: `{summary.get('generated_at', utc_now())}`",
        f"- Scope: `{scope}`",
        f"- Organization: `{summary.get('organization', '')}`",
        f"- Repository: `{repo}`",
        f"- Repository count: `{repo_count}`",
        f"- Enterprise organizations captured: `{org_count}`",
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
                f"- Organizations in inventory: `{org_count}`",
                "",
            ]
        )
    return "\n".join(lines)


def make_manifest(root: Path) -> Dict[str, Any]:
    files: List[Dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            continue
        if path.name in {"fedramp_ato_package.zip", "sa04-10-fedramp-enterprise-package.zip"}:
            continue
        files.append(
            {
                "path": str(path.relative_to(root)),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return {"generated_at": utc_now(), "file_count": len(files), "files": files}


def build_readme(summary: Dict[str, Any], controls: List[Dict[str, Any]], run_context: Dict[str, str], org_inventory: Dict[str, Any]) -> str:
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
            f"Repository: {summary.get('repository', 'unknown')}",
            f"Organization: {summary.get('organization', '')}",
            f"Scope: {summary.get('scope', 'unknown')}",
            f"Repository count: {summary.get('repository_count', 0)}",
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
            "- sa04-10-fedramp-enterprise-package.zip",
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


def copy_source_files(output_dir: Path, controls_manifest: Path) -> None:
    source_files = [
        Path(".github/workflows/sa-04-10-enterprise-fedramp-evidence.yml"),
        Path("scripts/gh_sa_04_10_enterprise_collector.py"),
        Path("scripts/build_sa04_30_day_spreadsheets_enterprise.py"),
        Path("scripts/build_poam_from_findings.py"),
        Path("scripts/build_fedramp_submission_package_enterprise.py"),
        controls_manifest,
        Path("enterprise_organizations.json"),
    ]
    for src in source_files:
        if src.exists():
            dst = output_dir / "Evidence" / "CI_CD" / "source" / src.name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)


def write_enterprise_inventory(org_inventory: Dict[str, Any], output_dir: Path) -> None:
    enterprise_dir = output_dir / "Evidence" / "Enterprise"
    enterprise_dir.mkdir(parents=True, exist_ok=True)

    write_json(enterprise_dir / "enterprise_organizations.json", org_inventory)

    orgs = org_inventory.get("organizations", []) or []
    csv_text = csv_rows_from_org_inventory(org_inventory)
    write_text(enterprise_dir / "enterprise_organizations.csv", csv_text)

    md_lines = [
        "# Enterprise Organization Inventory",
        "",
        f"- Inventory count: {len(orgs)}",
        "",
        "| Slug | Display Name | Role | Status | 2FA | Public Repos | Private Repos |",
        "|---|---|---|---|---:|---:|---:|",
    ]
    for org in orgs:
        md_lines.append(
            f"| {org.get('slug', '')} | {org.get('display_name', '')} | {org.get('role', '')} | "
            f"{org.get('status', '')} | {str(bool(org.get('two_factor_required', False))).lower()} | "
            f"{org.get('public_repos', org.get('public_repo_count', ''))} | {org.get('total_private_repos', '')} |"
        )
    write_text(enterprise_dir / "enterprise_organizations.md", "\n".join(md_lines) + "\n")

    write_json(output_dir / "enterprise_organizations.json", org_inventory)
    write_text(output_dir / "enterprise_organizations.csv", csv_text)
    write_text(output_dir / "enterprise_organizations.md", "\n".join(md_lines) + "\n")


def copy_tree_if_exists(src: Path, dst: Path) -> None:
    if src.exists():
        shutil.copytree(src, dst, dirs_exist_ok=True)


def copy_spreadsheets(spreadsheets_dir: Path, output_dir: Path) -> List[str]:
    copied: List[str] = []
    if not spreadsheets_dir.exists():
        return copied

    for src in sorted(spreadsheets_dir.iterdir()):
        if src.is_file() and src.suffix.lower() in {".xlsx", ".zip", ".txt"}:
            dst = output_dir / "Spreadsheets" / src.name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            copied.append(src.name)
    return copied


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
    spreadsheets_dir = Path(args.spreadsheets_dir)
    poam_dir = Path(args.poam_dir)
    controls_manifest = Path(args.controls_manifest)
    output_dir = Path(args.output_dir)

    summary = read_json(input_dir / "summary.json")
    if not summary:
        raise SystemExit(f"summary.json not found in {input_dir}")

    controls_doc = load_controls_manifest(controls_manifest)
    controls = controls_doc.get("controls", [])
    if not isinstance(controls, list) or not controls:
        controls = default_controls_manifest()["controls"]

    org_inventory = load_enterprise_org_inventory(summary, input_dir)

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

    copy_tree_if_exists(input_dir, output_dir / "Evidence" / "CI_CD")
    copy_tree_if_exists(poam_dir, output_dir / "POAM")
    copied_spreadsheets = copy_spreadsheets(spreadsheets_dir, output_dir)
    copy_source_files(output_dir, controls_manifest)
    write_enterprise_inventory(org_inventory, output_dir)

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
        write_text(output_dir / "Evidence" / "CI_CD" / "spreadsheets_manifest.txt", "\n".join(copied_spreadsheets) + "\n")

    write_text(
        output_dir / "SSP" / "sa-04-10-control-response.md",
        build_ssp_markdown(summary, controls, run_context, org_inventory),
    )
    write_json(output_dir / "OSCAL" / "ssp.json", build_oscal_ssp(summary, controls, run_context, has_sarif))
    write_json(output_dir / "manifest.json", make_manifest(output_dir))
    write_text(output_dir / "README.md", build_readme(summary, controls, run_context, org_inventory))

    zip_path = output_dir / "sa04-10-fedramp-enterprise-package.zip"
    zip_directory(output_dir, zip_path)

    print(f"FedRAMP package built at {output_dir}")
    print(f"Archive created at {zip_path}")
    print(f"Copied spreadsheets: {', '.join(copied_spreadsheets) if copied_spreadsheets else 'none'}")
    print(f"Enterprise organizations captured: {len(org_inventory.get('organizations', []) or [])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
