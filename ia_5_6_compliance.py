#!/usr/bin/env python3
"""IA-5(6) enterprise compliance evidence collector for GitHub.com.

This script authenticates with a GitHub App at runtime.

Auth flow:
1. Read GitHub App credentials from environment or CLI:
   - GH_APP_ID
   - GH_APP_PRIVATE_KEY or GH_APP_PRIVATE_KEY_FILE
   - GH_APP_INSTALLATION_ID (optional)
2. Generate a short-lived JWT for the GitHub App.
3. Exchange the JWT for an installation access token.
4. Use the installation token for all API calls.

Scopes supported:
- repo: one repository
- org: one or more organizations
- enterprise: survey ALL orgs in the enterprise by default

Enterprise behavior:
- The script first attempts to enumerate all orgs from the enterprise slug.
- If the enterprise endpoint is inaccessible, it can fall back to an org inventory CSV.
- If neither is available, it exits with a clear error.

Outputs:
- JSON evidence
- CSV manifest
- PDF report

This script collects evidence for FedRAMP IA-5(6) and related supporting controls.
It does not certify compliance.
"""

from __future__ import annotations

import argparse
import base64
import csv
import dataclasses
import json
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
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

try:
    import jwt  # PyJWT
except Exception:
    jwt = None

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
except Exception as exc:  # pragma: no cover
    raise SystemExit(
        "cryptography is required to sign the GitHub App JWT. "
        "Install it with: python -m pip install cryptography pyjwt"
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
    status: str
    evidence: str
    details: Dict[str, Any]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_csv_list(value: str) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def load_org_inventory(path_value: str) -> List[str]:
    if not path_value:
        return []
    inventory_path = Path(path_value)
    if not inventory_path.exists():
        raise SystemExit(f"Org inventory file not found: {inventory_path}")

    orgs: List[str] = []
    with inventory_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if "org" not in reader.fieldnames and "login" not in reader.fieldnames:
            raise SystemExit("Org inventory CSV must contain an 'org' or 'login' column.")
        for row in reader:
            org_name = (row.get("org") or row.get("login") or "").strip()
            if org_name:
                orgs.append(org_name)
    return orgs


def read_private_key_pem(args: argparse.Namespace) -> bytes:
    if args.private_key_file:
        key_path = Path(args.private_key_file)
        if not key_path.exists():
            raise SystemExit(f"GitHub App private key file not found: {key_path}")
        pem_text = key_path.read_text(encoding="utf-8")
        return pem_text.strip().encode("utf-8")

    raw = args.private_key or os.getenv("GH_APP_PRIVATE_KEY") or ""
    pem_text = raw.strip().replace("\r", "")
    if not pem_text:
        raise SystemExit(
            "No GitHub App private key found. Set GH_APP_PRIVATE_KEY or GH_APP_PRIVATE_KEY_FILE."
        )
    return pem_text.encode("utf-8")


def get_app_id(args: argparse.Namespace) -> int:
    raw = str(args.app_id or os.getenv("GH_APP_ID") or "").strip()
    if not raw:
        raise SystemExit("No GitHub App ID found. Set GH_APP_ID or pass --app-id.")
    try:
        return int(raw)
    except ValueError as exc:
        raise SystemExit(f"Invalid GitHub App ID: {raw}") from exc


def get_installation_id_hint(args: argparse.Namespace) -> Optional[int]:
    raw = str(args.installation_id or os.getenv("GH_APP_INSTALLATION_ID") or "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError as exc:
        raise SystemExit(f"Invalid GitHub App installation ID: {raw}") from exc


def github_headers(token: str) -> Dict[str, str]:
    clean_token = (token or "").strip().replace("\r", "").replace("\n", "")
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "ia-5-6-enterprise-compliance/1.0",
    }
    if clean_token:
        headers["Authorization"] = f"Bearer {clean_token}"
    return headers


def api_get(path: str, token: str, params: Optional[Dict[str, Any]] = None) -> Tuple[int, Any]:
    url = f"{API_BASE}{path}"
    resp = requests.get(url, headers=github_headers(token), params=params, timeout=45)
    try:
        payload = resp.json()
    except Exception:
        payload = resp.text
    return resp.status_code, payload


def api_post(path: str, token: str, payload: Dict[str, Any]) -> Tuple[int, Any]:
    url = f"{API_BASE}{path}"
    resp = requests.post(url, headers=github_headers(token), json=payload, timeout=45)
    try:
        data = resp.json()
    except Exception:
        data = resp.text
    return resp.status_code, data


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


def build_app_jwt(app_id: int, private_key_pem: bytes) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "iat": int((now - timedelta(seconds=60)).timestamp()),
        "exp": int((now + timedelta(minutes=9)).timestamp()),
        "iss": str(app_id),
    }

    if jwt is not None:
        return jwt.encode(payload, private_key_pem, algorithm="RS256")

    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    header = {"alg": "RS256", "typ": "JWT"}

    def b64url(data: bytes) -> bytes:
        return base64.urlsafe_b64encode(data).rstrip(b"=")

    header_b64 = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = header_b64 + b"." + payload_b64
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return (signing_input + b"." + b64url(signature)).decode("utf-8")


def discover_installation_id(app_jwt: str, args: argparse.Namespace, target_account: Optional[str] = None) -> int:
    hint = get_installation_id_hint(args)
    if hint:
        return hint

    status, payload = api_get("/app/installations", app_jwt)
    if status != 200 or not isinstance(payload, list):
        raise SystemExit(f"Failed to list app installations: HTTP {status} {payload}")

    candidates: List[Tuple[int, Dict[str, Any]]] = []
    for inst in payload:
        if not isinstance(inst, dict):
            continue
        inst_id = inst.get("id")
        account = inst.get("account") or {}
        account_login = None
        account_id = None
        if isinstance(account, dict):
            account_login = account.get("login")
            account_id = account.get("id")
        if isinstance(inst_id, int):
            candidates.append((inst_id, inst))
        if target_account:
            if account_login == target_account:
                return inst_id
            if str(account_login or "").lower() == str(target_account).lower():
                return inst_id
            if str(inst.get("app_slug") or "").lower() == str(target_account).lower():
                return inst_id
            if str(account_id or "") == str(target_account):
                return inst_id

    if len(candidates) == 1:
        return candidates[0][0]

    raise SystemExit(
        "Unable to determine GitHub App installation ID automatically. "
        "Set GH_APP_INSTALLATION_ID or ensure the app is installed on the target enterprise/org."
    )


def get_installation_access_token(app_jwt: str, installation_id: int, repo: Optional[str] = None, owner: Optional[str] = None) -> str:
    body: Dict[str, Any] = {}
    if repo and owner:
        body["repositories"] = [repo]

    status, payload = api_post(f"/app/installations/{installation_id}/access_tokens", app_jwt, body)
    if status not in (200, 201) or not isinstance(payload, dict):
        raise SystemExit(f"Failed to create installation token: HTTP {status} {payload}")

    token = str(payload.get("token") or "").strip()
    if not token:
        raise SystemExit("Installation token response did not include a token.")
    return token


def resolve_api_token(args: argparse.Namespace) -> str:
    app_id = get_app_id(args)
    private_key_pem = read_private_key_pem(args)
    app_jwt = build_app_jwt(app_id, private_key_pem)
    target_account = args.enterprise_slug or (parse_csv_list(args.orgs)[0] if args.orgs else None)
    installation_id = discover_installation_id(app_jwt, args, target_account=target_account)
    owner = parse_csv_list(args.orgs)[0] if args.orgs else None
    return get_installation_access_token(app_jwt, installation_id, repo=args.repo or None, owner=owner)


def repo_default_branch(repo: Dict[str, Any], fallback: str) -> str:
    return repo.get("default_branch") or fallback or "main"


def fetch_repository(owner: str, repo: str, token: str) -> Dict[str, Any]:
    status, payload = api_get(f"/repos/{owner}/{repo}", token)
    if status == 404:
        raise SystemExit(
            f"Repository not found or inaccessible: {owner}/{repo}. "
            "Check the owner, repo name, and token permissions."
        )
    if status != 200 or not isinstance(payload, dict):
        raise SystemExit(f"Failed to load repository metadata for {owner}/{repo}: HTTP {status} {payload}")
    return payload


def fetch_org_repos(org: str, token: str) -> List[Dict[str, Any]]:
    return paginated_get(
        f"/orgs/{org}/repos",
        token,
        params={"type": "all", "sort": "full_name", "direction": "asc"},
    )


def fetch_org_metadata(org: str, token: str) -> Tuple[int, Any]:
    return api_get(f"/orgs/{org}", token)


def fetch_enterprise_orgs(slug: str, token: str) -> List[Dict[str, Any]]:
    status, payload = api_get(f"/enterprises/{slug}/orgs", token)
    if status != 200 or not isinstance(payload, list):
        return []
    return payload


def fetch_branch_protection(owner: str, repo: str, branch: str, token: str) -> Tuple[int, Any]:
    return api_get(f"/repos/{owner}/{repo}/branches/{branch}/protection", token)


def fetch_workflow_files(owner: str, repo: str, default_branch: str, token: str) -> List[Dict[str, Any]]:
    status, payload = api_get(
        f"/repos/{owner}/{repo}/contents/.github/workflows",
        token,
        params={"ref": default_branch},
    )
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
    return "token.actions.githubusercontent.com" in text or "id-token: write" in text


def scan_workflow_text_for_secrets(text: str) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    for rx, label in SUSPICIOUS_PATTERNS:
        for m in rx.finditer(text):
            snippet = text[max(0, m.start() - 60) : min(len(text), m.end() + 60)].replace("\n", " ")
            findings.append(
                {
                    "pattern": label,
                    "match": m.group(0)[:120],
                    "snippet": snippet[:240],
                }
            )
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
    results.append(
        CheckResult(
            scope=scope_label,
            owner=owner,
            repo=repo_name,
            control="AC/CM",
            item=f"Branch protection on {default_branch}",
            status="PASS" if bp_status == 200 else "WARN",
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


def collect_scope(
    scope: str,
    enterprise_slug: str,
    orgs: List[str],
    org_inventory: List[str],
    repo: str,
    branch: str,
    token: str,
) -> List[CheckResult]:
    results: List[CheckResult] = []

    if scope == "repo":
        if not orgs:
            raise SystemExit("For repo scope, pass --orgs with one owner/org value.")
        owner = orgs[0]
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
            raise SystemExit("For enterprise scope, pass --enterprise-slug.")

        enterprise_orgs = fetch_enterprise_orgs(enterprise_slug, token)
        if not enterprise_orgs:
            if not org_inventory:
                raise SystemExit(
                    f"Enterprise org listing unavailable for '{enterprise_slug}'. "
                    "Provide --org-inventory CSV or verify that the GitHub App is installed on the enterprise and has permission to read the enterprise org listing endpoint."
                )
            for org_name in org_inventory:
                results.append(
                    CheckResult(
                        scope="enterprise",
                        owner=org_name,
                        repo="*",
                        control="IA-2",
                        item="Org discovered via org inventory fallback",
                        status="WARN",
                        evidence="org inventory CSV",
                        details={"note": "Enterprise org listing was unavailable; using supplied org inventory."},
                    )
                )
                repos = fetch_org_repos(org_name, token)
                for r in repos:
                    if not isinstance(r, dict) or not r.get("name"):
                        continue
                    results.extend(collect_repo_evidence(org_name, r["name"], token, scope_label="enterprise", branch_override=branch))
            return results

        for org in enterprise_orgs:
            org_login = org.get("login") if isinstance(org, dict) else None
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
    if meta.get("org_inventory"):
        story.append(Paragraph(f"Org inventory fallback: {meta['org_inventory']}", normal))
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
    parser.add_argument("--org-inventory", default=os.getenv("ORG_INVENTORY", ""))
    parser.add_argument("--repo", default=os.getenv("REPO", ""))
    parser.add_argument("--branch", default=os.getenv("BRANCH", "main"))
    parser.add_argument("--output-dir", default="compliance-output")
    parser.add_argument("--app-id", default=os.getenv("GH_APP_ID", ""))
    parser.add_argument("--private-key", default=os.getenv("GH_APP_PRIVATE_KEY", ""))
    parser.add_argument("--private-key-file", default=os.getenv("GH_APP_PRIVATE_KEY_FILE", ""))
    parser.add_argument("--installation-id", default=os.getenv("GH_APP_INSTALLATION_ID", ""))
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    orgs = parse_csv_list(args.orgs)
    org_inventory = load_org_inventory(args.org_inventory) if args.org_inventory else []

    api_token = resolve_api_token(args)

    results = collect_scope(args.scope, args.enterprise_slug, orgs, org_inventory, args.repo, args.branch, api_token)

    meta = {
        "generated_at": utc_now(),
        "scope": args.scope,
        "enterprise_slug": args.enterprise_slug,
        "orgs": orgs,
        "org_inventory": args.org_inventory,
        "repo": args.repo,
        "branch": args.branch,
        "app_id": args.app_id,
        "installation_id": args.installation_id,
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
    if args.org_inventory:
        print(f"Org inventory: {args.org_inventory}")
    if orgs:
        print(f"Orgs: {', '.join(orgs)}")
    if args.repo:
        print(f"Repo filter: {args.repo}")
    print()
    summary = evidence["summary"]
    for status in ["PASS", "WARN", "FAIL", "NA", "ERROR"]:
        if summary.get(status):
            print(f"{status}: {summary[status]}")
    print()
    print(f"Wrote: {json_path}")
    print(f"Wrote: {csv_path}")
    print(f"Wrote: {pdf_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
