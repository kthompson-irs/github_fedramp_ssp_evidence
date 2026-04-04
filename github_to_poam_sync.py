#!/usr/bin/env python3
"""Collect GitHub security findings and render them into the official FedRAMP POA&M workbook.

The script auto-detects which GitHub endpoints are accessible, preferring:
1) enterprise code scanning alerts, if GH_ENTERPRISE_SLUG is set and accessible,
2) repository code scanning alerts when GH_REPO is set,
3) organization code scanning alerts as the final fallback.

It also optionally collects repository security advisories when GH_REPO is set.

Outputs:
- poam-output/poam_github.csv
- poam-output/poam_github.json
- poam-output/poam_summary.json
- poam-output/fedramp_poam_populated.xlsx

Environment variables:
- GH_TOKEN (required) or GITHUB_TOKEN
- GH_OWNER (required) or GITHUB_OWNER
- GH_REPO (optional) or GITHUB_REPO
- GH_ENTERPRISE_SLUG (optional)
- GH_API_URL (optional, default https://api.github.com)
- GH_API_VERSION (optional, default 2022-11-28)
- OUTPUT_DIR (optional, default poam-output)
- OUTPUT_CSV (optional)
- OUTPUT_JSON (optional)
- OUTPUT_SUMMARY (optional)
- OUTPUT_XLSX (optional)
- TEMPLATE_PATH (optional, path to a local FedRAMP POA&M template)
- FEDRAMP_TEMPLATE_URL (optional, default official FedRAMP template URL)
- POAM_CSP_NAME (optional, defaults to GH_OWNER)
- POAM_CSO_NAME (optional, defaults to GH_REPO or "GitHub Security Findings")
- POAM_IMPACT_LEVEL (optional, defaults to Moderate)
"""

from __future__ import annotations

import csv
import dataclasses
import datetime as dt
import json
import os
import re
import sys
from copy import copy
from dataclasses import asdict, dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urljoin

import requests
from openpyxl import load_workbook
from openpyxl.formula.translate import Translator


DEFAULT_API_URL = "https://api.github.com"
DEFAULT_API_VERSION = "2022-11-28"
DEFAULT_TEMPLATE_URL = "https://www.fedramp.gov/resources/templates/FedRAMP-POAM-Template.xlsx"
DEFAULT_OUTPUT_DIR = "poam-output"

GH_TOKEN = os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN")
GH_OWNER = os.getenv("GH_OWNER") or os.getenv("GITHUB_OWNER")
GH_REPO = os.getenv("GH_REPO") or os.getenv("GITHUB_REPO") or ""
GH_ENTERPRISE_SLUG = os.getenv("GH_ENTERPRISE_SLUG") or os.getenv("GITHUB_ENTERPRISE") or ""
GH_API_URL = os.getenv("GH_API_URL") or os.getenv("GITHUB_API_URL") or DEFAULT_API_URL
GH_API_VERSION = os.getenv("GH_API_VERSION") or os.getenv("GITHUB_API_VERSION") or DEFAULT_API_VERSION

OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", DEFAULT_OUTPUT_DIR))
OUTPUT_CSV = Path(os.getenv("OUTPUT_CSV", str(OUTPUT_DIR / "poam_github.csv")))
OUTPUT_JSON = Path(os.getenv("OUTPUT_JSON", str(OUTPUT_DIR / "poam_github.json")))
OUTPUT_SUMMARY = Path(os.getenv("OUTPUT_SUMMARY", str(OUTPUT_DIR / "poam_summary.json")))
OUTPUT_XLSX = Path(os.getenv("OUTPUT_XLSX", str(OUTPUT_DIR / "fedramp_poam_populated.xlsx")))

TEMPLATE_PATH = os.getenv("TEMPLATE_PATH", "").strip()
FEDRAMP_TEMPLATE_URL = os.getenv("FEDRAMP_TEMPLATE_URL", DEFAULT_TEMPLATE_URL)

POAM_CSP_NAME = os.getenv("POAM_CSP_NAME") or GH_OWNER or "GitHub"
POAM_CSO_NAME = os.getenv("POAM_CSO_NAME") or (GH_REPO if GH_REPO else "GitHub Security Findings")
POAM_IMPACT_LEVEL = os.getenv("POAM_IMPACT_LEVEL") or "Moderate"

if not GH_TOKEN or not GH_OWNER:
    sys.exit("GH_TOKEN and GH_OWNER are required.")


# FedRAMP workbook layout
OPEN_POAM_SHEET = "Open POA&M Items"
OPEN_POAM_FIRST_DATA_ROW = 10
OPEN_POAM_TEMPLATE_ROW = 10

COL = {
    "poam_id": 2,
    "controls": 3,
    "weakness_name": 4,
    "weakness_description": 5,
    "weakness_detector_source": 6,
    "weakness_source_identifier": 7,
    "asset_identifier": 8,
    "point_of_contact": 9,
    "resources_required": 10,
    "remediation_plan": 11,
    "original_detection_date": 12,
    "scheduled_completion_date": 13,  # formula in template
    "status_date": 14,
    "vendor_dependency": 15,
    "last_vendor_checkin_date": 16,
    "vendor_dependent_product_name": 17,
    "original_risk_rating": 18,
    "adjusted_risk_rating": 19,
    "risk_adjustment": 20,
    "false_positive": 21,
    "operational_requirement": 22,
    "deviation_rationale": 23,
    "supporting_documents": 24,
    "comments": 25,
    "bod_2201_tracking": 26,
    "bod_2201_due_date": 27,
    "cve": 28,
}


class GitHubAPIError(RuntimeError):
    pass


@dataclass
class PoamRow:
    poam_id: str
    controls: str
    weakness_name: str
    weakness_description: str
    weakness_detector_source: str
    weakness_source_identifier: str
    asset_identifier: str
    point_of_contact: str
    resources_required: str
    remediation_plan: str
    original_detection_date: str
    status_date: str
    vendor_dependency: str
    last_vendor_checkin_date: str
    vendor_dependent_product_name: str
    original_risk_rating: str
    adjusted_risk_rating: str
    risk_adjustment: str
    false_positive: str
    operational_requirement: str
    deviation_rationale: str
    supporting_documents: str
    comments: str
    bod_2201_tracking: str
    bod_2201_due_date: str
    cve: str
    source_url: str
    source_kind: str
    source_scope: str


@dataclass
class SourceResult:
    rows: List[Dict[str, Any]]
    source_errors: List[str]


def _today() -> str:
    return dt.datetime.now(dt.timezone.utc).date().isoformat()


def _today_dt() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _normalize_ts(value: Any) -> str:
    if not value:
        return _today()
    if isinstance(value, (int, float)):
        # GitHub timestamps are usually ISO 8601, but support epoch seconds just in case.
        if value > 10_000_000_000:
            value = value / 1000.0
        return dt.datetime.fromtimestamp(value, tz=dt.timezone.utc).date().isoformat()
    if isinstance(value, str):
        return value[:10] if len(value) >= 10 and value[4] == "-" else value
    return str(value)


def _normalize_risk(sev: str) -> str:
    s = (sev or "").strip().lower()
    if s in {"critical", "high"}:
        return "High"
    if s in {"medium", "moderate"}:
        return "Moderate"
    return "Low"


def _safe_text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    return json.dumps(value, ensure_ascii=False, default=str)


def _deep_find(value: Any, keys: Sequence[str]) -> Optional[Any]:
    if isinstance(value, dict):
        for key in keys:
            if key in value and value[key] not in (None, ""):
                return value[key]
        for nested in value.values():
            found = _deep_find(nested, keys)
            if found not in (None, ""):
                return found
    elif isinstance(value, list):
        for item in value:
            found = _deep_find(item, keys)
            if found not in (None, ""):
                return found
    return None


def _extract_repo_full_name(alert: Dict[str, Any], fallback_owner: str, fallback_repo: str = "") -> str:
    repo = alert.get("repository") or alert.get("repo") or {}
    if isinstance(repo, dict):
        for key in ("full_name", "name_with_owner", "name"):
            if repo.get(key):
                if key == "name" and repo.get("owner", {}).get("login"):
                    return f"{repo['owner']['login']}/{repo['name']}"
                return str(repo[key])
        owner = repo.get("owner") or {}
        if isinstance(owner, dict) and owner.get("login") and repo.get("name"):
            return f"{owner['login']}/{repo['name']}"
    if fallback_repo:
        return f"{fallback_owner}/{fallback_repo}"
    return fallback_owner


def _extract_alert_identifier(alert: Dict[str, Any]) -> str:
    for key in ("number", "id", "ghsa_id", "dismissed_at"):
        if alert.get(key) not in (None, ""):
            return str(alert[key])
    return "unknown"


def _extract_source_url(alert: Dict[str, Any]) -> str:
    for key in ("html_url", "url", "browser_url", "html", "web_url"):
        if alert.get(key):
            return str(alert[key])
    return ""


def _extract_cve(alert: Dict[str, Any]) -> str:
    for key in ("cve_id", "cve", "cve_ids", "cveId", "cve_ids"):
        found = _deep_find(alert, [key])
        if found:
            if isinstance(found, list):
                return ", ".join(str(x) for x in found)
            return str(found)
    # Search recursively for any string that looks like CVE-YYYY-NNNN...
    text = json.dumps(alert, ensure_ascii=False, default=str)
    matches = re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE)
    if matches:
        return ", ".join(sorted(set(m.upper() for m in matches)))
    return ""


class GitHubClient:
    def __init__(self, token: str, api_url: str = GH_API_URL, api_version: str = GH_API_VERSION):
        self.api_url = api_url.rstrip("/") + "/"
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": api_version,
                "User-Agent": "github-to-poam-sync/2.0",
            }
        )

    def request(self, method: str, path: str, params: Optional[Dict[str, Any]] = None) -> requests.Response:
        url = urljoin(self.api_url, path.lstrip("/"))
        resp = self.session.request(method, url, params=params, timeout=30)
        if resp.status_code >= 400:
            raise GitHubAPIError(f"{method} {resp.url} failed: {resp.status_code} {resp.text[:600]}")
        return resp

    def get_json(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        return self.request("GET", path, params=params).json()

    def paginate(self, path: str, params: Optional[Dict[str, Any]] = None) -> Iterable[Any]:
        url = urljoin(self.api_url, path.lstrip("/"))
        next_params = dict(params or {})
        next_params.setdefault("per_page", 100)
        next_url = url
        while next_url:
            resp = self.session.get(next_url, params=next_params, timeout=30)
            if resp.status_code >= 400:
                raise GitHubAPIError(f"GET {resp.url} failed: {resp.status_code} {resp.text[:600]}")
            data = resp.json()
            if isinstance(data, list):
                for item in data:
                    yield item
            else:
                yield data
            next_url = resp.links.get("next", {}).get("url")
            next_params = {}


def _probe_list(client: GitHubClient, path: str, params: Optional[Dict[str, Any]], label: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    try:
        return list(client.paginate(path, params=params)), None
    except GitHubAPIError as exc:
        msg = str(exc)
        # 403/404/500 are treated as inaccessible or temporarily unavailable and do not stop the run.
        if any(f" {code} " in msg for code in ("403", "404", "500")):
            return [], f"{label} unavailable: {msg}"
        raise


def _collect_enterprise_code_scanning(client: GitHubClient) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    if not GH_ENTERPRISE_SLUG:
        return [], None
    path = f"/enterprises/{GH_ENTERPRISE_SLUG}/code-scanning/alerts"
    return _probe_list(
        client,
        path,
        params={"state": "open", "per_page": 100},
        label=f"enterprise code scanning alerts ({GH_ENTERPRISE_SLUG})",
    )


def _collect_org_code_scanning(client: GitHubClient) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    path = f"/orgs/{GH_OWNER}/code-scanning/alerts"
    return _probe_list(
        client,
        path,
        params={"state": "open", "per_page": 100},
        label=f"organization code scanning alerts ({GH_OWNER})",
    )


def _collect_repo_code_scanning(client: GitHubClient) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    if not GH_REPO:
        return [], None
    path = f"/repos/{GH_OWNER}/{GH_REPO}/code-scanning/alerts"
    return _probe_list(
        client,
        path,
        params={"state": "open", "per_page": 100},
        label=f"repository code scanning alerts ({GH_OWNER}/{GH_REPO})",
    )


def _collect_repo_security_advisories(client: GitHubClient) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    if not GH_REPO:
        return [], None
    path = f"/repos/{GH_OWNER}/{GH_REPO}/security-advisories"
    return _probe_list(
        client,
        path,
        params={"state": "open", "per_page": 100},
        label=f"repository security advisories ({GH_OWNER}/{GH_REPO})",
    )


def _select_code_scanning_source(client: GitHubClient) -> Tuple[List[Dict[str, Any]], str, List[str]]:
    errors: List[str] = []

    enterprise_alerts, err = _collect_enterprise_code_scanning(client)
    if err:
        errors.append(err)
    elif GH_ENTERPRISE_SLUG:
        return enterprise_alerts, f"enterprise:{GH_ENTERPRISE_SLUG}", errors

    if GH_REPO:
        repo_alerts, err = _collect_repo_code_scanning(client)
        if err:
            errors.append(err)
        else:
            return repo_alerts, f"repo:{GH_OWNER}/{GH_REPO}", errors

    org_alerts, err = _collect_org_code_scanning(client)
    if err:
        errors.append(err)
    else:
        return org_alerts, f"org:{GH_OWNER}", errors

    return [], "none", errors


def _alert_to_poam(
    alert: Dict[str, Any],
    *,
    source_kind: str,
    source_scope: str,
    today: str,
) -> PoamRow:
    detector = "GitHub Code Scanning / CodeQL"
    if source_kind == "advisory":
        detector = "GitHub Repository Security Advisory"
    elif source_kind == "enterprise_alert":
        detector = "GitHub Enterprise Code Scanning"

    repo_name = _extract_repo_full_name(alert, GH_OWNER, GH_REPO)
    identifier = _extract_alert_identifier(alert)
    source_url = _extract_source_url(alert)
    risk = _normalize_risk(
        _safe_text(
            alert.get("rule", {}).get("security_severity_level")
            or alert.get("most_recent_instance", {}).get("severity")
            or alert.get("severity")
            or alert.get("risk_rating")
            or "Low"
        )
    )
    title = (
        alert.get("rule", {}).get("description")
        or alert.get("rule", {}).get("id")
        or alert.get("summary")
        or "GitHub security finding"
    )

    weakness_name = _safe_text(title)[:120]
    weakness_description = _safe_text(
        alert.get("rule", {}).get("description")
        or alert.get("description")
        or title
    )
    if source_url:
        weakness_description = f"{weakness_description} Source: {source_url}"

    controls = "RA-5, SI-2"
    if source_kind == "enterprise_alert":
        controls = "RA-5, SI-2"

    remediation = (
        "Review the GitHub security finding, determine the impacted code or dependency, "
        "remediate the weakness, and validate closure through follow-up scanning."
    )

    advisory_cve = _extract_cve(alert) if source_kind == "advisory" else ""

    return PoamRow(
        poam_id=f"GHA-{source_scope.replace(':', '-').replace('/', '-')}-{identifier}",
        controls=controls,
        weakness_name=weakness_name,
        weakness_description=weakness_description,
        weakness_detector_source=detector,
        weakness_source_identifier=identifier,
        asset_identifier=repo_name if repo_name else source_scope,
        point_of_contact="DevSecOps",
        resources_required="",
        remediation_plan=remediation,
        original_detection_date=_normalize_ts(
            alert.get("created_at")
            or alert.get("updated_at")
            or alert.get("first_detected_at")
            or today
        ),
        status_date=today,
        vendor_dependency="No",
        last_vendor_checkin_date="",
        vendor_dependent_product_name="",
        original_risk_rating=risk,
        adjusted_risk_rating="",
        risk_adjustment="No",
        false_positive="No",
        operational_requirement="",
        deviation_rationale="",
        supporting_documents=source_url,
        comments=f"Collected from {source_scope} on {today}",
        bod_2201_tracking="",
        bod_2201_due_date="",
        cve=advisory_cve,
        source_url=source_url,
        source_kind=source_kind,
        source_scope=source_scope,
    )


def collect_findings(client: GitHubClient) -> Tuple[List[PoamRow], List[str]]:
    today = _today()
    rows: List[PoamRow] = []
    source_errors: List[str] = []

    code_scanning_alerts, scope, errors = _select_code_scanning_source(client)
    source_errors.extend(errors)

    if scope.startswith("enterprise:"):
        source_kind = "enterprise_alert"
    elif scope.startswith("repo:") or scope.startswith("org:"):
        source_kind = "code_scanning"
    else:
        source_kind = "code_scanning"

    for alert in code_scanning_alerts:
        rows.append(_alert_to_poam(alert, source_kind=source_kind, source_scope=scope, today=today))

    repo_advisories, err = _collect_repo_security_advisories(client)
    if err:
        source_errors.append(err)
    for adv in repo_advisories:
        rows.append(_alert_to_poam(adv, source_kind="advisory", source_scope=f"repo:{GH_OWNER}/{GH_REPO}", today=today))

    # De-duplicate by POAM ID while preserving order.
    seen = set()
    deduped: List[PoamRow] = []
    for row in rows:
        if row.poam_id in seen:
            continue
        seen.add(row.poam_id)
        deduped.append(row)

    return deduped, source_errors


def _write_csv_json_summary(rows: List[PoamRow], source_errors: List[str]) -> Dict[str, Any]:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_SUMMARY.parent.mkdir(parents=True, exist_ok=True)

    fields = [field.name for field in dataclasses.fields(PoamRow) if field.name not in {"source_url", "source_kind", "source_scope"}]
    with OUTPUT_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            payload = asdict(row)
            payload.pop("source_url", None)
            payload.pop("source_kind", None)
            payload.pop("source_scope", None)
            writer.writerow(payload)

    with OUTPUT_JSON.open("w", encoding="utf-8") as f:
        json.dump([
            {k: v for k, v in asdict(row).items() if k not in {"source_url", "source_kind", "source_scope"}}
            for row in rows
        ], f, indent=2, sort_keys=True)

    summary = {
        "generated_at": _today_dt().isoformat(),
        "owner": GH_OWNER,
        "repo": GH_REPO,
        "enterprise_slug": GH_ENTERPRISE_SLUG,
        "output_dir": str(OUTPUT_DIR),
        "total_count": len(rows),
        "high_count": sum(1 for r in rows if r.original_risk_rating.lower() == "high"),
        "moderate_count": sum(1 for r in rows if r.original_risk_rating.lower() == "moderate"),
        "low_count": sum(1 for r in rows if r.original_risk_rating.lower() == "low"),
        "source_errors": source_errors,
        "high_rows": [
            {
                **{k: v for k, v in asdict(r).items() if k not in {"source_url", "source_kind", "source_scope"}},
                "source_url": r.source_url,
            }
            for r in rows
            if r.original_risk_rating.lower() == "high"
        ],
    }

    OUTPUT_SUMMARY.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return summary


def _download_template(dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    resp = requests.get(FEDRAMP_TEMPLATE_URL, timeout=60)
    if resp.status_code >= 400:
        raise RuntimeError(f"Failed to download FedRAMP template: {resp.status_code} {resp.text[:400]}")
    dest.write_bytes(resp.content)
    return dest


def _resolve_template_path() -> Path:
    if TEMPLATE_PATH:
        path = Path(TEMPLATE_PATH)
        if path.exists():
            return path
        return _download_template(path)
    default_path = OUTPUT_DIR / "FedRAMP-POAM-Template.xlsx"
    if default_path.exists():
        return default_path
    return _download_template(default_path)


def _copy_row_style_and_formulas(ws, src_row: int, dst_row: int, max_col: int) -> None:
    ws.row_dimensions[dst_row].height = ws.row_dimensions[src_row].height
    for col in range(1, max_col + 1):
        src = ws.cell(src_row, col)
        dst = ws.cell(dst_row, col)
        if src.has_style:
            dst._style = copy(src._style)
        if src.font:
            dst.font = copy(src.font)
        if src.fill:
            dst.fill = copy(src.fill)
        if src.border:
            dst.border = copy(src.border)
        if src.alignment:
            dst.alignment = copy(src.alignment)
        if src.number_format:
            dst.number_format = src.number_format
        if src.protection:
            dst.protection = copy(src.protection)
        if isinstance(src.value, str) and src.value.startswith("="):
            dst.value = Translator(src.value, origin=src.coordinate).translate_formula(dst.coordinate)


def _populate_workbook(rows: List[PoamRow], summary: Dict[str, Any]) -> Path:
    template_path = _resolve_template_path()
    wb = load_workbook(template_path)
    if OPEN_POAM_SHEET not in wb.sheetnames:
        raise RuntimeError(f"Workbook missing expected sheet: {OPEN_POAM_SHEET}")

    ws = wb[OPEN_POAM_SHEET]

    # Optional metadata cells at the top of the FedRAMP workbook.
    ws["B2"] = POAM_CSP_NAME
    ws["C2"] = POAM_CSO_NAME
    ws["D2"] = POAM_IMPACT_LEVEL
    ws["E2"] = _today()

    start_row = OPEN_POAM_FIRST_DATA_ROW
    max_col = 48

    for idx, row in enumerate(rows, start=start_row):
        if idx > ws.max_row:
            _copy_row_style_and_formulas(ws, OPEN_POAM_TEMPLATE_ROW, idx, max_col)

        values = asdict(row)
        # keep the workbook official columns only
        sheet_values = {
            COL["poam_id"]: values["poam_id"],
            COL["controls"]: values["controls"],
            COL["weakness_name"]: values["weakness_name"],
            COL["weakness_description"]: values["weakness_description"],
            COL["weakness_detector_source"]: values["weakness_detector_source"],
            COL["weakness_source_identifier"]: values["weakness_source_identifier"],
            COL["asset_identifier"]: values["asset_identifier"],
            COL["point_of_contact"]: values["point_of_contact"],
            COL["resources_required"]: values["resources_required"],
            COL["remediation_plan"]: values["remediation_plan"],
            COL["original_detection_date"]: values["original_detection_date"],
            COL["status_date"]: values["status_date"],
            COL["vendor_dependency"]: values["vendor_dependency"],
            COL["last_vendor_checkin_date"]: values["last_vendor_checkin_date"],
            COL["vendor_dependent_product_name"]: values["vendor_dependent_product_name"],
            COL["original_risk_rating"]: values["original_risk_rating"],
            COL["adjusted_risk_rating"]: values["adjusted_risk_rating"],
            COL["risk_adjustment"]: values["risk_adjustment"],
            COL["false_positive"]: values["false_positive"],
            COL["operational_requirement"]: values["operational_requirement"],
            COL["deviation_rationale"]: values["deviation_rationale"],
            COL["supporting_documents"]: values["supporting_documents"],
            COL["comments"]: values["comments"],
            COL["bod_2201_tracking"]: values["bod_2201_tracking"],
            COL["bod_2201_due_date"]: values["bod_2201_due_date"],
            COL["cve"]: values["cve"],
        }

        for col_num, value in sheet_values.items():
            ws.cell(idx, col_num).value = value

    # If the template already has a formula in the scheduled completion date column, the copied rows preserve it.
    # For existing rows with no copied formula, leave the template as-is.

    # Write an audit summary sheet with source errors for the operator.
    if "Generated Summary" not in wb.sheetnames:
        ws2 = wb.create_sheet("Generated Summary")
    else:
        ws2 = wb["Generated Summary"]
    ws2["A1"] = "FedRAMP POA&M Export Summary"
    ws2["A3"] = "Generated At"
    ws2["B3"] = summary["generated_at"]
    ws2["A4"] = "Owner"
    ws2["B4"] = summary["owner"]
    ws2["A5"] = "Repository"
    ws2["B5"] = summary["repo"] or ""
    ws2["A6"] = "Enterprise Slug"
    ws2["B6"] = summary["enterprise_slug"] or ""
    ws2["A7"] = "Total Findings"
    ws2["B7"] = summary["total_count"]
    ws2["A8"] = "High Findings"
    ws2["B8"] = summary["high_count"]
    ws2["A9"] = "Moderate Findings"
    ws2["B9"] = summary["moderate_count"]
    ws2["A10"] = "Low Findings"
    ws2["B10"] = summary["low_count"]
    ws2["A12"] = "Source Errors"
    for i, err in enumerate(summary["source_errors"], start=13):
        ws2.cell(i, 1).value = f"- {err}"

    wb.save(OUTPUT_XLSX)
    return OUTPUT_XLSX


def main() -> int:
    client = GitHubClient(GH_TOKEN)
    rows, source_errors = collect_findings(client)
    summary = _write_csv_json_summary(rows, source_errors)
    workbook_path = _populate_workbook(rows, summary)

    print(f"Wrote {len(rows)} POA&M rows")
    print(f"Workbook: {workbook_path}")
    if source_errors:
        print("Source errors detected:")
        for err in source_errors:
            print(f"- {err}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
