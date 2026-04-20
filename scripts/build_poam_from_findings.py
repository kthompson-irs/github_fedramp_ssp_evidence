#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side


DARK = "1F4E78"
LIGHT = "D9EAF7"
WHITE = "FFFFFF"
thin = Side(style="thin", color="D1D5DB")
border = Border(left=thin, right=thin, top=thin, bottom=thin)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build POA&M artifacts from blocking findings.")

    parser.add_argument("--input-dir", dest="input_dir", default=None)
    parser.add_argument("--output-dir", dest="output_dir", default=None)

    parser.add_argument("--input", dest="input_legacy", default=None)
    parser.add_argument("--output", dest="output_legacy", default=None)

    args = parser.parse_args()
    args.input_dir = args.input_dir or args.input_legacy or "artifacts/sa-04-10"
    args.output_dir = args.output_dir or args.output_legacy or "poam"
    return args


def read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def csv_quote(value: str) -> str:
    if any(ch in value for ch in [",", "\"", "\n"]):
        return '"' + value.replace('"', '""') + '"'
    return value


def due_date_for_severity(severity: str) -> str:
    sev = (severity or "").lower()
    if sev in {"high", "critical"}:
        return "30 days"
    if sev in {"moderate", "medium"}:
        return "90 days"
    return "120 days"


def build_rows(findings: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for idx, finding in enumerate(findings, start=1):
        severity = str(finding.get("severity", "")).strip()
        rows.append(
            {
                "poam_id": f"POAM-{idx:03d}",
                "category": str(finding.get("category", "")),
                "identifier": str(finding.get("identifier", "")),
                "title": str(finding.get("title", "")),
                "severity": severity,
                "source_url": str(finding.get("html_url", "")),
                "status": "open",
                "recommended_due_date": due_date_for_severity(severity),
                "remediation_owner": "TBD",
                "tracking_reference": "",
                "notes": "Auto-generated from blocking SA-04(10) findings",
                "generated_at": utc_now(),
            }
        )
    return rows


def write_csv(path: Path, rows: List[Dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "poam_id",
        "category",
        "identifier",
        "title",
        "severity",
        "source_url",
        "status",
        "recommended_due_date",
        "remediation_owner",
        "tracking_reference",
        "notes",
        "generated_at",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_workbook(path: Path, rows: List[Dict[str, str]], generated_at: str) -> None:
    wb = Workbook()
    ws = wb.active
    ws.title = "POA&M"
    ws.sheet_view.showGridLines = False
    ws.freeze_panes = "A4"

    ws.merge_cells("A1:L1")
    ws["A1"] = "SA-04(10) Auto-generated POA&M"
    ws["A1"].font = Font(color=WHITE, bold=True, size=14)
    ws["A1"].fill = PatternFill("solid", fgColor=DARK)
    ws["A1"].alignment = Alignment(horizontal="center")

    ws.merge_cells("A2:L2")
    ws["A2"] = f"Generated {generated_at}"
    ws["A2"].fill = PatternFill("solid", fgColor=LIGHT)
    ws["A2"].alignment = Alignment(horizontal="left")

    headers = [
        "POAM ID",
        "Category",
        "Identifier",
        "Title",
        "Severity",
        "Source URL",
        "Status",
        "Due Date",
        "Owner",
        "Tracking Ref",
        "Notes",
        "Generated At",
    ]
    for idx, header in enumerate(headers, start=1):
        cell = ws.cell(3, idx, header)
        cell.font = Font(color=WHITE, bold=True)
        cell.fill = PatternFill("solid", fgColor=DARK)
        cell.border = border
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)

    for r_idx, row in enumerate(rows, start=4):
        values = [
            row["poam_id"],
            row["category"],
            row["identifier"],
            row["title"],
            row["severity"],
            row["source_url"],
            row["status"],
            row["recommended_due_date"],
            row["remediation_owner"],
            row["tracking_reference"],
            row["notes"],
            row["generated_at"],
        ]
        for c_idx, value in enumerate(values, start=1):
            cell = ws.cell(r_idx, c_idx, value)
            cell.border = border
            cell.alignment = Alignment(horizontal="left" if c_idx in {2, 3, 4, 6, 10, 11} else "center", vertical="center", wrap_text=True)

    widths = [14, 16, 24, 34, 12, 44, 12, 12, 18, 18, 30, 24]
    for idx, width in enumerate(widths, start=1):
        ws.column_dimensions[chr(64 + idx)].width = width

    wb.save(path)


def write_markdown(path: Path, rows: List[Dict[str, str]], generated_at: str) -> None:
    lines = [
        "# SA-04(10) POA&M",
        "",
        f"- Generated at: {generated_at}",
        f"- Finding count: {len(rows)}",
        "",
        "| POAM ID | Category | Identifier | Severity | Due Date | Status |",
        "|---|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| {row['poam_id']} | {row['category']} | {row['identifier']} | {row['severity']} | {row['recommended_due_date']} | {row['status']} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)

    output_dir.mkdir(parents=True, exist_ok=True)

    findings = read_json(input_dir / "blocking_findings.json", [])
    if not isinstance(findings, list):
        raise SystemExit("blocking_findings.json is malformed or not a list")

    rows = build_rows(findings)
    generated_at = utc_now()

    write_csv(output_dir / "poam.csv", rows)
    write_workbook(output_dir / "poam.xlsx", rows, generated_at)
    write_markdown(output_dir / "poam.md", rows, generated_at)

    print(f"POA&M generated with {len(rows)} row(s) in {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
