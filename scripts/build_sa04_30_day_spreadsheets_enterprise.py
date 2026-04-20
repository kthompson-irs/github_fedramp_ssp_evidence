#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.worksheet.table import Table, TableStyleInfo

DARK = "1F4E78"
LIGHT = "D9EAF7"
GREEN = "E8F5E9"
AMBER = "FFF4D6"
RED = "FDE8E8"
WHITE = "FFFFFF"
thin = Side(style="thin", color="D1D5DB")
border = Border(left=thin, right=thin, top=thin, bottom=thin)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build enterprise SA-04(10) 30-day spreadsheets.")
    parser.add_argument("--input-dir", dest="input_dir", default=None)
    parser.add_argument("--output-dir", dest="output_dir", default=None)
    parser.add_argument("--input", dest="input_legacy", default=None)
    parser.add_argument("--output", dest="output_legacy", default=None)
    args = parser.parse_args()
    args.input_dir = args.input_dir or args.input_legacy or "artifacts/sa-04-10"
    args.output_dir = args.output_dir or args.output_legacy or "spreadsheets"
    return args


def read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def safe_date(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date().isoformat()
    except Exception:
        return None


def read_history(input_dir: Path) -> List[Dict[str, Any]]:
    history_dir = input_dir / "history"
    records: List[Dict[str, Any]] = []

    history_jsonl = history_dir / "history.jsonl"
    if history_jsonl.exists():
        for line in history_jsonl.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                records.append(obj)

    if not records:
        current = read_json(input_dir / "current_snapshot.json")
        if isinstance(current, dict) and current:
            records.append(current)
        else:
            summary = read_json(input_dir / "summary.json")
            if isinstance(summary, dict) and summary:
                records.append(summary)

    dedup: Dict[str, Dict[str, Any]] = {}
    for rec in records:
        day = rec.get("date") or safe_date(rec.get("generated_at"))
        if day:
            dedup[day] = rec

    return [dedup[k] for k in sorted(dedup.keys())]


def last_30_days(history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return history[-30:] if len(history) > 30 else history


def severity_rank(value: Optional[str]) -> int:
    return {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "moderate": 2,
        "low": 1,
    }.get((value or "").lower(), 0)


def normalize_severity(value: Optional[str], category: str = "") -> str:
    if not value:
        if category == "secret_scanning":
            return "high"
        return "unknown"
    return str(value).strip().lower()


def entries_from_snapshot(snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    results = snapshot.get("results", {}) or {}
    date = snapshot.get("date") or safe_date(snapshot.get("generated_at")) or ""
    scope = snapshot.get("scope") or ""
    repository = snapshot.get("repository") or ""
    generated_at = snapshot.get("generated_at") or ""

    for alert in (results.get("code_scanning", {}) or {}).get("alerts", []) or []:
        rule = alert.get("rule") or {}
        severity = normalize_severity(rule.get("severity"), "code_scanning")
        location = (alert.get("most_recent_instance") or {}).get("location") or {}
        entries.append({
            "date": date,
            "scope": scope,
            "repository": repository,
            "category": "CodeQL",
            "severity": severity,
            "severity_rank": severity_rank(severity),
            "status": str(alert.get("state") or "open"),
            "identifier": rule.get("id") or "unknown-rule",
            "title": rule.get("name") or "unknown-title",
            "source_url": alert.get("html_url") or "",
            "path": location.get("path") or "",
            "manifest": "",
            "evidence_ref": generated_at,
            "notes": "Historical CodeQL alert",
            "source": "code_scanning",
        })

    for alert in (results.get("dependabot", {}) or {}).get("alerts", []) or []:
        advisory = alert.get("security_advisory") or {}
        severity = normalize_severity(advisory.get("severity"), "dependabot")
        dependency = (((alert.get("dependency") or {}).get("package") or {}).get("name")) or "unknown-package"
        entries.append({
            "date": date,
            "scope": scope,
            "repository": repository,
            "category": "Dependabot",
            "severity": severity,
            "severity_rank": severity_rank(severity),
            "status": str(alert.get("state") or "open"),
            "identifier": advisory.get("ghsa_id") or advisory.get("cve_id") or "unknown-advisory",
            "title": advisory.get("summary") or "unknown-advisory",
            "source_url": alert.get("html_url") or "",
            "path": dependency,
            "manifest": (((alert.get("dependency") or {}).get("manifest_path")) or ""),
            "evidence_ref": generated_at,
            "notes": "Historical Dependabot alert",
            "source": "dependabot",
        })

    for alert in (results.get("secret_scanning", {}) or {}).get("alerts", []) or []:
        severity = normalize_severity("high" if str(alert.get("state") or "").lower() == "open" else "low", "secret_scanning")
        entries.append({
            "date": date,
            "scope": scope,
            "repository": repository,
            "category": "Secret Scanning",
            "severity": severity,
            "severity_rank": severity_rank(severity),
            "status": str(alert.get("state") or "open"),
            "identifier": alert.get("secret_type") or alert.get("secret_type_display_name") or "unknown-secret",
            "title": alert.get("secret_type_display_name") or alert.get("secret_type") or "unknown-secret",
            "source_url": alert.get("html_url") or "",
            "path": "",
            "manifest": "",
            "evidence_ref": generated_at,
            "notes": "Historical secret scanning alert",
            "source": "secret_scanning",
        })

    return entries


def sort_entries(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # Highest severity first, then most recent date, then category, then identifier.
    return sorted(
        entries,
        key=lambda e: (
            -int(e.get("severity_rank", 0)),
            str(e.get("date", "")),
            str(e.get("category", "")),
            str(e.get("identifier", "")),
        ),
        reverse=False,
    )


def write_header_and_table(
    ws,
    title: str,
    subtitle: str,
    headers: List[str],
    rows: List[List[Any]],
    table_name: str,
    widths: List[int],
) -> None:
    cols = len(headers)
    end_col = chr(64 + cols)

    ws.sheet_view.showGridLines = False
    ws.freeze_panes = "A4"

    ws.merge_cells(start_row=1, start_column=1, end_row=1, end_column=cols)
    ws["A1"] = title
    ws["A1"].font = Font(color=WHITE, bold=True, size=14)
    ws["A1"].fill = PatternFill("solid", fgColor=DARK)
    ws["A1"].alignment = Alignment(horizontal="center", vertical="center")

    ws.merge_cells(start_row=2, start_column=1, end_row=2, end_column=cols)
    ws["A2"] = subtitle
    ws["A2"].fill = PatternFill("solid", fgColor=LIGHT)
    ws["A2"].alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)

    for idx, header in enumerate(headers, 1):
        c = ws.cell(3, idx, header)
        c.font = Font(color=WHITE, bold=True)
        c.fill = PatternFill("solid", fgColor=DARK)
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        c.border = border

    for r_idx, row in enumerate(rows, 4):
        for c_idx, value in enumerate(row, 1):
            c = ws.cell(r_idx, c_idx, value)
            c.border = border
            c.alignment = Alignment(
                horizontal="left" if c_idx in {3, 8, 9, 10, 11, 12, 13} else "center",
                vertical="center",
                wrap_text=True,
            )
            if c_idx == 1 and value:
                c.number_format = "yyyy-mm-dd"
            if c_idx == 5:
                sev = str(value).lower()
                if sev in {"critical", "high"}:
                    c.fill = PatternFill("solid", fgColor=RED)
                elif sev in {"medium", "moderate"}:
                    c.fill = PatternFill("solid", fgColor=AMBER)
                elif sev == "low":
                    c.fill = PatternFill("solid", fgColor=GREEN)

    if rows:
        ref = f"A3:{end_col}{len(rows) + 3}"
        table = Table(displayName=table_name, ref=ref)
        table.tableStyleInfo = TableStyleInfo(
            name="TableStyleMedium2",
            showFirstColumn=False,
            showLastColumn=False,
            showRowStripes=True,
            showColumnStripes=False,
        )
        ws.add_table(table)

    for idx, width in enumerate(widths, 1):
        ws.column_dimensions[chr(64 + idx)].width = width


def write_summary_sheet(ws, title: str, rows: List[List[Any]]) -> None:
    ws.sheet_view.showGridLines = False
    ws.merge_cells("A1:B1")
    ws["A1"] = title
    ws["A1"].font = Font(color=WHITE, bold=True, size=13)
    ws["A1"].fill = PatternFill("solid", fgColor=DARK)
    ws["A1"].alignment = Alignment(horizontal="center")

    for i, (k, v) in enumerate(rows, 3):
        ws.cell(i, 1, k).font = Font(bold=True)
        ws.cell(i, 1).fill = PatternFill("solid", fgColor=LIGHT)
        ws.cell(i, 1).border = border
        ws.cell(i, 2, v).border = border
        ws.cell(i, 2).alignment = Alignment(wrap_text=True)

    ws.column_dimensions["A"].width = 30
    ws.column_dimensions["B"].width = 95


def build_workbook(
    path: Path,
    title: str,
    rows: List[List[Any]],
    summary_rows: List[List[Any]],
    notes: List[str],
    table_name: str,
    widths: List[int],
) -> None:
    wb = Workbook()
    ws = wb.active
    ws.title = "30-Day Log"

    headers = ["Date", "Scope", "Repository", "Category", "Severity", "Status", "Identifier", "Title", "Source URL", "Path", "Manifest", "Evidence Ref", "Notes"]
    write_header_and_table(
        ws,
        title=title,
        subtitle="Real historical alert entries aggregated from artifacts/sa-04-10/history. No placeholder rows are inserted.",
        headers=headers,
        rows=rows,
        table_name=table_name,
        widths=widths,
    )

    summary = wb.create_sheet("Snapshot Summary")
    write_summary_sheet(summary, f"{title} Summary", summary_rows)

    readme = wb.create_sheet("Read Me")
    readme.sheet_view.showGridLines = False
    readme.merge_cells("A1:B1")
    readme["A1"] = f"{title} — Audit Notes"
    readme["A1"].font = Font(color=WHITE, bold=True, size=13)
    readme["A1"].fill = PatternFill("solid", fgColor=DARK)

    for i, note in enumerate(notes, 3):
        readme.cell(i, 1, f"Note {i-2}").font = Font(bold=True)
        readme.cell(i, 1).fill = PatternFill("solid", fgColor=LIGHT)
        readme.cell(i, 1).border = border
        readme.cell(i, 2, note).border = border
        readme.cell(i, 2).alignment = Alignment(wrap_text=True)

    readme.column_dimensions["A"].width = 18
    readme.column_dimensions["B"].width = 95

    wb.save(path)


def main() -> int:
    args = parse_args()
    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    history = last_30_days(read_history(input_dir))
    if not history:
        raise SystemExit("No historical snapshots found in artifacts/sa-04-10")

    entries = sort_entries(entries_from_snapshot(history[0]))
    for snap in history[1:]:
        entries.extend(entries_from_snapshot(snap))
    entries = sort_entries(entries)

    if not entries:
        print("No alert entries found in the 30-day history. Workbooks will be created empty with summaries.")

    dependabot_rows = [
        [e["date"], e["scope"], e["repository"], e["category"], e["severity"], e["status"], e["identifier"], e["title"], e["source_url"], e["path"], e["manifest"], e["evidence_ref"], e["notes"]]
        for e in entries if e["source"] == "dependabot"
    ]
    codeql_rows = [
        [e["date"], e["scope"], e["repository"], e["category"], e["severity"], e["status"], e["identifier"], e["title"], e["source_url"], e["path"], e["manifest"], e["evidence_ref"], e["notes"]]
        for e in entries if e["source"] == "code_scanning"
    ]
    security_rows = [
        [e["date"], e["scope"], e["repository"], e["category"], e["severity"], e["status"], e["identifier"], e["title"], e["source_url"], e["path"], e["manifest"], e["evidence_ref"], e["notes"]]
        for e in entries
    ]

    latest = history[-1]
    results = latest.get("results", {}) or {}

    build_workbook(
        path=output_dir / "dependabot_30_day_log.xlsx",
        title="Dependabot 30-Day Log",
        rows=dependabot_rows,
        summary_rows=[
            ["Generated At", latest.get("generated_at", "")],
            ["Scope", latest.get("scope", "")],
            ["Repository", latest.get("repository", "")],
            ["Entry Count", len(dependabot_rows)],
            ["Blocking Findings", (results.get("dependabot", {}) or {}).get("blocking_count", 0)],
            ["Status", (latest.get("overall", {}) or {}).get("status", "").title()],
        ],
        notes=[
            "This workbook lists real Dependabot alert entries from the last 30 days.",
            "Rows are sorted by severity first, then by date.",
            "No placeholder rows are inserted.",
        ],
        table_name="dependabot_30_day_log",
        widths=[12, 16, 42, 16, 12, 12, 24, 34, 44, 30, 24, 24, 30],
    )

    build_workbook(
        path=output_dir / "codeql_30_day_log.xlsx",
        title="CodeQL 30-Day Log",
        rows=codeql_rows,
        summary_rows=[
            ["Generated At", latest.get("generated_at", "")],
            ["Scope", latest.get("scope", "")],
            ["Repository", latest.get("repository", "")],
            ["Entry Count", len(codeql_rows)],
            ["Blocking Findings", (results.get("code_scanning", {}) or {}).get("blocking_count", 0)],
            ["Status", (latest.get("overall", {}) or {}).get("status", "").title()],
        ],
        notes=[
            "This workbook lists real CodeQL alert entries from the last 30 days.",
            "Rows are sorted by severity first, then by date.",
            "Evidence references point back to the originating snapshot.",
        ],
        table_name="codeql_30_day_log",
        widths=[12, 16, 42, 16, 12, 12, 24, 34, 44, 30, 24, 24, 30],
    )

    build_workbook(
        path=output_dir / "security_30_day_log.xlsx",
        title="Security 30-Day Log",
        rows=security_rows,
        summary_rows=[
            ["Generated At", latest.get("generated_at", "")],
            ["Scope", latest.get("scope", "")],
            ["Repository", latest.get("repository", "")],
            ["Entry Count", len(security_rows)],
            ["Blocking Findings", (latest.get("overall", {}) or {}).get("blocking_count", 0)],
            ["Collection Errors", (latest.get("overall", {}) or {}).get("error_count", 0)],
            ["Status", (latest.get("overall", {}) or {}).get("status", "").title()],
        ],
        notes=[
            "This workbook combines CodeQL, Dependabot, and Secret Scanning entries from the last 30 days.",
            "Entries are sorted by severity first, then by date.",
            "Use this workbook as the aggregate enterprise security evidence log.",
        ],
        table_name="security_30_day_log",
        widths=[12, 16, 42, 16, 12, 12, 24, 34, 44, 30, 24, 24, 30],
    )

    print(f"Spreadsheets generated in {output_dir}")
    print(f"Dependabot rows: {len(dependabot_rows)}")
    print(f"CodeQL rows: {len(codeql_rows)}")
    print(f"Security rows: {len(security_rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
