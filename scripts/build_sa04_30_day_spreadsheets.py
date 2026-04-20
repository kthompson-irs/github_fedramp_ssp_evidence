#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

from openpyxl import Workbook


# ----------------------------
# ARGUMENT HANDLING (FIXED)
# ----------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build SA-04(10) 30-day spreadsheets")

    # NEW (preferred)
    parser.add_argument("--input-dir", dest="input_dir", default=None)
    parser.add_argument("--output-dir", dest="output_dir", default=None)

    # OLD (backward compatibility)
    parser.add_argument("--input", dest="input_legacy", default=None)
    parser.add_argument("--output", dest="output_legacy", default=None)

    args = parser.parse_args()

    # Resolve final values
    args.input_dir = args.input_dir or args.input_legacy or "artifacts/sa-04-10"
    args.output_dir = args.output_dir or args.output_legacy or "spreadsheets"

    return args


# ----------------------------
# UTIL
# ----------------------------
def read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


# ----------------------------
# BUILD WORKBOOK
# ----------------------------
def build_workbook(path: Path, title: str, count: int):
    wb = Workbook()
    ws = wb.active
    ws.title = "30-Day Log"

    ws.append(["Date", "Count"])

    today = datetime.utcnow().date()

    for i in range(30):
        ws.append([str(today), count if i == 0 else ""])

    wb.save(path)


# ----------------------------
# MAIN
# ----------------------------
def main() -> int:
    args = parse_args()

    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)

    print(f"[INFO] Input dir: {input_dir}")
    print(f"[INFO] Output dir: {output_dir}")

    summary = read_json(input_dir / "summary.json", {})

    if not summary:
        raise SystemExit("summary.json not found or empty")

    results = summary.get("results", {})

    # clean output
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # build files
    build_workbook(
        output_dir / "dependabot_30_day_log.xlsx",
        "Dependabot",
        results.get("dependabot", {}).get("count", 0),
    )

    build_workbook(
        output_dir / "security_30_day_log.xlsx",
        "Security",
        summary.get("overall", {}).get("blocking_count", 0),
    )

    build_workbook(
        output_dir / "codeql_30_day_log.xlsx",
        "CodeQL",
        results.get("code_scanning", {}).get("count", 0),
    )

    print("[SUCCESS] Spreadsheets generated")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
