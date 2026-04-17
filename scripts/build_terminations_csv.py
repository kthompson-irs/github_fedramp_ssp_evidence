#!/usr/bin/env python3
"""
Build data/terminations.csv from either:
- a source file (.csv, .json, .jsonl), or
- the TERMINATIONS_JSON environment variable containing a JSON array.

Expected row fields:
- employee_id
- github_identity
- termination_time_utc
- identity_model
- deadline_minutes
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

FIELDNAMES = [
    "employee_id",
    "github_identity",
    "termination_time_utc",
    "identity_model",
    "deadline_minutes",
]


def parse_utc_datetime(value: str) -> datetime:
    raw = value.strip()
    if not raw:
        raise ValueError("empty datetime value")
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def format_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def row_get(row: Dict[str, Any], *keys: str, default: str = "") -> str:
    for key in keys:
        value = row.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return default


def normalize_identity_model(value: str) -> str:
    v = (value or "").strip().lower()
    if v in {"emu", "managed", "managed_user", "managed-users", "manageduser"}:
        return "emu"
    return "personal"


def normalize_deadline_minutes(value: str, default: int) -> int:
    raw = (value or "").strip()
    if not raw:
        return default
    minutes = int(raw)
    if minutes <= 0:
        raise ValueError("deadline_minutes must be greater than 0")
    return minutes


def normalize_record(row: Dict[str, Any], default_deadline_minutes: int) -> Dict[str, str]:
    github_identity = row_get(row, "github_identity", "github_username", "github_user", "user", "login", "email")
    if not github_identity:
        raise ValueError("missing github_identity/github_username/user/login/email")

    termination_time_raw = row_get(row, "termination_time_utc", "terminated_at_utc", "termination_time")
    if not termination_time_raw:
        raise ValueError("missing termination_time_utc")

    employee_id = row_get(row, "employee_id", "id", default="")
    identity_model = normalize_identity_model(row_get(row, "identity_model", default="personal"))
    deadline_minutes = normalize_deadline_minutes(row_get(row, "deadline_minutes", default=""), default_deadline_minutes)

    return {
        "employee_id": employee_id,
        "github_identity": github_identity,
        "termination_time_utc": format_utc(parse_utc_datetime(termination_time_raw)),
        "identity_model": identity_model,
        "deadline_minutes": str(deadline_minutes),
    }


def load_rows(source: Optional[Path], json_env_var: str) -> List[Dict[str, Any]]:
    if source is None:
        raw = os.getenv(json_env_var, "").strip()
        if not raw:
            raise SystemExit(
                f"Provide --source <csv|json|jsonl> or set {json_env_var} to a JSON array of rows."
            )
        data = json.loads(raw)
        if not isinstance(data, list):
            raise SystemExit(f"{json_env_var} must be a JSON array")
        return [row for row in data if isinstance(row, dict)]

    if not source.exists():
        raise SystemExit(f"Source file not found: {source}")

    suffix = source.suffix.lower()

    if suffix == ".csv":
        with source.open(newline="", encoding="utf-8") as fh:
            return [dict(row) for row in csv.DictReader(fh)]

    if suffix == ".json":
        data = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise SystemExit(f"{source}: expected a JSON array")
        return [row for row in data if isinstance(row, dict)]

    if suffix == ".jsonl":
        rows: List[Dict[str, Any]] = []
        for line_no, line in enumerate(source.read_text(encoding="utf-8").splitlines(), start=1):
            text = line.strip()
            if not text:
                continue
            item = json.loads(text)
            if not isinstance(item, dict):
                raise SystemExit(f"{source}:{line_no}: expected a JSON object per line")
            rows.append(item)
        return rows

    raise SystemExit(f"Unsupported source type: {source.suffix}. Use .csv, .json, or .jsonl")


def write_csv(rows: List[Dict[str, str]], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build data/terminations.csv from source data or inline JSON.")
    parser.add_argument("--source", type=Path, default=None, help="Optional source file (.csv, .json, .jsonl).")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/terminations.csv"),
        help="Output CSV path.",
    )
    parser.add_argument(
        "--default-deadline-minutes",
        type=int,
        default=60,
        help="Default SLA when deadline_minutes is missing.",
    )
    parser.add_argument(
        "--json-env",
        default="TERMINATIONS_JSON",
        help="Environment variable containing a JSON array of rows.",
    )
    parser.add_argument("--allow-empty", action="store_true", help="Allow writing only the header row.")
    args = parser.parse_args()

    source_rows = load_rows(args.source, args.json_env)

    normalized_rows: List[Dict[str, str]] = []
    errors: List[str] = []

    for idx, row in enumerate(source_rows, start=1):
        try:
            normalized_rows.append(normalize_record(row, args.default_deadline_minutes))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"row {idx}: {exc}")

    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1

    if not normalized_rows and not args.allow_empty:
        print("ERROR: no termination rows found; refusing to write an empty file", file=sys.stderr)
        return 1

    write_csv(normalized_rows, args.output)
    print(f"Wrote {len(normalized_rows)} row(s) to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
