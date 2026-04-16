#!/usr/bin/env python3
"""
Enterprise IA-2(8) SSP Report Generator
"""

import json, argparse
from pathlib import Path

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--run-dir", required=True)
    args = p.parse_args()

    run = Path(args.run_dir)
    summary = json.loads((run / "summary.json").read_text())

    report = f"""
# IA-2(8) Enterprise Audit Log Evidence

Enterprise: {summary['enterprise']}
Events Collected: {summary['count']}
Collected At: {summary['collected']}

## Description
Enterprise audit log evidence demonstrating authentication and activity monitoring.

## Evidence
- enterprise_audit_log.jsonl
- summary.json
"""

    out = Path("artifacts")
    out.mkdir(exist_ok=True)

    (out / "ia_enterprise_report.md").write_text(report.strip())

if __name__ == "__main__":
    main()
