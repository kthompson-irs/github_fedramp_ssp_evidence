#!/usr/bin/env python3
"""
Generate an SSP-style evidence summary for GitHub Enterprise Cloud enterprise audit-log collection.

This report is intentionally enterprise-focused:
- uses "enterprise audit log" terminology throughout
- avoids org-scoped language unless explicitly referring to supporting artifacts
- reads the output of github_enterprise_ia208_collector.py

Expected input directory contents:
- enterprise_installation.json
- enterprise_audit_log.jsonl
- enterprise_audit_log.csv
- summary.json
- control_map.json
- manifest.md

Outputs:
- reports/ssp_evidence_summary.md
- reports/ssp_evidence_summary.txt
- reports/report_metadata.json
"""

from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class RunArtifacts:
    run_dir: Path
    reports_dir: Path
    summary: Dict[str, Any]
    control_map: Dict[str, List[str]]
    enterprise_installation: Dict[str, Any]
    manifest_text: str
    audit_rows: List[Dict[str, Any]]


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        return data
    raise ValueError(f"Expected JSON object in {path}, got {type(data).__name__}")


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            item = json.loads(line)
            if isinstance(item, dict):
                rows.append(item)
    return rows


def load_manifest(path: Path) -> str:
    if not path.exists():
        return "# Manifest not found\n"
    return path.read_text(encoding="utf-8")


def load_artifacts(run_dir: Path) -> RunArtifacts:
    summary = load_json(run_dir / "summary.json")
    control_map = load_json(run_dir / "control_map.json")
    enterprise_installation = load_json(run_dir / "enterprise_installation.json")
    manifest_text = load_manifest(run_dir / "manifest.md")
    audit_rows = load_jsonl(run_dir / "enterprise_audit_log.jsonl")

    reports_dir = run_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    return RunArtifacts(
        run_dir=run_dir,
        reports_dir=reports_dir,
        summary=summary,
        control_map=control_map,
        enterprise_installation=enterprise_installation,
        manifest_text=manifest_text,
        audit_rows=audit_rows,
    )


def count_auth_related_events(audit_rows: List[Dict[str, Any]]) -> int:
    tokens = ("auth", "saml", "oauth", "token", "credential", "2fa", "mfa", "login", "sign_in", "signin")
    count = 0
    for row in audit_rows:
        action = str(row.get("action", "")).lower()
        raw = json.dumps(row.get("raw", {}), default=str).lower()
        text = f"{action} {raw}"
        if any(token in text for token in tokens):
            count += 1
    return count


def first_nonempty(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, (int, float, bool)):
            return str(value)
        if isinstance(value, (dict, list)) and value:
            return json.dumps(value, indent=2, sort_keys=True, default=str)
    return ""


def summarize_control_map(control_map: Dict[str, List[str]]) -> List[Tuple[str, str]]:
    rows: List[Tuple[str, str]] = []
    for artifact, controls in sorted(control_map.items()):
        rows.append((artifact, ", ".join(controls)))
    return rows


def build_markdown_report(artifacts: RunArtifacts) -> str:
    summary = artifacts.summary
    control_map = artifacts.control_map
    install = artifacts.enterprise_installation
    audit_rows = artifacts.audit_rows

    enterprise_name = first_nonempty(
        summary.get("enterprise"),
        install.get("enterprise"),
        "Unknown enterprise",
    )

    installation_id = first_nonempty(
        summary.get("installation_id"),
        install.get("installation_id"),
    )

    collected_at = first_nonempty(
        summary.get("collected_at"),
        install.get("collected_at"),
    )

    total_events = len(audit_rows)
    auth_related_events = first_nonempty(
        summary.get("auth_related_event_count"),
        count_auth_related_events(audit_rows),
    )

    checkpoint_day = first_nonempty(summary.get("checkpoint_last_processed_day"), "N/A")
    collection_mode = first_nonempty(summary.get("collection_mode"), "unknown")
    audit_window_days = first_nonempty(summary.get("audit_window_days"), "N/A")
    max_windows = first_nonempty(summary.get("max_windows_per_run"), "N/A")

    potential_gaps = summary.get("potential_gaps") or []
    controls_covered = summary.get("controls_covered") or []

    lines: List[str] = []
    lines.append("# FedRAMP IA-2(8) Enterprise Audit Log Evidence Summary")
    lines.append("")
    lines.append(f"**Enterprise:** {enterprise_name}")
    lines.append(f"**Enterprise installation ID:** {installation_id}")
    lines.append(f"**Collected at:** {collected_at}")
    lines.append(f"**Collection mode:** {collection_mode}")
    lines.append(f"**Checkpoint last processed day:** {checkpoint_day}")
    lines.append(f"**Audit window days:** {audit_window_days}")
    lines.append(f"**Max windows per run:** {max_windows}")
    lines.append("")

    lines.append("## Scope")
    lines.append("")
    lines.append(
        "This report summarizes evidence collected from the GitHub Enterprise Cloud enterprise audit log "
        "for the purpose of demonstrating replay-resistant authentication support for IA-2(8)."
    )
    lines.append(
        "The evidence package is enterprise-scoped and is intended to support review of authentication, "
        "token, and administrative audit activity at the enterprise boundary."
    )
    lines.append("")

    lines.append("## Evidence Summary")
    lines.append("")
    lines.append(f"- Enterprise audit log events collected: **{total_events}**")
    lines.append(f"- Authentication-related enterprise audit log events: **{auth_related_events}**")
    lines.append(f"- Controls covered: **{', '.join(controls_covered) if controls_covered else 'N/A'}**")
    lines.append("")

    lines.append("## Enterprise Audit Log Artifacts")
    lines.append("")
    lines.append("| Artifact | Purpose |")
    lines.append("|---|---|")
    lines.append("| `enterprise_installation.json` | Records the enterprise installation used to access the enterprise audit log. |")
    lines.append("| `enterprise_audit_log.jsonl` | Raw enterprise audit log events in JSON Lines format. |")
    lines.append("| `enterprise_audit_log.csv` | Tabular enterprise audit log export for review and analysis. |")
    lines.append("| `summary.json` | Machine-readable summary of the collection run. |")
    lines.append("| `control_map.json` | Mapping between artifacts and controls supported. |")
    lines.append("| `manifest.md` | File manifest for the collection package. |")
    lines.append("")

    lines.append("## IA-2(8) Implementation Statement")
    lines.append("")
    lines.append(
        "The organization collects and reviews GitHub Enterprise Cloud enterprise audit log data to support "
        "evidence of replay-resistant authentication controls. Authentication to the enterprise is performed "
        "through the approved GitHub App enterprise installation and associated GitHub enterprise access "
        "controls. The enterprise audit log is retained and reviewed as part of the organization’s monitoring "
        "and evidence collection process."
    )
    lines.append(
        "Where authentication-related actions occur within the enterprise boundary, the enterprise audit log "
        "provides traceability for authentication, token, and administrative events. This evidence is used to "
        "support review of replay-resistant authentication implementation, monitoring, and auditability."
    )
    lines.append("")

    lines.append("## Enterprise Audit Log Control Mapping")
    lines.append("")
    lines.append("| Artifact | Controls Supported |")
    lines.append("|---|---|")
    for artifact, controls in summarize_control_map(control_map):
        lines.append(f"| `{artifact}` | {controls} |")
    lines.append("")

    lines.append("## Review Notes")
    lines.append("")
    if potential_gaps:
        lines.append("The following potential gaps were detected during collection:")
        lines.append("")
        for gap in potential_gaps:
            lines.append(f"- {gap}")
    else:
        lines.append(
            "No collection-time gaps were flagged by the collector. This does not replace a manual review "
            "of enterprise access configuration, granted permissions, and event interpretation."
        )
    lines.append("")

    lines.append("## Enterprise Audit Log Observations")
    lines.append("")
    if audit_rows:
        sample = audit_rows[:10]
        lines.append("Representative enterprise audit log events:")
        lines.append("")
        lines.append("| created_at | action | actor | org | repo |")
        lines.append("|---|---|---|---|---|")
        for row in sample:
            lines.append(
                "| {created_at} | {action} | {actor} | {org} | {repo} |".format(
                    created_at=str(row.get("created_at", ""))[:32],
                    action=str(row.get("action", ""))[:80].replace("|", "\\|"),
                    actor=str(row.get("actor", ""))[:80].replace("|", "\\|"),
                    org=str(row.get("org", ""))[:80].replace("|", "\\|"),
                    repo=str(row.get("repo", ""))[:80].replace("|", "\\|"),
                )
            )
    else:
        lines.append("No enterprise audit log events were available in the collection output.")
    lines.append("")

    lines.append("## Reviewer Guidance")
    lines.append("")
    lines.append(
        "For audit review, focus on whether the enterprise installation is valid, the enterprise audit log "
        "is accessible, and the enterprise audit log contains the expected authentication and administrative "
        "events required to support IA-2(8) evidence."
    )
    lines.append(
        "If additional proof is needed, pair the enterprise audit log with IdP authentication records to show "
        "that the enterprise login sequence was preceded by MFA performed at the identity provider."
    )
    lines.append("")

    lines.append("## Manifest")
    lines.append("")
    lines.append("```text")
    lines.append(artifacts.manifest_text.rstrip("\n"))
    lines.append("```")
    lines.append("")

    return "\n".join(lines)


def build_plain_text_report(markdown: str) -> str:
    replacements = [
        ("**", ""),
        ("`", ""),
        ("|", " | "),
    ]
    text = markdown
    for old, new in replacements:
        text = text.replace(old, new)
    return text


def write_report_files(artifacts: RunArtifacts, markdown: str) -> Dict[str, str]:
    md_path = artifacts.reports_dir / "ssp_evidence_summary.md"
    txt_path = artifacts.reports_dir / "ssp_evidence_summary.txt"
    meta_path = artifacts.reports_dir / "report_metadata.json"

    plain_text = build_plain_text_report(markdown)

    md_path.write_text(markdown, encoding="utf-8")
    txt_path.write_text(plain_text, encoding="utf-8")

    meta = {
        "run_dir": str(artifacts.run_dir),
        "reports_dir": str(artifacts.reports_dir),
        "enterprise": first_nonempty(
            artifacts.summary.get("enterprise"),
            artifacts.enterprise_installation.get("enterprise"),
        ),
        "installation_id": first_nonempty(
            artifacts.summary.get("installation_id"),
            artifacts.enterprise_installation.get("installation_id"),
        ),
        "collected_at": first_nonempty(
            artifacts.summary.get("collected_at"),
            artifacts.enterprise_installation.get("collected_at"),
        ),
        "audit_event_count": len(artifacts.audit_rows),
        "auth_related_event_count": count_auth_related_events(artifacts.audit_rows),
        "files_written": {
            "markdown": str(md_path),
            "text": str(txt_path),
        },
    }
    meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return {
        "markdown": str(md_path),
        "text": str(txt_path),
        "metadata": str(meta_path),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate enterprise-audit-log SSP evidence summary.")
    parser.add_argument(
        "--run-dir",
        required=True,
        help="Path to the output directory produced by github_enterprise_ia208_collector.py",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    run_dir = Path(args.run_dir).expanduser().resolve()

    if not run_dir.exists():
        print(f"Run directory does not exist: {run_dir}", file=sys.stderr)
        return 2

    artifacts = load_artifacts(run_dir)
    markdown = build_markdown_report(artifacts)
    outputs = write_report_files(artifacts, markdown)

    print(json.dumps(outputs, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(main())
