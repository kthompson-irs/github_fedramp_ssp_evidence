#!/usr/bin/env python3
"""Generate SSP-ready Markdown and PDF summaries from a collector run directory."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List

from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
from xml.sax.saxutils import escape


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_manifest_entries(path: Path) -> List[str]:
    entries: List[str] = []
    if not path.exists():
        return entries
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("- "):
            entries.append(line[2:].strip())
    return entries


def build_markdown(summary: Dict[str, Any], manifest_entries: List[str]) -> str:
    controls = summary.get("controls_covered", [])
    control_map = summary.get("control_map", {})
    potential_gaps = summary.get("potential_gaps", [])

    lines: List[str] = []
    lines.append("# FedRAMP IA-2(8) Evidence Summary")
    lines.append("")
    lines.append(f"- Organization: {summary.get('org')}")
    lines.append(f"- Collection mode: {summary.get('collection_mode')}")
    lines.append(f"- Collected at: {summary.get('collected_at')}")
    lines.append(f"- Days collected: {summary.get('days_collected')}")
    lines.append(f"- Checkpoint file: {summary.get('checkpoint_file')}")
    lines.append(f"- Checkpoint last processed day: {summary.get('checkpoint_last_processed_day')}")
    lines.append(f"- Backfill complete: {summary.get('checkpoint_backfill_complete')}")
    lines.append(f"- Archive slice: {summary.get('persistent_archive_slice_dir')}")
    lines.append("")

    lines.append("## Control coverage")
    for control in controls:
        lines.append(f"- {control}")
    lines.append("")

    lines.append("## Evidence inventory")
    for item in manifest_entries:
        lines.append(f"- {item}")
    lines.append("")

    lines.append("## File-to-control mapping")
    for filename, mapped in control_map.items():
        lines.append(f"- {filename}: {', '.join(mapped)}")
    lines.append("")

    lines.append("## Key findings")
    lines.append(f"- Organization 2FA requirement enabled: {summary.get('org_two_factor_requirement_enabled')}")
    lines.append(f"- Audit events collected this run: {summary.get('audit_event_count')}")
    lines.append(f"- Auth-related audit events: {summary.get('auth_related_event_count')}")
    lines.append(f"- Credential authorizations count: {summary.get('credential_authorization_count')}")
    lines.append(f"- Installations count: {summary.get('installation_count')}")
    lines.append("")

    lines.append("## Potential gaps")
    if potential_gaps:
        for gap in potential_gaps:
            lines.append(f"- {gap}")
    else:
        lines.append("- None noted")
    lines.append("")

    lines.append("## Notes for SSP insertion")
    lines.append("- IA-2(8): evidence shows GitHub App installation + audit-log collection workflow.")
    lines.append("- AC-2: organization-level context and installation visibility.")
    lines.append("- AU-2 / AU-6 / AU-12: audit event capture, review, and retention slice.")
    lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def build_pdf(run_dir: Path, summary: Dict[str, Any], manifest_entries: List[str]) -> Path:
    reports_dir = run_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = reports_dir / "ssp_evidence_summary.pdf"

    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="BodySmall",
            parent=styles["BodyText"],
            fontSize=9,
            leading=12,
            spaceAfter=6,
            alignment=TA_LEFT,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Section",
            parent=styles["Heading2"],
            spaceBefore=10,
            spaceAfter=6,
        )
    )

    story: List[Any] = []
    story.append(Paragraph("FedRAMP IA-2(8) Evidence Summary", styles["Title"]))
    story.append(Spacer(1, 0.15 * inch))
    story.append(Paragraph(f"Organization: {escape(str(summary.get('org', '')))}", styles["BodySmall"]))
    story.append(Paragraph(f"Collection mode: {escape(str(summary.get('collection_mode', '')))}", styles["BodySmall"]))
    story.append(Paragraph(f"Collected at: {escape(str(summary.get('collected_at', '')))}", styles["BodySmall"]))
    story.append(Paragraph(f"Days collected: {escape(str(summary.get('days_collected', '')))}", styles["BodySmall"]))
    story.append(Paragraph(f"Checkpoint: {escape(str(summary.get('checkpoint_file', '')))}", styles["BodySmall"]))
    story.append(Paragraph(f"Checkpoint last day: {escape(str(summary.get('checkpoint_last_processed_day', '')))}", styles["BodySmall"]))
    story.append(Paragraph(f"Archive slice: {escape(str(summary.get('persistent_archive_slice_dir', '')))}", styles["BodySmall"]))

    story.append(Paragraph("Control coverage", styles["Section"]))
    for control in summary.get("controls_covered", []):
        story.append(Paragraph(f"• {escape(str(control))}", styles["BodySmall"]))

    story.append(Paragraph("Evidence inventory", styles["Section"]))
    for item in manifest_entries:
        story.append(Paragraph(f"• {escape(item)}", styles["BodySmall"]))

    story.append(Paragraph("File-to-control mapping", styles["Section"]))
    for filename, mapped in summary.get("control_map", {}).items():
        story.append(Paragraph(f"• {escape(filename)}: {escape(', '.join(mapped))}", styles["BodySmall"]))

    story.append(Paragraph("Key findings", styles["Section"]))
    story.append(Paragraph(f"• Organization 2FA requirement enabled: {escape(str(summary.get('org_two_factor_requirement_enabled')))}", styles["BodySmall"]))
    story.append(Paragraph(f"• Audit events collected this run: {escape(str(summary.get('audit_event_count')))}", styles["BodySmall"]))
    story.append(Paragraph(f"• Auth-related audit events: {escape(str(summary.get('auth_related_event_count')))}", styles["BodySmall"]))
    story.append(Paragraph(f"• Credential authorizations count: {escape(str(summary.get('credential_authorization_count')))}", styles["BodySmall"]))
    story.append(Paragraph(f"• Installations count: {escape(str(summary.get('installation_count')))}", styles["BodySmall"]))

    story.append(Paragraph("Potential gaps", styles["Section"]))
    gaps = summary.get("potential_gaps") or []
    if gaps:
        for gap in gaps:
            story.append(Paragraph(f"• {escape(str(gap))}", styles["BodySmall"]))
    else:
        story.append(Paragraph("• None noted", styles["BodySmall"]))

    story.append(Paragraph("SSP insertion notes", styles["Section"]))
    story.append(Paragraph("• IA-2(8): GitHub App installation and audit-log evidence.", styles["BodySmall"]))
    story.append(Paragraph("• AC-2: organization-level context and installation visibility.", styles["BodySmall"]))
    story.append(Paragraph("• AU-2 / AU-6 / AU-12: audit event capture, review, and retention slice.", styles["BodySmall"]))

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=letter,
        rightMargin=0.7 * inch,
        leftMargin=0.7 * inch,
        topMargin=0.7 * inch,
        bottomMargin=0.7 * inch,
    )
    doc.build(story)

    return pdf_path


def append_report_index(archive_slice_dir: Path, record: Dict[str, Any]) -> None:
    index_path = archive_slice_dir.parent.parent.parent.parent / "index.jsonl"
    index_path.parent.mkdir(parents=True, exist_ok=True)
    with index_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True))
        f.write("\n")


def sync_directory_to_s3(directory: Path, bucket: str, prefix: str, region: str | None) -> None:
    try:
        import boto3  # type: ignore
    except Exception as exc:
        raise RuntimeError("boto3 is required for GH_ARCHIVE_S3_BUCKET uploads") from exc

    client = boto3.client("s3", region_name=region or None)
    base_prefix = prefix.strip("/")

    for file_path in directory.rglob("*"):
        if not file_path.is_file():
            continue
        rel = file_path.relative_to(directory).as_posix()
        key = f"{base_prefix}/{rel}" if base_prefix else rel
        client.upload_file(str(file_path), bucket, key)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True, help="Collector output directory")
    args = parser.parse_args()

    run_dir = Path(args.run_dir).resolve()
    summary_path = run_dir / "summary.json"
    manifest_path = run_dir / "manifest.md"

    if not summary_path.exists():
        print(f"Missing summary.json in {run_dir}", file=sys.stderr)
        return 1

    summary = load_json(summary_path)
    manifest_entries = read_manifest_entries(manifest_path)

    reports_dir = run_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    markdown_text = build_markdown(summary, manifest_entries)
    markdown_path = reports_dir / "ssp_evidence_summary.md"
    markdown_path.write_text(markdown_text, encoding="utf-8")

    pdf_path = build_pdf(run_dir, summary, manifest_entries)

    archive_slice = summary.get("persistent_archive_slice_dir")
    if archive_slice:
        archive_slice_dir = Path(str(archive_slice))
        archive_slice_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(markdown_path, archive_slice_dir / markdown_path.name)
        shutil.copy2(pdf_path, archive_slice_dir / pdf_path.name)

        archive_index_record = {
            "run_stamp": summary.get("run_stamp"),
            "org": summary.get("org"),
            "run_dir": str(run_dir),
            "archive_slice_dir": str(archive_slice_dir),
            "record_type": "report",
            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "report_files": [markdown_path.name, pdf_path.name],
        }
        append_report_index(archive_slice_dir, archive_index_record)

        bucket = os.environ.get("GH_ARCHIVE_S3_BUCKET") or None
        if bucket:
            prefix = os.environ.get("GH_ARCHIVE_S3_PREFIX", "irsdigitalservice").strip("/")
            region = os.environ.get("GH_AWS_REGION") or None
            sync_directory_to_s3(
                archive_slice_dir,
                bucket,
                f"{prefix}/{archive_slice_dir.as_posix().split('archive/', 1)[-1]}",
                region,
            )

    print(str(markdown_path))
    print(str(pdf_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
