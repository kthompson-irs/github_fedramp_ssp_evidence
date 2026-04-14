#!/usr/bin/env python3
"""Generate a FedRAMP CA-6 ATO compliance package with PDF reports.

Outputs (in --out_dir):
- compliance_package_index.pdf
- ato_executive_summary.pdf
- github_third_party_risk_assessment.pdf
- control_evidence_index.pdf
- poam_summary.pdf
- package_manifest.json

This is a starter template. Replace placeholders with system-specific data before use.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Sequence

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    PageTemplate,
    PageBreak,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    SimpleDocTemplate,
    KeepTogether,
)


@dataclass
class ReportSpec:
    filename: str
    title: str
    subtitle: str
    sections: List[tuple[str, str]]


def build_styles():
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="Title2",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#17324d"),
            alignment=TA_LEFT,
            spaceAfter=10,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Subtitle2",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=10,
            leading=13,
            textColor=colors.HexColor("#4b5563"),
            alignment=TA_LEFT,
            spaceAfter=12,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Section2",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=15,
            textColor=colors.HexColor("#17324d"),
            spaceBefore=8,
            spaceAfter=6,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Body2",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=13,
            spaceAfter=6,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Small2",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=8.3,
            leading=10.5,
            textColor=colors.HexColor("#374151"),
        )
    )
    styles.add(
        ParagraphStyle(
            name="Note2",
            parent=styles["BodyText"],
            fontName="Helvetica-Oblique",
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#6b7280"),
        )
    )
    return styles


STYLES = build_styles()


def header_footer(canvas, doc):
    canvas.saveState()
    w, h = LETTER
    canvas.setStrokeColor(colors.HexColor("#d1d5db"))
    canvas.setLineWidth(0.5)
    canvas.line(doc.leftMargin, h - 0.55 * inch, w - doc.rightMargin, h - 0.55 * inch)
    canvas.line(doc.leftMargin, 0.62 * inch, w - doc.rightMargin, 0.62 * inch)
    canvas.setFont("Helvetica-Bold", 8.5)
    canvas.setFillColor(colors.HexColor("#17324d"))
    canvas.drawString(doc.leftMargin, h - 0.42 * inch, "FedRAMP CA-6 ATO Compliance Package")
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#6b7280"))
    canvas.drawRightString(w - doc.rightMargin, h - 0.42 * inch, f"Page {doc.page}")
    canvas.drawString(doc.leftMargin, 0.38 * inch, "Generated template - replace placeholders with live evidence before submission")
    canvas.restoreState()


def story_from_sections(sections: List[tuple[str, str]]):
    story = []
    for heading, body in sections:
        story.append(Paragraph(heading, STYLES["Section2"]))
        story.append(Paragraph(body, STYLES["Body2"]))
    return story


def bullet_table(rows: Sequence[Sequence[str]], col_widths: Sequence[float]) -> Table:
    t = Table(rows, colWidths=col_widths, hAlign="LEFT")
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17324d")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("LEADING", (0, 0), (-1, -1), 10.5),
                ("ALIGN", (0, 0), (-1, 0), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#9ca3af")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.HexColor("#f8fafc")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return t


def make_title_block(title: str, subtitle: str):
    return [
        Spacer(1, 0.08 * inch),
        Paragraph(title, STYLES["Title2"]),
        Paragraph(subtitle, STYLES["Subtitle2"]),
        Spacer(1, 0.07 * inch),
    ]


def make_cover_index(out_path: Path):
    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=LETTER,
        leftMargin=0.8 * inch,
        rightMargin=0.8 * inch,
        topMargin=0.9 * inch,
        bottomMargin=0.8 * inch,
    )
    story = []
    story += make_title_block(
        "FedRAMP CA-6 ATO Compliance Package",
        "Starter PDF index for AWS GovCloud, Azure Government, Kubernetes, Terraform, and GitHub.com as an external service.",
    )
    story.append(Paragraph("Package Contents", STYLES["Section2"]))
    rows = [
        ["Document", "Purpose"],
        ["ato_executive_summary.pdf", "Authorization overview and scope"],
        ["github_third_party_risk_assessment.pdf", "GitHub.com external service risk review"],
        ["control_evidence_index.pdf", "Control-to-evidence mapping"],
        ["poam_summary.pdf", "Open findings and remediation tracking"],
    ]
    story.append(bullet_table(rows, [2.3 * inch, 4.7 * inch]))
    story.append(Spacer(1, 0.12 * inch))
    story.append(Paragraph("Usage Note", STYLES["Section2"]))
    story.append(
        Paragraph(
            "This package is a template. Before use in an assessment, replace placeholder text, fill in system-specific names, dates, findings, owners, and evidence references, and validate that the attached artifacts match the current SSP, SAR, POA&M, and ATO letter.",
            STYLES["Body2"],
        )
    )
    doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)


def make_executive_summary(out_path: Path):
    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=LETTER,
        leftMargin=0.8 * inch,
        rightMargin=0.8 * inch,
        topMargin=0.9 * inch,
        bottomMargin=0.8 * inch,
    )
    story = []
    story += make_title_block(
        "ATO Executive Summary",
        "FedRAMP CA-6 authorization summary for a multi-cloud production environment.",
    )
    sections = [
        (
            "System Scope",
            "The system operates in AWS GovCloud (US) and Azure Government with Kubernetes workloads deployed using Terraform. GitHub.com is used as an external service for source control and CI/CD support and is treated as an external information system service under SA-9.",
        ),
        (
            "Authorization Basis",
            "The system authorization is based on the current SSP, SAR, POA&M, and an AO risk acceptance decision. Residual risk is documented and accepted in accordance with CA-6.",
        ),
        (
            "Key Evidence Categories",
            "Evidence should include identity and access exports, audit log exports, repository security settings, rulesets, branch protection status, vulnerability scan results, cloud policy compliance, Terraform plan output, and Kubernetes RBAC and network policy exports.",
        ),
        (
            "Critical Notes",
            "GitHub.com must remain limited to sanitized code and infrastructure-as-code. Secrets, production data, and controlled information must not be stored in repositories or workflow artifacts. The package should be refreshed whenever the boundary, repo scope, or cloud configuration changes.",
        ),
    ]
    story += story_from_sections(sections)
    doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)


def make_github_risk_assessment(out_path: Path):
    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=LETTER,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.9 * inch,
        bottomMargin=0.75 * inch,
    )
    story = []
    story += make_title_block(
        "GitHub.com Third-Party Risk Assessment",
        "External service assessment for SA-9 support in the FedRAMP authorization package.",
    )
    story.append(Paragraph("Service Overview", STYLES["Section2"]))
    story.append(Paragraph("GitHub.com is used for source code management and CI/CD support. It is treated as an external service and is not inside the federal cloud authorization boundary.", STYLES["Body2"]))

    rows = [
        ["Risk ID", "Risk", "Impact", "Mitigation"],
        ["GH-01", "Sensitive data exposure in repositories", "High", "Private repos, data classification, no CUI or secrets"],
        ["GH-02", "Weak access control or stale collaborators", "High", "MFA, SSO, periodic membership review"],
        ["GH-03", "Secret leakage in commits or workflows", "High", "Secret scanning, push protection, external secret store"],
        ["GH-04", "Supply chain compromise through code changes", "High", "Branch protection, required reviews, signed changes, scanning"],
        ["GH-05", "Insufficient audit visibility", "Medium", "Audit-log export to SIEM and recurring review"],
    ]
    story.append(Spacer(1, 0.05 * inch))
    story.append(bullet_table(rows, [0.7 * inch, 2.9 * inch, 0.9 * inch, 2.3 * inch]))
    story.append(Spacer(1, 0.1 * inch))
    story.append(Paragraph("Residual Risk Statement", STYLES["Section2"]))
    story.append(Paragraph("Residual risk is acceptable only when GitHub remains restricted to non-sensitive source code and IaC, security controls are enabled and monitored, and the AO explicitly accepts the external-service risk in the authorization package.", STYLES["Body2"]))
    doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)


def make_control_index(out_path: Path):
    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=LETTER,
        leftMargin=0.72 * inch,
        rightMargin=0.72 * inch,
        topMargin=0.9 * inch,
        bottomMargin=0.75 * inch,
    )
    story = []
    story += make_title_block(
        "Control Evidence Index",
        "Control-to-evidence mapping for CA-6, SA-9, cloud, Kubernetes, and GitHub evidence collection.",
    )
    rows = [
        ["Control", "Evidence", "Command / Source", "POA&M"],
        ["CA-6", "ATO_Letter.pdf, SSP.pdf, SAR.pdf, POAM.xlsx", "Document review", "N/A"],
        ["SA-9", "GitHub_Risk_Assessment.pdf, org.json, repos.json", "gh api /orgs/<ORG>", "GH-01"],
        ["AC-2", "members.json, outside_collaborators.json", "gh api /orgs/<ORG>/members", "GH-02"],
        ["AC-3", "repo rulesets, branch protection, role exports", "gh api /repos/<ORG>/<REPO>/rulesets", "GH-03"],
        ["IA-2", "MFA settings, org settings exports", "gh api /orgs/<ORG>", "GH-04"],
        ["AU-2/AU-6", "audit_log.json, siem export", "gh api /orgs/<ORG>/audit-log", "GH-05"],
        ["CM-2/CM-6", "Terraform plan/state, cloud policies", "terraform plan; AWS/Azure policy exports", "GH-06"],
        ["RA-5", "secret scanning, code scanning, dependabot", "gh api /repos/<ORG>/<REPO>/...", "GH-07"],
    ]
    story.append(bullet_table(rows, [0.7 * inch, 2.15 * inch, 2.65 * inch, 0.6 * inch]))
    story.append(Spacer(1, 0.1 * inch))
    story.append(Paragraph("Reminder", STYLES["Section2"]))
    story.append(Paragraph("Keep filenames and live commands aligned. If the workflow collects a file with one name, the binder and evidence index must use the same name exactly.", STYLES["Body2"]))
    doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)


def make_poam_summary(out_path: Path):
    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=LETTER,
        leftMargin=0.72 * inch,
        rightMargin=0.72 * inch,
        topMargin=0.9 * inch,
        bottomMargin=0.75 * inch,
    )
    story = []
    story += make_title_block(
        "POA&M Summary",
        "Starter remediation tracker with GitHub-specific items and cloud control issues.",
    )
    rows = [
        ["ID", "Weakness", "Severity", "Owner", "Due", "Status"],
        ["GH-01", "GitHub used as external service; risk acceptance missing or stale", "Medium", "Security", "Ongoing", "Open"],
        ["GH-02", "MFA not enforced for all org users", "High", "IAM / Security", "15 days", "Open"],
        ["GH-03", "Over-permissive repository access or stale collaborators", "Medium", "DevOps", "30 days", "Open"],
        ["GH-04", "Secrets detected or push protection disabled", "High", "Platform", "15 days", "Open"],
        ["GH-05", "Audit logs not centralized or reviewed", "High", "SecOps", "15 days", "Open"],
        ["GH-06", "Drift or policy noncompliance in Terraform / cloud controls", "Medium", "Platform", "30 days", "Open"],
        ["GH-07", "Dependency or code scanning gaps", "Medium", "DevOps", "30 days", "Open"],
    ]
    story.append(bullet_table(rows, [0.55 * inch, 2.9 * inch, 0.65 * inch, 0.85 * inch, 0.65 * inch, 0.55 * inch]))
    story.append(Spacer(1, 0.1 * inch))
    story.append(Paragraph("Note", STYLES["Section2"]))
    story.append(Paragraph("This is a template POA&M summary. Replace placeholder owners, due dates, and status values with actual remediation data before audit submission.", STYLES["Body2"]))
    doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate FedRAMP ATO compliance package PDFs.")
    parser.add_argument("--out_dir", default="fedramp_ato_package", help="Output directory")
    args = parser.parse_args()

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    reports = [
        ("compliance_package_index.pdf", make_cover_index),
        ("ato_executive_summary.pdf", make_executive_summary),
        ("github_third_party_risk_assessment.pdf", make_github_risk_assessment),
        ("control_evidence_index.pdf", make_control_index),
        ("poam_summary.pdf", make_poam_summary),
    ]

    created = []
    for filename, builder in reports:
        path = out_dir / filename
        builder(path)
        created.append(filename)

    manifest = {
        "output_dir": str(out_dir),
        "files": created,
        "notes": [
            "Template only; replace placeholders with live evidence before audit use.",
            "File names should match your evidence binder and workflow outputs exactly.",
        ],
    }
    (out_dir / "package_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(f"Created FedRAMP ATO package in: {out_dir}")
    for f in created:
        print(f" - {f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
