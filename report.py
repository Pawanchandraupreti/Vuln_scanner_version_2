"""
PDF Report Generator for Network Vulnerability Scanner
Produces a clean, professional security report using ReportLab
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from datetime import datetime
import os


# ── Brand colors ──────────────────────────────────────────────────────────────
C_BG        = colors.HexColor("#0D1117")
C_ACCENT    = colors.HexColor("#58A6FF")
C_CRITICAL  = colors.HexColor("#FF4444")
C_HIGH      = colors.HexColor("#FF8C00")
C_MEDIUM    = colors.HexColor("#FFD700")
C_LOW       = colors.HexColor("#3FB950")
C_INFO      = colors.HexColor("#58A6FF")
C_TEXT      = colors.HexColor("#C9D1D9")
C_SUBTEXT   = colors.HexColor("#8B949E")
C_ROW_ALT   = colors.HexColor("#161B22")
C_BORDER    = colors.HexColor("#30363D")
C_WHITE     = colors.white

SEV_COLORS = {
    "CRITICAL": C_CRITICAL,
    "HIGH":     C_HIGH,
    "MEDIUM":   C_MEDIUM,
    "LOW":      C_LOW,
    "INFO":     C_INFO,
}


def _sev_badge_color(sev):
    return SEV_COLORS.get(sev, C_INFO)


# ── Styles ────────────────────────────────────────────────────────────────────

def build_styles():
    base = getSampleStyleSheet()

    styles = {
        "title": ParagraphStyle(
            "title",
            fontName="Helvetica-Bold",
            fontSize=26,
            textColor=C_WHITE,
            spaceAfter=4,
            alignment=TA_LEFT,
        ),
        "subtitle": ParagraphStyle(
            "subtitle",
            fontName="Helvetica",
            fontSize=11,
            textColor=C_ACCENT,
            spaceAfter=2,
        ),
        "meta": ParagraphStyle(
            "meta",
            fontName="Helvetica",
            fontSize=9,
            textColor=C_SUBTEXT,
            spaceAfter=2,
        ),
        "section": ParagraphStyle(
            "section",
            fontName="Helvetica-Bold",
            fontSize=13,
            textColor=C_ACCENT,
            spaceBefore=18,
            spaceAfter=6,
        ),
        "device_title": ParagraphStyle(
            "device_title",
            fontName="Helvetica-Bold",
            fontSize=11,
            textColor=C_WHITE,
            spaceBefore=12,
            spaceAfter=2,
        ),
        "device_meta": ParagraphStyle(
            "device_meta",
            fontName="Helvetica",
            fontSize=9,
            textColor=C_SUBTEXT,
            spaceAfter=6,
        ),
        "advice": ParagraphStyle(
            "advice",
            fontName="Helvetica-Oblique",
            fontSize=8,
            textColor=C_SUBTEXT,
            leading=11,
        ),
        "normal": ParagraphStyle(
            "normal",
            fontName="Helvetica",
            fontSize=9,
            textColor=C_TEXT,
        ),
        "footer": ParagraphStyle(
            "footer",
            fontName="Helvetica",
            fontSize=8,
            textColor=C_SUBTEXT,
            alignment=TA_CENTER,
        ),
    }
    return styles


# ── Page canvas ───────────────────────────────────────────────────────────────

def dark_page(canvas, doc):
    """Draw dark background on every page."""
    canvas.saveState()
    canvas.setFillColor(C_BG)
    canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)

    # Top accent bar
    canvas.setFillColor(C_ACCENT)
    canvas.rect(0, A4[1] - 4, A4[0], 4, fill=1, stroke=0)

    # Footer
    canvas.setFillColor(C_SUBTEXT)
    canvas.setFont("Helvetica", 8)
    canvas.drawCentredString(A4[0] / 2, 1.2 * cm,
        f"Network Vulnerability Report  •  Page {doc.page}  •  CONFIDENTIAL")
    canvas.restoreState()


# ── Summary table ─────────────────────────────────────────────────────────────

def summary_counts(devices: list) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for d in devices:
        for f in d["findings"]:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts


def build_summary_table(devices, styles):
    counts = summary_counts(devices)
    total_devices = len(devices)
    total_findings = sum(len(d["findings"]) for d in devices)

    # Stats row
    stat_data = [
        [
            Paragraph(f'<font color="#58A6FF"><b>{total_devices}</b></font>', styles["title"]),
            Paragraph(f'<font color="#FF4444"><b>{counts["CRITICAL"]}</b></font>', styles["title"]),
            Paragraph(f'<font color="#FF8C00"><b>{counts["HIGH"]}</b></font>', styles["title"]),
            Paragraph(f'<font color="#FFD700"><b>{counts["MEDIUM"]}</b></font>', styles["title"]),
            Paragraph(f'<font color="#3FB950"><b>{counts["LOW"]}</b></font>', styles["title"]),
        ],
        [
            Paragraph("Devices Found", styles["meta"]),
            Paragraph("Critical", styles["meta"]),
            Paragraph("High", styles["meta"]),
            Paragraph("Medium", styles["meta"]),
            Paragraph("Low", styles["meta"]),
        ]
    ]

    col_w = (A4[0] - 4 * cm) / 5
    tbl = Table(stat_data, colWidths=[col_w] * 5)
    tbl.setStyle(TableStyle([
        ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND",  (0, 0), (-1, -1), C_ROW_ALT),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_ROW_ALT]),
        ("BOX",         (0, 0), (-1, -1), 1, C_BORDER),
        ("INNERGRID",   (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",  (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return tbl


# ── Device findings table ─────────────────────────────────────────────────────

def build_findings_table(findings, styles):
    if not findings:
        return Paragraph("No open ports detected on this device.", styles["normal"])

    header = ["Port", "Service", "Version Detected", "Severity", "Recommendation"]
    rows = [header]

    for f in findings:
        sev = f["severity"]
        sev_col = SEV_COLORS.get(sev, C_INFO)
        rows.append([
            Paragraph(str(f["port"]), styles["normal"]),
            Paragraph(f["service"], styles["normal"]),
            Paragraph(f["detected_version"] or "—", styles["normal"]),
            Paragraph(f'<font color="#{_hex(sev_col)}"><b>{sev}</b></font>', styles["normal"]),
            Paragraph(f["advice"], styles["advice"]),
        ])

    col_widths = [1.1*cm, 2.3*cm, 3.5*cm, 2*cm, 8*cm]
    tbl = Table(rows, colWidths=col_widths, repeatRows=1)

    style = TableStyle([
        # Header
        ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1C2128")),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_ACCENT),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 8),
        ("ALIGN",         (0, 0), (-1, 0), "LEFT"),
        # Body
        ("FONTSIZE",      (0, 1), (-1, -1), 8),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_BG, C_ROW_ALT]),
        ("BOX",           (0, 0), (-1, -1), 1, C_BORDER),
        ("INNERGRID",     (0, 0), (-1, -1), 0.3, C_BORDER),
    ])
    tbl.setStyle(style)
    return tbl


def _hex(color) -> str:
    r = int(color.red * 255)
    g = int(color.green * 255)
    b = int(color.blue * 255)
    return f"{r:02X}{g:02X}{b:02X}"


# ── Main report builder ───────────────────────────────────────────────────────

def generate_report(devices: list, output_path: str = "vulnerability_report.pdf",
                    scan_target: str = "", scan_time: str = "") -> str:
    styles = build_styles()
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2*cm,
        rightMargin=2*cm,
        topMargin=2.5*cm,
        bottomMargin=2*cm,
    )

    story = []

    # ── Cover section ─────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph("NETWORK VULNERABILITY", styles["title"]))
    story.append(Paragraph("SECURITY REPORT", styles["title"]))
    story.append(Spacer(1, 0.3*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(f"Target Network: {scan_target}", styles["subtitle"]))
    story.append(Paragraph(f"Scan Date: {scan_time}", styles["meta"]))
    story.append(Paragraph("Classification: CONFIDENTIAL — Internal Use Only", styles["meta"]))
    story.append(Spacer(1, 0.8*cm))

    # ── Summary ───────────────────────────────────────────────────────────────
    story.append(Paragraph("EXECUTIVE SUMMARY", styles["section"]))
    story.append(build_summary_table(devices, styles))
    story.append(Spacer(1, 0.5*cm))

    if not devices:
        story.append(Paragraph("No active hosts found on the network.", styles["normal"]))
        doc.build(story, onFirstPage=dark_page, onLaterPages=dark_page)
        return output_path

    # ── Device overview table ─────────────────────────────────────────────────
    story.append(Paragraph("DEVICE OVERVIEW", styles["section"]))
    dev_header = ["IP Address", "Hostname", "OS (Detected)", "Open Ports", "Risk Level"]
    dev_rows = [dev_header]
    for d in devices:
        sev_col = SEV_COLORS.get(d["risk"], C_INFO)
        dev_rows.append([
            Paragraph(d["ip"], styles["normal"]),
            Paragraph(d["hostname"][:30], styles["normal"]),
            Paragraph((d["os"] or "Unknown")[:35], styles["normal"]),
            Paragraph(", ".join(str(p) for p in d["open_ports"]) or "None", styles["normal"]),
            Paragraph(f'<font color="#{_hex(sev_col)}"><b>{d["risk"]}</b></font>', styles["normal"]),
        ])

    col_w2 = [2.5*cm, 4*cm, 5*cm, 3.5*cm, 2*cm]
    dev_tbl = Table(dev_rows, colWidths=col_w2, repeatRows=1)
    dev_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1C2128")),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_ACCENT),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_BG, C_ROW_ALT]),
        ("BOX",           (0, 0), (-1, -1), 1, C_BORDER),
        ("INNERGRID",     (0, 0), (-1, -1), 0.3, C_BORDER),
    ]))
    story.append(dev_tbl)

    # ── Per-device findings ───────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("DETAILED FINDINGS", styles["section"]))

    for d in devices:
        risk_col = SEV_COLORS.get(d["risk"], C_INFO)
        story.append(Paragraph(
            f'<font color="#{_hex(risk_col)}">▐</font>  {d["ip"]}  —  {d["hostname"]}',
            styles["device_title"]
        ))
        story.append(Paragraph(
            f'OS: {d["os"]}   •   Open Ports: {len(d["open_ports"])}   •   '
            f'Risk: <font color="#{_hex(risk_col)}"><b>{d["risk"]}</b></font>',
            styles["device_meta"]
        ))
        story.append(build_findings_table(d["findings"], styles))
        story.append(Spacer(1, 0.5*cm))

    # ── Remediation guide ─────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("REMEDIATION PRIORITY GUIDE", styles["section"]))

    guide = [
        ("CRITICAL", "Address within 24 hours.",
         "Disable the service or firewall the port immediately. These represent active exploitation risk."),
        ("HIGH", "Address within 1 week.",
         "Update software, enforce authentication, or restrict access via firewall rules."),
        ("MEDIUM", "Address within 1 month.",
         "Review configuration. Consider enforcing encryption or restricting service to internal use only."),
        ("LOW", "Address at next maintenance window.",
         "Low risk but worth hardening. Verify the service is intentionally exposed."),
    ]

    for sev, timeline, desc in guide:
        sev_col = SEV_COLORS[sev]
        story.append(Paragraph(
            f'<font color="#{_hex(sev_col)}"><b>{sev}</b></font> — {timeline}',
            styles["normal"]
        ))
        story.append(Paragraph(desc, styles["advice"]))
        story.append(Spacer(1, 0.3*cm))

    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        "This report was generated by the Local Network Vulnerability Scanner. "
        "Results are based on open port detection and known service risk profiles. "
        "Always verify findings manually before taking remediation action.",
        styles["footer"]
    ))

    doc.build(story, onFirstPage=dark_page, onLaterPages=dark_page)
    print(f"[+] Report saved: {output_path}")
    return output_path

