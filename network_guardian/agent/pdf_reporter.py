# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Network Guardian — ReAct Threat Report PDF Generator

Uses ReportLab Platypus to produce professional, branded PDF reports
documenting a full ReAct cycle (Observe → Reason → Act → Learn) with
threat inventory, actions taken, and recommendations.
"""

from __future__ import annotations

import logging
import os
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("network_guardian.agent.pdf_reporter")

# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------

_BRAND_DARK   = (0.07, 0.09, 0.14)   # #121724 — near-black
_BRAND_BLUE   = (0.12, 0.47, 0.87)   # #1e78de
_BRAND_GREEN  = (0.13, 0.77, 0.55)   # #21c48c
_BRAND_RED    = (0.86, 0.21, 0.27)   # #db3645
_BRAND_YELLOW = (0.96, 0.69, 0.13)   # #f5b021
_BRAND_GREY   = (0.55, 0.55, 0.60)   # #8c8c99

_SEV_COLOUR = {
    "critical": _BRAND_RED,
    "high":     (0.93, 0.38, 0.12),   # orange-red
    "medium":   _BRAND_YELLOW,
    "low":      _BRAND_GREEN,
    "info":     _BRAND_BLUE,
    "clean":    _BRAND_GREEN,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rl_colour(rgb: tuple[float, float, float]):
    """Return a ReportLab Color from an (r, g, b) float tuple."""
    from reportlab.lib.colors import Color
    return Color(*rgb)


def _sev_colour(severity: str):
    return _rl_colour(_SEV_COLOUR.get(severity.lower(), _BRAND_GREY))


def _wrap(text: str, width: int = 90) -> str:
    """Soft-wrap long text for table cells."""
    return "\n".join(textwrap.wrap(str(text), width)) if text else "—"


# ---------------------------------------------------------------------------
# Core builder
# ---------------------------------------------------------------------------

def build_report_pdf(
    report_type: str,             # "malware" | "ransomware"
    report_id: str,
    agent_label: str,
    risk_level: str,
    threat_score: float,          # 0-100
    react_steps: list[dict],      # [{phase, thought, detail, timestamp}, ...]
    threats: list[dict],          # [{title, severity, category, detail, action_taken, resolved}, ...]
    actions: list[dict],          # [{action, detail, success}, ...]
    recommendations: list[str],
    observations: dict[str, Any],
    output_path: Path | None = None,
) -> Path:
    """
    Build and save a PDF threat report.

    Returns the path to the written PDF.
    """
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import cm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, KeepTogether,
    )
    from reportlab.lib.colors import Color, white, black

    # -- Output path --------------------------------------------------------
    if output_path is None:
        report_dir = Path.home() / ".network_guardian" / "pdf_reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        now_tag = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
        output_path = report_dir / f"NG_{report_type.upper()}_REPORT_{now_tag}_{report_id[:8]}.pdf"

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Also mirror to project folder
    proj_dir = Path("pdf_reports")
    proj_dir.mkdir(parents=True, exist_ok=True)
    proj_copy = proj_dir / output_path.name

    # -- Styles -------------------------------------------------------------
    brand_dark   = _rl_colour(_BRAND_DARK)
    brand_blue   = _rl_colour(_BRAND_BLUE)
    brand_green  = _rl_colour(_BRAND_GREEN)
    brand_red    = _rl_colour(_BRAND_RED)
    brand_yellow = _rl_colour(_BRAND_YELLOW)
    brand_grey   = _rl_colour(_BRAND_GREY)

    styles = getSampleStyleSheet()

    def _style(name: str, parent: str = "Normal", **kwargs) -> ParagraphStyle:
        return ParagraphStyle(name, parent=styles[parent], **kwargs)

    S_TITLE       = _style("NG_Title",      fontSize=22, textColor=white,
                            fontName="Helvetica-Bold", alignment=TA_LEFT, leading=28)
    S_SUBTITLE    = _style("NG_Subtitle",   fontSize=11, textColor=_rl_colour((0.7, 0.8, 0.9)),
                            fontName="Helvetica", alignment=TA_LEFT)
    S_SECTION     = _style("NG_Section",    fontSize=13, textColor=brand_blue,
                            fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=4)
    S_BODY        = _style("NG_Body",       fontSize=9,  textColor=brand_dark,
                            fontName="Helvetica", leading=13)
    S_BODY_SMALL  = _style("NG_BodySm",     fontSize=8,  textColor=brand_dark,
                            fontName="Helvetica", leading=11)
    S_MONO        = _style("NG_Mono",       fontSize=8,  textColor=brand_dark,
                            fontName="Courier", leading=11)
    S_MONO_BOLD   = _style("NG_MonoBold",   fontSize=8,  textColor=brand_dark,
                            fontName="Courier-Bold", leading=11)
    S_LABEL       = _style("NG_Label",      fontSize=8,  textColor=brand_grey,
                            fontName="Helvetica-Bold")
    S_TABLE_HDR   = _style("NG_TblHdr",     fontSize=8,  textColor=white,
                            fontName="Helvetica-Bold", alignment=TA_LEFT)
    S_TABLE_CELL  = _style("NG_TblCell",    fontSize=8,  textColor=brand_dark,
                            fontName="Helvetica", leading=11)
    S_REACT_PHASE = _style("NG_ReactPhase", fontSize=9,  textColor=white,
                            fontName="Helvetica-Bold", alignment=TA_CENTER)
    S_REACT_TEXT  = _style("NG_ReactText",  fontSize=8,  textColor=brand_dark,
                            fontName="Helvetica", leading=11)
    S_FOOTER      = _style("NG_Footer",     fontSize=7,  textColor=brand_grey,
                            fontName="Helvetica", alignment=TA_CENTER)

    # -- Phase colours for ReAct chain
    PHASE_COLOURS = {
        "observe": _rl_colour((0.12, 0.47, 0.87)),
        "reason":  _rl_colour((0.60, 0.20, 0.80)),
        "act":     _rl_colour((0.86, 0.21, 0.27)),
        "learn":   _rl_colour((0.13, 0.77, 0.55)),
    }

    # -- Common table style helper ------------------------------------------
    def _tbl_style(header_bg=None, row_alt=True) -> list:
        hbg = header_bg or brand_blue
        base = [
            ("BACKGROUND",  (0, 0), (-1, 0),  hbg),
            ("TEXTCOLOR",   (0, 0), (-1, 0),  white),
            ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 8),
            ("ALIGN",       (0, 0), (-1, -1), "LEFT"),
            ("VALIGN",      (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",  (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",(0,0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",(0, 0), (-1, -1), 6),
            ("GRID",        (0, 0), (-1, -1), 0.4, _rl_colour((0.85, 0.87, 0.90))),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1),
             [white, _rl_colour((0.96, 0.97, 0.99))] if row_alt else [white]),
        ]
        return base

    # -- Document layout ---------------------------------------------------
    page_w, page_h = A4
    margin = 1.8 * cm
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=margin,
        rightMargin=margin,
        topMargin=margin,
        bottomMargin=2.0 * cm,
        title=f"Network Guardian {report_type.title()} Threat Report",
        author="Network Guardian Autonomous Agent",
    )
    usable_w = page_w - 2 * margin

    story: list = []

    # -- Header banner (drawn as table row for full-width colour) -----------
    now_utc = datetime.now(timezone.utc)
    date_str = now_utc.strftime("%B %d, %Y  %H:%M UTC")
    risk_colour = _sev_colour(risk_level)

    banner_data = [[
        Paragraph(f"NETWORK GUARDIAN", S_TITLE),
        Paragraph(
            f"<b>{report_type.upper()} THREAT REPORT</b><br/>"
            f"Report ID: {report_id}<br/>{date_str}",
            S_SUBTITLE,
        ),
    ]]
    banner_tbl = Table(banner_data, colWidths=[usable_w * 0.45, usable_w * 0.55])
    banner_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), brand_dark),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
        ("LEFTPADDING",   (0, 0), (-1, -1), 14),
    ]))
    story.append(banner_tbl)
    story.append(Spacer(1, 0.3 * cm))

    # -- Risk / score KPI row -----------------------------------------------
    score_pct = min(100, max(0, threat_score))
    risk_label = risk_level.upper()
    threat_count = len(threats)
    action_count = len([a for a in actions if a.get("success")])

    kpi_data = [[
        Paragraph(f"<b>RISK LEVEL</b><br/><font size='16'>{risk_label}</font>", S_TABLE_HDR),
        Paragraph(f"<b>THREAT SCORE</b><br/><font size='16'>{score_pct:.0f}/100</font>", S_TABLE_HDR),
        Paragraph(f"<b>THREATS FOUND</b><br/><font size='16'>{threat_count}</font>", S_TABLE_HDR),
        Paragraph(f"<b>ACTIONS TAKEN</b><br/><font size='16'>{action_count}</font>", S_TABLE_HDR),
    ]]
    kpi_tbl = Table(kpi_data, colWidths=[usable_w / 4] * 4)
    kpi_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (0, 0), risk_colour),
        ("BACKGROUND",    (1, 0), (1, 0), brand_blue),
        ("BACKGROUND",    (2, 0), (2, 0), brand_dark),
        ("BACKGROUND",    (3, 0), (3, 0), brand_green),
        ("TEXTCOLOR",     (0, 0), (-1, -1), white),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(kpi_tbl)
    story.append(Spacer(1, 0.4 * cm))

    # -- Agent / scan info --------------------------------------------------
    story.append(Paragraph("1. Assessment Overview", S_SECTION))
    story.append(HRFlowable(width=usable_w, thickness=1, color=brand_blue))
    story.append(Spacer(1, 0.15 * cm))

    obs_rows = [
        [Paragraph("<b>Agent</b>", S_LABEL),          Paragraph(agent_label, S_TABLE_CELL)],
        [Paragraph("<b>Report Type</b>", S_LABEL),     Paragraph(report_type.title(), S_TABLE_CELL)],
        [Paragraph("<b>Risk Level</b>", S_LABEL),      Paragraph(risk_label, S_TABLE_CELL)],
        [Paragraph("<b>Threat Score</b>", S_LABEL),    Paragraph(f"{score_pct:.0f} / 100", S_TABLE_CELL)],
        [Paragraph("<b>Generated</b>", S_LABEL),       Paragraph(date_str, S_TABLE_CELL)],
    ]
    for k, v in observations.items():
        obs_rows.append([
            Paragraph(f"<b>{str(k).replace('_', ' ').title()}</b>", S_LABEL),
            Paragraph(_wrap(str(v), 80), S_TABLE_CELL),
        ])

    obs_tbl = Table(obs_rows, colWidths=[usable_w * 0.28, usable_w * 0.72])
    obs_tbl.setStyle(TableStyle([
        ("ALIGN",       (0, 0), (-1, -1), "LEFT"),
        ("VALIGN",      (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",  (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",(0,0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("GRID",        (0, 0), (-1, -1), 0.3, _rl_colour((0.85, 0.87, 0.90))),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [white, _rl_colour((0.96, 0.97, 0.99))]),
    ]))
    story.append(obs_tbl)
    story.append(Spacer(1, 0.4 * cm))

    # -- ReAct Chain --------------------------------------------------------
    story.append(Paragraph("2. ReAct Reasoning Chain", S_SECTION))
    story.append(HRFlowable(width=usable_w, thickness=1, color=brand_blue))
    story.append(Spacer(1, 0.15 * cm))
    story.append(Paragraph(
        "The autonomous agent executed the following Observe → Reason → Act → Learn cycle:",
        S_BODY_SMALL,
    ))
    story.append(Spacer(1, 0.15 * cm))

    for step in react_steps:
        phase   = str(step.get("phase", "")).lower()
        thought = str(step.get("thought", ""))
        detail  = step.get("detail")
        ts      = str(step.get("timestamp", ""))[:19].replace("T", " ")

        phase_col = PHASE_COLOURS.get(phase, brand_grey)
        phase_upper = phase.upper()

        step_data = [[
            Paragraph(phase_upper, S_REACT_PHASE),
            Paragraph(_wrap(thought, 85), S_REACT_TEXT),
        ]]
        if detail and isinstance(detail, dict):
            detail_lines = "  ·  ".join(f"{k}: {v}" for k, v in list(detail.items())[:6])
            step_data.append([
                Paragraph("", S_LABEL),
                Paragraph(f'<font name="Courier" size="7" color="#555566">{_wrap(detail_lines, 90)}</font>', S_BODY_SMALL),
            ])
        elif detail:
            step_data.append([
                Paragraph("", S_LABEL),
                Paragraph(f'<font name="Courier" size="7" color="#555566">{_wrap(str(detail), 90)}</font>', S_BODY_SMALL),
            ])

        if ts:
            step_data.append([
                Paragraph("", S_LABEL),
                Paragraph(f'<font size="7" color="#8c8c99">{ts}</font>', S_BODY_SMALL),
            ])

        step_tbl = Table(step_data, colWidths=[usable_w * 0.12, usable_w * 0.88])
        step_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (0, -1), phase_col),
            ("BACKGROUND",    (1, 0), (1, -1), white),
            ("TEXTCOLOR",     (0, 0), (0, -1), white),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            ("BOX",           (0, 0), (-1, -1), 0.5, _rl_colour((0.82, 0.84, 0.88))),
            ("LINEAFTER",     (0, 0), (0, -1),  1.0, _rl_colour((0.82, 0.84, 0.88))),
        ]))
        story.append(KeepTogether([step_tbl, Spacer(1, 0.1 * cm)]))

    story.append(Spacer(1, 0.3 * cm))

    # -- Threat inventory ---------------------------------------------------
    story.append(Paragraph("3. Threat Inventory", S_SECTION))
    story.append(HRFlowable(width=usable_w, thickness=1, color=brand_blue))
    story.append(Spacer(1, 0.15 * cm))

    if threats:
        t_header = [
            Paragraph("Severity",  S_TABLE_HDR),
            Paragraph("Threat",    S_TABLE_HDR),
            Paragraph("Category",  S_TABLE_HDR),
            Paragraph("Detail",    S_TABLE_HDR),
            Paragraph("Action",    S_TABLE_HDR),
            Paragraph("Resolved",  S_TABLE_HDR),
        ]
        t_rows = [t_header]
        for t in threats:
            sev  = str(t.get("severity", "medium"))
            scol = _sev_colour(sev)
            resolved = "✓" if t.get("resolved") else "✗"
            t_rows.append([
                Paragraph(f'<font color="{scol.hexval()}">{sev.upper()}</font>', S_TABLE_CELL),
                Paragraph(_wrap(t.get("title", ""), 30), S_TABLE_CELL),
                Paragraph(_wrap(t.get("category", ""), 20), S_TABLE_CELL),
                Paragraph(_wrap(t.get("detail", ""), 40), S_TABLE_CELL),
                Paragraph(_wrap(t.get("action_taken", "—"), 30), S_TABLE_CELL),
                Paragraph(resolved, S_TABLE_CELL),
            ])
        t_tbl = Table(t_rows, colWidths=[
            usable_w * 0.10,
            usable_w * 0.18,
            usable_w * 0.13,
            usable_w * 0.32,
            usable_w * 0.19,
            usable_w * 0.08,
        ], repeatRows=1)
        t_tbl.setStyle(TableStyle(_tbl_style()))
        story.append(t_tbl)
    else:
        story.append(Paragraph("No threats detected in this assessment cycle. System appears clean.", S_BODY))

    story.append(Spacer(1, 0.4 * cm))

    # -- Actions taken ------------------------------------------------------
    story.append(Paragraph("4. Automated Actions Taken", S_SECTION))
    story.append(HRFlowable(width=usable_w, thickness=1, color=brand_blue))
    story.append(Spacer(1, 0.15 * cm))

    if actions:
        a_header = [
            Paragraph("Action",   S_TABLE_HDR),
            Paragraph("Detail",   S_TABLE_HDR),
            Paragraph("Result",   S_TABLE_HDR),
        ]
        a_rows = [a_header]
        for a in actions:
            result_text = "SUCCESS" if a.get("success") else "FAILED"
            result_col  = brand_green if a.get("success") else brand_red
            a_rows.append([
                Paragraph(_wrap(a.get("action", "—"), 30), S_TABLE_CELL),
                Paragraph(_wrap(a.get("detail", "—"), 60), S_TABLE_CELL),
                Paragraph(
                    f'<font color="{result_col.hexval()}"><b>{result_text}</b></font>',
                    S_TABLE_CELL,
                ),
            ])
        a_tbl = Table(a_rows, colWidths=[usable_w * 0.25, usable_w * 0.62, usable_w * 0.13], repeatRows=1)
        a_tbl.setStyle(TableStyle(_tbl_style()))
        story.append(a_tbl)
    else:
        story.append(Paragraph("No automated actions were executed.", S_BODY))

    story.append(Spacer(1, 0.4 * cm))

    # -- Recommendations ----------------------------------------------------
    story.append(Paragraph("5. Recommendations", S_SECTION))
    story.append(HRFlowable(width=usable_w, thickness=1, color=brand_blue))
    story.append(Spacer(1, 0.15 * cm))

    if recommendations:
        for i, rec in enumerate(recommendations, 1):
            story.append(Paragraph(f"<b>{i}.</b>  {rec}", S_BODY))
            story.append(Spacer(1, 0.08 * cm))
    else:
        story.append(Paragraph("No specific recommendations for this cycle.", S_BODY))

    story.append(Spacer(1, 0.4 * cm))

    # -- Footer strip -------------------------------------------------------
    footer_data = [[
        Paragraph(
            f"Network Guardian  ·  {report_type.title()} Threat Report  ·  "
            f"Report {report_id}  ·  {date_str}  ·  CONFIDENTIAL",
            S_FOOTER,
        )
    ]]
    footer_tbl = Table(footer_data, colWidths=[usable_w])
    footer_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), _rl_colour((0.93, 0.94, 0.96))),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("BOX",           (0, 0), (-1, -1), 0.3, brand_grey),
    ]))
    story.append(footer_tbl)

    # -- Build PDF ----------------------------------------------------------
    doc.build(story)
    logger.info("[PDF] Report written to %s", output_path)

    # Mirror to project pdf_reports/ folder
    try:
        import shutil
        shutil.copy2(str(output_path), str(proj_copy))
        logger.info("[PDF] Mirrored to %s", proj_copy)
    except OSError as e:
        logger.warning("Failed to mirror PDF: %s", e)

    return output_path
