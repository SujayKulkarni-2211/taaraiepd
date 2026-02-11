"""
Taara Words - Professional PDF Report Generator
=================================================

Generates comprehensive, branded PDF security reports.
This is the paid tier (₹50k-1L) deliverable.

Report includes:
- Executive summary with quantum risk score
- Detailed findings by category
- Quantum analysis with circuit explanation
- Prioritized remediation steps
- Cost-benefit analysis (fix cost vs breach cost)
- Cloud spending analysis (Preserve Cash)
- Professional branding: "Prevent Crash, Preserve Cash"
"""

import streamlit as st
import time
import io
import os
import json
from typing import Dict, List, Optional
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm, cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, Image, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.graphics.shapes import Drawing, Rect, Circle, String, Line
from reportlab.graphics import renderPDF


TAARA_RED = colors.HexColor('#e94560')
TAARA_DARK = colors.HexColor('#1a1a2e')
TAARA_NAVY = colors.HexColor('#16213e')
TAARA_BLUE = colors.HexColor('#0f3460')
TAARA_LIGHT = colors.HexColor('#a0a0b0')
TAARA_WHITE = colors.HexColor('#f0f0f0')
SEVERITY_COLORS = {
    'critical': colors.HexColor('#ff0000'),
    'high': colors.HexColor('#ff6600'),
    'medium': colors.HexColor('#ffaa00'),
    'low': colors.HexColor('#00cc00'),
    'info': colors.HexColor('#4488ff')
}


def _get_styles():
    """Create custom report styles."""
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name='TaaraTitle', fontSize=28, textColor=TAARA_RED,
        fontName='Helvetica-Bold', alignment=TA_CENTER, spaceAfter=6
    ))
    styles.add(ParagraphStyle(
        name='TaaraSubtitle', fontSize=14, textColor=TAARA_LIGHT,
        fontName='Helvetica', alignment=TA_CENTER, spaceAfter=20
    ))
    styles.add(ParagraphStyle(
        name='SectionHeader', fontSize=16, textColor=TAARA_RED,
        fontName='Helvetica-Bold', spaceAfter=10, spaceBefore=20,
        borderWidth=0, borderColor=TAARA_RED, borderPadding=5
    ))
    styles.add(ParagraphStyle(
        name='SubHeader', fontSize=12, textColor=TAARA_BLUE,
        fontName='Helvetica-Bold', spaceAfter=6, spaceBefore=10
    ))
    styles.add(ParagraphStyle(
        name='BodyText2', fontSize=10, textColor=colors.black,
        fontName='Helvetica', alignment=TA_JUSTIFY, spaceAfter=6,
        leading=14
    ))
    styles.add(ParagraphStyle(
        name='FindingTitle', fontSize=11, textColor=colors.black,
        fontName='Helvetica-Bold', spaceAfter=3
    ))
    styles.add(ParagraphStyle(
        name='FindingDetail', fontSize=9, textColor=colors.HexColor('#444444'),
        fontName='Helvetica', spaceAfter=4, leftIndent=20, leading=12
    ))
    styles.add(ParagraphStyle(
        name='Footer', fontSize=8, textColor=TAARA_LIGHT,
        fontName='Helvetica', alignment=TA_CENTER
    ))
    styles.add(ParagraphStyle(
        name='Disclaimer', fontSize=7, textColor=colors.HexColor('#999999'),
        fontName='Helvetica-Oblique', alignment=TA_CENTER, leading=9
    ))
    return styles


def generate_report_pdf(analysis_results: Dict, report_config: Dict = None) -> bytes:
    """
    Generate a complete professional PDF report.

    Args:
        analysis_results: Results from TaaraAnalysis
        report_config: Optional configuration (client name, etc.)

    Returns:
        bytes: PDF file content
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=1.5*cm, bottomMargin=2*cm,
        leftMargin=2*cm, rightMargin=2*cm
    )

    styles = _get_styles()
    story = []
    config = report_config or {}

    _build_cover_page(story, styles, analysis_results, config)
    story.append(PageBreak())

    _build_executive_summary(story, styles, analysis_results)
    story.append(PageBreak())

    _build_quantum_analysis(story, styles, analysis_results)
    story.append(PageBreak())

    _build_detailed_findings(story, styles, analysis_results)
    story.append(PageBreak())

    _build_remediation_plan(story, styles, analysis_results)
    story.append(PageBreak())

    _build_cost_benefit(story, styles, analysis_results)

    cost_analysis = analysis_results.get('cost_analysis')
    if cost_analysis and not cost_analysis.get('error'):
        story.append(PageBreak())
        _build_cloud_cost_section(story, styles, cost_analysis)

    story.append(PageBreak())
    _build_appendix(story, styles, analysis_results)

    def add_page_number(canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(TAARA_LIGHT)
        page_num = canvas.getPageNumber()
        canvas.drawCentredString(A4[0]/2, 1*cm, f"TAARA Security Report — Page {page_num}")
        canvas.drawString(2*cm, 1*cm, "CONFIDENTIAL")
        canvas.drawRightString(A4[0] - 2*cm, 1*cm, "Prevent Crash, Preserve Cash")
        canvas.restoreState()

    doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
    return buffer.getvalue()


def _build_cover_page(story, styles, results, config):
    """Build the report cover page."""
    story.append(Spacer(1, 3*cm))

    story.append(Paragraph("TAARA", styles['TaaraTitle']))
    story.append(Paragraph(
        "Trajectory-Aware Adaptive Residual Analysis",
        styles['TaaraSubtitle']
    ))
    story.append(Spacer(1, 0.5*cm))

    d = Drawing(400, 2)
    d.add(Line(0, 1, 400, 1, strokeColor=TAARA_RED, strokeWidth=2))
    story.append(d)

    story.append(Spacer(1, 1*cm))
    story.append(Paragraph(
        "Quantum-Enhanced Security Assessment Report",
        ParagraphStyle('CoverSub', fontSize=18, textColor=TAARA_NAVY,
                       fontName='Helvetica-Bold', alignment=TA_CENTER, spaceAfter=30)
    ))

    quantum_risk = results.get('quantum_risk', {})
    risk_score = quantum_risk.get('risk_score', 0)
    severity = quantum_risk.get('severity', 'UNKNOWN')

    score_table_data = [
        ['Quantum Risk Score', f'{risk_score}/100'],
        ['Severity Level', severity],
        ['Platform', results.get('platform', 'Unknown').upper()],
        ['Scan Date', datetime.now().strftime('%B %d, %Y')],
    ]

    if config.get('client_name'):
        score_table_data.insert(0, ['Client', config['client_name']])

    score_table = Table(score_table_data, colWidths=[200, 200])
    score_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), TAARA_NAVY),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.white),
        ('BACKGROUND', (1, 0), (1, -1), colors.HexColor('#f5f5f5')),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 12),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#cccccc')),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.HexColor('#f9f9f9'), colors.white]),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(score_table)

    story.append(Spacer(1, 2*cm))
    story.append(Paragraph(
        "Prevent Crash, Preserve Cash",
        ParagraphStyle('Tagline', fontSize=16, textColor=TAARA_RED,
                       fontName='Helvetica-BoldOblique', alignment=TA_CENTER)
    ))
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph(
        "This report is confidential and intended solely for the named recipient. "
        "Unauthorized distribution is prohibited.",
        styles['Disclaimer']
    ))


def _build_executive_summary(story, styles, results):
    """Build the executive summary section."""
    story.append(Paragraph("1. Executive Summary", styles['SectionHeader']))

    d = Drawing(460, 2)
    d.add(Line(0, 1, 460, 1, strokeColor=TAARA_RED, strokeWidth=1))
    story.append(d)

    quantum_risk = results.get('quantum_risk', {})
    security_data = results.get('security_data', {})
    summary = security_data.get('summary', {})

    total = sum(summary.values())
    critical = summary.get('critical', 0)
    high = summary.get('high', 0)

    risk_score = quantum_risk.get('risk_score', 0)
    severity = quantum_risk.get('severity', 'UNKNOWN')

    story.append(Paragraph(
        f"TAARA's quantum-enhanced security assessment identified <b>{total} security findings</b> "
        f"across the target {results.get('platform', '').upper()} environment, including "
        f"<font color='red'><b>{critical} critical</b></font> and "
        f"<font color='#ff6600'><b>{high} high</b></font> severity issues.",
        styles['BodyText2']
    ))
    story.append(Spacer(1, 0.3*cm))

    story.append(Paragraph(
        f"The quantum risk score of <b>{risk_score}/100 ({severity})</b> was computed using "
        f"TAARA's reconstruction-based novelty detection with 4-qubit PennyLane quantum "
        f"validation circuit. This score reflects both the magnitude and <i>directional novelty</i> "
        f"of detected vulnerabilities — measuring not just how severe issues are, but whether "
        f"they represent fundamentally new attack surfaces.",
        styles['BodyText2']
    ))

    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph("Findings Summary", styles['SubHeader']))

    summary_data = [
        ['Severity', 'Count', 'Percentage'],
        ['Critical', str(critical), f'{critical/max(total,1)*100:.0f}%'],
        ['High', str(high), f'{high/max(total,1)*100:.0f}%'],
        ['Medium', str(summary.get('medium', 0)), f'{summary.get("medium",0)/max(total,1)*100:.0f}%'],
        ['Low', str(summary.get('low', 0)), f'{summary.get("low",0)/max(total,1)*100:.0f}%'],
        ['Total', str(total), '100%']
    ]

    t = Table(summary_data, colWidths=[150, 100, 100])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), TAARA_NAVY),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9f9f9')]),
        ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#e8e8e8')),
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(t)


def _build_quantum_analysis(story, styles, results):
    """Build quantum analysis section with circuit explanation."""
    story.append(Paragraph("2. Quantum Analysis", styles['SectionHeader']))

    d = Drawing(460, 2)
    d.add(Line(0, 1, 460, 1, strokeColor=TAARA_RED, strokeWidth=1))
    story.append(d)

    story.append(Paragraph("2.1 Quantum-Enhanced Detection Methodology", styles['SubHeader']))
    story.append(Paragraph(
        "TAARA employs a novel approach to security analysis: rather than relying solely on "
        "statistical deviation detection (which sophisticated attackers can evade by operating "
        "within 'normal' ranges), TAARA uses <b>reconstruction-based novelty detection</b> with "
        "<b>quantum fidelity validation</b>.",
        styles['BodyText2']
    ))
    story.append(Paragraph(
        "The system asks: 'Can this behavioral state be explained by prior observations?' "
        "If the reconstruction residual exceeds all previously observed residuals, the behavior "
        "is flagged as <b>novel</b> — regardless of whether individual metrics appear statistically normal.",
        styles['BodyText2']
    ))

    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("2.2 Quantum Validation Circuit", styles['SubHeader']))
    story.append(Paragraph(
        "TAARA's quantum validation layer uses a 4-qubit PennyLane circuit to distinguish "
        "between magnitude novelty (same direction, different scale) and directional novelty "
        "(genuinely new behavioral dimension). The circuit architecture:",
        styles['BodyText2']
    ))

    circuit_data = [
        ['Layer', 'Operation', 'Purpose'],
        ['1', 'Amplitude Embedding', 'Encode residual direction into quantum state |ψ⟩'],
        ['2', 'Hadamard Gates (H)', 'Create superposition across all 4 qubits'],
        ['3', 'Ring CNOT (0→1→2→3→0)', 'Entangle qubits in ring topology'],
        ['4', 'RX, RY, RZ (π/4)', 'Parameterized rotations for state transformation'],
        ['5', 'State Measurement', 'Extract statevector for fidelity computation'],
    ]

    ct = Table(circuit_data, colWidths=[40, 160, 260])
    ct.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), TAARA_BLUE),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f5ff')]),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(ct)

    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("2.3 Fidelity Measurement Results", styles['SubHeader']))

    qr = results.get('quantum_risk', {})
    fidelity_data = [
        ['Metric', 'Value', 'Interpretation'],
        ['Quantum Risk Score', f'{qr.get("risk_score", 0)}/100', qr.get('severity', 'N/A')],
        ['Minimum Fidelity (F_min)', f'{qr.get("f_min", 0):.4f}',
         'Low = orthogonal to prior states'],
        ['Quantum Novelty', f'{qr.get("quantum_novelty", 0)}%',
         'High = genuinely new behavioral direction'],
        ['Directionally Novel', 'Yes' if qr.get('is_directionally_novel') else 'No',
         'F_min < 0.5 confirms directional shift'],
    ]

    ft = Table(fidelity_data, colWidths=[130, 100, 230])
    ft.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), TAARA_NAVY),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9f9f9')]),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(ft)

    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        "<b>Note on quantum claims:</b> TAARA does not claim quantum advantage or speedup. "
        "The current 4-qubit circuit is classically simulable. Quantum state fidelity measurement "
        "is used specifically to <i>validate</i> classical detections — confirming that flagged "
        "novelty represents directional behavioral shifts, not merely magnitude variations. "
        "This is an honest, narrow application of quantum computing's strengths.",
        ParagraphStyle('Disclaimer2', fontSize=8, textColor=colors.HexColor('#666666'),
                       fontName='Helvetica-Oblique', leading=10, spaceAfter=6)
    ))


def _build_detailed_findings(story, styles, results):
    """Build detailed findings section."""
    story.append(Paragraph("3. Detailed Findings", styles['SectionHeader']))

    d = Drawing(460, 2)
    d.add(Line(0, 1, 460, 1, strokeColor=TAARA_RED, strokeWidth=1))
    story.append(d)

    security_data = results.get('security_data', {})
    finding_num = 0

    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}

    all_findings = []
    for cat_key, cat_data in security_data.get('categories', {}).items():
        cat_name = cat_data.get('name', cat_key)
        for finding in cat_data.get('findings', []):
            finding['category'] = cat_name
            all_findings.append(finding)

    all_findings.sort(key=lambda x: severity_order.get(x.get('severity', 'info'), 5))

    for finding in all_findings:
        finding_num += 1
        sev = finding.get('severity', 'info')
        sev_color = SEVERITY_COLORS.get(sev, colors.gray)

        story.append(Paragraph(
            f"<font color='{sev_color.hexval()}'>[{sev.upper()}]</font> "
            f"Finding #{finding_num}: {finding.get('title', 'Untitled')}",
            styles['FindingTitle']
        ))
        story.append(Paragraph(
            f"<b>Category:</b> {finding.get('category', 'General')}",
            styles['FindingDetail']
        ))
        story.append(Paragraph(
            f"<b>Detail:</b> {finding.get('detail', 'No details available')}",
            styles['FindingDetail']
        ))
        story.append(Paragraph(
            f"<b>Remediation:</b> {finding.get('remediation', 'Consult security team')}",
            styles['FindingDetail']
        ))
        story.append(Spacer(1, 0.2*cm))

    if not all_findings:
        story.append(Paragraph(
            "No significant security findings were identified during this assessment.",
            styles['BodyText2']
        ))


def _build_remediation_plan(story, styles, results):
    """Build prioritized remediation plan."""
    story.append(Paragraph("4. Prioritized Remediation Plan", styles['SectionHeader']))

    d = Drawing(460, 2)
    d.add(Line(0, 1, 460, 1, strokeColor=TAARA_RED, strokeWidth=1))
    story.append(d)

    security_data = results.get('security_data', {})
    all_findings = []
    for cat_data in security_data.get('categories', {}).values():
        all_findings.extend(cat_data.get('findings', []))

    priorities = {
        'critical': {'label': 'Immediate (24 hours)', 'findings': []},
        'high': {'label': 'Short-term (1 week)', 'findings': []},
        'medium': {'label': 'Medium-term (1 month)', 'findings': []},
        'low': {'label': 'Long-term (quarterly)', 'findings': []}
    }

    for f in all_findings:
        sev = f.get('severity', 'info')
        if sev in priorities:
            priorities[sev]['findings'].append(f)

    for sev, data in priorities.items():
        if data['findings']:
            sev_color = SEVERITY_COLORS.get(sev, colors.gray)
            story.append(Paragraph(
                f"<font color='{sev_color.hexval()}'>{sev.upper()}</font> — {data['label']}",
                styles['SubHeader']
            ))
            for i, f in enumerate(data['findings'], 1):
                story.append(Paragraph(
                    f"{i}. <b>{f.get('title', '')}</b> — {f.get('remediation', '')}",
                    styles['FindingDetail']
                ))
            story.append(Spacer(1, 0.3*cm))


def _build_cost_benefit(story, styles, results):
    """Build cost-benefit analysis section."""
    story.append(Paragraph("5. Cost-Benefit Analysis", styles['SectionHeader']))

    d = Drawing(460, 2)
    d.add(Line(0, 1, 460, 1, strokeColor=TAARA_RED, strokeWidth=1))
    story.append(d)

    security_data = results.get('security_data', {})
    summary = security_data.get('summary', {})
    total = sum(summary.values())
    critical = summary.get('critical', 0)

    breach_cost_lakh = max(5, total * 2 + critical * 15)

    remediation_data = [
        ['Item', 'Estimated Cost', 'Timeline'],
        ['TAARA Security Assessment', '₹50,000 - ₹1,00,000', 'Completed'],
        ['Critical Issue Remediation', f'₹{critical * 25000:,}', '1-2 weeks'],
        ['Security Infrastructure', '₹50,000 - ₹2,00,000', '1-3 months'],
        ['Continuous Monitoring (Annual)', '₹3,00,000 - ₹6,00,000', 'Ongoing'],
        ['', '', ''],
        ['Total Investment', f'₹{(critical * 25000 + 300000):,} - ₹{(critical * 25000 + 900000):,}', ''],
        ['Estimated Breach Cost (Avoided)', f'₹{breach_cost_lakh} Lakh - ₹{breach_cost_lakh * 3} Lakh', ''],
        ['ROI', f'{breach_cost_lakh * 100000 / max((critical * 25000 + 300000), 1):.0f}x return', ''],
    ]

    t = Table(remediation_data, colWidths=[200, 150, 110])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), TAARA_NAVY),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -2), [colors.white, colors.HexColor('#f9f9f9')]),
        ('BACKGROUND', (0, -3), (-1, -1), colors.HexColor('#fff0f0')),
        ('FONTNAME', (0, -3), (-1, -1), 'Helvetica-Bold'),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t)

    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph(
        f"<b>Key Insight:</b> For every ₹1 invested in security remediation, "
        f"the estimated return is ₹{breach_cost_lakh * 100000 / max((critical * 25000 + 300000), 1):.0f} "
        f"in avoided breach costs. The average MSME data breach in India costs ₹2-5 Crore "
        f"(IBM Cost of Data Breach Report 2025), not including reputational damage and "
        f"regulatory penalties under DPDPA 2023.",
        styles['BodyText2']
    ))


def _build_cloud_cost_section(story, styles, cost_analysis):
    """Build cloud cost optimization section."""
    story.append(Paragraph("6. Cloud Cost Analysis — Preserve Cash", styles['SectionHeader']))

    d = Drawing(460, 2)
    d.add(Line(0, 1, 460, 1, strokeColor=TAARA_RED, strokeWidth=1))
    story.append(d)

    story.append(Paragraph(
        f"Monthly Cloud Spend: <b>${cost_analysis.get('total_monthly_cost', 0):,.2f}</b> | "
        f"Potential Savings: <b>${cost_analysis.get('potential_monthly_savings', 0):,.2f}/month</b> | "
        f"Preserve Cash Score: <b>{cost_analysis.get('preserve_cash_score', 0)}/100</b>",
        styles['BodyText2']
    ))

    for w in cost_analysis.get('waste_findings', []):
        story.append(Paragraph(
            f"<font color='#ff6600'>[WASTE]</font> <b>{w.get('title', '')}</b> "
            f"— Savings: {w.get('potential_savings', 'N/A')}",
            styles['FindingDetail']
        ))

    for r in cost_analysis.get('optimization_recommendations', []):
        story.append(Paragraph(
            f"<font color='#0066cc'>[OPTIMIZE]</font> <b>{r.get('title', '')}</b> "
            f"— Savings: {r.get('potential_savings', 'N/A')}",
            styles['FindingDetail']
        ))


def _build_appendix(story, styles, results):
    """Build appendix with methodology and disclaimers."""
    story.append(Paragraph("Appendix: Methodology & Disclaimers", styles['SectionHeader']))

    d = Drawing(460, 2)
    d.add(Line(0, 1, 460, 1, strokeColor=TAARA_RED, strokeWidth=1))
    story.append(d)

    story.append(Paragraph("About TAARA", styles['SubHeader']))
    story.append(Paragraph(
        "TAARA (Trajectory-Aware Adaptive Residual Analysis) is a reconstruction-based "
        "behavioral novelty detection system. Unlike traditional security tools that rely "
        "on deviation detection (statistical thresholds), TAARA identifies behavioral patterns "
        "that cannot be reconstructed from prior observations — detecting the emergence of "
        "fundamentally new behavioral dimensions before they manifest as statistical anomalies.",
        styles['BodyText2']
    ))

    story.append(Paragraph("Quantum Validation Layer", styles['SubHeader']))
    story.append(Paragraph(
        "The quantum validation component uses PennyLane (default.qubit simulator) to perform "
        "state fidelity measurement between residual direction vectors. This validates whether "
        "classical novelty detections represent genuine directional behavioral shifts (new attack "
        "surfaces) or merely magnitude variations (workload changes). The 4-qubit circuit is "
        "classically simulable — no quantum advantage is claimed.",
        styles['BodyText2']
    ))

    story.append(Paragraph("Limitations", styles['SubHeader']))
    story.append(Paragraph(
        "This assessment represents a point-in-time snapshot. Security posture changes continuously. "
        "Findings are based on automated scanning and may not capture all vulnerabilities. "
        "False positives are possible. This report does not constitute a penetration test. "
        "Recommendations should be reviewed by qualified security professionals before implementation.",
        styles['BodyText2']
    ))

    story.append(Spacer(1, 1*cm))
    story.append(Paragraph(
        "Generated by TAARA Security Analyzer | Prevent Crash, Preserve Cash",
        styles['Footer']
    ))
    story.append(Paragraph(
        f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
        f"TAARA v2.0 | Quantum-Enhanced Pattern Detection",
        styles['Disclaimer']
    ))


def render_taara_words(analysis_results: Dict):
    """Render the Taara Words (Report Generator) page in Streamlit."""

    st.markdown("""
    <div style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                padding: 30px; border-radius: 15px; margin-bottom: 20px;
                border: 1px solid #0f3460;">
        <h1 style="color: #e94560; margin: 0; font-size: 2.2em;">
            Taara Words
        </h1>
        <p style="color: #a0a0b0; margin: 5px 0 0 0; font-size: 1.1em;">
            Professional Security Assessment Report Generator
        </p>
    </div>
    """, unsafe_allow_html=True)

    if not analysis_results:
        st.warning("No analysis data available. Run TaaraAnalysis first.")
        return

    st.markdown("### Report Configuration")

    col1, col2 = st.columns(2)
    with col1:
        client_name = st.text_input("Client Name", value="", placeholder="Enter client organization name")
    with col2:
        report_type = st.selectbox("Report Type", [
            "Full Security Assessment",
            "Executive Summary Only",
            "Technical Deep-Dive"
        ])

    include_cost = st.checkbox("Include Cloud Cost Analysis (Preserve Cash)", value=True)
    include_quantum = st.checkbox("Include Quantum Analysis Details", value=True)

    quantum_risk = analysis_results.get('quantum_risk', {})
    security_data = analysis_results.get('security_data', {})
    summary = security_data.get('summary', {})
    total = sum(summary.values())

    st.markdown("### Report Preview")
    pcol1, pcol2, pcol3 = st.columns(3)
    with pcol1:
        st.metric("Total Findings", total)
    with pcol2:
        st.metric("Risk Score", f"{quantum_risk.get('risk_score', 0)}/100")
    with pcol3:
        st.metric("Report Pages", "8-12 (estimated)")

    if st.button("Generate PDF Report", type="primary", use_container_width=True):
        with st.spinner("Generating professional report with quantum analysis..."):
            config = {'client_name': client_name}
            pdf_bytes = generate_report_pdf(analysis_results, config)

            st.success("Report generated successfully!")
            st.download_button(
                label="Download TAARA Security Report (PDF)",
                data=pdf_bytes,
                file_name=f"TAARA_Security_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
                mime="application/pdf",
                type="primary",
                use_container_width=True
            )

            st.markdown(f"""
            <div style="text-align: center; padding: 15px; background: #0a1a0a;
                        border-radius: 10px; margin-top: 15px; border: 1px solid #00cc00;">
                <p style="color: #00cc00; font-size: 1.2em; margin: 0;">
                    Report generated: {total} findings | Risk Score: {quantum_risk.get('risk_score', 0)}/100
                </p>
            </div>
            """, unsafe_allow_html=True)
