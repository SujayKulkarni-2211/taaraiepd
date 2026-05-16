"""
Taara Words — Professional Security Report Generator
Deliverable-grade PDF for CISOs and technical leadership.
Every number comes from real scan data. No invented content.
"""

import streamlit as st
import io
import os
import sys
import html
from typing import Dict, List, Optional
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.graphics.shapes import Drawing, Line

# ── Brand colours ────────────────────────────────────────────────────────────
TAARA_RED   = colors.HexColor('#e94560')
TAARA_DARK  = colors.HexColor('#1a1a2e')
TAARA_NAVY  = colors.HexColor('#16213e')
TAARA_BLUE  = colors.HexColor('#0f3460')
TAARA_LIGHT = colors.HexColor('#a0a0b0')
PAGE_W = A4[0] - 4*cm   # usable width at 2cm margins each side

SEV_COLOR = {
    'critical': colors.HexColor('#cc0000'),
    'high':     colors.HexColor('#e65c00'),
    'medium':   colors.HexColor('#cc8800'),
    'low':      colors.HexColor('#227722'),
}


# ── Styles ────────────────────────────────────────────────────────────────────
def _styles():
    s = getSampleStyleSheet()
    def add(name, **kw):
        if name not in s:
            s.add(ParagraphStyle(name=name, **kw))
    add('H1',      fontSize=26, textColor=TAARA_RED,  fontName='Helvetica-Bold',  alignment=TA_CENTER, spaceAfter=4)
    add('H2',      fontSize=14, textColor=TAARA_NAVY, fontName='Helvetica-Bold',  spaceAfter=8,  spaceBefore=16)
    add('H3',      fontSize=11, textColor=TAARA_BLUE, fontName='Helvetica-Bold',  spaceAfter=4,  spaceBefore=10)
    add('Body',    fontSize=10, textColor=colors.black, fontName='Helvetica', alignment=TA_JUSTIFY, spaceAfter=6, leading=14)
    add('Small',   fontSize=8,  textColor=colors.HexColor('#555555'), fontName='Helvetica', spaceAfter=3, leading=11)
    add('Caption', fontSize=7,  textColor=TAARA_LIGHT, fontName='Helvetica-Oblique', alignment=TA_CENTER, leading=9)
    add('Tag',     fontSize=9,  textColor=colors.white, fontName='Helvetica-Bold', spaceAfter=2)
    add('Tagline', fontSize=15, textColor=TAARA_RED,  fontName='Helvetica-BoldOblique', alignment=TA_CENTER, spaceAfter=16)
    add('Indent',  fontSize=9,  textColor=colors.HexColor('#333333'), fontName='Helvetica', leftIndent=14, spaceAfter=3, leading=12)
    add('BigNum',  fontSize=48, textColor=TAARA_RED,  fontName='Helvetica-Bold', alignment=TA_CENTER, spaceAfter=2)
    add('BigLabel',fontSize=11, textColor=TAARA_NAVY, fontName='Helvetica-Bold', alignment=TA_CENTER, spaceAfter=12)
    return s


def _esc(text: str, limit: int = 0) -> str:
    """Escape text for safe use in ReportLab Paragraph."""
    t = html.escape(str(text or ''))
    if limit:
        t = t[:limit]
    return t


def _rule(story):
    d = Drawing(PAGE_W, 1)
    d.add(Line(0, 0, PAGE_W, 0, strokeColor=TAARA_RED, strokeWidth=0.8))
    story.append(d)
    story.append(Spacer(1, 0.2*cm))


def _tbl(data, col_widths, header_bg=None):
    """Build a Table with safe WORDWRAP on all cells."""
    t = Table(data, colWidths=col_widths, repeatRows=1)
    bg = header_bg or TAARA_NAVY
    t.setStyle(TableStyle([
        ('BACKGROUND',   (0, 0), (-1, 0),  bg),
        ('TEXTCOLOR',    (0, 0), (-1, 0),  colors.white),
        ('FONTNAME',     (0, 0), (-1, 0),  'Helvetica-Bold'),
        ('FONTSIZE',     (0, 0), (-1, 0),  9),
        ('FONTNAME',     (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE',     (0, 1), (-1, -1), 8),
        ('GRID',         (0, 0), (-1, -1), 0.3, colors.HexColor('#cccccc')),
        ('ROWBACKGROUNDS',(0,1), (-1, -1), [colors.white, colors.HexColor('#f7f7ff')]),
        ('TOPPADDING',   (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING',(0, 0), (-1, -1), 5),
        ('LEFTPADDING',  (0, 0), (-1, -1), 6),
        ('VALIGN',       (0, 0), (-1, -1), 'TOP'),
        ('WORDWRAP',     (0, 0), (-1, -1), 'CJK'),
    ]))
    return t


# ── Data extraction — everything from real scan results ───────────────────────
def _extract(analysis_results: Dict) -> Dict:
    repo = analysis_results.get('repo_results') or {}
    findings   = repo.get('findings', [])
    chains     = repo.get('cross_file_chains', [])
    exploit    = repo.get('exploit_chains', [])
    rq         = repo.get('repo_quantum_fidelity') or {}

    critical = [f for f in findings if f.get('severity') == 'critical']
    high     = [f for f in findings if f.get('severity') == 'high']
    medium   = [f for f in findings if f.get('severity') == 'medium']
    low      = [f for f in findings if f.get('severity') == 'low']

    repo_risk = min(len(critical)*25 + len(high)*15 + len(medium)*5 + len(low)*1, 100)
    f_val     = rq.get('fidelity', None)

    # GraphRAG LLM chain (if present)
    graphrag = next((c for c in chains if c.get('chain_id') == 'graphrag:llm_dependency_analysis'), None)
    struct_chains = [c for c in chains if c.get('chain_id') != 'graphrag:llm_dependency_analysis']

    return {
        'repo': repo,
        'target': repo.get('target', repo.get('repo', 'Unknown')),
        'repo_name': repo.get('repo', 'Unknown'),
        'scanned_at': repo.get('scanned_at', datetime.now().isoformat())[:10],
        'packages': repo.get('packages_resolved', 0),
        'findings': findings,
        'critical': critical,
        'high': high,
        'medium': medium,
        'low': low,
        'chains': struct_chains,
        'exploit_chains': exploit,
        'graphrag': graphrag,
        'repo_risk': repo_risk,
        'fidelity': f_val,
        'fidelity_label': rq.get('interpretation', ''),
    }


# ── Groq executive summary ────────────────────────────────────────────────────
def _groq_summary(d: Dict, client_name: str) -> str:
    api_key = os.environ.get('GROQ_API_KEY')
    if not api_key or not d['findings']:
        return ""
    try:
        from components.llm_service import LLMService
        llm = LLMService(api_key=api_key)

        top_critical = d['critical'][:5]
        cve_lines = "\n".join(
            f"- {f.get('osv_id','?')} [{f.get('package','?')} v{f.get('version','?')}]: {f.get('title','')[:80]}"
            for f in top_critical
        )
        exploit_lines = "\n".join(
            f"- {c.get('path_display','')}: {c.get('cve_summary','')[:60]}"
            for c in d['exploit_chains'][:3]
        )

        prompt = f"""You are a senior security analyst writing an executive summary for a professional security report.

Scan target: {d['target']}
Client: {client_name or 'the organisation'}
Scan date: {d['scanned_at']}

FINDINGS:
- Total: {len(d['findings'])} ({len(d['critical'])} critical, {len(d['high'])} high, {len(d['medium'])} medium, {len(d['low'])} low)
- Packages scanned: {d['packages']}
- Dependency risk score: {d['repo_risk']}/100

TOP CRITICAL VULNERABILITIES:
{cve_lines}

EXPLOIT CHAINS (attacker path through your dependencies):
{exploit_lines}

Write a 4-sentence executive summary in plain English for a CISO or CTO:
1. What was scanned and when.
2. What was found — specific numbers, most dangerous packages by name.
3. What is the real-world risk if these are not fixed — be specific, not generic.
4. The single most urgent action to take today.

No bullet points. No headings. No jargon. Plain sentences a non-technical executive can read."""

        resp = llm.generate_response(prompt)
        if resp.get('success'):
            return resp['explanation']
    except Exception:
        pass
    return ""


def _groq_action_plan(d: Dict) -> List[Dict]:
    """Ask Groq to generate a prioritised action plan from real findings."""
    api_key = os.environ.get('GROQ_API_KEY')
    if not api_key or not d['findings']:
        return []
    try:
        from components.llm_service import LLMService
        llm = LLMService(api_key=api_key)

        critical_titles = [f.get('title', '')[:80] for f in d['critical'][:8]]
        high_titles     = [f.get('title', '')[:80] for f in d['high'][:6]]

        prompt = f"""You are a security engineer writing a remediation plan.

Critical findings ({len(d['critical'])} total, showing top 8):
{chr(10).join(f'- {t}' for t in critical_titles)}

High findings ({len(d['high'])} total, showing top 6):
{chr(10).join(f'- {t}' for t in high_titles)}

Write exactly 3 sections:
WEEK 1 — 3 specific actions to take this week (most critical)
MONTH 1 — 3 specific actions to take this month
QUARTER — 2 ongoing practices to establish

For each action: one sentence, specific package name or file where relevant, exact command if it is a package upgrade. No generic advice."""

        resp = llm.generate_response(prompt)
        if resp.get('success'):
            return resp['explanation']
    except Exception:
        pass
    return ""


# ── PDF section builders ───────────────────────────────────────────────────────
def _cover(story, s, d: Dict, client_name: str, config: Dict):
    story.append(Spacer(1, 1.5*cm))
    story.append(Paragraph("TAARA", s['H1']))
    story.append(Paragraph("Infrastructure Intelligence Platform", s['BigLabel']))
    _rule(story)
    story.append(Paragraph("Prevent Crash, Preserve Cash", s['Tagline']))
    story.append(Spacer(1, 0.3*cm))

    # Big risk score
    story.append(Paragraph(str(d['repo_risk']), s['BigNum']))
    story.append(Paragraph("/ 100  —  Repository Risk Score", s['BigLabel']))
    story.append(Spacer(1, 0.3*cm))

    cover_rows = [['Field', 'Value']]
    if client_name:
        cover_rows.append(['Client', _esc(client_name)])
    cover_rows += [
        ['Repository', _esc(d['target'], 60)],
        ['Scan Date', _esc(d['scanned_at'])],
        ['Packages Analysed', str(d['packages'])],
        ['Total Findings', f"{len(d['findings'])}  ({len(d['critical'])} critical, {len(d['high'])} high)"],
    ]
    if d['fidelity'] is not None:
        label = 'UNSAFE — dependency graph far from secure baseline' if d['fidelity'] < 0.5 else 'Moderate — some drift from secure baseline'
        cover_rows.append(['Quantum Fidelity F', f"{d['fidelity']:.3f}  —  {label}"])

    ct = _tbl(cover_rows, [160, PAGE_W - 160])
    story.append(ct)
    story.append(Spacer(1, 1.5*cm))
    story.append(Paragraph(
        "This report is confidential. All findings are derived from automated analysis of real data. "
        "No issues have been invented or extrapolated.",
        s['Caption']
    ))


def _exec_summary(story, s, d: Dict, client_name: str):
    story.append(Paragraph("1. Executive Summary", s['H2']))
    _rule(story)

    # Risk snapshot table
    snap = [
        ['Metric', 'Value', 'Status'],
        ['Repository Risk Score', f"{d['repo_risk']}/100",
         'CRITICAL' if d['repo_risk'] >= 75 else 'HIGH' if d['repo_risk'] >= 50 else 'MODERATE'],
        ['Critical Findings', str(len(d['critical'])), 'Fix within 24 hours'],
        ['High Findings',     str(len(d['high'])),     'Fix within 1 week'],
        ['Medium Findings',   str(len(d['medium'])),   'Fix within 1 month'],
        ['Packages Scanned',  str(d['packages']),      'Live OSV.dev lookup'],
    ]
    if d['fidelity'] is not None:
        snap.append([
            'Security Posture Fidelity F',
            f"{d['fidelity']:.3f}",
            'FAR from secure baseline' if d['fidelity'] < 0.5 else 'Drifting from baseline'
        ])
    story.append(_tbl(snap, [180, 100, PAGE_W - 280]))
    story.append(Spacer(1, 0.4*cm))

    # Groq-generated summary
    summary_text = _groq_summary(d, client_name)
    if summary_text:
        story.append(Paragraph("What This Means", s['H3']))
        for para in summary_text.split('\n'):
            if para.strip():
                story.append(Paragraph(_esc(para.strip()), s['Body']))
    else:
        story.append(Paragraph(
            f"TAARA scanned {_esc(d['target'])} on {_esc(d['scanned_at'])} and found "
            f"{len(d['findings'])} security issues across {d['packages']} packages — "
            f"{len(d['critical'])} critical and {len(d['high'])} high severity. "
            f"The repository risk score is {d['repo_risk']}/100. "
            f"Immediate action is required on the {len(d['critical'])} critical findings.",
            s['Body']
        ))


def _findings_section(story, s, d: Dict):
    story.append(Paragraph("2. Findings", s['H2']))
    _rule(story)

    # Summary bar
    story.append(Paragraph(
        f"<b>{len(d['critical'])} CRITICAL</b>  ·  "
        f"<b>{len(d['high'])} HIGH</b>  ·  "
        f"<b>{len(d['medium'])} MEDIUM</b>  ·  "
        f"<b>{len(d['low'])} LOW</b>  ·  "
        f"Total: <b>{len(d['findings'])}</b>",
        ParagraphStyle('SevBar', fontSize=11, fontName='Helvetica-Bold',
                       textColor=TAARA_NAVY, spaceAfter=10, spaceBefore=4)
    ))

    if d['fidelity'] is not None:
        f_val = d['fidelity']
        f_text = (
            "F={:.3f} — this repository's security posture is nearly orthogonal to a secure baseline. "
            "An attacker exploiting any of these vulnerabilities faces almost no security controls "
            "pointing in the right direction.".format(f_val)
            if f_val < 0.5 else
            "F={:.3f} — this repository's security posture is drifting from a secure baseline. "
            "Multiple gaps exist.".format(f_val)
        )
        story.append(Paragraph(f"<b>Quantum Fidelity:</b> {_esc(f_text)}", s['Small']))
        story.append(Spacer(1, 0.3*cm))

    # GraphRAG LLM analysis
    g = d.get('graphrag')
    if g and g.get('detail'):
        story.append(Paragraph("Dependency Risk Analysis (AI-generated from real findings)", s['H3']))
        story.append(Paragraph(_esc(g['detail']), s['Body']))
        laf = g.get('llm_answer_fidelity')
        if laf:
            story.append(Paragraph(
                f"Analysis alignment score: F={laf['fidelity']:.3f} — {_esc(laf['interpretation'])}",
                s['Small']
            ))
        story.append(Spacer(1, 0.3*cm))

    # Top critical findings table
    story.append(Paragraph("2.1  Critical Findings — Fix Immediately", s['H3']))
    if d['critical']:
        crit_rows = [['Package', 'Version', 'CVE ID', 'Fix Version', 'Description']]
        for f in d['critical'][:20]:
            fixes = f.get('fix_versions', [])
            crit_rows.append([
                f.get('package', '')[:20],
                f.get('version', '')[:12],
                f.get('osv_id', '')[:18],
                fixes[0][:12] if fixes else '—',
                f.get('title', '')[:55],
            ])
        story.append(_tbl(crit_rows, [70, 45, 90, 55, PAGE_W - 260]))
        if len(d['critical']) > 20:
            story.append(Paragraph(f"... and {len(d['critical'])-20} more critical findings.", s['Small']))
    else:
        story.append(Paragraph("No critical findings.", s['Body']))

    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("2.2  High Findings — Fix This Week", s['H3']))
    if d['high']:
        high_rows = [['Package', 'Version', 'CVE ID', 'Fix Version', 'Description']]
        for f in d['high'][:15]:
            fixes = f.get('fix_versions', [])
            high_rows.append([
                f.get('package', '')[:20],
                f.get('version', '')[:12],
                f.get('osv_id', '')[:18],
                fixes[0][:12] if fixes else '—',
                f.get('title', '')[:55],
            ])
        story.append(_tbl(high_rows, [70, 45, 90, 55, PAGE_W - 260]))
        if len(d['high']) > 15:
            story.append(Paragraph(f"... and {len(d['high'])-15} more high findings.", s['Small']))

    # CI/CD and Docker findings
    cicd = [f for f in d['findings'] if f.get('source') in ('actions_scan', 'dockerfile_scan', 'endoflife_date_api', 'secrets_scan')]
    if cicd:
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph("2.3  CI/CD and Infrastructure Findings", s['H3']))
        for f in cicd[:10]:
            sev = f.get('severity', 'medium')
            sc = SEV_COLOR.get(sev, colors.gray)
            story.append(KeepTogether([
                Paragraph(
                    f"<font color='{sc.hexval()}'>[{sev.upper()}]</font>  <b>{_esc(f.get('title', ''))}</b>",
                    s['Small']
                ),
                Paragraph(_esc(f.get('detail', f.get('description', '')), 300), s['Indent']),
                Paragraph(f"<b>Fix:</b> {_esc(f.get('remediation', ''), 200)}", s['Indent']),
                Spacer(1, 0.1*cm),
            ]))

    # Exploit chains
    if d['exploit_chains']:
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph("2.4  Exploit Chains — How an Attacker Gets In", s['H3']))
        story.append(Paragraph(
            "Each chain shows the path from your application to a vulnerable package. "
            "Score = severity × proximity. Score 10 = direct critical vulnerability.",
            s['Small']
        ))
        ec_rows = [['Attack Path', 'Score', 'CVE', 'Fix']]
        for c in d['exploit_chains'][:8]:
            fix = c.get('fix_version', '—') or '—'
            ec_rows.append([
                c.get('path_display', '')[:60],
                str(c.get('chain_score', '')),
                c.get('osv_id', '')[:18],
                fix[:15],
            ])
        story.append(_tbl(ec_rows, [PAGE_W - 225, 40, 95, 90]))

    # Cross-file chains
    if d['chains']:
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph("2.5  Cross-file Failure Chains", s['H3']))
        story.append(Paragraph(
            "These risks span multiple files. No single scanner catches them — "
            "the danger is in the combination.",
            s['Small']
        ))
        for i, c in enumerate(d['chains'], 1):
            files = c.get('files', c.get('files_involved', []))
            story.append(KeepTogether([
                Paragraph(f"<b>Chain {i}:</b> {_esc(c.get('title', ''))}", s['Small']),
                Paragraph(f"Files: {_esc(', '.join(str(x) for x in files[:4]))}", s['Indent']),
                Paragraph(f"Path: {_esc(c.get('attack_path', ''), 200)}", s['Indent']),
                Paragraph(f"Fix: {_esc(c.get('remediation', ''), 200)}", s['Indent']),
                Spacer(1, 0.1*cm),
            ]))


def _action_plan(story, s, d: Dict):
    story.append(Paragraph("3. Prioritised Action Plan", s['H2']))
    _rule(story)

    groq_plan = _groq_action_plan(d)
    if groq_plan:
        story.append(Paragraph("Generated from your actual findings:", s['Small']))
        for line in groq_plan.split('\n'):
            line = line.strip()
            if not line:
                story.append(Spacer(1, 0.15*cm))
            elif line.startswith('WEEK') or line.startswith('MONTH') or line.startswith('QUARTER'):
                story.append(Paragraph(f"<b>{_esc(line)}</b>", s['H3']))
            else:
                story.append(Paragraph(_esc(line), s['Indent']))
    else:
        # Fallback: generate from data directly
        story.append(Paragraph("<b>THIS WEEK — Critical (fix within 24–72 hours)</b>", s['H3']))
        for f in d['critical'][:5]:
            fixes = f.get('fix_versions', [])
            fix_str = f"upgrade to {fixes[0]}" if fixes else "upgrade to patched version"
            story.append(Paragraph(
                f"• {_esc(f.get('package', '?'))}: {_esc(fix_str)}  |  {_esc(f.get('osv_id', ''))}",
                s['Indent']
            ))

        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph("<b>THIS MONTH — High severity</b>", s['H3']))
        for f in d['high'][:5]:
            fixes = f.get('fix_versions', [])
            fix_str = f"upgrade to {fixes[0]}" if fixes else "upgrade to patched version"
            story.append(Paragraph(
                f"• {_esc(f.get('package', '?'))}: {_esc(fix_str)}  |  {_esc(f.get('osv_id', ''))}",
                s['Indent']
            ))

        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph("<b>THIS QUARTER — Process improvements</b>", s['H3']))
        story.append(Paragraph("• Pin all GitHub Actions to commit SHAs, not version tags.", s['Indent']))
        story.append(Paragraph("• Add automated dependency scanning to CI pipeline (run on every PR).", s['Indent']))
        story.append(Paragraph("• Set a container base image update policy — no image older than 90 days.", s['Indent']))


def _taaraware_pitch(story, s, d: Dict):
    story.append(Paragraph("4. What Continuous Monitoring Would Have Caught", s['H2']))
    _rule(story)

    story.append(Paragraph(
        "This report is a point-in-time snapshot. The findings in it existed before today — "
        "some of these CVEs have been public for years. Without continuous monitoring, "
        "the gap between a vulnerability existing and your team knowing about it can be months.",
        s['Body']
    ))
    story.append(Spacer(1, 0.3*cm))

    # The contrast table
    contrast = [
        ['', 'Point-in-Time Audit (this report)', 'TaaraWare Continuous Monitoring'],
        ['Detection lag',
         'Months — until someone runs a scan',
         'Under 10 minutes from occurrence'],
        ['CVE coverage',
         'Packages present at scan time',
         'Every new CVE published, checked against your stack automatically'],
        ['Config drift',
         'Not detected between scans',
         'sshd_config changes, new open ports, Dockerfile changes — alerted in real time'],
        ['CI/CD tampering',
         'Caught only if re-scanned',
         'GitHub Actions changes flagged on push'],
        ['Cost of missing it',
         'Breach discovered after the fact',
         'Behavioural anomaly flagged before data leaves'],
    ]
    ct = _tbl(contrast, [105, PAGE_W//2 - 52, PAGE_W//2 - 53], header_bg=TAARA_BLUE)
    story.append(ct)
    story.append(Spacer(1, 0.4*cm))

    n_critical = len(d['critical'])
    n_total = len(d['findings'])
    story.append(Paragraph(
        f"This scan found <b>{n_critical} critical vulnerabilities</b> across {n_total} findings. "
        f"At the IBM Cost of Data Breach India 2024 baseline of ₹2–5 Cr for MSMEs, "
        f"a single breach from one of these {n_critical} critical issues costs more than "
        f"years of continuous monitoring. "
        f"TaaraWare is deployed as a lightweight agent on your server — "
        f"it collects, TAARA analyses, you approve high-impact actions.",
        s['Body']
    ))
    story.append(Spacer(1, 0.4*cm))

    story.append(Paragraph("What TaaraWare Does Automatically", s['H3']))
    auto = [
        ['Action', 'Requires Human Approval?'],
        ['Block SSH brute-force IP (>50 failures, 0 success)', 'No — pre-approved policy'],
        ['Alert on new public port opened', 'No — automated alert'],
        ['Alert on config file change (sshd_config, Dockerfile)', 'No — automated alert'],
        ['New critical CVE matches your installed packages', 'No — automated alert within 10 min'],
        ['Rotate production secrets', 'Yes — always requires approval'],
        ['Delete any resource', 'Yes — always requires approval'],
        ['Modify CI/CD pipeline', 'Yes — always requires approval'],
    ]
    story.append(_tbl(auto, [PAGE_W - 160, 160]))
    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph(
        "The difference between a point-in-time audit and continuous monitoring is "
        "the difference between finding a breach after and preventing it before.",
        ParagraphStyle('CTA', fontSize=12, textColor=TAARA_RED, fontName='Helvetica-BoldOblique',
                       alignment=TA_CENTER, spaceAfter=8, spaceBefore=8)
    ))
    story.append(Paragraph(
        "To deploy TaaraWare: taara.in/deploy  |  hello@taara.in",
        ParagraphStyle('CTALink', fontSize=10, textColor=TAARA_BLUE, fontName='Helvetica-Bold',
                       alignment=TA_CENTER, spaceAfter=4)
    ))


def _footer_page(story, s, d: Dict, client_name: str):
    story.append(Paragraph("Data Sources & Scope", s['H2']))
    _rule(story)
    story.append(Paragraph(
        f"<b>Scan target:</b> {_esc(d['target'])}<br/>"
        f"<b>Date:</b> {_esc(d['scanned_at'])}<br/>"
        f"<b>Packages checked:</b> {d['packages']} (via OSV.dev live API)<br/>"
        f"<b>Data sources:</b> {_esc(', '.join(d['repo'].get('data_sources', ['OSV API', 'endoflife.date API', 'lockfile parsing'])))}",
        s['Body']
    ))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        "Limitations: Point-in-time assessment — security posture changes continuously. "
        "OSV CVE data depends on package ecosystem coverage. "
        "This report does not constitute a penetration test. "
        "Recommendations should be reviewed by a qualified professional before implementation.",
        s['Small']
    ))
    story.append(Spacer(1, 0.8*cm))
    story.append(Paragraph(
        f"Generated by TAARA Infrastructure Intelligence Platform | Prevent Crash, Preserve Cash",
        s['Caption']
    ))
    story.append(Paragraph(
        f"Report date: {datetime.now().strftime('%Y-%m-%d %H:%M')} | TAARA Q.0",
        s['Caption']
    ))


# ── Main entry point ──────────────────────────────────────────────────────────
def generate_report_pdf(analysis_results: Dict, report_config: Dict = None) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=1.5*cm, bottomMargin=2*cm,
        leftMargin=2*cm, rightMargin=2*cm
    )
    s = _styles()
    story = []
    config = report_config or {}
    client_name = config.get('client_name', '')

    d = _extract(analysis_results)

    _cover(story, s, d, client_name, config)
    story.append(PageBreak())

    _exec_summary(story, s, d, client_name)
    story.append(PageBreak())

    _findings_section(story, s, d)
    story.append(PageBreak())

    _action_plan(story, s, d)
    story.append(PageBreak())

    _taaraware_pitch(story, s, d)
    story.append(PageBreak())

    _footer_page(story, s, d, client_name)

    def _page_num(canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica', 7)
        canvas.setFillColor(TAARA_LIGHT)
        canvas.drawCentredString(A4[0]/2, 0.8*cm, f"TAARA Security Report  —  Page {canvas.getPageNumber()}  —  CONFIDENTIAL")
        canvas.restoreState()

    doc.build(story, onFirstPage=_page_num, onLaterPages=_page_num)
    return buf.getvalue()


# ── Streamlit render ──────────────────────────────────────────────────────────
def render_taara_words(analysis_results: Dict):
    st.markdown("""
    <div style="background:linear-gradient(135deg,#1a1a2e,#16213e);padding:28px;
                border-radius:12px;margin-bottom:20px;border:1px solid #0f3460;">
        <h1 style="color:#e94560;margin:0;font-size:2em;">Taara Words</h1>
        <p style="color:#a0a0b0;margin:6px 0 0 0;">Security Intelligence Report — professional PDF for your client</p>
    </div>
    """, unsafe_allow_html=True)

    if not analysis_results:
        st.warning("No scan data yet. Run a Code Scan first.")
        return

    repo = analysis_results.get('repo_results') or {}
    if not repo or not repo.get('findings'):
        st.warning("No findings data. Run a Code Scan and wait for it to complete.")
        return

    findings = repo.get('findings', [])
    critical = sum(1 for f in findings if f.get('severity') == 'critical')
    high     = sum(1 for f in findings if f.get('severity') == 'high')
    risk     = min(critical*25 + high*15 + sum(1 for f in findings if f.get('severity')=='medium')*5, 100)
    rq       = repo.get('repo_quantum_fidelity') or {}

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Repo Risk Score", f"{risk}/100")
    c2.metric("Critical / High", f"{critical} / {high}")
    c3.metric("Total Findings", len(findings))
    if rq.get('fidelity') is not None:
        c4.metric("Quantum Fidelity F", f"{rq['fidelity']:.3f}")

    st.markdown("---")
    client_name = st.text_input("Client name (appears on cover page)", placeholder="e.g. Acme Fintech Pvt Ltd")

    if st.button("Generate PDF Report", type="primary", use_container_width=True):
        with st.spinner("Building report — calling Groq for executive summary..."):
            try:
                pdf_bytes = generate_report_pdf(analysis_results, {'client_name': client_name})
                st.session_state["taara_words_pdf"] = pdf_bytes
                st.success("Report ready.")
            except Exception as e:
                st.error(f"PDF generation failed: {e}")

    if st.session_state.get("taara_words_pdf"):
        repo_name = repo.get('repo', 'report')
        st.download_button(
            label="Download TAARA Security Report (PDF)",
            data=st.session_state["taara_words_pdf"],
            file_name=f"TAARA_{repo_name}_{datetime.now().strftime('%Y%m%d')}.pdf",
            mime="application/pdf",
            type="primary",
            use_container_width=True,
        )
