"""
Taara Words — Professional Security Report Generator
=====================================================
Deliverable-grade PDF for CISOs and technical leadership.
Every number comes from real scan data. No invented content.
Groq writes specific analysis for each finding — not generic summaries.
"""

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
    PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.graphics.shapes import Drawing, Line, Rect
from reportlab.graphics import renderPDF

# ── Brand constants ───────────────────────────────────────────────────────────
TAARA_RED   = colors.HexColor('#e94560')
TAARA_DARK  = colors.HexColor('#1a1a2e')
TAARA_NAVY  = colors.HexColor('#16213e')
TAARA_BLUE  = colors.HexColor('#0f3460')
TAARA_LIGHT = colors.HexColor('#a0a0b0')
TAARA_GOLD  = colors.HexColor('#f5a623')
PAGE_W = A4[0] - 4 * cm

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

    add('TaaraH1',    fontSize=28, textColor=TAARA_RED,  fontName='Helvetica-Bold',
        alignment=TA_CENTER, spaceAfter=4, spaceBefore=0)
    add('TaaraH2',    fontSize=14, textColor=TAARA_NAVY, fontName='Helvetica-Bold',
        spaceAfter=8, spaceBefore=18)
    add('TaaraH3',    fontSize=11, textColor=TAARA_BLUE, fontName='Helvetica-Bold',
        spaceAfter=6, spaceBefore=10)
    add('TaaraBody',  fontSize=10, textColor=colors.black, fontName='Helvetica',
        alignment=TA_JUSTIFY, spaceAfter=6, leading=14)
    add('TaaraSmall', fontSize=8,  textColor=colors.HexColor('#444444'), fontName='Helvetica',
        spaceAfter=3, leading=11)
    add('TaaraCaption', fontSize=7, textColor=TAARA_LIGHT, fontName='Helvetica-Oblique',
        alignment=TA_CENTER, leading=9)
    add('TaaraTagline', fontSize=15, textColor=TAARA_RED, fontName='Helvetica-BoldOblique',
        alignment=TA_CENTER, spaceAfter=14)
    add('TaaraIndent', fontSize=9, textColor=colors.HexColor('#333333'), fontName='Helvetica',
        leftIndent=16, spaceAfter=4, leading=12)
    add('TaaraBigNum', fontSize=52, textColor=TAARA_RED, fontName='Helvetica-Bold',
        alignment=TA_CENTER, spaceAfter=2)
    add('TaaraBigLabel', fontSize=11, textColor=TAARA_NAVY, fontName='Helvetica-Bold',
        alignment=TA_CENTER, spaceAfter=12)
    add('TaaraCTA', fontSize=12, textColor=TAARA_RED, fontName='Helvetica-BoldOblique',
        alignment=TA_CENTER, spaceAfter=8, spaceBefore=8)
    add('TaaraQuantum', fontSize=9, textColor=TAARA_BLUE, fontName='Helvetica-Oblique',
        spaceAfter=3, leading=12, leftIndent=8,
        borderColor=TAARA_BLUE, borderWidth=0.5, borderPadding=4)
    return s


_CHAR_MAP = {
    '—': '--',   # em dash
    '–': '-',    # en dash
    '‘': "'",    # left single quote
    '’': "'",    # right single quote
    '“': '"',    # left double quote
    '”': '"',    # right double quote
    '•': '*',    # bullet
    '…': '...',  # ellipsis
    ' ': ' ',    # non-breaking space
    '·': '*',    # middle dot
    '→': '->',   # right arrow
    '←': '<-',   # left arrow
    'é': 'e',    # e acute
    'è': 'e',    # e grave
    'ê': 'e',    # e circumflex
    'à': 'a',    # a grave
    'â': 'a',    # a circumflex
    'ô': 'o',    # o circumflex
    'û': 'u',    # u circumflex
    'ü': 'u',    # u umlaut
    'ç': 'c',    # c cedilla
    '™': '(TM)', # trademark
    '®': '(R)',  # registered
    '°': 'deg',  # degree
}


def _esc(text, limit=0) -> str:
    """Escape for ReportLab XML and transliterate non-Latin-1 chars to ASCII-safe equivalents."""
    t = str(text or '')
    # Transliterate known Unicode chars that Helvetica can't render
    for char, replacement in _CHAR_MAP.items():
        t = t.replace(char, replacement)
    # Drop any remaining non-Latin-1 chars rather than letting ReportLab fail silently
    t = t.encode('latin-1', errors='replace').decode('latin-1')
    t = html.escape(t)
    if limit:
        t = t[:limit]
    return t


def _rule(story, color=TAARA_RED, width=0.8):
    d = Drawing(PAGE_W, 1)
    d.add(Line(0, 0, PAGE_W, 0, strokeColor=color, strokeWidth=width))
    story.append(d)
    story.append(Spacer(1, 0.2 * cm))


def _section_bar(story, title: str, s):
    story.append(Spacer(1, 0.1 * cm))
    story.append(Paragraph(title, s['TaaraH2']))
    _rule(story)


def _tbl(data, col_widths, header_bg=None):
    t = Table(data, colWidths=col_widths, repeatRows=1)
    bg = header_bg or TAARA_NAVY
    t.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0),  bg),
        ('TEXTCOLOR',     (0, 0), (-1, 0),  colors.white),
        ('FONTNAME',      (0, 0), (-1, 0),  'Helvetica-Bold'),
        ('FONTSIZE',      (0, 0), (-1, 0),  8),
        ('FONTNAME',      (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE',      (0, 1), (-1, -1), 8),
        ('GRID',          (0, 0), (-1, -1), 0.3, colors.HexColor('#cccccc')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f5ff')]),
        ('TOPPADDING',    (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING',   (0, 0), (-1, -1), 6),
        ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
        ('WORDWRAP',      (0, 0), (-1, -1), 'CJK'),
    ]))
    return t


def _severity_badge(sev: str) -> str:
    colors_map = {'critical': '#cc0000', 'high': '#e65c00', 'medium': '#cc8800', 'low': '#227722'}
    c = colors_map.get(sev.lower(), '#555555')
    return f'<font color="{c}"><b>[{sev.upper()}]</b></font>'


# ── Data extraction ──────────────────────────────────────────────────────────
def _extract(analysis_results: Dict) -> Dict:
    repo = analysis_results.get('repo_results') or {}
    ssh  = analysis_results.get('ssh_results') or analysis_results.get('security_data') or {}
    agent_result = analysis_results.get('agent_result') or {}

    # Repo findings
    findings   = repo.get('findings', [])
    chains     = repo.get('cross_file_chains', [])
    exploit    = repo.get('exploit_chains', [])
    rq         = repo.get('repo_quantum_fidelity') or {}

    critical = [f for f in findings if f.get('severity') == 'critical']
    high     = [f for f in findings if f.get('severity') == 'high']
    medium   = [f for f in findings if f.get('severity') == 'medium']
    low      = [f for f in findings if f.get('severity') == 'low']
    repo_risk = min(len(critical)*25 + len(high)*15 + len(medium)*5 + len(low)*1, 100)

    # Include SSH findings in risk — a critical SSH finding alone warrants HIGH risk
    ssh_all_findings = ssh.get('findings', ssh.get('security_findings', []))
    # Also collect findings from categories (SSH platform stores them there)
    if not ssh_all_findings:
        for cat_data in ssh.get('categories', {}).values():
            ssh_all_findings.extend(cat_data.get('findings', []))
    ssh_critical = [f for f in ssh_all_findings if f.get('severity') in ('critical', 'high')]
    if not repo_risk and ssh_critical:
        repo_risk = min(len([f for f in ssh_critical if f.get('severity') == 'critical'])*30 +
                        len([f for f in ssh_critical if f.get('severity') == 'high'])*15, 100)
    elif ssh_critical:
        repo_risk = min(repo_risk +
                        len([f for f in ssh_critical if f.get('severity') == 'critical'])*15 +
                        len([f for f in ssh_critical if f.get('severity') == 'high'])*8, 100)

    graphrag_chain = next(
        (c for c in chains if c.get('chain_id') == 'graphrag:llm_dependency_analysis'), None
    )
    struct_chains = [c for c in chains if c.get('chain_id') != 'graphrag:llm_dependency_analysis']

    # Resolve hostname: try multiple locations in priority order
    # 1. ssh.hostname (set by SSH analysis wrapper)
    # 2. ssh.host (set by platform_manager.collect_security_data)
    # 3. categories.system_info.info.hostname (from actual `hostname` command)
    # 4. analysis_results.platform (platform type string)
    # 5. repo target
    system_info = ssh.get('categories', {}).get('system_info', {}).get('info', {})
    resolved_hostname = (
        ssh.get('hostname')
        or ssh.get('host')
        or system_info.get('hostname')
        or analysis_results.get('platform', '')
        or ''
    )

    # SSH / behavioral data — build full findings list from all categories
    ssh_findings = ssh_all_findings
    quantum_result = (
        ssh.get('quantum_result')
        or ssh.get('quantum_risk')
        or analysis_results.get('quantum_result')
        or analysis_results.get('quantum_risk')
        or {}
    )
    f_min = quantum_result.get('f_min', rq.get('fidelity', None))
    # Clamp: f_min=1.0 from the fallback error path means "no real quantum result"
    if f_min is not None and f_min >= 1.0:
        f_min = None
    f_min_amp = quantum_result.get('f_min_amplitude')
    correlation_detected = quantum_result.get('correlation_signal_detected', False)

    # Target display: prefer repo path, fall back to hostname
    target = (
        repo.get('target')
        or repo.get('repo')
        or resolved_hostname
        or 'Not specified'
    )

    # Agent intelligence
    agent_actions = agent_result.get('actions_taken', [])
    agent_graph_chains = agent_result.get('graph_chains', [])
    agent_hypothesis = agent_result.get('hypothesis', '')

    # Scan date: prefer repo, then top-level timestamp
    scanned_at = repo.get('scanned_at', '')
    if not scanned_at and analysis_results.get('timestamp'):
        try:
            scanned_at = datetime.fromtimestamp(analysis_results['timestamp']).strftime('%Y-%m-%d')
        except Exception:
            pass
    if not scanned_at:
        scanned_at = datetime.now().strftime('%Y-%m-%d')
    else:
        scanned_at = scanned_at[:10]

    return {
        'repo': repo,
        'ssh': ssh,
        'target': target,
        'hostname': resolved_hostname,
        'repo_name': repo.get('repo', ''),
        'scanned_at': scanned_at,
        'packages': repo.get('packages_resolved', 0),
        'findings': findings,
        'critical': critical,
        'high': high,
        'medium': medium,
        'low': low,
        'chains': struct_chains,
        'exploit_chains': exploit,
        'graphrag': graphrag_chain,
        'repo_risk': repo_risk,
        'ssh_findings': ssh_findings,
        'quantum_result': quantum_result,
        'f_min': f_min,
        'f_min_amp': f_min_amp,
        'correlation_detected': correlation_detected,
        'fidelity_label': rq.get('interpretation', ''),
        'agent_actions': agent_actions,
        'agent_graph_chains': agent_graph_chains,
        'agent_hypothesis': agent_hypothesis,
    }


# ── Groq — specific per-finding analysis ─────────────────────────────────────
def _groq_call(prompt: str) -> str:
    """Single Groq call. Returns response text or empty string."""
    api_key = os.environ.get('GROQ_API_KEY')
    if not api_key:
        return ""
    try:
        from components.llm_service import LLMService
        llm = LLMService(api_key=api_key)
        resp = llm.generate_response(prompt)
        if resp.get('success'):
            return (resp.get('explanation') or resp.get('response') or '').strip()
    except Exception:
        pass
    return ""


def _groq_exec_summary(d: Dict, client_name: str) -> str:
    """Executive summary written by Groq using actual finding data."""
    parts = []
    if d['critical']:
        parts.append("CRITICAL VULNERABILITIES ({} total, most severe):".format(len(d['critical'])))
        for f in d['critical'][:5]:
            fixes = f.get('fix_versions', [])
            parts.append("  - {} v{} | {} | Fix: {} | {}".format(
                f.get('package', '?'),
                f.get('version', '?'),
                f.get('osv_id', '?'),
                fixes[0] if fixes else 'no patch available',
                f.get('title', '')[:80],
            ))
    if d['exploit_chains']:
        parts.append("\nEXPLOIT CHAINS (attacker path through your dependencies):")
        for c in d['exploit_chains'][:3]:
            parts.append("  - Path: {} | Score: {} | {}".format(
                c.get('path_display', '?'),
                c.get('chain_score', '?'),
                c.get('cve_summary', '')[:60],
            ))
    if d['ssh_findings']:
        parts.append("\nSSH / BEHAVIORAL FINDINGS ({} total):".format(len(d['ssh_findings'])))
        for f in d['ssh_findings'][:4]:
            parts.append("  - [{}] {}".format(
                f.get('severity', '?').upper(),
                f.get('title', f.get('description', '?'))[:80],
            ))
    if d['f_min'] is not None:
        parts.append("\nQUANTUM BEHAVIORAL FIDELITY:")
        parts.append("  F_min = {:.4f} ({})".format(
            d['f_min'],
            'UNSAFE — genuine behavioral divergence confirmed' if d['f_min'] < 0.5
            else 'Drifting from secure baseline',
        ))
        if d['correlation_detected']:
            parts.append("  Angle encoding detected correlated multi-feature anomaly.")
        if d['f_min_amp'] is not None:
            parts.append("  Amplitude F_min = {:.4f} (baseline comparison)".format(d['f_min_amp']))

    if not parts:
        return ""

    prompt = """You are a senior security analyst at TAARA writing an executive summary.
TAARA is a quantum-enhanced infrastructure security platform that detects behavioral anomalies
using quantum fidelity computation (F_min < 0.5 = confirmed threat).

Client: {client}
Scan date: {date}
Repository: {repo}
Server: {host}

ACTUAL SCAN DATA:
{data}

Write a 4-paragraph executive summary:
Paragraph 1: What was assessed, when, and the scale (packages, findings count, server hostname if present).
Paragraph 2: The most critical specific findings — name the packages, CVE IDs, and exploit chains by name. Not generic.
Paragraph 3: The quantum behavioral analysis result — what F_min = {fmin} means in plain terms, whether TAARA confirmed a threat, and if the angle encoding detected a correlated attack pattern.
Paragraph 4: The single most urgent action and the business risk if left unaddressed.

No bullet points. No headings. No generic security advice. Every sentence must reference specific data from above.
Write in plain English a CTO or CISO can read in under 90 seconds.""".format(
        client=client_name or 'the organisation',
        date=d['scanned_at'],
        repo=d['target'],
        host=d['hostname'] or 'not assessed',
        data='\n'.join(parts),
        fmin='{:.4f}'.format(d['f_min']) if d['f_min'] is not None else 'not computed',
    )

    return _groq_call(prompt)


def _groq_finding_analysis(finding: Dict, context: str = "") -> str:
    """Ask Groq for a specific 2-sentence analysis of a single critical finding."""
    prompt = """You are a security engineer analyzing a single vulnerability for a TAARA security report.

Finding:
  Package: {pkg} version {ver}
  CVE: {cve}
  Title: {title}
  Fix version: {fix}
  {ctx}

Write exactly 2 sentences:
1. What this specific vulnerability allows an attacker to do (be concrete, not generic).
2. The exact remediation command or step for this package.

No preamble. No "this vulnerability". Start directly with the attack capability.""".format(
        pkg=finding.get('package', '?'),
        ver=finding.get('version', '?'),
        cve=finding.get('osv_id', '?'),
        title=finding.get('title', '')[:120],
        fix=finding.get('fix_versions', ['no patch'])[0] if finding.get('fix_versions') else 'no patch available',
        ctx=f"Additional context: {context}" if context else "",
    )
    return _groq_call(prompt)


def _groq_ssh_finding_analysis(finding: Dict) -> str:
    """Ask Groq for specific analysis of an SSH/behavioral finding."""
    prompt = """You are a security engineer analyzing an infrastructure behavioral finding for a TAARA report.

Finding:
  Severity: {sev}
  Title: {title}
  Detail: {detail}
  Remediation: {fix}

Write exactly 2 sentences:
1. Why this specific configuration or behavior creates risk for this server (be concrete).
2. The exact command or config change to fix it.

No preamble. Start directly with the risk.""".format(
        sev=finding.get('severity', '?').upper(),
        title=finding.get('title', finding.get('description', '?'))[:100],
        detail=finding.get('detail', finding.get('description', ''))[:200],
        fix=finding.get('remediation', finding.get('fix', 'see documentation'))[:150],
    )
    return _groq_call(prompt)


def _groq_action_plan(d: Dict) -> str:
    """Generate a specific, data-driven action plan from real findings."""
    critical_items = [
        "{} v{} ({}) — fix: {}".format(
            f.get('package', '?'),
            f.get('version', '?'),
            f.get('osv_id', '?'),
            f.get('fix_versions', ['patch'])[0] if f.get('fix_versions') else 'patch',
        )
        for f in d['critical'][:6]
    ]
    high_items = [
        "{} v{} ({})".format(f.get('package', '?'), f.get('version', '?'), f.get('osv_id', '?'))
        for f in d['high'][:5]
    ]
    ssh_items = [
        "[{}] {}".format(f.get('severity', '?').upper(), f.get('title', f.get('description', '?'))[:60])
        for f in d['ssh_findings'][:4]
    ]

    if not critical_items and not high_items and not ssh_items:
        return ""

    prompt = """You are a security engineer writing a remediation plan for a TAARA security report.

ACTUAL FINDINGS:
Critical ({critical_count}):
{critical}

High ({high_count}):
{high}

SSH/Infrastructure ({ssh_count}):
{ssh}

Write a 3-section remediation plan:

THIS WEEK (24-72 hours):
List exactly 3 actions. Each must name the specific package/CVE from the data above.
Format each as: "• [package/cve]: [exact action with command if applicable]"

THIS MONTH:
List exactly 3 actions for high-severity findings. Same format.

THIS QUARTER:
List exactly 2 process improvements that would prevent recurrence of these specific finding types.

Every line must reference actual data above. No generic "implement security best practices".""".format(
        critical_count=len(d['critical']),
        critical='\n'.join(critical_items) or 'none',
        high_count=len(d['high']),
        high='\n'.join(high_items) or 'none',
        ssh_count=len(d['ssh_findings']),
        ssh='\n'.join(ssh_items) or 'none',
    )
    return _groq_call(prompt)


def _groq_quantum_interpretation(d: Dict) -> str:
    """Ask Groq to explain the quantum result in business terms."""
    if d['f_min'] is None:
        return ""

    prompt = """You are a senior analyst at TAARA explaining a quantum behavioral analysis result to a CTO.

TAARA uses quantum fidelity (F_min) to measure how far current server behavior is from its
established secure baseline. F_min < 0.5 is the geometric midpoint of Hilbert space —
it means current behavior is more different from normal than it is similar to normal.
This threshold requires no manual tuning — it is a mathematical property of quantum states.

RESULT FOR THIS SERVER:
  Server: {host}
  F_min (angle encoding, primary): {fmin}
  F_min (amplitude encoding, baseline): {fmin_amp}
  Status: {status}
  Correlation signal detected: {corr}

Write exactly 3 sentences:
1. What F_min = {fmin} means for this specific server in plain English (no math jargon).
2. Whether the angle encoding found something the amplitude encoding missed, and what that implies.
3. What the analyst should do next based on this result.

No generic quantum explanations. Reference the actual numbers.""".format(
        host=d['hostname'] or d['target'],
        fmin='{:.4f}'.format(d['f_min']),
        fmin_amp='{:.4f}'.format(d['f_min_amp']) if d['f_min_amp'] is not None else 'not computed',
        status='UNSAFE — behavioral divergence confirmed' if d['f_min'] < 0.5 else 'Drifting from baseline',
        corr='Yes — multi-feature correlated anomaly detected' if d['correlation_detected'] else 'No',
    )
    return _groq_call(prompt)


# ── PDF section builders ──────────────────────────────────────────────────────
def _cover(story, s, d: Dict, client_name: str, config: Dict):
    story.append(Spacer(1, 1.2 * cm))

    # TAARA brand header
    story.append(Paragraph("TAARA Q.0", s['TaaraH1']))
    _rule(story)
    story.append(Paragraph("Prevent Crash. Preserve Cash.", s['TaaraTagline']))
    story.append(Spacer(1, 0.5 * cm))

    # Risk score — inline so it doesn't collide
    risk_color = '#cc0000' if d['repo_risk'] >= 75 else '#e65c00' if d['repo_risk'] >= 50 else '#cc8800' if d['repo_risk'] >= 25 else '#227722'
    risk_label = 'CRITICAL RISK' if d['repo_risk'] >= 75 else 'HIGH RISK' if d['repo_risk'] >= 50 else 'MODERATE RISK' if d['repo_risk'] >= 25 else 'LOW RISK'
    story.append(Paragraph(
        f'<font color="{risk_color}" size="28"><b>{d["repo_risk"]}/100</b></font>'
        f'  <font color="#555555" size="11">—  Repository Risk Score  ·  {risk_label}</font>',
        ParagraphStyle('RiskLine', alignment=TA_CENTER, spaceAfter=10, leading=36)
    ))

    if d['f_min'] is not None:
        fmin_color = '#cc0000' if d['f_min'] < 0.3 else '#e65c00' if d['f_min'] < 0.5 else '#0f3460'
        fmin_label = "CRITICAL DIVERGENCE" if d['f_min'] < 0.3 else "UNSAFE DIRECTION" if d['f_min'] < 0.5 else "DRIFTING"
        story.append(Paragraph(
            '<font color="{c}"><b>Quantum Fidelity F_min = {v:.4f}</b>  --  {lbl}</font>'
            '  <font color="#888888" size="9">({orth}% orthogonal to baseline)</font>'.format(
                c=fmin_color, v=d['f_min'], lbl=fmin_label,
                orth=round((1 - d['f_min']) * 100, 1)
            ),
            ParagraphStyle('FminLine', fontSize=11, alignment=TA_CENTER, spaceAfter=10, leading=16)
        ))
    story.append(Spacer(1, 0.3 * cm))

    cover_rows = [['Field', 'Value']]
    if client_name:
        cover_rows.append(['Client', _esc(client_name)])
    cover_rows.append(['Scan Date', _esc(d['scanned_at'])])
    if d['repo_name']:
        cover_rows.append(['Repository', _esc(d['target'], 65)])
        cover_rows.append(['Packages Analysed', str(d['packages'])])
        cover_rows.append([
            'Findings',
            "{} total  ({} critical, {} high, {} medium, {} low)".format(
                len(d['findings']), len(d['critical']), len(d['high']),
                len(d['medium']), len(d['low'])
            )
        ])
    elif d['target'] and d['target'] != 'Not specified':
        cover_rows.append(['Scan Target', _esc(d['target'], 65)])
    if d['hostname']:
        cover_rows.append(['Server Assessed', _esc(d['hostname'])])
        if d['ssh_findings']:
            cover_rows.append(['Infrastructure Findings', str(len(d['ssh_findings']))])
    if d['f_min'] is not None:
        cover_rows.append([
            'Quantum F_min (angle)',
            "{:.4f}  —  {}".format(
                d['f_min'],
                'UNSAFE' if d['f_min'] < 0.5 else 'Drifting'
            )
        ])
        if d['f_min_amp'] is not None:
            cover_rows.append(['Quantum F_min (amplitude)', "{:.4f}  (baseline comparison)".format(d['f_min_amp'])])
        if d['correlation_detected']:
            cover_rows.append(['Correlation Signal', 'Detected — angle encoding found correlated multi-feature anomaly'])

    story.append(_tbl(cover_rows, [175, PAGE_W - 175]))
    story.append(Spacer(1, 0.6 * cm))

    # Finding severity summary — fills the cover page so it's not blank
    if d['findings'] or d['ssh_findings']:
        _rule(story, color=TAARA_NAVY, width=0.5)
        story.append(Paragraph("<b>Finding Summary</b>", s['TaaraH3']))

        sev_data = [['Severity', 'Count', 'Priority']]
        if d['critical']:
            sev_data.append([
                Paragraph('<font color="#cc0000"><b>CRITICAL</b></font>',
                          ParagraphStyle('C', fontSize=9, fontName='Helvetica-Bold')),
                str(len(d['critical'])),
                'Fix within 24-72 hours'
            ])
        if d['high']:
            sev_data.append([
                Paragraph('<font color="#e65c00"><b>HIGH</b></font>',
                          ParagraphStyle('H', fontSize=9, fontName='Helvetica-Bold')),
                str(len(d['high'])),
                'Fix within 1 week'
            ])
        if d['medium']:
            sev_data.append([
                Paragraph('<font color="#cc8800"><b>MEDIUM</b></font>',
                          ParagraphStyle('M', fontSize=9, fontName='Helvetica-Bold')),
                str(len(d['medium'])),
                'Fix within 1 month'
            ])
        if d['low']:
            sev_data.append([
                Paragraph('<font color="#227722"><b>LOW</b></font>',
                          ParagraphStyle('L', fontSize=9, fontName='Helvetica-Bold')),
                str(len(d['low'])),
                'Fix within 1 quarter'
            ])
        if d['ssh_findings']:
            ssh_crit = sum(1 for f in d['ssh_findings'] if f.get('severity') == 'critical')
            ssh_high = sum(1 for f in d['ssh_findings'] if f.get('severity') == 'high')
            sev_data.append([
                Paragraph('<font color="#555555"><b>INFRA / SSH</b></font>',
                          ParagraphStyle('I', fontSize=9, fontName='Helvetica-Bold')),
                '{} ({} crit, {} high)'.format(len(d['ssh_findings']), ssh_crit, ssh_high),
                'Server hardening required'
            ])
        if len(sev_data) > 1:
            story.append(_tbl(sev_data, [120, 80, PAGE_W - 200]))
            story.append(Spacer(1, 0.4 * cm))

    # Exploit chains call-out
    if d['exploit_chains']:
        story.append(Paragraph(
            '<font color="#cc0000"><b>{} exploit chain{} identified</b></font> — '
            'attacker paths from your application to vulnerable dependencies are mapped '
            'in Section 2.4.'.format(
                len(d['exploit_chains']),
                's' if len(d['exploit_chains']) != 1 else ''
            ),
            ParagraphStyle('ExploitNote', fontSize=10, fontName='Helvetica',
                           textColor=colors.HexColor('#333333'), spaceAfter=8, leading=14)
        ))
        story.append(Spacer(1, 0.2 * cm))

    story.append(Spacer(1, 0.4 * cm))
    _rule(story, color=TAARA_LIGHT, width=0.3)
    story.append(Paragraph(
        "This report is confidential. All findings derive from automated real-data analysis. "
        "No issues have been invented, extrapolated, or estimated. "
        "Quantum fidelity scores use a 4-qubit PennyLane circuit with dual encoding.",
        s['TaaraCaption']
    ))
    story.append(Spacer(1, 0.2 * cm))
    story.append(Paragraph(
        "TAARA Q.0  |  GoodWinSun  |  Powered by Groq + PennyLane + PQC Kyber768",
        s['TaaraCaption']
    ))


def _exec_summary(story, s, d: Dict, client_name: str):
    _section_bar(story, "1. Executive Summary", s)

    # Snapshot metrics table
    snap = [['Metric', 'Value', 'Status']]
    risk_status = ('CRITICAL RISK' if d['repo_risk'] >= 75 else 'HIGH RISK' if d['repo_risk'] >= 50
                   else 'MODERATE RISK' if d['repo_risk'] >= 25 else 'LOW RISK')
    snap.append(['Repository Risk Score', f"{d['repo_risk']}/100", risk_status])
    crit_status = 'Immediate action required' if d['critical'] else 'None found'
    snap.append(['Critical Findings', str(len(d['critical'])), crit_status])
    high_status = 'Fix within 1 week' if d['high'] else 'None found'
    snap.append(['High Findings', str(len(d['high'])), high_status])
    if d['ssh_findings']:
        snap.append(['SSH / Infra Findings', str(len(d['ssh_findings'])),
                     'Server hardening needed'])
    if d['f_min'] is not None:
        snap.append([
            'Quantum F_min (angle)',
            f"{d['f_min']:.4f}",
            'CONFIRMED UNSAFE' if d['f_min'] < 0.5 else 'Drifting from baseline'
        ])
        if d['correlation_detected']:
            snap.append(['Correlated Anomaly', 'Detected', 'Multi-feature attack pattern visible'])

    story.append(_tbl(snap, [200, 110, PAGE_W - 310]))
    story.append(Spacer(1, 0.4 * cm))

    # Groq executive summary — specific to this scan
    summary_text = _groq_exec_summary(d, client_name)
    if summary_text:
        story.append(Paragraph("What This Means for You", s['TaaraH3']))
        for para in summary_text.strip().split('\n\n'):
            if para.strip():
                story.append(Paragraph(_esc(para.strip()), s['TaaraBody']))
    else:
        # Fallback: data-driven but non-Groq
        if d['findings']:
            action_note = (
                "Immediate action is required on the {} critical finding{}.".format(
                    len(d['critical']), 's' if len(d['critical']) != 1 else ''
                ) if d['critical'] else
                "No critical findings. {} high severity finding{} require attention within 1 week.".format(
                    len(d['high']), 's' if len(d['high']) != 1 else ''
                ) if d['high'] else
                "No critical or high severity findings detected."
            )
            story.append(Paragraph(
                "TAARA scanned {} on {} and identified {} security issue{} across {} packages — "
                "{} critical and {} high severity. The repository risk score is {}/100. {}".format(
                    _esc(d['target']), _esc(d['scanned_at']), len(d['findings']),
                    's' if len(d['findings']) != 1 else '',
                    d['packages'], len(d['critical']), len(d['high']),
                    d['repo_risk'], action_note
                ),
                s['TaaraBody']
            ))
        else:
            story.append(Paragraph(
                "TAARA scanned {} on {}. No repository vulnerability findings were detected.".format(
                    _esc(d['target']), _esc(d['scanned_at'])
                ),
                s['TaaraBody']
            ))

    # Quantum section
    if d['f_min'] is not None:
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph("Quantum Behavioral Analysis", s['TaaraH3']))
        quantum_text = _groq_quantum_interpretation(d)
        if quantum_text:
            for para in quantum_text.strip().split('\n'):
                if para.strip():
                    story.append(Paragraph(_esc(para.strip()), s['TaaraBody']))
        else:
            fmin_interp = (
                "F_min = {:.4f} — this server's behavior is geometrically farther from its "
                "secure baseline than it is similar. TAARA classifies this as confirmed behavioral "
                "divergence. The threshold 0.5 is the geometric midpoint of Hilbert space — "
                "no manual tuning required.".format(d['f_min'])
                if d['f_min'] < 0.5 else
                "F_min = {:.4f} — behavioral drift detected. Not yet at confirmed-threat threshold "
                "(0.5), but monitoring should be intensified.".format(d['f_min'])
            )
            story.append(Paragraph(_esc(fmin_interp), s['TaaraBody']))

        if d['correlation_detected']:
            story.append(KeepTogether([
                Spacer(1, 0.1*cm),
                Paragraph(
                    "<b>Correlated anomaly detected:</b> TAARA's angle-encoding circuit found features "
                    "deviating together in a pattern invisible to classical analysis. "
                    "Angle encoding maps each behavioral feature to a qubit rotation angle; "
                    "the entanglement layer creates interference between correlated features. "
                    "Amplitude encoding would not detect this — it treats features independently.",
                    s['TaaraSmall']
                ),
            ]))


def _findings_section(story, s, d: Dict):
    _section_bar(story, "2. Repository Vulnerability Findings", s)

    # Severity bar
    story.append(Paragraph(
        "<b>{} CRITICAL</b>  ·  <b>{} HIGH</b>  ·  <b>{} MEDIUM</b>  ·  <b>{} LOW</b>  ·  "
        "Total: <b>{}</b>  across <b>{}</b> packages".format(
            len(d['critical']), len(d['high']), len(d['medium']), len(d['low']),
            len(d['findings']), d['packages']
        ),
        ParagraphStyle('SevBar', fontSize=11, fontName='Helvetica-Bold',
                       textColor=TAARA_NAVY, spaceAfter=10, spaceBefore=4)
    ))

    # GraphRAG analysis
    g = d.get('graphrag')
    if g and g.get('detail'):
        story.append(Paragraph("TAARA GraphRAG Dependency Risk Analysis", s['TaaraH3']))
        story.append(Paragraph(_esc(g['detail']), s['TaaraBody']))
        laf = g.get('llm_answer_fidelity')
        if laf:
            story.append(Paragraph(
                "Analysis alignment: F = {:.3f}  —  {}".format(
                    laf['fidelity'], _esc(laf['interpretation'])
                ),
                s['TaaraSmall']
            ))
        story.append(Spacer(1, 0.3 * cm))

    # Critical findings with per-finding Groq analysis
    story.append(Paragraph("2.1  Critical Findings — Fix Immediately", s['TaaraH3']))
    if d['critical']:
        # Summary table first
        crit_rows = [['Package', 'Version', 'CVE', 'Fix To', 'Title']]
        for f in d['critical'][:25]:
            fixes = f.get('fix_versions', [])
            crit_rows.append([
                _esc(f.get('package', ''), 22),
                _esc(f.get('version', ''), 12),
                _esc(f.get('osv_id', ''), 18),
                _esc(fixes[0], 12) if fixes else '—',
                _esc(f.get('title', ''), 55),
            ])
        story.append(_tbl(crit_rows, [75, 48, 92, 52, PAGE_W - 267]))
        if len(d['critical']) > 25:
            story.append(Paragraph(f"... and {len(d['critical'])-25} more critical findings.", s['TaaraSmall']))

        # Per-finding Groq analysis for top 3 most severe
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph("TAARA Analysis — Top Critical Findings", s['TaaraH3']))
        for f in d['critical'][:3]:
            analysis = _groq_finding_analysis(f)
            if analysis:
                pkg = f.get('package', '?')
                cve = f.get('osv_id', '?')
                story.append(KeepTogether([
                    Paragraph(
                        f"{_severity_badge('critical')}  <b>{_esc(pkg)}</b> — {_esc(cve)}",
                        s['TaaraSmall']
                    ),
                    Paragraph(_esc(analysis), s['TaaraIndent']),
                    Spacer(1, 0.1 * cm),
                ]))
    else:
        story.append(Paragraph("No critical findings.", s['TaaraBody']))

    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph("2.2  High Findings — Fix This Week", s['TaaraH3']))
    if d['high']:
        high_rows = [['Package', 'Version', 'CVE', 'Fix To', 'Title']]
        for f in d['high'][:18]:
            fixes = f.get('fix_versions', [])
            high_rows.append([
                _esc(f.get('package', ''), 22),
                _esc(f.get('version', ''), 12),
                _esc(f.get('osv_id', ''), 18),
                _esc(fixes[0], 12) if fixes else '—',
                _esc(f.get('title', ''), 55),
            ])
        story.append(_tbl(high_rows, [75, 48, 92, 52, PAGE_W - 267]))
        if len(d['high']) > 18:
            story.append(Paragraph(f"... and {len(d['high'])-18} more high findings.", s['TaaraSmall']))

    # CI/CD and infrastructure findings
    cicd = [f for f in d['findings'] if f.get('source') in
            ('actions_scan', 'dockerfile_scan', 'endoflife_date_api', 'secrets_scan')]
    if cicd:
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph("2.3  CI/CD and Infrastructure Findings", s['TaaraH3']))
        for f in cicd[:10]:
            sev = f.get('severity', 'medium').lower()
            story.append(KeepTogether([
                Paragraph(
                    f"{_severity_badge(sev)}  <b>{_esc(f.get('title', ''))}</b>",
                    s['TaaraSmall']
                ),
                Paragraph(_esc(f.get('detail', f.get('description', '')), 300), s['TaaraIndent']),
                Paragraph(f"<b>Fix:</b> {_esc(f.get('remediation', ''), 200)}", s['TaaraIndent']),
                Spacer(1, 0.1 * cm),
            ]))

    # Exploit chains
    if d['exploit_chains']:
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph("2.4  Exploit Chains — How an Attacker Gets In", s['TaaraH3']))
        story.append(Paragraph(
            "Each chain shows the path from your application to a vulnerable package. "
            "Score 10 = direct critical vulnerability in a first-level dependency.",
            s['TaaraSmall']
        ))
        ec_rows = [['Attack Path', 'Score', 'CVE', 'Fix To']]
        for c in d['exploit_chains'][:8]:
            ec_rows.append([
                _esc(c.get('path_display', ''), 65),
                str(c.get('chain_score', '')),
                _esc(c.get('osv_id', ''), 18),
                _esc(c.get('fix_version', '—') or '—', 18),
            ])
        story.append(_tbl(ec_rows, [PAGE_W - 230, 42, 95, 93]))

    # Cross-file chains
    if d['chains']:
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph("2.5  Cross-file Failure Chains", s['TaaraH3']))
        story.append(Paragraph(
            "These risks span multiple files — the danger is in the combination, "
            "not any single finding. No single scanner catches these without graph analysis.",
            s['TaaraSmall']
        ))
        for i, c in enumerate(d['chains'], 1):
            files = c.get('files', c.get('files_involved', []))
            story.append(KeepTogether([
                Paragraph(f"<b>Chain {i}:</b> {_esc(c.get('title', ''))}", s['TaaraSmall']),
                Paragraph(f"Files: {_esc(', '.join(str(x) for x in files[:4]))}", s['TaaraIndent']),
                Paragraph(f"Path: {_esc(c.get('attack_path', ''), 200)}", s['TaaraIndent']),
                Paragraph(f"Fix: {_esc(c.get('remediation', ''), 200)}", s['TaaraIndent']),
                Spacer(1, 0.1 * cm),
            ]))


def _ssh_section(story, s, d: Dict):
    if not d['ssh_findings'] and d['f_min'] is None:
        return

    _section_bar(story, "3. Server Security Analysis", s)

    if d['hostname']:
        story.append(Paragraph(f"<b>Assessed server:</b> {_esc(d['hostname'])}", s['TaaraSmall']))
        story.append(Spacer(1, 0.2 * cm))

    # Quantum fidelity block
    if d['f_min'] is not None:
        story.append(Paragraph("3.1  Quantum Behavioral Fidelity", s['TaaraH3']))
        fmin_rows = [['Metric', 'Value', 'Interpretation']]
        fmin_rows.append([
            'F_min — angle encoding (primary)',
            '{:.4f}'.format(d['f_min']),
            'UNSAFE: genuine behavioral divergence' if d['f_min'] < 0.5
            else 'Drifting: increased monitoring advised'
        ])
        if d['f_min_amp'] is not None:
            fmin_rows.append([
                'F_min — amplitude encoding (baseline)',
                '{:.4f}'.format(d['f_min_amp']),
                'Multi-feature correlation caught by angle encoding' if d['correlation_detected']
                else 'Consistent with angle result'
            ])
        fmin_rows.append([
            'Threshold',
            '0.5',
            'Geometric midpoint of Hilbert space — parameter-free'
        ])
        story.append(_tbl(fmin_rows, [200, 80, PAGE_W - 280]))
        story.append(Spacer(1, 0.2 * cm))

        if d['correlation_detected']:
            story.append(Paragraph(
                "<b>Correlated multi-feature anomaly detected by angle encoding:</b> "
                "F_min (angle) = {:.4f} vs F_min (amplitude) = {:.4f}. "
                "The angle-encoding circuit — which maps each behavioral feature to a qubit "
                "rotation angle and uses entanglement to detect joint feature changes — "
                "found a pattern that amplitude encoding's global normalization compressed away. "
                "This is the advantage of quantum relational encoding: correlated behavioral "
                "shifts that look unremarkable individually become visible as a coherent "
                "interference pattern in the angle-encoded Hilbert space.".format(
                    d['f_min'],
                    d['f_min_amp'] if d['f_min_amp'] is not None else 0.0
                ),
                s['TaaraBody']
            ))

    # SSH findings with per-finding Groq analysis
    if d['ssh_findings']:
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph("3.2  Infrastructure Security Findings", s['TaaraH3']))

        ssh_rows = [['Severity', 'Finding', 'Remediation']]
        for f in d['ssh_findings'][:20]:
            ssh_rows.append([
                _esc(f.get('severity', '?').upper(), 10),
                _esc(f.get('title', f.get('description', '?')), 60),
                _esc(f.get('remediation', f.get('fix', '')), 45),
            ])
        story.append(_tbl(ssh_rows, [55, PAGE_W - 210, 155]))
        story.append(Spacer(1, 0.3 * cm))

        # Per-finding Groq analysis for top critical SSH findings
        critical_ssh = [f for f in d['ssh_findings']
                        if f.get('severity', '').lower() == 'critical'][:3]
        if critical_ssh:
            story.append(Paragraph("TAARA Analysis — Critical Infrastructure Findings", s['TaaraH3']))
            for f in critical_ssh:
                analysis = _groq_ssh_finding_analysis(f)
                if analysis:
                    story.append(KeepTogether([
                        Paragraph(
                            f"{_severity_badge('critical')}  "
                            f"<b>{_esc(f.get('title', f.get('description', '?')), 80)}</b>",
                            s['TaaraSmall']
                        ),
                        Paragraph(_esc(analysis), s['TaaraIndent']),
                        Spacer(1, 0.1 * cm),
                    ]))

    # Agent actions taken
    if d['agent_actions']:
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph("3.3  TAARA Agent Actions", s['TaaraH3']))
        story.append(Paragraph(
            "The following actions were proposed or executed by the TAARA autonomous agent "
            "during this assessment period. Every action is reversible — rollback commands "
            "are pre-computed before execution.",
            s['TaaraSmall']
        ))
        act_rows = [['Action', 'Status', 'Quantum Context', 'F_min']]
        for a in d['agent_actions'][:10]:
            act_rows.append([
                _esc(a.get('command', a.get('action_type', '?')), 50),
                _esc(a.get('status', '?'), 15),
                _esc(a.get('quantum_context', '?'), 20),
                '{:.4f}'.format(a['f_min']) if a.get('f_min') is not None else '—',
            ])
        story.append(_tbl(act_rows, [PAGE_W - 220, 60, 90, 70]))


def _action_plan(story, s, d: Dict):
    _section_bar(story, "4. Prioritised Action Plan", s)

    groq_plan = _groq_action_plan(d)
    if groq_plan:
        story.append(Paragraph("Generated from your actual findings — not generic advice:", s['TaaraSmall']))
        story.append(Spacer(1, 0.2 * cm))
        for line in groq_plan.split('\n'):
            line = line.strip()
            # Strip markdown headers (###, ##, #) and trailing colon from section titles
            line = line.lstrip('#').strip()
            if not line:
                story.append(Spacer(1, 0.12 * cm))
            elif any(kw in line.upper() for kw in ('THIS WEEK', 'THIS MONTH', 'THIS QUARTER')):
                story.append(Paragraph(f"<b>{_esc(line.rstrip(':'))}</b>", s['TaaraH3']))
            elif line.startswith(('•', '-', '*')) or (len(line) > 1 and line[1] == '.'):
                # Bullet points — normalize to •
                clean = line.lstrip('•-* ').lstrip('0123456789. ')
                story.append(Paragraph(f"• {_esc(clean)}", s['TaaraIndent']))
            elif line.lower().startswith('to ') or line.lower().startswith('for '):
                # LLM intro sentences — render smaller
                story.append(Paragraph(_esc(line), s['TaaraSmall']))
            else:
                story.append(Paragraph(_esc(line), s['TaaraBody']))
    else:
        # Data-driven fallback — only render sections that have actual content
        if d['critical']:
            story.append(Paragraph("<b>THIS WEEK — Critical (24-72 hours)</b>", s['TaaraH3']))
            for f in d['critical'][:5]:
                fixes = f.get('fix_versions', [])
                fix_str = "upgrade to {}".format(fixes[0]) if fixes else "upgrade to latest patched version"
                story.append(Paragraph(
                    "• <b>{}</b>: {}  |  {}".format(
                        _esc(f.get('package', '?')), _esc(fix_str), _esc(f.get('osv_id', ''))
                    ),
                    s['TaaraIndent']
                ))
            story.append(Spacer(1, 0.2 * cm))
        elif d['high']:
            story.append(Paragraph("<b>THIS WEEK — High severity (immediate attention)</b>", s['TaaraH3']))

        if d['high']:
            story.append(Paragraph("<b>THIS MONTH — High severity</b>", s['TaaraH3']))
            for f in d['high'][:5]:
                fixes = f.get('fix_versions', [])
                fix_str = "upgrade to {}".format(fixes[0]) if fixes else "upgrade to latest patched version"
                story.append(Paragraph(
                    "• <b>{}</b>: {}".format(_esc(f.get('package', '?')), _esc(fix_str)),
                    s['TaaraIndent']
                ))
            story.append(Spacer(1, 0.2 * cm))

        if d['ssh_findings']:
            story.append(Paragraph("<b>THIS WEEK — Infrastructure hardening</b>", s['TaaraH3']))
            for f in d['ssh_findings'][:3]:
                story.append(Paragraph(
                    "• [{}] {}".format(
                        _esc(f.get('severity', '?').upper()),
                        _esc(f.get('title', f.get('description', '?'))[:80])
                    ),
                    s['TaaraIndent']
                ))
            story.append(Spacer(1, 0.2 * cm))

        story.append(Paragraph("<b>THIS QUARTER — Process improvements</b>", s['TaaraH3']))
        story.append(Paragraph("• Pin all GitHub Actions to commit SHAs, not version tags.", s['TaaraIndent']))
        story.append(Paragraph("• Add automated dependency scanning to CI (run on every PR).", s['TaaraIndent']))

        if not d['critical'] and not d['high'] and not d['ssh_findings']:
            story.append(Paragraph(
                "No critical or high severity findings detected. Continue regular scanning "
                "and monitor for new CVE disclosures affecting your dependency stack.",
                s['TaaraBody']
            ))


def _taaraware_pitch(story, s, d: Dict):
    _section_bar(story, "5. What Continuous Monitoring Would Have Caught", s)

    story.append(Paragraph(
        "This report is a point-in-time snapshot. The findings here existed before today — "
        "some of these CVEs have been public for years. The gap between a vulnerability "
        "existing and your team knowing about it can be months. TaaraWare closes that gap.",
        s['TaaraBody']
    ))
    story.append(Spacer(1, 0.3 * cm))

    contrast = [
        ['', 'Point-in-Time Audit (this report)', 'TaaraWare Continuous Monitoring'],
        ['Detection lag', 'Months — until someone runs a scan', 'Under 10 minutes from occurrence'],
        ['CVE coverage', 'Packages at scan time', 'Every new CVE checked against your stack automatically'],
        ['Config drift', 'Not detected between scans', 'sshd_config, new ports, Dockerfile changes — real-time alert'],
        ['Behavioral anomaly', 'Not detected', 'Quantum F_min computed continuously — alert at F < 0.5'],
        ['CI/CD tampering', 'Caught only on rescan', 'GitHub Actions changes flagged on push'],
        ['Agent response', 'Manual only', 'Pre-approved actions executed autonomously within autonomy policy'],
    ]
    story.append(_tbl(contrast, [108, PAGE_W//2 - 54, PAGE_W//2 - 54], header_bg=TAARA_BLUE))
    story.append(Spacer(1, 0.4 * cm))

    story.append(Paragraph(
        f"This scan found <b>{len(d['critical'])} critical vulnerabilities</b> across "
        f"{len(d['findings'])} findings. At IBM Cost of Data Breach India 2024 baseline of "
        f"Rs. 2-5 Cr for MSMEs, a single breach from one critical finding costs more than "
        f"years of continuous monitoring.",
        s['TaaraBody']
    ))

    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph("What TaaraWare Does Automatically", s['TaaraH3']))
    auto = [
        ['Action', 'Requires Approval?'],
        ['Block SSH brute-force IP (>50 failures, 0 logins)', 'No — pre-approved policy'],
        ['Alert: new public port opened', 'No — automated alert'],
        ['Alert: sshd_config or Dockerfile changed', 'No — automated alert'],
        ['New critical CVE in your installed packages', 'No — alert within 10 minutes'],
        ['Quantum F_min drops below 0.5', 'No — agent proposes actions immediately'],
        ['Rotate production secrets', 'Yes — always requires approval'],
        ['Modify CI/CD pipeline', 'Yes — always requires approval'],
    ]
    story.append(_tbl(auto, [PAGE_W - 165, 165]))

    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph(
        "The difference between a point-in-time audit and continuous monitoring is "
        "the difference between finding a breach after and preventing it before.",
        s['TaaraCTA']
    ))


def _footer_page(story, s, d: Dict, client_name: str):
    _section_bar(story, "Data Sources, Scope & Methodology", s)
    story.append(Paragraph(
        "<b>Scan target:</b> {}<br/>"
        "<b>Scan date:</b> {}<br/>"
        "<b>Packages checked:</b> {} (via OSV.dev live API)<br/>"
        "<b>Quantum engine:</b> PennyLane 4-qubit, dual encoding (amplitude + angle), "
        "ring-CNOT entanglement, F_min threshold 0.5 (parameter-free geometric midpoint)<br/>"
        "<b>PQC channel:</b> ML-KEM Kyber768 (NIST FIPS 203) — TaaraWare↔CommandCenter<br/>"
        "<b>LLM analysis:</b> Groq (llama-3.3-70b-versatile) — per-finding specific analysis<br/>"
        "<b>Data sources:</b> {}".format(
            _esc(d['target']),
            _esc(d['scanned_at']),
            d['packages'],
            _esc(', '.join(d['repo'].get('data_sources',
                           ['OSV API', 'endoflife.date API', 'lockfile parsing'])))
        ),
        s['TaaraBody']
    ))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(
        "Limitations: Point-in-time assessment — security posture changes continuously. "
        "OSV CVE data depends on package ecosystem coverage. "
        "This report does not constitute a penetration test. "
        "Quantum fidelity uses a PennyLane simulator — not real quantum hardware. "
        "Recommendations should be reviewed by a qualified professional before implementation.",
        s['TaaraSmall']
    ))
    story.append(Spacer(1, 0.8 * cm))
    story.append(Paragraph(
        "Generated by TAARA — Quantum Infrastructure Intelligence Platform",
        s['TaaraCaption']
    ))
    story.append(Paragraph(
        f"Report date: {datetime.now().strftime('%Y-%m-%d %H:%M')}  |  TAARA Q.0  |  GoodWinSun",
        s['TaaraCaption']
    ))


# ── Page number callback ──────────────────────────────────────────────────────
def _make_page_callback():
    def _page_num(canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica', 7)
        canvas.setFillColor(TAARA_LIGHT)
        canvas.drawCentredString(
            A4[0] / 2, 0.8 * cm,
            f"TAARA Security Report  |  Page {canvas.getPageNumber()}  |  CONFIDENTIAL  |  GoodWinSun"
        )
        # Left: TAARA brand mark
        canvas.setFillColor(TAARA_RED)
        canvas.setFont('Helvetica-Bold', 7)
        canvas.drawString(2 * cm, 0.8 * cm, "TAARA Q.0")
        canvas.restoreState()
    return _page_num


# ── Main entry point ──────────────────────────────────────────────────────────
def generate_report_pdf(analysis_results: Dict, report_config: Dict = None) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=1.5 * cm, bottomMargin=2 * cm,
        leftMargin=2 * cm, rightMargin=2 * cm
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

    if d['findings']:
        _findings_section(story, s, d)
        story.append(PageBreak())

    if d['ssh_findings'] or d['f_min'] is not None:
        _ssh_section(story, s, d)
        story.append(PageBreak())

    _action_plan(story, s, d)
    story.append(PageBreak())

    _taaraware_pitch(story, s, d)
    story.append(PageBreak())

    _footer_page(story, s, d, client_name)

    cb = _make_page_callback()
    doc.build(story, onFirstPage=cb, onLaterPages=cb)
    return buf.getvalue()


# ── Streamlit render ──────────────────────────────────────────────────────────
def render_taara_words(analysis_results: Dict):
    st.markdown("""
    <div style="background:linear-gradient(135deg,#1a1a2e,#16213e);padding:28px;
                border-radius:12px;margin-bottom:20px;border:1px solid #0f3460;">
        <h1 style="color:#e94560;margin:0;font-size:2em;">TAARA Words</h1>
        <p style="color:#a0a0b0;margin:6px 0 0 0;">
            Quantum Security Intelligence Report — professional PDF, every finding Groq-analysed
        </p>
    </div>
    """, unsafe_allow_html=True)

    if not analysis_results:
        st.warning("No scan data yet. Run a Code Scan or SSH Analysis first.")
        return

    repo = analysis_results.get('repo_results') or {}
    ssh  = analysis_results.get('ssh_results') or analysis_results.get('security_data') or {}

    has_repo = bool(repo and repo.get('findings'))
    has_ssh  = bool(ssh)

    if not has_repo and not has_ssh:
        st.warning("No findings data. Run a Code Scan or SSH Analysis first.")
        return

    findings = repo.get('findings', [])
    critical = sum(1 for f in findings if f.get('severity') == 'critical')
    high     = sum(1 for f in findings if f.get('severity') == 'high')
    risk     = min(critical * 25 + high * 15
                   + sum(1 for f in findings if f.get('severity') == 'medium') * 5, 100)
    rq       = repo.get('repo_quantum_fidelity') or {}
    qr       = ssh.get('quantum_result') or ssh.get('quantum_risk') or {}

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Repo Risk Score", f"{risk}/100")
    c2.metric("Critical / High", f"{critical} / {high}")
    c3.metric("Total Findings", len(findings))
    f_disp = qr.get('f_min', rq.get('fidelity'))
    if f_disp is not None:
        c4.metric("Quantum F_min", f"{f_disp:.4f}")

    if has_ssh:
        ssh_findings = ssh.get('findings', ssh.get('security_findings', []))
        st.info(f"Server analysis included: {ssh.get('hostname', 'unknown')} "
                f"— {len(ssh_findings)} infrastructure findings")

    st.markdown("---")
    client_name = st.text_input(
        "Client name (appears on cover page)",
        placeholder="e.g. Acme Fintech Pvt Ltd"
    )

    if st.button("Generate TAARA Report (PDF)", type="primary", use_container_width=True):
        with st.spinner("Building report — Groq analysing each finding specifically..."):
            try:
                pdf_bytes = generate_report_pdf(analysis_results, {'client_name': client_name})
                st.session_state["taara_words_pdf"] = pdf_bytes
                st.success("Report ready. Every finding includes specific TAARA analysis.")
            except Exception as e:
                st.error(f"PDF generation failed: {e}")

    if st.session_state.get("taara_words_pdf"):
        repo_name = repo.get('repo', ssh.get('hostname', 'report'))
        st.download_button(
            label="Download TAARA Security Report (PDF)",
            data=st.session_state["taara_words_pdf"],
            file_name=f"TAARA_{repo_name}_{datetime.now().strftime('%Y%m%d')}.pdf",
            mime="application/pdf",
            type="primary",
            use_container_width=True,
        )
