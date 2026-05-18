"""
TAARA User Manual — built with ReportLab.
Run standalone: python taara_manual.py
Or call build_manual() from server.py to generate on-demand.
"""
import os
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor, white, black
from reportlab.lib.units import mm, cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether,
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.lib import colors

# ── Color palette ─────────────────────────────────────────────────────────────
C_BG        = HexColor('#0a0a1a')
C_SURFACE   = HexColor('#0e0e20')
C_ACCENT    = HexColor('#e94560')
C_BLUE      = HexColor('#4a9eff')
C_GREEN     = HexColor('#22cc66')
C_TEXT      = HexColor('#e8e8f0')
C_DIM       = HexColor('#8888aa')
C_BORDER    = HexColor('#1e1e38')
C_AMBER     = HexColor('#f5a623')
C_PURPLE    = HexColor('#9b7dff')

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), 'models', 'taara_user_manual.pdf')


def build_manual(output_path: str = OUTPUT_PATH) -> str:
    """Generate the TAARA user manual PDF. Returns the output path."""
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=2.2*cm,
        leftMargin=2.2*cm,
        topMargin=2.4*cm,
        bottomMargin=2.4*cm,
        title="TAARA Q.0 — User Manual",
        author="GoodWinSun",
    )

    styles = getSampleStyleSheet()
    W = A4[0] - 4.4*cm  # usable width

    # ── Custom styles ──────────────────────────────────────────────────────────
    def S(name, **kw):
        base = kw.pop('parent', 'Normal')
        s = ParagraphStyle(name, parent=styles[base], **kw)
        styles.add(s)
        return s

    h1  = S('H1', fontSize=22, textColor=C_TEXT, spaceAfter=6, fontName='Helvetica-Bold', leading=28)
    h2  = S('H2', fontSize=14, textColor=C_ACCENT, spaceAfter=4, spaceBefore=16, fontName='Helvetica-Bold', leading=18)
    h3  = S('H3', fontSize=11, textColor=C_BLUE, spaceAfter=3, spaceBefore=10, fontName='Helvetica-Bold', leading=14)
    body = S('Body', fontSize=9.5, textColor=C_TEXT, spaceAfter=6, leading=15, alignment=TA_JUSTIFY)
    body_l = S('BodyL', fontSize=9.5, textColor=C_TEXT, spaceAfter=6, leading=15, alignment=TA_LEFT)
    dim  = S('Dim', fontSize=8.5, textColor=C_DIM, spaceAfter=4, leading=13)
    mono = S('Mono', fontSize=8.5, textColor=C_GREEN, fontName='Courier', spaceAfter=4, leading=13,
             backColor=HexColor('#0d0d1f'), borderPadding=4)
    caption = S('Caption', fontSize=8, textColor=C_DIM, alignment=TA_CENTER, spaceAfter=8)
    toc_item = S('TOC', fontSize=10, textColor=C_TEXT, spaceAfter=3, leading=14)
    cover_tag = S('CoverTag', fontSize=9, textColor=C_DIM, spaceAfter=3, leading=12, alignment=TA_CENTER)
    cover_title = S('CoverTitle', fontSize=32, textColor=C_TEXT, fontName='Helvetica-Bold',
                    leading=38, alignment=TA_CENTER, spaceAfter=6)
    cover_sub = S('CoverSub', fontSize=13, textColor=C_DIM, alignment=TA_CENTER, spaceAfter=4)
    cover_version = S('CoverVer', fontSize=10, textColor=C_ACCENT, alignment=TA_CENTER, spaceAfter=10,
                      fontName='Helvetica-Bold')
    label = S('Label', fontSize=8, textColor=C_DIM, fontName='Helvetica-Bold',
              letterSpacing=0.5, spaceAfter=2, leading=11)
    formula = S('Formula', fontSize=10, textColor=C_ACCENT, fontName='Courier',
                alignment=TA_CENTER, spaceAfter=6, leading=16)
    callout = S('Callout', fontSize=9, textColor=C_TEXT, leading=14, spaceAfter=4)

    story = []
    def HR(color=C_BORDER, thickness=0.5):
        return HRFlowable(width='100%', thickness=thickness, color=color, spaceAfter=6, spaceBefore=6)

    # ── Cover page ─────────────────────────────────────────────────────────────
    story.append(Spacer(1, 3.5*cm))
    story.append(Paragraph("TAARA Q.0", cover_title))
    story.append(Paragraph("Quantum Behavioral Analysis Platform", cover_sub))
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph("User Manual — v1.0", cover_version))
    story.append(Spacer(1, 0.6*cm))
    story.append(HR(C_ACCENT, 1))
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph("GoodWinSun · Confidential", cover_tag))
    story.append(Paragraph("May 2026", cover_tag))
    story.append(Spacer(1, 2.5*cm))

    # Tagline box
    tagline_data = [[
        Paragraph(
            "TAARA detects behavioral anomalies that classical tools miss — "
            "not by setting thresholds, but by measuring the geometric distance "
            "between current system state and every prior normal state using "
            "quantum fidelity.",
            S('TaglineBox', fontSize=10, textColor=C_TEXT, leading=16, alignment=TA_CENTER)
        )
    ]]
    tagline_table = Table(tagline_data, colWidths=[W])
    tagline_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), HexColor('#0e0e20')),
        ('BOX', (0,0), (-1,-1), 1, C_BLUE),
        ('TOPPADDING', (0,0), (-1,-1), 14),
        ('BOTTOMPADDING', (0,0), (-1,-1), 14),
        ('LEFTPADDING', (0,0), (-1,-1), 18),
        ('RIGHTPADDING', (0,0), (-1,-1), 18),
    ]))
    story.append(tagline_table)
    story.append(PageBreak())

    # ── Table of Contents ──────────────────────────────────────────────────────
    story.append(Paragraph("Contents", h1))
    story.append(HR())
    story.append(Spacer(1, 0.3*cm))
    toc = [
        ("1", "What is TAARA?", "3"),
        ("2", "First Connection", "4"),
        ("3", "Understanding F_min", "5"),
        ("4", "Reading a Finding", "6"),
        ("5", "Agent Autonomy Levels", "7"),
        ("6", "Generating a Client Report", "8"),
        ("7", "Glossary", "9"),
        ("8", "Benchmark Methodology", "10"),
    ]
    for num, title, page in toc:
        row_data = [[
            Paragraph(f"<b>{num}</b>", S(f'TOCNum{num}', fontSize=10, textColor=C_ACCENT, fontName='Helvetica-Bold')),
            Paragraph(title, toc_item),
            Paragraph(page, S(f'TOCPg{num}', fontSize=10, textColor=C_DIM, alignment=TA_RIGHT)),
        ]]
        t = Table(row_data, colWidths=[0.8*cm, W-1.4*cm, 0.6*cm])
        t.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(t)
        story.append(HR(C_BORDER, 0.3))
    story.append(PageBreak())

    # ── 1. What is TAARA? ──────────────────────────────────────────────────────
    story.append(Paragraph("1.  What is TAARA?", h1))
    story.append(HR(C_ACCENT, 0.8))
    story.append(Spacer(1, 0.2*cm))

    story.append(Paragraph(
        "TAARA (Threat-Aware Adaptive Reasoning Agent) is a cybersecurity platform for "
        "independent security consultants and managed service providers. It monitors servers, "
        "cloud infrastructure, and application environments by analyzing behavioral patterns — "
        "not known signatures.",
        body
    ))
    story.append(Paragraph(
        "Most security tools work by matching activity against a list of known attacks. "
        "If the attack is new, unknown, or deliberately crafted to avoid signatures, "
        "it goes undetected. TAARA takes a fundamentally different approach: it learns "
        "what <i>normal</i> looks like for a specific system and measures how far the current "
        "behavior has drifted from that baseline.",
        body
    ))
    story.append(Paragraph(
        "The measurement is quantum-geometric: each behavioral snapshot is encoded as a "
        "quantum state and compared to all prior normal states using <b>fidelity</b> — "
        "a cosine-like inner product in Hilbert space. A result below 0.5 means the current "
        "state is more orthogonal (dissimilar) than parallel to anything seen before. "
        "No threshold to tune. No signatures to update. No false-positive calibration.",
        body
    ))

    # What TAARA is used for
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("PRIMARY USE CASES", label))
    use_cases = [
        ["SSH server monitoring", "Detects lateral movement, privilege escalation, login anomalies"],
        ["Cloud workload analysis", "Monitors AWS/GCP/Azure instance behavioral drift"],
        ["Post-incident review", "Identifies the moment of behavioral change with F_min timestamp"],
        ["Autonomous remediation", "Agent proposes and executes containment with operator approval"],
    ]
    uc_table = Table(
        [[Paragraph(a, S(f'UCHead{i}', fontSize=9, textColor=C_BLUE, fontName='Helvetica-Bold')),
          Paragraph(b, dim)] for i, (a, b) in enumerate(use_cases)],
        colWidths=[4*cm, W-4*cm]
    )
    uc_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), HexColor('#0c0c1e')),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [HexColor('#0c0c1e'), HexColor('#0e0e22')]),
        ('GRID', (0,0), (-1,-1), 0.3, C_BORDER),
        ('TOPPADDING', (0,0), (-1,-1), 7),
        ('BOTTOMPADDING', (0,0), (-1,-1), 7),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(uc_table)
    story.append(PageBreak())

    # ── 2. First Connection ────────────────────────────────────────────────────
    story.append(Paragraph("2.  First Connection", h1))
    story.append(HR(C_ACCENT, 0.8))
    story.append(Spacer(1, 0.2*cm))

    story.append(Paragraph(
        "TAARA connects to servers over SSH. No agent is required on the target server "
        "for initial analysis — TAARA reads logs, process lists, and network state "
        "remotely over the SSH session.",
        body
    ))

    story.append(Paragraph("STEP-BY-STEP", label))
    steps = [
        ("1", "Open the TAARA app", "Click the TAARA icon on your desktop or run launch_taara.sh."),
        ("2", "Select a client or add new", "The home screen shows your client portfolio. Click a client card to pre-fill connection details, or click + Add Client."),
        ("3", "Enter SSH credentials", "Host IP/hostname, port (default 22), username, and either password or key path."),
        ("4", "Click Connect →", "TAARA establishes the SSH session and begins collecting the 17-feature behavioral vector."),
        ("5", "Run TAARA Analysis", "Click the blue Run Analysis button. TAARA collects logs, checks auth events, and runs quantum fidelity scoring. This takes 30-60 seconds."),
        ("6", "Review results", "The analysis dashboard shows findings, F_min score, MITRE ATT&CK mappings, and recommended fixes."),
    ]
    for num, title, desc in steps:
        step_data = [[
            Paragraph(num, S(f'StepNum{num}', fontSize=14, textColor=C_ACCENT, fontName='Helvetica-Bold', alignment=TA_CENTER)),
            [Paragraph(title, h3), Paragraph(desc, body_l)],
        ]]
        t = Table(step_data, colWidths=[1.2*cm, W-1.4*cm], rowHeights=None)
        t.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 2),
            ('LEFTPADDING', (0,0), (-1,-1), 4),
            ('RIGHTPADDING', (0,0), (-1,-1), 0),
        ]))
        story.append(KeepTogether([t, Spacer(1, 0.1*cm)]))

    story.append(Spacer(1, 0.3*cm))
    note_data = [[Paragraph(
        "<b>Note:</b> If you don't have a live server to connect to, use <b>Demo Mode</b> "
        "(button on the Client Portfolio screen). Demo Mode runs a synthetic SSH intrusion "
        "scenario with real quantum math — all F_min values and findings are computed "
        "from the actual quantum engine, not hardcoded.",
        callout
    )]]
    note = Table(note_data, colWidths=[W])
    note.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), HexColor('#0a0f1a')),
        ('BOX', (0,0), (-1,-1), 0.8, C_BLUE),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('LEFTPADDING', (0,0), (-1,-1), 14),
        ('RIGHTPADDING', (0,0), (-1,-1), 14),
    ]))
    story.append(note)
    story.append(PageBreak())

    # ── 3. Understanding F_min ─────────────────────────────────────────────────
    story.append(Paragraph("3.  Understanding F_min", h1))
    story.append(HR(C_ACCENT, 0.8))
    story.append(Spacer(1, 0.2*cm))

    story.append(Paragraph(
        "F_min is TAARA's core output. Every analysis produces a single number between 0 and 1. "
        "It is not a score, a percentage, or a risk rating — it is a mathematical quantity "
        "from quantum information theory.",
        body
    ))

    # Formula box
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph("F = |⟨ψ_t | ψ_m⟩|²", formula))
    story.append(Paragraph(
        "where ψ_t is the quantum state encoding current behavior and ψ_m is the closest "
        "state in the behavioral memory basis",
        caption
    ))
    story.append(Spacer(1, 0.2*cm))

    story.append(Paragraph("What the formula means in plain language:", h3))
    story.append(Paragraph(
        "TAARA converts the 17-feature behavioral vector into a unit vector in a "
        "high-dimensional Hilbert space using angle encoding. Each prior normal state is "
        "also stored as a unit vector. F_min is the squared inner product between the "
        "current state and the most similar prior normal state.",
        body
    ))
    story.append(Paragraph(
        "A value of <b>1.0</b> means current behavior is identical to something seen before — "
        "completely normal. A value of <b>0.0</b> means current behavior is completely orthogonal "
        "to every prior normal state — geometrically as anomalous as possible. The threshold "
        "of <b>0.5</b> is not arbitrary: it is the midpoint of Hilbert space, the point at which "
        "a state is equally similar and dissimilar to the memory basis.",
        body
    ))

    # F_min threshold table
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("F_MIN INTERPRETATION", label))
    thresholds = [
        ("0.7 – 1.0", "NORMAL", C_GREEN, "Behavior matches prior normal states. No action required."),
        ("0.5 – 0.7", "DRIFTING", C_BLUE, "Behavioral drift detected. Monitor closely. May indicate misconfiguration or early-stage anomaly."),
        ("0.3 – 0.5", "UNSAFE DIRECTION", C_AMBER, "Current state is more orthogonal than parallel to normal basis. Investigation recommended."),
        ("0.0 – 0.3", "CRITICAL DIVERGENCE", C_ACCENT, "Extreme behavioral deviation. Quantum-confirmed anomaly. Immediate action required."),
    ]
    thresh_rows = []
    for range_str, label_str, color, desc in thresholds:
        thresh_rows.append([
            Paragraph(range_str, S(f'TR{range_str}', fontSize=9, textColor=color, fontName='Courier', fontName2='Courier-Bold')),
            Paragraph(f"<b>{label_str}</b>", S(f'TL{label_str}', fontSize=9, textColor=color, fontName='Helvetica-Bold')),
            Paragraph(desc, dim),
        ])
    thresh_table = Table(thresh_rows, colWidths=[2.2*cm, 3.5*cm, W-5.9*cm])
    thresh_table.setStyle(TableStyle([
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [HexColor('#0c0c1e'), HexColor('#0e0e22')]),
        ('GRID', (0,0), (-1,-1), 0.3, C_BORDER),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(thresh_table)
    story.append(PageBreak())

    # ── 4. Reading a Finding ───────────────────────────────────────────────────
    story.append(Paragraph("4.  Reading a Finding", h1))
    story.append(HR(C_ACCENT, 0.8))
    story.append(Spacer(1, 0.2*cm))

    story.append(Paragraph(
        "Each finding in the analysis results represents a specific security issue "
        "detected on the monitored system. Findings include a severity, a description, "
        "a quantum deviation score, and an actionable fix command.",
        body
    ))

    story.append(Paragraph("FINDING ANATOMY", label))
    story.append(Spacer(1, 0.1*cm))
    fields = [
        ("Severity", "CRITICAL / HIGH / MEDIUM / LOW / INFO — how urgently this needs to be addressed."),
        ("CVE / ID", "Identifier for the vulnerability or finding type. CVE IDs link to NVD."),
        ("Description", "What was found and why it matters in plain language."),
        ("F_dev score", "F_dev = deviation of this specific feature from its safe-state quantum embedding. High F_dev means this feature was the primary driver of the anomaly."),
        ("Fix command", "Exact shell command to remediate, ready to paste into a terminal."),
        ("MITRE tactic", "The ATT&CK tactic this finding maps to — useful for client reports and compliance."),
    ]
    field_rows = [[
        Paragraph(f, S(f'FF{i}', fontSize=9, textColor=C_BLUE, fontName='Helvetica-Bold')),
        Paragraph(d, dim)
    ] for i, (f, d) in enumerate(fields)]
    field_table = Table(field_rows, colWidths=[3.5*cm, W-3.5*cm])
    field_table.setStyle(TableStyle([
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [HexColor('#0c0c1e'), HexColor('#0e0e22')]),
        ('GRID', (0,0), (-1,-1), 0.3, C_BORDER),
        ('TOPPADDING', (0,0), (-1,-1), 7),
        ('BOTTOMPADDING', (0,0), (-1,-1), 7),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(field_table)

    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph("ANOMALY ALERT BANNER", h3))
    story.append(Paragraph(
        "When F_min drops below 0.5 during live monitoring or analysis, TAARA fires a full-width "
        "red anomaly banner at the top of the screen. The banner shows: server name, F_min value, "
        "top offending features, correlation detection status, and the number of agent actions "
        "auto-executed or awaiting approval. This banner cannot be missed — it is the visual "
        "confirmation that TAARA has caught something.",
        body
    ))
    story.append(PageBreak())

    # ── 5. Agent Autonomy Levels ───────────────────────────────────────────────
    story.append(Paragraph("5.  Agent Autonomy Levels", h1))
    story.append(HR(C_ACCENT, 0.8))
    story.append(Spacer(1, 0.2*cm))

    story.append(Paragraph(
        "TAARA's agent component (TaaraWare) can take remediation actions automatically "
        "or propose them for operator approval. The autonomy level controls this behavior.",
        body
    ))

    autonomy_levels = [
        ("0%", "Observe only", "Agent detects anomalies and logs them. No actions proposed or taken. Use for initial assessment periods."),
        ("25%", "Suggest only", "Agent proposes actions and explains rationale. All actions require manual approval in the TaaraWare → Agent & Actions tab."),
        ("50%", "Supervised", "Actions with high historical approval rates (>90%) and success rates (>85%) are pre-approved. Novel actions still require approval."),
        ("75%", "High autonomy", "Agent executes most actions automatically. Only actions with potential for service disruption are held for approval."),
        ("100%", "Full autonomy", "Agent acts immediately on any detected anomaly. Full execution log available in Rollback Log tab. One-click rollback on any action."),
    ]
    al_rows = []
    for pct, title, desc in autonomy_levels:
        al_rows.append([
            Paragraph(pct, S(f'AL{pct}', fontSize=12, textColor=C_ACCENT, fontName='Courier-Bold', alignment=TA_CENTER)),
            [Paragraph(title, h3), Paragraph(desc, body_l)],
        ])
    al_table = Table(al_rows, colWidths=[1.6*cm, W-1.8*cm])
    al_table.setStyle(TableStyle([
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [HexColor('#0c0c1e'), HexColor('#0e0e22')]),
        ('BOX', (0,0), (-1,-1), 0.5, C_BORDER),
        ('INNERGRID', (0,0), (-1,-1), 0.3, C_BORDER),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(al_table)

    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("CONTRASTIVE BANDIT LEARNING", h3))
    story.append(Paragraph(
        "The autonomy level is not a static setting — it is informed by TAARA's contrastive bandit. "
        "The bandit tracks each action type's approval rate (how often operators approve it) and "
        "success rate (how often the issue resolved after execution). Actions that consistently "
        "get approved and work are promoted to auto-execution. This means TAARA becomes more "
        "useful over time as it learns each operator's judgment.",
        body
    ))
    story.append(PageBreak())

    # ── 6. Generating a Client Report ─────────────────────────────────────────
    story.append(Paragraph("6.  Generating a Client Report", h1))
    story.append(HR(C_ACCENT, 0.8))
    story.append(Spacer(1, 0.2*cm))

    story.append(Paragraph(
        "After completing an analysis, TAARA can generate a professional PDF report "
        "for your client. The report includes: executive summary, all findings with "
        "severity and fix commands, quantum fidelity chart, agent action log, and "
        "a risk score summary.",
        body
    ))

    story.append(Paragraph("TO GENERATE A REPORT", label))
    report_steps = [
        "Complete a full analysis (Connect → Run Analysis → wait for results).",
        "In the Analysis view, click <b>Generate Report</b> in the top-right of the results panel.",
        "TAARA generates the PDF using the LLM-powered executive summary engine.",
        "The report opens automatically in your system PDF viewer.",
        "Send the PDF directly to your client — it is formatted for non-technical readers.",
    ]
    for i, step in enumerate(report_steps):
        story.append(Paragraph(
            f"<b>{i+1}.</b>  {step}",
            S(f'RS{i}', parent='Body', fontSize=9.5, textColor=C_TEXT, spaceAfter=5, leading=15)
        ))

    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("REPORT PRICING", h3))
    story.append(Paragraph(
        "TAARA enables independent consultants to offer paid security assessments at ₹15,000 "
        "per engagement. The report is the deliverable — a professional document the client "
        "receives after TAARA runs the analysis. No manual writeup required.",
        body
    ))
    story.append(PageBreak())

    # ── 7. Glossary ────────────────────────────────────────────────────────────
    story.append(Paragraph("7.  Glossary", h1))
    story.append(HR(C_ACCENT, 0.8))
    story.append(Spacer(1, 0.2*cm))

    glossary = [
        ("Quantum Fidelity",
         "A measure of how similar two quantum states are. "
         "Defined as F = |⟨ψ₁|ψ₂⟩|². Value of 1 = identical states, 0 = orthogonal (maximally dissimilar)."),
        ("F_min",
         "The minimum fidelity between the current behavioral state and any state in the normal memory basis. "
         "TAARA's primary anomaly signal. Below 0.5 triggers an alert."),
        ("Angle Encoding",
         "A quantum circuit technique where feature values are encoded as rotation angles in qubit states. "
         "TAARA uses AngleEmbedding with parameterized RX/RY/RZ gates followed by Ring-CNOT entanglement layers."),
        ("Behavioral Memory",
         "The set of quantum states representing all prior normal observations for a given identity. "
         "TAARA builds this memory during the baseline period and updates it during operation."),
        ("Correlation Signal",
         "Detected when F_angle < F_amplitude − 0.05. Indicates the directional (angle-encoded) representation "
         "shows a stronger anomaly than the magnitude-only representation — signature of coordinated multi-feature attacks."),
        ("Contrastive Bandit",
         "TAARA's reinforcement learning component that tracks action outcomes and adjusts auto-execution thresholds. "
         "Uses approval_rate and success_rate per action type."),
        ("PQC Kyber768",
         "Post-quantum cryptographic key encapsulation mechanism standardized as ML-KEM (NIST FIPS 203). "
         "Protects the TaaraWare↔CommandCenter channel against Shor's algorithm attacks on RSA/ECC."),
        ("TaaraWare",
         "The lightweight agent deployed to the monitored server. Collects the 17-feature behavioral vector "
         "every 10 seconds, runs local quantum fidelity checks, and reports back over the PQC channel."),
        ("17-Feature Vector",
         "The behavioral fingerprint TAARA collects: CPU, memory, disk, network I/O, connections, "
         "process count, load averages (1/5/15m), failed logins, new processes, suspicious connections, "
         "privilege escalations, temporal rhythm deviation, causal chain novelty, and concealment signal."),
        ("Harvest-Now-Decrypt-Later",
         "An attack strategy where adversaries capture encrypted traffic today, storing it to decrypt "
         "once quantum computers break current cryptography. PQC Kyber768 is the defense against this."),
    ]
    for term, defn in glossary:
        story.append(Paragraph(f"<b>{term}</b>", S(f'GTerm{term[:4]}', fontSize=10, textColor=C_BLUE, fontName='Helvetica-Bold', spaceAfter=2)))
        story.append(Paragraph(defn, dim))
        story.append(Spacer(1, 0.15*cm))
    story.append(PageBreak())

    # ── 8. Benchmark Methodology ───────────────────────────────────────────────
    story.append(Paragraph("8.  Benchmark Methodology", h1))
    story.append(HR(C_ACCENT, 0.8))
    story.append(Spacer(1, 0.2*cm))

    story.append(Paragraph(
        "TAARA's benchmark claims are based on controlled evaluation against public intrusion "
        "detection datasets using a held-out test set. This section documents the methodology "
        "so results can be independently reproduced.",
        body
    ))

    story.append(Paragraph("DATASETS USED", h3))
    datasets = [
        ("SSH Log Dataset", "Structured SSH authentication logs with labeled brute-force and intrusion events."),
        ("CICIDS 2017", "Canadian Institute for Cybersecurity Intrusion Detection Evaluation Dataset 2017."),
        ("Synthetic Demo (internal)", "Generated using fixed seed (np.random.default_rng(42)) for reproducibility. Not used in published benchmarks."),
    ]
    ds_rows = [[Paragraph(n, S(f'DS{i}', fontSize=9, textColor=C_BLUE, fontName='Helvetica-Bold')), Paragraph(d, dim)]
               for i, (n, d) in enumerate(datasets)]
    ds_table = Table(ds_rows, colWidths=[4*cm, W-4*cm])
    ds_table.setStyle(TableStyle([
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [HexColor('#0c0c1e'), HexColor('#0e0e22')]),
        ('GRID', (0,0), (-1,-1), 0.3, C_BORDER),
        ('TOPPADDING', (0,0), (-1,-1), 7),
        ('BOTTOMPADDING', (0,0), (-1,-1), 7),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(ds_table)

    story.append(Paragraph("EVALUATION PROTOCOL", h3))
    story.append(Paragraph(
        "Models are trained on the first 70% of temporal data (preserving time order to avoid "
        "look-ahead bias). Evaluation is on the remaining 30%. Metrics: F1-score, precision, "
        "recall, and false positive rate at the same operating point. "
        "TAARA's quantum fidelity detector is compared against: Isolation Forest (baseline), "
        "One-Class SVM, and Local Outlier Factor.",
        body
    ))

    story.append(Paragraph("HONESTY STATEMENT", h3))
    story.append(Paragraph(
        "TAARA's quantum circuit runs on classical simulation (PennyLane default.qubit). "
        "No quantum speedup is claimed. The advantage over classical methods is geometric: "
        "angle encoding detects directional anomalies that amplitude-only methods miss, "
        "specifically correlated multi-feature attacks where each feature individually "
        "appears within normal range but the combination is anomalous.",
        body
    ))

    # Footer note
    story.append(Spacer(1, 0.8*cm))
    story.append(HR(C_BORDER))
    story.append(Paragraph(
        "TAARA User Manual v1.0 · GoodWinSun · May 2026 · Confidential",
        S('FooterNote', fontSize=8, textColor=C_DIM, alignment=TA_CENTER)
    ))

    doc.build(story)
    return output_path


if __name__ == '__main__':
    path = build_manual()
    print(f"Manual written to: {path}")
