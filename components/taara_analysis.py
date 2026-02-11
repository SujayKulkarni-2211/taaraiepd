"""
TaaraAnalysis - Organizational Health Analysis (OHA) Scanner
=============================================================

The free-tier entry point for TAARA security consulting.

Runs comprehensive security scans across all supported platforms:
- SSH (Linux/Unix servers)
- AWS, GCP, Azure cloud environments
- Docker containers
- Kubernetes clusters

Produces a quantum-enhanced risk score and identifies vulnerabilities.
Does NOT generate downloadable reports (paid tier limitation).
"""

import streamlit as st
import time
import json
import numpy as np
from typing import Dict, List, Optional
from datetime import datetime


def render_taara_analysis(platform, taara_analyzer, cloud_analyzer=None, llm_service=None):
    """Render the TaaraAnalysis (OHA) page."""

    st.markdown("""
    <div style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                padding: 30px; border-radius: 15px; margin-bottom: 20px;
                border: 1px solid #0f3460;">
        <h1 style="color: #e94560; margin: 0; font-size: 2.2em;">
            TaaraAnalysis
        </h1>
        <p style="color: #a0a0b0; margin: 5px 0 0 0; font-size: 1.1em;">
            Organizational Health Analysis — Prevent Crash, Preserve Cash
        </p>
    </div>
    """, unsafe_allow_html=True)

    platform_info = platform.get_platform_info()
    ptype = platform_info.get('type', 'unknown')

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Platform", ptype.upper())
    with col2:
        st.metric("Status", "Connected" if platform.connected else "Disconnected")
    with col3:
        st.metric("Analysis Mode", "Quantum-Enhanced")

    if not platform.connected:
        st.error("Platform not connected. Please connect first.")
        return

    if 'analysis_results' not in st.session_state:
        st.session_state.analysis_results = None
    if 'analysis_running' not in st.session_state:
        st.session_state.analysis_running = False

    st.markdown("---")

    col_a, col_b = st.columns([3, 1])
    with col_a:
        st.markdown("### Scan Configuration")
        scan_depth = st.selectbox("Scan Depth", ["Standard", "Deep", "Quick"], index=0)
    with col_b:
        st.markdown("### ")
        st.markdown("### ")
        run_scan = st.button("Run TaaraAnalysis", type="primary", use_container_width=True)

    if run_scan:
        st.session_state.analysis_running = True
        _run_analysis(platform, taara_analyzer, cloud_analyzer, llm_service, scan_depth, ptype)
        st.session_state.analysis_running = False

    if st.session_state.analysis_results:
        _display_results(st.session_state.analysis_results, ptype)


def _run_analysis(platform, taara_analyzer, cloud_analyzer, llm_service, scan_depth, ptype):
    """Execute the full TaaraAnalysis pipeline."""
    progress = st.progress(0, text="Initializing TaaraAnalysis...")
    results = {
        'timestamp': time.time(),
        'platform': ptype,
        'scan_depth': scan_depth,
        'security_data': None,
        'quantum_risk': None,
        'cost_analysis': None,
        'ai_summary': None,
        'duration': 0
    }
    start_time = time.time()

    progress.progress(10, text="Collecting security data from target...")
    try:
        security_data = platform.collect_security_data()
        results['security_data'] = security_data
    except Exception as e:
        st.error(f"Security scan error: {e}")
        security_data = {'categories': {}, 'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}, 'features': {}}
        results['security_data'] = security_data

    progress.progress(30, text="Running TAARA reconstruction-based novelty detection...")
    try:
        features = security_data.get('features', {})
        feature_vector = np.array([
            features.get('failed_logins', 0),
            features.get('accepted_logins', 0),
            features.get('invalid_users', 0),
            features.get('established_connections', 0),
            features.get('unique_outbound_ips', 0),
            features.get('total_findings', 0),
            features.get('weighted_severity_score', 0),
        ], dtype=np.float32)

        if len(feature_vector) < 4:
            feature_vector = np.pad(feature_vector, (0, 4 - len(feature_vector)))

        quantum_risk = taara_analyzer.get_quantum_risk_assessment(
            feature_vector, identity_id=f'{ptype}_system'
        )
        results['quantum_risk'] = quantum_risk
    except Exception as e:
        st.warning(f"Quantum analysis notice: {e}")
        summary = security_data.get('summary', {})
        score = min(
            summary.get('critical', 0) * 25 +
            summary.get('high', 0) * 15 +
            summary.get('medium', 0) * 5 +
            summary.get('low', 0) * 1,
            100
        )
        results['quantum_risk'] = {
            'risk_score': score,
            'severity': 'CRITICAL' if score >= 75 else 'HIGH' if score >= 50 else 'MEDIUM' if score >= 25 else 'LOW',
            'quantum_novelty': 0,
            'f_min': 1.0,
            'is_directionally_novel': False
        }

    progress.progress(55, text="Analyzing cloud spending patterns...")
    if cloud_analyzer and ptype in ['aws', 'gcp', 'azure']:
        try:
            cost_data = platform.collect_cost_data()
            cost_analysis = cloud_analyzer.analyze_platform_costs(platform, cost_data)
            results['cost_analysis'] = cost_analysis
        except Exception as e:
            results['cost_analysis'] = {'error': str(e)}
    else:
        results['cost_analysis'] = None

    progress.progress(75, text="Generating AI-powered analysis summary...")
    if llm_service:
        try:
            summary = security_data.get('summary', {})
            risk = results.get('quantum_risk', {})
            prompt = f"""You are TAARA, a quantum-enhanced security analyst. Analyze these findings concisely:

Platform: {ptype.upper()}
Critical Issues: {summary.get('critical', 0)}
High Issues: {summary.get('high', 0)}
Medium Issues: {summary.get('medium', 0)}
Low Issues: {summary.get('low', 0)}
Quantum Risk Score: {risk.get('risk_score', 0)}/100
Quantum Novelty: {risk.get('quantum_novelty', 0)}%

Top findings:
"""
            all_findings = []
            for cat in security_data.get('categories', {}).values():
                for f in cat.get('findings', []):
                    all_findings.append(f"{f.get('severity', '').upper()}: {f.get('title', '')}")

            prompt += "\n".join(all_findings[:10])
            prompt += "\n\nProvide: 1) Executive summary (3 lines) 2) Top 3 immediate actions 3) Estimated breach cost for an Indian MSME"

            response = llm_service.generate_response(prompt)
            if response.get('success'):
                results['ai_summary'] = response.get('explanation', '')
        except Exception:
            pass

    progress.progress(95, text="Finalizing analysis...")
    results['duration'] = round(time.time() - start_time, 1)
    st.session_state.analysis_results = results
    progress.progress(100, text="TaaraAnalysis complete!")
    time.sleep(0.5)


def _display_results(results: Dict, ptype: str):
    """Display TaaraAnalysis results."""
    st.markdown("---")

    quantum_risk = results.get('quantum_risk', {})
    risk_score = quantum_risk.get('risk_score', 0)
    severity = quantum_risk.get('severity', 'UNKNOWN')

    severity_colors = {
        'CRITICAL': '#ff0000', 'HIGH': '#ff6600',
        'MEDIUM': '#ffaa00', 'LOW': '#00cc00',
        'BOOTSTRAPPING': '#888888'
    }
    color = severity_colors.get(severity, '#888888')

    st.markdown(f"""
    <div style="background: linear-gradient(135deg, #0a0a1a 0%, #1a1a3e 100%);
                padding: 30px; border-radius: 15px; margin: 20px 0;
                border: 2px solid {color}; text-align: center;">
        <h2 style="color: {color}; margin: 0; font-size: 3em;">{risk_score}</h2>
        <p style="color: #a0a0b0; margin: 5px 0;">Quantum Risk Score</p>
        <span style="background: {color}; color: white; padding: 5px 20px;
                     border-radius: 20px; font-weight: bold; font-size: 1.2em;">
            {severity}
        </span>
        <p style="color: #666; margin-top: 15px; font-size: 0.9em;">
            Powered by TAARA Quantum-Enhanced Pattern Detection (PennyLane 4-Qubit Validation)
        </p>
    </div>
    """, unsafe_allow_html=True)

    security_data = results.get('security_data', {})
    summary = security_data.get('summary', {})

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Critical", summary.get('critical', 0), delta=None)
    with col2:
        st.metric("High", summary.get('high', 0))
    with col3:
        st.metric("Medium", summary.get('medium', 0))
    with col4:
        st.metric("Low", summary.get('low', 0))
    with col5:
        total = sum(summary.values())
        st.metric("Total Issues", total)

    total_findings = sum(summary.values())
    if total_findings > 0:
        breach_cost_lakh = max(5, total_findings * 2 + summary.get('critical', 0) * 15)
        st.markdown(f"""
        <div style="background: #2a0a0a; padding: 20px; border-radius: 10px;
                    margin: 15px 0; border-left: 4px solid #e94560;">
            <h3 style="color: #e94560; margin: 0;">Estimated Breach Impact</h3>
            <p style="color: #ff6666; font-size: 2em; margin: 10px 0;">
                ₹{breach_cost_lakh} Lakh - ₹{breach_cost_lakh * 3} Lakh
            </p>
            <p style="color: #999;">
                Based on {total_findings} vulnerabilities found including {summary.get('critical', 0)} critical issues.
                Average MSME breach cost in India: ₹2-5 Cr (source: IBM Cost of Data Breach Report).
            </p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("### Quantum Analysis Details")
    qcol1, qcol2, qcol3, qcol4 = st.columns(4)
    with qcol1:
        novelty = quantum_risk.get('quantum_novelty', 0)
        st.metric("Quantum Novelty", f"{novelty}%")
    with qcol2:
        f_min = quantum_risk.get('f_min', 1.0)
        st.metric("Minimum Fidelity", f"{f_min:.4f}")
    with qcol3:
        directional = quantum_risk.get('is_directionally_novel', False)
        st.metric("Directional Novelty", "Yes" if directional else "No")
    with qcol4:
        mag = quantum_risk.get('magnitude_score', 0)
        st.metric("Magnitude Score", f"{mag}%")

    st.markdown("""
    <div style="background: #0a1a2a; padding: 15px; border-radius: 10px;
                margin: 10px 0; border: 1px solid #0f3460;">
        <p style="color: #66b3ff; margin: 0; font-size: 0.9em;">
            <b>Quantum Enhancement:</b> TAARA uses a 4-qubit PennyLane circuit to validate
            whether detected anomalies represent genuine directional behavioral shifts
            (not just magnitude variations). This catches sophisticated threats that
            traditional statistical methods miss — threats that operate within "normal" ranges
            but exhibit fundamentally new behavioral patterns.
        </p>
    </div>
    """, unsafe_allow_html=True)

    if results.get('ai_summary'):
        st.markdown("### AI Analysis Summary")
        st.markdown(f"""
        <div style="background: #1a1a2e; padding: 20px; border-radius: 10px;
                    border: 1px solid #0f3460;">
            {results['ai_summary'].replace(chr(10), '<br>')}
        </div>
        """, unsafe_allow_html=True)

    st.markdown("### Detailed Findings by Category")
    for cat_key, cat_data in security_data.get('categories', {}).items():
        findings = cat_data.get('findings', [])
        cat_name = cat_data.get('name', cat_key)

        severity_icon = {
            'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢', 'info': '🔵'
        }

        if findings:
            with st.expander(f"{cat_name} ({len(findings)} findings)", expanded=False):
                for finding in findings:
                    sev = finding.get('severity', 'info')
                    icon = severity_icon.get(sev, '⚪')
                    st.markdown(f"""
                    **{icon} [{sev.upper()}] {finding.get('title', '')}**
                    > {finding.get('detail', '')}
                    > **Remediation:** {finding.get('remediation', 'N/A')}
                    """)
        else:
            info = cat_data.get('info', {})
            if info:
                with st.expander(f"{cat_name} (No issues found)", expanded=False):
                    for k, v in info.items():
                        st.text(f"{k}: {v}")

    if results.get('cost_analysis') and not results['cost_analysis'].get('error'):
        cost = results['cost_analysis']
        st.markdown("### Cloud Cost Analysis — Preserve Cash")

        ccol1, ccol2, ccol3 = st.columns(3)
        with ccol1:
            st.metric("Monthly Spend", f"${cost.get('total_monthly_cost', 0):,.2f}")
        with ccol2:
            st.metric("Potential Savings", f"${cost.get('potential_monthly_savings', 0):,.2f}/mo")
        with ccol3:
            score = cost.get('preserve_cash_score', 0)
            st.metric("Preserve Cash Score", f"{score}/100")

        if cost.get('waste_findings'):
            with st.expander(f"Waste Identified ({len(cost['waste_findings'])} items)", expanded=False):
                for w in cost['waste_findings']:
                    st.markdown(f"**{w.get('title', '')}** — Savings: {w.get('potential_savings', 'N/A')}")
                    st.caption(w.get('detail', ''))

        if cost.get('optimization_recommendations'):
            with st.expander(f"Optimization Opportunities ({len(cost['optimization_recommendations'])} items)", expanded=False):
                for r in cost['optimization_recommendations']:
                    st.markdown(f"**{r.get('title', '')}** — Savings: {r.get('potential_savings', 'N/A')}")
                    st.caption(r.get('detail', ''))

    st.markdown("---")
    st.markdown(f"""
    <div style="text-align: center; padding: 20px; background: linear-gradient(135deg, #1a1a2e, #16213e);
                border-radius: 10px; border: 1px solid #e94560;">
        <h3 style="color: #e94560;">Want the Full Report?</h3>
        <p style="color: #a0a0b0;">
            Get detailed remediation steps, quantum circuit analysis, cost-benefit breakdown,
            and executive-ready PDF report with Taara Words.
        </p>
        <p style="color: #666; font-size: 0.8em;">
            Analysis completed in {results.get('duration', 0)}s | Scan depth: {results.get('scan_depth', 'Standard')}
        </p>
    </div>
    """, unsafe_allow_html=True)

    if st.button("Generate Full Report with Taara Words", type="secondary"):
        st.session_state.nav_target = 'taara_words'
        st.rerun()
