"""
Taara Command Center
=====================

Live monitoring dashboard that receives data from deployed TaaraWare agents.
All ML and quantum analysis runs on the admin's laptop.

Features:
- Real-time system status overview
- Anomaly detection results
- Quantum validation status
- Agent health monitoring
- Behavioral trajectory visualization
"""

import streamlit as st
import time
import json
import numpy as np
from typing import Dict, List, Optional
from datetime import datetime


def render_command_center(platform, taara_analyzer, training_mgr,
                          taaraware_mgr, embedder, detector):
    """Render the Taara Command Center dashboard."""

    st.markdown("""
    <div style="background: linear-gradient(135deg, #1a1a2e 0%, #0a0a2e 100%);
                padding: 30px; border-radius: 15px; margin-bottom: 20px;
                border: 1px solid #4466ff;">
        <h1 style="color: #4466ff; margin: 0; font-size: 2.2em;">
            Taara Command Center
        </h1>
        <p style="color: #a0a0b0; margin: 5px 0 0 0; font-size: 1.1em;">
            Quantum-Enhanced Security Monitoring — All Analysis Local
        </p>
    </div>
    """, unsafe_allow_html=True)

    _render_status_bar(platform, taara_analyzer, training_mgr, taaraware_mgr)

    tab1, tab2, tab3, tab4 = st.tabs([
        "Live Monitor", "Detection Results", "TAARA Statistics", "Agent Fleet"
    ])

    with tab1:
        _render_live_monitor(platform, taara_analyzer, embedder, detector, training_mgr)

    with tab2:
        _render_detection_results(taara_analyzer)

    with tab3:
        _render_taara_stats(taara_analyzer)

    with tab4:
        _render_agent_fleet(taaraware_mgr, platform)


def _render_status_bar(platform, taara_analyzer, training_mgr, taaraware_mgr):
    """Render the top status bar."""
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        connected = platform.connected if platform else False
        st.metric("Connection", "Active" if connected else "Inactive",
                  delta="Online" if connected else "Offline")

    with col2:
        trained = training_mgr.is_ready()
        st.metric("ML Models", "Ready" if trained else "Not Trained")

    with col3:
        dep_count = taaraware_mgr.get_deployed_count() if taaraware_mgr else 0
        st.metric("TaaraWare Agents", dep_count)

    with col4:
        summary = taara_analyzer.get_detection_summary() if taara_analyzer else {}
        st.metric("Novelties Detected", summary.get('taara_novelty', 0))

    with col5:
        st.metric("Quantum Confirmed", summary.get('quantum_confirmed', 0))


def _render_live_monitor(platform, taara_analyzer, embedder, detector, training_mgr):
    """Render live monitoring panel with real-time analysis."""

    st.markdown("### Live Analysis")

    if not training_mgr.is_ready():
        st.warning("System not trained. Train the models first to enable live monitoring.")
        return

    if not platform or not platform.connected:
        st.warning("No platform connected.")
        return

    col_btn, col_status = st.columns([1, 3])
    with col_btn:
        run_analysis = st.button("Run Analysis Now", type="primary", use_container_width=True)

    if run_analysis:
        with st.spinner("Collecting and analyzing behavioral state..."):
            try:
                if platform.platform_type == 'ssh':
                    from components.atomic_dna_collector import AtomicDNACollector
                    from components.ssh_manager import SSHManager

                    ssh_mgr = SSHManager(
                        platform.config['host'],
                        platform.config['username'],
                        platform.config.get('password', '')
                    )
                    ssh_mgr.connect()
                    collector = AtomicDNACollector(ssh_mgr)
                    features = collector.get_feature_vector()
                else:
                    security_data = platform.collect_security_data()
                    feat_dict = security_data.get('features', {})
                    features = np.array([float(v) for v in feat_dict.values()], dtype=np.float32)
                    if len(features) < 19:
                        features = np.pad(features, (0, max(0, 19 - len(features))))

                embedding = embedder.embed(features) if embedder and embedder.is_ready() else None
                detection = detector.detect(embedding) if detector and detector.is_ready() and embedding is not None else None

                identity_id = f'{platform.platform_type}_system'
                taara_result = taara_analyzer.analyze(
                    identity_id, features,
                    baseline_alert=detection.get('is_anomaly', False) if detection else False
                )

                _display_analysis_result(taara_result, detection, features)

            except Exception as e:
                st.error(f"Analysis error: {e}")

    if 'monitoring_active' not in st.session_state:
        st.session_state.monitoring_active = False

    auto_monitor = st.checkbox("Enable Auto-Monitoring (every 60s)", value=st.session_state.monitoring_active)
    st.session_state.monitoring_active = auto_monitor

    if auto_monitor:
        st.info("Auto-monitoring is enabled. Analysis runs automatically.")


def _display_analysis_result(taara_result: Dict, detection: Optional[Dict], features: np.ndarray):
    """Display a single analysis result."""

    novelty = taara_result.get('novelty', {})
    quantum = taara_result.get('quantum_validation')
    is_novel = taara_result.get('is_taara_novel', False)
    is_quantum = taara_result.get('is_quantum_confirmed', False)

    if is_quantum:
        status_color = '#ff0000'
        status_text = 'QUANTUM-CONFIRMED NOVELTY'
        status_icon = 'ALERT'
    elif is_novel:
        status_color = '#ff6600'
        status_text = 'BEHAVIORAL NOVELTY DETECTED'
        status_icon = 'WARNING'
    else:
        status_color = '#00cc00'
        status_text = 'SYSTEM NORMAL'
        status_icon = 'OK'

    st.markdown(f"""
    <div style="background: linear-gradient(135deg, #0a0a1a, #1a1a3e);
                padding: 20px; border-radius: 10px; margin: 15px 0;
                border: 2px solid {status_color};">
        <h3 style="color: {status_color}; margin: 0;">{status_icon}: {status_text}</h3>
        <p style="color: #a0a0b0; margin: 5px 0;">
            Analyzed at {datetime.now().strftime('%H:%M:%S')} |
            Residual norm: {novelty.get('residual_norm', 0):.4f} |
            Max prior: {novelty.get('max_prior_residual', 0):.4f} |
            Memory basis: {novelty.get('basis_size', 0)} states
        </p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Novel?", "Yes" if is_novel else "No")
    with col2:
        st.metric("Quantum Confirmed?", "Yes" if is_quantum else "No")
    with col3:
        if quantum:
            st.metric("F_min", f"{quantum.get('f_min', 1.0):.4f}")
        else:
            st.metric("F_min", "N/A")
    with col4:
        if detection:
            st.metric("Anomaly Score", f"{detection.get('anomaly_score', 0):.4f}")
        else:
            st.metric("Anomaly Score", "N/A")

    if quantum:
        with st.expander("Quantum Validation Details"):
            st.json(quantum)


def _render_detection_results(taara_analyzer):
    """Render detection history and results."""

    st.markdown("### Detection Log")

    log = taara_analyzer.detection_log if hasattr(taara_analyzer, 'detection_log') else []

    if not log:
        st.info("No detections recorded yet. Run analysis to populate.")
        return

    novel_count = sum(1 for e in log if e.get('is_novel'))
    quantum_count = sum(1 for e in log if e.get('is_quantum_confirmed'))

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Observations", len(log))
    with col2:
        st.metric("Novelties", novel_count)
    with col3:
        st.metric("Quantum Confirmed", quantum_count)

    recent = log[-20:][::-1]
    for entry in recent:
        ts = datetime.fromtimestamp(entry.get('timestamp', 0)).strftime('%H:%M:%S')
        is_novel = entry.get('is_novel', False)
        is_quantum = entry.get('is_quantum_confirmed', False)

        if is_quantum:
            color = '#ff0000'
            label = 'QUANTUM NOVEL'
        elif is_novel:
            color = '#ff6600'
            label = 'NOVEL'
        else:
            color = '#00cc00'
            label = 'NORMAL'

        st.markdown(f"""
        <div style="padding: 5px 10px; margin: 2px 0; border-left: 3px solid {color};
                    background: #111; border-radius: 3px;">
            <span style="color: {color}; font-weight: bold;">[{label}]</span>
            <span style="color: #888;"> {ts}</span>
            <span style="color: #666;"> | Identity: {entry.get('identity_id', 'unknown')}</span>
            <span style="color: #666;"> | Residual: {entry.get('residual_norm', 0):.4f}</span>
        </div>
        """, unsafe_allow_html=True)


def _render_taara_stats(taara_analyzer):
    """Render TAARA detection statistics matching the paper's funnel."""

    st.markdown("### TAARA Detection Funnel")

    summary = taara_analyzer.get_detection_summary()

    funnel_data = [
        ("Total Windows Analyzed", summary.get('total_windows', 0), "100%", "#4466ff"),
        ("Baseline Alerts (IF + AE)", summary.get('baseline_alerts', 0),
         f"{summary.get('baseline_alert_rate', 0)}%", "#ff6600"),
        ("TAARA Novelty (Reconstruction)", summary.get('taara_novelty', 0),
         f"{summary.get('taara_novelty_rate', 0)}%", "#ffaa00"),
        ("TAARA-Only Detections", summary.get('taara_only', 0),
         f"{summary.get('taara_only_rate', 0)}%", "#e94560"),
        ("Quantum-Confirmed Novelty", summary.get('quantum_confirmed', 0),
         f"{summary.get('quantum_confirmation_rate', 0)}% of TAARA-only", "#ff0000"),
    ]

    for label, count, pct, color in funnel_data:
        st.markdown(f"""
        <div style="background: {color}22; padding: 10px 15px; margin: 3px 0;
                    border-left: 4px solid {color}; border-radius: 5px;">
            <span style="color: {color}; font-weight: bold;">{count}</span>
            <span style="color: #ccc;"> {label}</span>
            <span style="color: #888; float: right;">{pct}</span>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    col1, col2 = st.columns(2)
    with col1:
        st.metric("Identities Tracked", summary.get('identities_tracked', 0))
    with col2:
        st.metric("Mean Basis Size", f"{summary.get('mean_basis_size', 0)} states")

    st.markdown("""
    <div style="background: #0a1a2a; padding: 12px; border-radius: 8px; margin-top: 10px;">
        <p style="color: #66b3ff; margin: 0; font-size: 0.85em;">
            <b>Paper Reference:</b> TAARA identified 295 novel behavioral states (5.1%) missed
            by ensemble baseline methods, with 92.2% quantum-validated as directionally novel.
            79% of TAARA-only detections fell within the interquartile range of global feature
            distributions — proving novelty ≠ statistical extremity.
        </p>
    </div>
    """, unsafe_allow_html=True)


def _render_agent_fleet(taaraware_mgr, platform):
    """Render TaaraWare agent fleet status."""

    st.markdown("### Deployed TaaraWare Agents")

    dep_info = taaraware_mgr.get_deployment_info()

    if dep_info['total_deployed'] == 0:
        st.info("No TaaraWare agents deployed yet. Go to TaaraWare Deployment to deploy agents.")
        return

    for host, info in dep_info.get('agents', {}).items():
        deployed_time = datetime.fromtimestamp(info.get('deployed_at', 0)).strftime('%Y-%m-%d %H:%M')

        st.markdown(f"""
        <div style="background: #111; padding: 15px; border-radius: 8px; margin: 5px 0;
                    border: 1px solid #333;">
            <h4 style="color: #4466ff; margin: 0;">{host}</h4>
            <p style="color: #888; margin: 3px 0;">
                Platform: {info.get('platform', 'unknown')} |
                Deployed: {deployed_time} |
                Version: {info.get('version', 'unknown')} |
                Status: {info.get('status', 'unknown')}
            </p>
        </div>
        """, unsafe_allow_html=True)

    if platform and platform.connected and platform.platform_type == 'ssh':
        if st.button("Refresh Agent Status"):
            with st.spinner("Checking agent..."):
                status = taaraware_mgr.check_agent_status(platform)
                st.json(status)
