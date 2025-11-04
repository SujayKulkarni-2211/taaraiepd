import streamlit as st
import json
import os
from datetime import datetime
from components.frontend import render_main_layout
from components.ssh_manager import SSHManager
from components.dna_engine import DNAEngine
from components.security_integrator import SecurityIntegrator
from components.reasoning_engine import ReasoningEngine
from components.llm_service import LLMService
from components.niad_engine import NIADEngine
from components.rollback_manager import RollbackManager
from components.monitor_agent import MonitorAgent
from components.dashboard import render_comprehensive_dashboard

# Initialize session state
if "api_keys" not in st.session_state:
    st.session_state.api_keys = {}
if "ssh_manager" not in st.session_state:
    st.session_state.ssh_manager = None
if "llm_service" not in st.session_state:
    st.session_state.llm_service = None
if "connected" not in st.session_state:
    st.session_state.connected = False
if "servers" not in st.session_state:
    st.session_state.servers = []
if "pending_commands" not in st.session_state:
    st.session_state.pending_commands = []
if "cli_output" not in st.session_state:
    st.session_state.cli_output = []
if "actions_log" not in st.session_state:
    st.session_state.actions_log = []
if "monitor_agent" not in st.session_state:
    st.session_state.monitor_agent = None
if "monitor_data" not in st.session_state:
    st.session_state.monitor_data = None

def setup_screen():
    """Initial setup screen for API keys and SSH credentials."""
    st.set_page_config(page_title="Taara - DevSecOps Control", layout="wide")
    
    st.title("🔐 Taara")
    st.markdown("**Threat-Aware Autonomous Response Agent** - Enterprise DevSecOps Control Plane")
    st.write("Configure your security orchestration system.")
    
    with st.container(border=True):
        st.subheader("🔑 Security Configuration")
        col1, col2 = st.columns(2)
        
        with col1:
            llm_key = st.text_input(
                "Reasoning Engine API Key",
                type="password",
                help="API key for intelligent analysis system (as instructed by administrator)"
            )
            st.session_state.api_keys["llm"] = llm_key
        
        with col2:
            security_key = st.text_input(
                "Security Stack API Key",
                type="password",
                help="API key for threat intelligence integrations"
            )
            st.session_state.api_keys["security"] = security_key
    
    with st.container(border=True):
        st.subheader("🖥️ Remote VPS Configuration")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            vps_ip = st.text_input("VPS IP Address", placeholder="1.2.3.4")
        with col2:
            vps_user = st.text_input("SSH Username", placeholder="root")
        with col3:
            vps_pass = st.text_input("SSH Password", type="password")
    
    if st.button("🚀 Connect & Initialize", use_container_width=True, type="primary"):
        if vps_ip and vps_user and vps_pass and st.session_state.api_keys.get("llm"):
            try:
                # Test SSH connection
                ssh_mgr = SSHManager(vps_ip, vps_user, vps_pass)
                if ssh_mgr.connect():
                    st.session_state.ssh_manager = ssh_mgr
                    st.session_state.connected = True
                    
                    # Initialize LLM service
                    st.session_state.llm_service = LLMService(st.session_state.api_keys["llm"])

                    # Initialize monitor agent
                    st.session_state.monitor_agent = MonitorAgent(ssh_mgr)

                    # Initialize server state
                    st.session_state.servers = [{
                        "id": "srv1",
                        "ip": vps_ip,
                        "user": vps_user,
                        "status": "connected",
                        "baseline_dna": None,
                        "current_dna": None,
                        "similarity_score": 1.0,
                        "crowdsec_alerts": [],
                        "clamav_alerts": [],
                        "actions_log": []
                    }]
                    
                    # Collect baseline DNA and initial monitoring data
                    with st.spinner("📊 Collecting system baseline and monitoring data..."):
                        dna_engine = DNAEngine(ssh_mgr)
                        baseline = dna_engine.collect_system_dna()
                        st.session_state.servers[0]["baseline_dna"] = baseline
                        st.session_state.servers[0]["current_dna"] = baseline

                        # Collect initial monitoring data
                        st.session_state.monitor_data = st.session_state.monitor_agent.collect_all_metrics()
                    
                    st.success("✅ Connected and baseline initialized!")
                    st.rerun()
                else:
                    st.error("❌ Failed to connect to VPS. Check credentials.")
            except Exception as e:
                st.error(f"❌ Connection error: {str(e)}")
        else:
            st.warning("⚠️ Please fill in all required fields")

def main_app():
    """Main application interface."""
    st.set_page_config(
        page_title="Taara - DevSecOps Control",
        layout="wide",
        initial_sidebar_state="collapsed"
    )
    
    st.title("⚡ Taara")
    st.markdown("**Threat-Aware Autonomous Response Agent**")
    
    # Navigation sidebar
    view = st.sidebar.radio(
        "Navigation",
        ["Dashboard", "DevOps Actions", "Security Actions", "AI Chat", "Agent", "Actions Log"],
        key="nav"
    )
    
    # Monitoring refresh button
    with st.sidebar:
        if st.button("🔄 Update All Metrics", use_container_width=True, type="primary"):
            if st.session_state.servers and st.session_state.ssh_manager:
                with st.spinner("📊 Collecting comprehensive metrics..."):
                    server = st.session_state.servers[0]

                    # Initialize monitor agent if not exists
                    if st.session_state.monitor_agent is None:
                        st.session_state.monitor_agent = MonitorAgent(st.session_state.ssh_manager)

                    # Collect ALL monitoring data
                    st.session_state.monitor_data = st.session_state.monitor_agent.collect_all_metrics()

                    # Update DNA
                    dna_engine = DNAEngine(st.session_state.ssh_manager)
                    current_dna = dna_engine.collect_system_dna()
                    server["current_dna"] = current_dna

                    # Check drift
                    drift = dna_engine.detect_drift(server["baseline_dna"], current_dna)
                    server["similarity_score"] = drift["similarity_score"]

                    # Security scan
                    security = SecurityIntegrator(st.session_state.ssh_manager)
                    status = security.get_security_status()
                    server["clamav_alerts"] = status["clamav_alerts"]
                    server["crowdsec_alerts"] = status["crowdsec_alerts"]

                    # Reasoning analysis if anomaly detected
                    if drift["is_anomaly"] and st.session_state.llm_service:
                        reasoning = ReasoningEngine(st.session_state.api_keys["llm"])
                        analysis = reasoning.correlate_events(drift, server["clamav_alerts"] + server["crowdsec_alerts"])

                        if analysis.get("llm_analysis", {}).get("success"):
                            st.sidebar.warning("⚠️ Anomaly Detected!")
                            st.sidebar.info(analysis["llm_analysis"]["explanation"][:200])

                st.success("✅ Metrics updated!")
                st.rerun()
    
    # Main content
    render_main_layout(view, st.session_state.servers[0] if st.session_state.servers else None)

# Main flow
if not st.session_state.connected:
    setup_screen()
else:
    main_app()
