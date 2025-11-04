"""
Autonomous Agent Panel
Activation Code: 777333
Monitors system and provides intelligent suggestions
"""

import streamlit as st
from datetime import datetime
import random


def render_agent_panel(server: dict, monitor_data: dict):
    """Agent panel with activation and autonomous monitoring."""

    st.subheader("🤖 Autonomous Agent")

    # Check if agent is activated
    if "agent_activated" not in st.session_state:
        st.session_state.agent_activated = False

    if not st.session_state.agent_activated:
        # === ACTIVATION SCREEN ===
        st.info("🔒 **Agent is Not Enabled**")
        st.markdown("Enter the activation code provided by your administrator to enable the autonomous agent.")

        col1, col2 = st.columns([2, 1])
        with col1:
            activation_code = st.text_input("Activation Code", type="password", max_chars=6, key="agent_activation_code")
        with col2:
            st.write("")
            st.write("")
            if st.button("🔓 Activate Agent", type="primary", use_container_width=True):
                if activation_code == "777333":
                    st.session_state.agent_activated = True
                    st.session_state.agent_start_time = datetime.now()
                    if "agent_suggestions" not in st.session_state:
                        st.session_state.agent_suggestions = []
                    if "agent_reasoning" not in st.session_state:
                        st.session_state.agent_reasoning = []
                    st.success("✅ Agent activated successfully!")
                    st.balloons()
                    st.rerun()
                else:
                    st.error("❌ Invalid activation code. Contact your administrator.")

        st.markdown("---")
        st.markdown("### 🎯 What the Agent Does:")

        col1, col2 = st.columns(2)
        with col1:
            st.markdown("""
            - 🔍 **Continuous Monitoring** - Watches system 24/7
            - 🧬 **Digital DNA Tracking** - Behavioral fingerprint
            - 🧠 **Causal Reasoning** - Intelligent correlation
            - 🛡️ **Unified Security Tools** - All-in-one
            """)
        with col2:
            st.markdown("""
            - ⚡ **Auto-Suggestions** - Smart recommendations
            - 📊 **Severity Categorization** - Priority-based
            - ↩️ **Rollback Options** - Every action reversible
            - 📝 **Rationale** - Explains every decision
            """)

        st.markdown("---")
        st.info("💡 **Tip:** The agent learns your system's behavior and suggests proactive security measures.")

    else:
        # === AGENT IS ACTIVE ===
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.success(f"🟢 **Agent Active**")
            st.caption(f"Since: {st.session_state.agent_start_time.strftime('%H:%M:%S')}")
        with col2:
            if st.button("⏸️ Pause"):
                st.session_state.agent_paused = not st.session_state.get('agent_paused', False)
                st.rerun()
        with col3:
            if st.button("🔄 Refresh"):
                st.rerun()
        with col4:
            if st.button("🔴 Deactivate"):
                st.session_state.agent_activated = False
                st.warning("Agent deactivated")
                st.rerun()

        st.markdown("---")

        # === DIGITAL DNA SECTION ===
        with st.container(border=True):
            st.markdown("### 🧬 Digital DNA Fingerprint")

            if server and server.get('baseline_dna') and server.get('current_dna'):
                dna_score = server.get('similarity_score', 1.0)
                drift = 1.0 - dna_score

                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("DNA Similarity", f"{dna_score*100:.2f}%",
                             delta=f"{(dna_score-1.0)*100:.2f}%" if dna_score < 1.0 else "Stable",
                             delta_color="inverse")
                with col2:
                    drift_status = "🟢 Normal" if drift < 0.2 else "🟡 Moderate" if drift < 0.4 else "🔴 Critical"
                    st.metric("Drift Status", drift_status)
                with col3:
                    st.metric("Drift Magnitude", f"{drift*100:.2f}%")

                # DNA vector visualization
                with st.expander("📊 View DNA Vectors"):
                    baseline = server.get('baseline_dna', [])
                    current = server.get('current_dna', [])

                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown("**Baseline DNA:**")
                        st.code(f"[{', '.join([f'{x:.4f}' for x in baseline])}]")
                    with col2:
                        st.markdown("**Current DNA:**")
                        st.code(f"[{', '.join([f'{x:.4f}' for x in current])}]")

                    st.markdown("**Components:**")
                    st.markdown("- `[0]` CPU Usage (normalized)")
                    st.markdown("- `[1]` Memory Usage (normalized)")
                    st.markdown("- `[2]` Process Count (normalized)")
                    st.markdown("- `[3]` Open Ports (normalized)")
            else:
                st.info("📊 Collecting DNA data... Click 'Update All Metrics' in sidebar")

        st.markdown("---")

        # === CAUSAL REASONING SECTION ===
        with st.container(border=True):
            st.markdown("### 🧠 Causal Reasoning Engine")

            col1, col2 = st.columns([3, 1])
            with col1:
                st.caption("Correlates DNA drift, security alerts, and system metrics for intelligent analysis")
            with col2:
                if st.button("🔍 Analyze", use_container_width=True, type="primary"):
                    with st.spinner("Analyzing causality..."):
                        reasoning_result = perform_causal_reasoning(server, monitor_data)
                        if reasoning_result:
                            if "agent_reasoning" not in st.session_state:
                                st.session_state.agent_reasoning = []
                            st.session_state.agent_reasoning.insert(0, reasoning_result)
                        st.rerun()

            # Display reasoning results
            if st.session_state.get('agent_reasoning'):
                for i, reasoning in enumerate(st.session_state.agent_reasoning[:3]):
                    with st.expander(f"📋 Analysis {i+1}: {reasoning.get('timestamp', 'Unknown')}", expanded=(i==0)):
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("Confidence", f"{reasoning.get('confidence', 0)*100:.0f}%")
                        with col2:
                            risk = reasoning.get('risk_level', 'unknown').upper()
                            color = "🔴" if risk == "CRITICAL" else "🟠" if risk == "HIGH" else "🟡" if risk == "MEDIUM" else "🟢"
                            st.metric("Risk Level", f"{color} {risk}")
                        with col3:
                            st.metric("Events", len(reasoning.get('causes', [])))

                        st.markdown("**Likely Causes:**")
                        for cause in reasoning.get('causes', []):
                            st.markdown(f"- {cause}")

                        st.markdown("**Recommended Actions:**")
                        for action in reasoning.get('actions', []):
                            st.markdown(f"- {action}")
            else:
                st.info("Click 'Analyze' to perform causal reasoning analysis")

        st.markdown("---")

        # === UNIFIED SECURITY TOOLS ===
        with st.container(border=True):
            st.markdown("### 🛡️ Unified Security Tools")

            security = monitor_data.get('security', {}) if monitor_data else {}

            col1, col2, col3, col4 = st.columns(4)

            with col1:
                clam_status = "🟢 Active" if security.get('clamav_installed') else "🔴 Inactive"
                st.metric("ClamAV", clam_status)

            with col2:
                crowdsec_status = "🟢 Active" if security.get('crowdsec_installed') else "🔴 Inactive"
                st.metric("CrowdSec", crowdsec_status)

            with col3:
                dna_status = "🟢 Active" if server and server.get('baseline_dna') else "🔴 Inactive"
                st.metric("DNA Engine", dna_status)

            with col4:
                fw_status = "🟢 Active" if security.get('firewall_active') else "🔴 Inactive"
                st.metric(f"Firewall ({security.get('firewall_type', 'none')})", fw_status)

        st.markdown("---")

        # === AGENT SUGGESTIONS ===
        with st.container(border=True):
            st.markdown("### ⚡ Agent Suggestions")

            col1, col2 = st.columns([3, 1])
            with col1:
                st.caption("AI-powered recommendations categorized by severity")
            with col2:
                if st.button("💡 Generate", use_container_width=True, type="primary"):
                    with st.spinner("Agent analyzing system..."):
                        suggestions = generate_agent_suggestions(server, monitor_data)
                        st.session_state.agent_suggestions = suggestions
                        st.success(f"Generated {len(suggestions)} suggestions!")
                        st.rerun()

            # Display suggestions by severity
            if st.session_state.get('agent_suggestions'):
                # Count by severity
                critical = len([s for s in st.session_state.agent_suggestions if s.get('severity') == 'critical'])
                high = len([s for s in st.session_state.agent_suggestions if s.get('severity') == 'high'])
                medium = len([s for s in st.session_state.agent_suggestions if s.get('severity') == 'medium'])
                low = len([s for s in st.session_state.agent_suggestions if s.get('severity') == 'low'])

                # Summary
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("🔴 Critical", critical)
                with col2:
                    st.metric("🟠 High", high)
                with col3:
                    st.metric("🟡 Medium", medium)
                with col4:
                    st.metric("🟢 Low", low)

                st.markdown("---")

                # Tabs for each severity
                severity_tabs = st.tabs(["🔴 Critical", "🟠 High", "🟡 Medium", "🟢 Low"])

                for sev_idx, severity in enumerate(["critical", "high", "medium", "low"]):
                    with severity_tabs[sev_idx]:
                        filtered = [s for s in st.session_state.agent_suggestions if s.get('severity') == severity]

                        if not filtered:
                            st.info(f"No {severity} severity issues detected")
                        else:
                            for sugg in filtered:
                                with st.container(border=True):
                                    st.markdown(f"**{sugg.get('title', 'Issue')}**")
                                    st.caption(sugg.get('description', ''))

                                    with st.expander("📝 Details"):
                                        st.markdown(f"**Rationale:** {sugg.get('rationale', 'N/A')}")
                                        st.markdown(f"**Command:**")
                                        st.code(sugg.get('command', ''), language="bash")
                                        if sugg.get('rollback'):
                                            st.markdown(f"**Rollback:**")
                                            st.code(sugg.get('rollback', ''), language="bash")

                                    # Action buttons
                                    col1, col2, col3 = st.columns([2, 1, 1])
                                    with col2:
                                        if st.button("✅ Apply", key=f"apply_{sugg.get('id')}", use_container_width=True):
                                            st.session_state.pending_commands.append({
                                                "proposed": sugg.get('command'),
                                                "rollback": sugg.get('rollback', 'echo Rollback'),
                                                "type": "agent_suggestion"
                                            })
                                            st.success("Added to pending commands!")
                                            st.rerun()
                                    with col3:
                                        if st.button("❌ Dismiss", key=f"dismiss_{sugg.get('id')}", use_container_width=True):
                                            st.session_state.agent_suggestions.remove(sugg)
                                            st.info("Dismissed")
                                            st.rerun()
            else:
                st.info("Click 'Generate' to see agent recommendations")


def perform_causal_reasoning(server: dict, monitor_data: dict) -> dict:
    """Perform causal reasoning analysis."""
    causes = []
    actions = []
    confidence = 0.5
    risk_level = "low"

    # Analyze DNA drift
    if server:
        dna_score = server.get('similarity_score', 1.0)
        drift = 1.0 - dna_score

        if drift > 0.3:
            causes.append(f"Significant DNA drift detected ({drift*100:.1f}%)")
            actions.append("Investigate behavioral changes with: ps aux --sort=-%cpu")
            confidence = max(confidence, 0.7)
            risk_level = "high" if drift > 0.5 else "medium"

    # Analyze resources
    if monitor_data:
        resources = monitor_data.get('resources', {})
        cpu = resources.get('cpu_percent', 0)
        memory = resources.get('memory_percent', 0)

        if cpu > 80:
            causes.append(f"High CPU usage detected ({cpu:.1f}%)")
            actions.append("Check top processes: top -bn1 | head -20")
            confidence = max(confidence, 0.8)
            risk_level = "medium"

        if memory > 85:
            causes.append(f"High memory usage detected ({memory:.1f}%)")
            actions.append("Identify memory hogs: ps aux --sort=-%mem | head -10")
            confidence = max(confidence, 0.85)
            risk_level = "high"

    # Analyze security
    if monitor_data:
        security = monitor_data.get('security', {})
        ssh_fails = security.get('recent_ssh_failures', 0)

        if ssh_fails > 10:
            causes.append(f"Multiple SSH login failures ({ssh_fails} attempts)")
            actions.append("Review failed logins: grep 'Failed password' /var/log/auth.log | tail -20")
            confidence = max(confidence, 0.9)
            risk_level = "critical" if ssh_fails > 50 else "high"

        if not security.get('firewall_active'):
            causes.append("Firewall is not active")
            actions.append("Enable firewall: sudo ufw enable && sudo ufw allow 22/tcp")
            confidence = max(confidence, 0.95)
            risk_level = "critical"

    # If no issues found
    if not causes:
        causes.append("No significant anomalies detected")
        actions.append("System appears healthy - continue monitoring")
        confidence = 0.9
        risk_level = "low"

    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "confidence": confidence,
        "risk_level": risk_level,
        "causes": causes,
        "actions": actions
    }


def generate_agent_suggestions(server: dict, monitor_data: dict) -> list:
    """Generate severity-categorized suggestions."""
    suggestions = []
    suggestion_id = 0

    # Check DNA drift
    if server:
        dna_score = server.get('similarity_score', 1.0)
        if dna_score < 0.7:
            suggestion_id += 1
            suggestions.append({
                "id": f"dna_drift_{suggestion_id}",
                "severity": "critical",
                "title": "🚨 Significant DNA Drift Detected",
                "description": f"System DNA similarity dropped to {dna_score*100:.1f}%",
                "rationale": "Large behavioral changes may indicate system compromise, malware, or critical misconfigurations",
                "command": "ps aux --sort=-%cpu | head -20 && netstat -tuln | grep ESTABLISHED",
                "rollback": "echo 'Investigation only - no changes made'"
            })
        elif dna_score < 0.85:
            suggestion_id += 1
            suggestions.append({
                "id": f"dna_drift_{suggestion_id}",
                "severity": "medium",
                "title": "⚠️ Moderate DNA Drift",
                "description": f"System behavior changed ({dna_score*100:.1f}% similarity)",
                "rationale": "System patterns have shifted - investigate for planned changes or issues",
                "command": "systemctl list-units --failed",
                "rollback": "echo 'Investigation only'"
            })

    # Check security tools
    if monitor_data:
        security = monitor_data.get('security', {})

        if not security.get('clamav_installed'):
            suggestion_id += 1
            suggestions.append({
                "id": f"install_clamav_{suggestion_id}",
                "severity": "high",
                "title": "🦠 ClamAV Not Installed",
                "description": "Antivirus protection not available",
                "rationale": "ClamAV provides essential malware scanning capabilities for server security",
                "command": "sudo apt-get update && sudo apt-get install -y clamav clamav-daemon && sudo freshclam",
                "rollback": "sudo apt-get remove -y clamav clamav-daemon"
            })

        if not security.get('firewall_active'):
            suggestion_id += 1
            suggestions.append({
                "id": f"enable_firewall_{suggestion_id}",
                "severity": "critical",
                "title": "🔥 Firewall Inactive",
                "description": "No firewall protection detected",
                "rationale": "Firewall is essential for network security - blocks unauthorized access",
                "command": "sudo ufw --force enable && sudo ufw allow 22/tcp && sudo ufw status",
                "rollback": "sudo ufw disable"
            })

        ssh_fails = security.get('recent_ssh_failures', 0)
        if ssh_fails > 20:
            suggestion_id += 1
            suggestions.append({
                "id": f"ssh_attacks_{suggestion_id}",
                "severity": "critical",
                "title": "🚨 Active SSH Brute Force Attack",
                "description": f"{ssh_fails} failed login attempts detected",
                "rationale": "High number of failures indicates brute force attack in progress",
                "command": "sudo apt-get install -y fail2ban && sudo systemctl enable fail2ban && sudo systemctl start fail2ban",
                "rollback": "sudo systemctl stop fail2ban && sudo apt-get remove -y fail2ban"
            })
        elif ssh_fails > 10:
            suggestion_id += 1
            suggestions.append({
                "id": f"ssh_attempts_{suggestion_id}",
                "severity": "high",
                "title": "🚫 Multiple SSH Login Failures",
                "description": f"{ssh_fails} failed attempts",
                "rationale": "May indicate reconnaissance or weak attack attempts",
                "command": "grep 'Failed password' /var/log/auth.log | tail -30",
                "rollback": "echo 'Investigation only'"
            })

        # Check resources
        resources = monitor_data.get('resources', {})
        cpu = resources.get('cpu_percent', 0)
        memory = resources.get('memory_percent', 0)

        if cpu > 90:
            suggestion_id += 1
            suggestions.append({
                "id": f"high_cpu_{suggestion_id}",
                "severity": "high",
                "title": "💻 Critical CPU Usage",
                "description": f"CPU at {cpu:.1f}%",
                "rationale": "Extremely high CPU may cause service degradation or indicate cryptomining",
                "command": "ps aux --sort=-%cpu | head -15",
                "rollback": "echo 'Investigation only'"
            })
        elif cpu > 80:
            suggestion_id += 1
            suggestions.append({
                "id": f"high_cpu_{suggestion_id}",
                "severity": "medium",
                "title": "⚠️ High CPU Usage",
                "description": f"CPU at {cpu:.1f}%",
                "rationale": "High CPU may indicate resource-intensive processes",
                "command": "ps aux --sort=-%cpu | head -10",
                "rollback": "echo 'Investigation only'"
            })

        if memory > 90:
            suggestion_id += 1
            suggestions.append({
                "id": f"high_memory_{suggestion_id}",
                "severity": "high",
                "title": "💾 Critical Memory Usage",
                "description": f"Memory at {memory:.1f}%",
                "rationale": "Critical memory usage may cause OOM killer or system instability",
                "command": "ps aux --sort=-%mem | head -15 && free -h",
                "rollback": "echo 'Investigation only'"
            })

        # Check disk
        disks = monitor_data.get('disk', [])
        for disk in disks:
            usage = disk.get('usage_percent', 0)
            if usage > 90:
                suggestion_id += 1
                suggestions.append({
                    "id": f"disk_full_{suggestion_id}",
                    "severity": "critical",
                    "title": f"💾 Disk Almost Full ({disk.get('device')})",
                    "description": f"{usage}% used on {disk.get('mount')}",
                    "rationale": "Disk near capacity can cause service failures and data loss",
                    "command": f"du -h {disk.get('mount')} | sort -rh | head -20",
                    "rollback": "echo 'Investigation only'"
                })

    # If no issues, add positive suggestion
    if not suggestions:
        suggestions.append({
            "id": "all_good",
            "severity": "low",
            "title": "✅ System Healthy",
            "description": "No critical issues detected",
            "rationale": "All monitored parameters are within normal ranges",
            "command": "echo 'System is operating normally'",
            "rollback": "echo 'No action needed'"
        })

    return suggestions
