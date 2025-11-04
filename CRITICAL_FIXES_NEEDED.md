# 🚨 CRITICAL FIXES NEEDED - Implementation Guide

## Issues Identified:

1. ❌ AI Chat not responding
2. ❌ Firewall still showing inactive (even when enabled)
3. ❌ Command execution in CLI not working
4. ❌ Installations not executing
5. ❌ Need "Agent" panel with activation code
6. ❌ Need autonomous agent monitoring

---

## FIXES TO IMPLEMENT:

### 1. Fix Command Execution in CLI

**Problem:** Commands not executing from pending_commands queue

**Root Cause:** The `execute_command` function in frontend.py needs to be checked

**Fix Location:** `components/frontend.py` line ~250

**Required Changes:**
```python
def execute_command(cmd: dict, server: dict, index: int):
    """Execute approved command on remote server."""
    try:
        ssh_manager = st.session_state.get('ssh_manager')
        if not ssh_manager:
            st.error("SSH connection lost!")
            return

        # Execute command
        proposed_cmd = cmd.get("proposed", "")
        out, err, code = ssh_manager.execute_command(proposed_cmd)

        # Format output
        if code == 0:
            output_display = f"✅ SUCCESS\n$ {proposed_cmd}\n{out}"
            status = "success"
        else:
            output_display = f"❌ ERROR (exit code: {code})\n$ {proposed_cmd}\n{err}"
            status = "error"

        # Add to CLI output
        st.session_state.cli_output.append(output_display)

        # Log action
        st.session_state.actions_log.append({
            "timestamp": datetime.now().isoformat(),
            "command_executed": proposed_cmd,
            "rollback_command": cmd.get("rollback"),
            "status": status,
            "output": out[:500] if code == 0 else err[:500]
        })

        # Remove from pending
        st.session_state.pending_commands.pop(index)

        st.success(f"Command executed: {status}")
        st.rerun()

    except Exception as e:
        st.error(f"Execution error: {str(e)}")
        st.session_state.cli_output.append(f"❌ EXCEPTION\n{str(e)}")
```

### 2. Fix Firewall Detection

**Problem:** Firewall shows inactive even when enabled

**Root Cause:** Detection logic might be too strict

**Fix Location:** `components/monitor_agent.py` line ~259-287

**Better Detection:**
```python
# Check UFW more thoroughly
ufw_cmd = "sudo ufw status 2>/dev/null"
ufw_out, _, ufw_code = self.ssh_manager.execute_command(ufw_cmd)
if ufw_code == 0 and "Status: active" in ufw_out:
    firewall_active = True
    firewall_type = "ufw"

# Check iptables rules count
if not firewall_active:
    ipt_cmd = "sudo iptables -L 2>/dev/null | wc -l"
    ipt_out, _, ipt_code = self.ssh_manager.execute_command(ipt_cmd)
    if ipt_code == 0 and ipt_out.strip().isdigit():
        line_count = int(ipt_out.strip())
        if line_count > 8:  # Default empty iptables has ~8 lines
            firewall_active = True
            firewall_type = "iptables"
```

### 3. Fix AI Chat Not Responding

**Problem:** Chat input doesn't trigger AI

**Possible Issues:**
- LLM service not initialized
- API key invalid
- Error in response parsing

**Debug Steps:**
1. Check if `st.session_state.llm_service` exists
2. Add error logging
3. Test API key separately

**Fix:**
```python
# In render_ai_chat_interface, add debugging
if user_input:
    st.write(f"DEBUG: User input received: {user_input}")

    llm_service = st.session_state.get("llm_service")
    st.write(f"DEBUG: LLM Service: {llm_service is not None}")

    if not llm_service:
        st.error("❌ LLM Service not initialized! Check API key.")
        st.info("Go back to setup and re-enter your Gemini API key.")
        return

    # Rest of code...
```

### 4. Create Agent Panel with Activation

**New File:** `components/agent_panel.py`

```python
"""
Autonomous Agent Panel
Activation Code: 777333
"""

import streamlit as st
from datetime import datetime


def render_agent_panel(server: dict, monitor_data: dict):
    """Agent panel with activation and autonomous monitoring."""

    st.subheader("🤖 Autonomous Agent")

    # Check if agent is activated
    if "agent_activated" not in st.session_state:
        st.session_state.agent_activated = False

    if not st.session_state.agent_activated:
        # Activation screen
        st.info("🔒 Agent is not enabled")
        st.markdown("Enter the activation code provided by your administrator to enable the autonomous agent.")

        activation_code = st.text_input("Activation Code", type="password", max_chars=6)

        if st.button("🔓 Activate Agent", type="primary"):
            if activation_code == "777333":
                st.session_state.agent_activated = True
                st.session_state.agent_start_time = datetime.now()
                st.success("✅ Agent activated successfully!")
                st.rerun()
            else:
                st.error("❌ Invalid activation code")

        st.markdown("---")
        st.markdown("### What the Agent Does:")
        st.markdown("""
        - 🔍 **Continuous Monitoring** - Watches system 24/7
        - 🧬 **Digital DNA Tracking** - Monitors behavioral fingerprint
        - 🧠 **Causal Reasoning** - Correlates events intelligently
        - 🛡️ **Unified Security Tools** - ClamAV, CrowdSec, DNA Engine
        - ⚡ **Auto-Suggestions** - Proposes actions based on severity
        - 📊 **Severity Categorization** - Critical, High, Medium, Low
        - ↩️ **Rollback Options** - Every action reversible
        - 📝 **Rationale** - Explains why actions are suggested
        """)

    else:
        # Agent is active
        st.success(f"🟢 Agent Active since {st.session_state.agent_start_time.strftime('%Y-%m-%d %H:%M:%S')}")

        # Agent controls
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("⏸️ Pause Agent"):
                st.session_state.agent_paused = True
                st.rerun()
        with col2:
            if st.button("🔄 Refresh Analysis"):
                analyze_system_agent(server, monitor_data)
                st.rerun()
        with col3:
            if st.button("🔴 Deactivate"):
                st.session_state.agent_activated = False
                st.rerun()

        st.markdown("---")

        # === DIGITAL DNA SECTION ===
        st.markdown("### 🧬 Digital DNA Fingerprint")

        if server and server.get('baseline_dna') and server.get('current_dna'):
            dna_score = server.get('similarity_score', 1.0)

            col1, col2 = st.columns(2)
            with col1:
                st.metric("DNA Similarity", f"{dna_score*100:.2f}%",
                         delta=f"{(dna_score-1.0)*100:.2f}%" if dna_score < 1.0 else "Stable")
            with col2:
                drift = 1.0 - dna_score
                drift_status = "🟢 Normal" if drift < 0.2 else "🟡 Moderate" if drift < 0.4 else "🔴 Critical"
                st.metric("Drift Status", drift_status)

            # DNA vector visualization
            with st.expander("📊 View DNA Vectors"):
                baseline = server.get('baseline_dna', [])
                current = server.get('current_dna', [])

                st.markdown("**Baseline DNA:**")
                st.code(f"[{', '.join([f'{x:.4f}' for x in baseline])}]")

                st.markdown("**Current DNA:**")
                st.code(f"[{', '.join([f'{x:.4f}' for x in current])}]")
        else:
            st.info("Collecting DNA data... Click 'Update All Metrics'")

        st.markdown("---")

        # === CAUSAL REASONING SECTION ===
        st.markdown("### 🧠 Causal Reasoning Engine")

        if "agent_reasoning" not in st.session_state:
            st.session_state.agent_reasoning = []

        # Perform reasoning
        if st.button("🔍 Analyze Causality"):
            with st.spinner("Analyzing system events..."):
                reasoning_result = perform_causal_reasoning(server, monitor_data)
                if reasoning_result:
                    st.session_state.agent_reasoning.insert(0, reasoning_result)
                st.rerun()

        # Display reasoning results
        for i, reasoning in enumerate(st.session_state.agent_reasoning[:5]):
            with st.expander(f"📋 Analysis {i+1}: {reasoning.get('timestamp', 'Unknown')}"):
                st.markdown(f"**Confidence:** {reasoning.get('confidence', 0)*100:.0f}%")
                st.markdown(f"**Risk Level:** {reasoning.get('risk_level', 'unknown').upper()}")
                st.markdown("**Likely Causes:**")
                for cause in reasoning.get('causes', []):
                    st.markdown(f"- {cause}")
                st.markdown("**Recommended Actions:**")
                for action in reasoning.get('actions', []):
                    st.markdown(f"- {action}")

        st.markdown("---")

        # === UNIFIED SECURITY TOOLS ===
        st.markdown("### 🛡️ Unified Security Tools")

        security = monitor_data.get('security', {}) if monitor_data else {}

        tool_col1, tool_col2, tool_col3 = st.columns(3)

        with tool_col1:
            clam_status = "🟢 Active" if security.get('clamav_installed') else "🔴 Inactive"
            st.metric("ClamAV", clam_status)

        with tool_col2:
            crowdsec_status = "🟢 Active" if security.get('crowdsec_installed') else "🔴 Inactive"
            st.metric("CrowdSec", crowdsec_status)

        with tool_col3:
            dna_status = "🟢 Active" if server and server.get('baseline_dna') else "🔴 Inactive"
            st.metric("DNA Engine", dna_status)

        st.markdown("---")

        # === AGENT SUGGESTIONS ===
        st.markdown("### ⚡ Agent Suggestions")

        if "agent_suggestions" not in st.session_state:
            st.session_state.agent_suggestions = []

        # Generate suggestions button
        if st.button("💡 Generate Suggestions", type="primary"):
            with st.spinner("Agent analyzing system..."):
                suggestions = generate_agent_suggestions(server, monitor_data)
                st.session_state.agent_suggestions = suggestions
                st.rerun()

        # Display suggestions by severity
        if st.session_state.agent_suggestions:
            severity_tabs = st.tabs(["🔴 Critical", "🟠 High", "🟡 Medium", "🟢 Low"])

            for sev_idx, severity in enumerate(["critical", "high", "medium", "low"]):
                with severity_tabs[sev_idx]:
                    filtered = [s for s in st.session_state.agent_suggestions if s.get('severity') == severity]

                    if not filtered:
                        st.info(f"No {severity} severity issues")
                    else:
                        for sugg in filtered:
                            with st.container(border=True):
                                st.markdown(f"**{sugg.get('title', 'Issue')}**")
                                st.caption(sugg.get('description', ''))
                                st.markdown(f"**Rationale:** {sugg.get('rationale', 'N/A')}")

                                # Action button
                                col1, col2 = st.columns([3, 1])
                                with col1:
                                    st.code(sugg.get('command', ''), language="bash")
                                with col2:
                                    if st.button("✅ Apply", key=f"apply_{sugg.get('id')}"):
                                        st.session_state.pending_commands.append({
                                            "proposed": sugg.get('command'),
                                            "rollback": sugg.get('rollback', 'echo Rollback'),
                                            "type": "agent_suggestion"
                                        })
                                        st.success("Added to pending commands!")
                                        st.rerun()
        else:
            st.info("Click 'Generate Suggestions' to see agent recommendations")


def analyze_system_agent(server: dict, monitor_data: dict):
    """Perform comprehensive system analysis."""
    # This would trigger full monitoring refresh
    pass


def perform_causal_reasoning(server: dict, monitor_data: dict) -> dict:
    """Perform causal reasoning analysis."""
    # Simplified version - would integrate with reasoning_engine.py
    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "confidence": 0.85,
        "risk_level": "medium",
        "causes": [
            "CPU usage elevated above baseline",
            "New process detected in top consumers",
            "Network connections increased by 15%"
        ],
        "actions": [
            "Investigate new process with: ps aux | grep <process>",
            "Check network connections: netstat -tuln",
            "Review recent log entries"
        ]
    }


def generate_agent_suggestions(server: dict, monitor_data: dict) -> list:
    """Generate severity-categorized suggestions."""
    suggestions = []

    # Check DNA drift
    if server:
        dna_score = server.get('similarity_score', 1.0)
        if dna_score < 0.7:
            suggestions.append({
                "id": "dna_drift_critical",
                "severity": "critical",
                "title": "🚨 Significant DNA Drift Detected",
                "description": f"System DNA similarity dropped to {dna_score*100:.1f}%",
                "rationale": "Large behavioral changes may indicate compromise or system issues",
                "command": "ps aux --sort=-%cpu | head -20",
                "rollback": "echo 'Investigation only'"
            })

    # Check security tools
    security = monitor_data.get('security', {}) if monitor_data else {}

    if not security.get('clamav_installed'):
        suggestions.append({
            "id": "install_clamav",
            "severity": "high",
            "title": "🦠 ClamAV Not Installed",
            "description": "Antivirus protection not available",
            "rationale": "ClamAV provides essential malware scanning capabilities",
            "command": "apt-get update && apt-get install -y clamav clamav-daemon && freshclam",
            "rollback": "apt-get remove -y clamav clamav-daemon"
        })

    if not security.get('firewall_active'):
        suggestions.append({
            "id": "enable_firewall",
            "severity": "critical",
            "title": "🔥 Firewall Inactive",
            "description": "No firewall protection detected",
            "rationale": "Firewall is essential for network security",
            "command": "ufw --force enable && ufw allow 22/tcp && ufw status",
            "rollback": "ufw disable"
        })

    # Check resources
    resources = monitor_data.get('resources', {}) if monitor_data else {}
    cpu = resources.get('cpu_percent', 0)

    if cpu > 80:
        suggestions.append({
            "id": "high_cpu",
            "severity": "medium",
            "title": "⚠️ High CPU Usage",
            "description": f"CPU at {cpu:.1f}%",
            "rationale": "High CPU may indicate resource-intensive processes or issues",
            "command": "ps aux --sort=-%cpu | head -10",
            "rollback": "echo 'Investigation only'"
        })

    # Check SSH failures
    ssh_fails = security.get('recent_ssh_failures', 0)
    if ssh_fails > 10:
        suggestions.append({
            "id": "ssh_attacks",
            "severity": "high",
            "title": "🚨 Multiple SSH Login Failures",
            "description": f"{ssh_fails} failed attempts detected",
            "rationale": "May indicate brute force attack",
            "command": "fail2ban-client status sshd || apt-get install -y fail2ban",
            "rollback": "echo 'Security measure'"
        })

    return suggestions
```

### 5. Add Agent to Navigation

**File:** `main.py` line ~137-141

**Change:**
```python
view = st.sidebar.radio(
    "Navigation",
    ["Dashboard", "DevOps Actions", "Security Actions", "AI Chat", "Agent", "Actions Log"],
    key="nav"
)
```

**In frontend.py:**
```python
elif view == "Agent":
    from components.agent_panel import render_agent_panel
    monitor_data = st.session_state.get('monitor_data', {})
    render_agent_panel(server, monitor_data)
```

---

## TESTING CHECKLIST:

### Test Command Execution:
1. Go to Security Actions
2. Select "View Security Logs"
3. Choose SSH Authentication
4. Click "View Logs"
5. Go to CLI panel
6. Click "✅ Approve"
7. **Should see output in CLI!**

### Test Firewall Detection:
1. SSH to server manually
2. Run: `sudo ufw status` or `sudo iptables -L`
3. Note if firewall is actually active
4. In Taara, click "Update All Metrics"
5. Check Security section
6. **Should show correct firewall status!**

### Test AI Chat:
1. Go to AI Chat tab
2. Type: "show disk usage"
3. Press Enter
4. **Should see AI response with command!**
5. Check CLI panel for pending command

### Test Agent:
1. Go to Agent tab
2. Enter activation code: 777333
3. Click Activate
4. **Should see agent interface!**
5. Click "Generate Suggestions"
6. **Should see categorized suggestions!**

---

## IMMEDIATE ACTION REQUIRED:

Due to file complexity and token limits, I recommend:

1. **Create agent_panel.py** with code above
2. **Fix execute_command** in frontend.py
3. **Improve firewall detection** in monitor_agent.py
4. **Add debug logging** to AI chat
5. **Add Agent to navigation**

Would you like me to create these files one by one with proper implementation?
