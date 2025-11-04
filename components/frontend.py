import streamlit as st
from datetime import datetime
import time
from components.dashboard import render_comprehensive_dashboard
from components.security_actions import render_security_actions_pro, render_ai_chat_interface

def render_main_layout(view: str, server: dict):
    """Render main application layout with CLI and chat."""
    
    # Create two-column layout
    cli_col, chat_col = st.columns([1, 1.2], gap="medium")
    
    with cli_col:
        st.subheader("⌨️ Command Line Interface")

        # Server status
        if server:
            status_color = "🟢" if server["status"] == "connected" else "🔴"
            st.metric("Server Status", f"{status_color} {server['ip']}")
            dna_score = server.get('similarity_score', 1.0)
            threat_color = "🟢" if dna_score > 0.8 else "🟡" if dna_score > 0.6 else "🔴"
            st.metric("System Health", f"{threat_color} {dna_score*100:.1f}%")

        # MANUAL COMMAND INPUT (NEW!)
        with st.expander("✏️ Manual Command Input", expanded=False):
            st.caption("Type commands directly (experts only)")
            manual_cmd = st.text_area("Command:", placeholder="ls -la", height=68, key="manual_cmd_input")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("➕ Add to Queue", use_container_width=True):
                    if manual_cmd.strip():
                        st.session_state.pending_commands.append({
                            "proposed": manual_cmd.strip(),
                            "rollback": "echo 'Manual command - no auto rollback'",
                            "type": "manual"
                        })
                        st.success("Added to pending!")
                        st.rerun()
            with col2:
                if st.button("⚡ Execute Now", use_container_width=True, type="primary"):
                    if manual_cmd.strip() and server:
                        # Execute immediately
                        execute_command_now({
                            "proposed": manual_cmd.strip(),
                            "rollback": "echo 'Manual'",
                            "type": "manual_instant"
                        }, server)
                        st.rerun()

        # CLI Output with scrollable container
        with st.container(border=True, height=400):
            st.caption("Command Output")
            if st.session_state.cli_output:
                # Show last 10 outputs
                output_text = "\n\n---\n\n".join(st.session_state.cli_output[-10:])
                st.text_area("", value=output_text, height=300, disabled=True, key="cli_output_display")

                # Copy button for last output
                if st.button("📋 Copy Last Output"):
                    st.code(st.session_state.cli_output[-1], language="text")
            else:
                st.info("No command output yet")
        
        # Pending commands with approval workflow
        if st.session_state.pending_commands:
            st.subheader(f"⏳ Pending Commands ({len(st.session_state.pending_commands)})")
            for i, cmd in enumerate(st.session_state.pending_commands):
                with st.container(border=True):
                    st.caption(f"Command #{i+1}")
                    
                    # Show proposed command
                    proposed = cmd.get("proposed", "")
                    st.code(proposed, language="bash")
                    
                    # Show rollback (if exists)
                    if cmd.get("rollback"):
                        with st.expander("View Rollback"):
                            st.code(cmd.get("rollback"), language="bash")
                    
                    # Approval buttons
                    col1, col2, col3 = st.columns([2, 1, 1])
                    with col1:
                        st.caption(f"Type: {cmd.get('type', 'unknown')}")
                    with col2:
                        if st.button("✅ Approve", key=f"approve_{i}"):
                            execute_command(cmd, server, i)
                    with col3:
                        if st.button("❌ Reject", key=f"reject_{i}"):
                            st.session_state.pending_commands.pop(i)
                            st.rerun()
    
    with chat_col:
        if view == "Dashboard":
            # Use comprehensive dashboard with monitoring data
            monitor_data = st.session_state.get('monitor_data', {})
            render_comprehensive_dashboard(server, monitor_data)
        elif view == "DevOps Actions":
            render_devops_actions(server)
        elif view == "Security Actions":
            # Use new production-level security actions
            monitor_data = st.session_state.get('monitor_data', {})
            render_security_actions_pro(server, monitor_data)
        elif view == "AI Chat":
            # AI-powered chat interface
            render_ai_chat_interface(server)
        elif view == "Agent":
            # Autonomous Agent with activation code
            from components.agent_panel import render_agent_panel
            monitor_data = st.session_state.get('monitor_data', {})
            render_agent_panel(server, monitor_data)
        elif view == "Actions Log":
            render_actions_log()

def render_dashboard(server: dict):
    """Dashboard view with system metrics and threat analysis."""
    st.subheader("📊 System Dashboard")
    
    if not server:
        st.warning("No server connected")
        return
    
    # Metrics
    col1, col2 = st.columns(2)
    with col1:
        st.metric("IP Address", server.get("ip", "N/A"))
        st.metric("Connection Status", server.get("status", "disconnected"))
    with col2:
        dna_score = server.get("similarity_score", 1.0)
        st.metric("System DNA Match", f"{dna_score*100:.1f}%")
        status = "🔴 Drift Detected" if dna_score < 0.8 else "🟢 Normal"
        st.metric("Anomaly Status", status)
    
    # Security Alerts Section
    st.subheader("🛡️ Security Status")
    alerts = server.get("clamav_alerts", []) + server.get("crowdsec_alerts", [])
    
    if alerts:
        st.warning(f"⚠️ {len(alerts)} Active Threat(s)")
        for alert in alerts:
            with st.container(border=True):
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.error(f"**{alert.get('type', 'Unknown').upper()}**")
                    st.write(alert.get('message', ''))
                    st.caption(f"Severity: {alert.get('severity', 'unknown')}")
                with col2:
                    if st.button("Investigate", key=f"investigate_{alert.get('timestamp')}"):
                        st.session_state.show_investigation = alert
    else:
        st.success("✅ No active threats detected")

def render_devops_actions(server: dict):
    """DevOps action interface with LLM-powered proposals."""
    st.subheader("🚀 DevOps Actions")
    
    action = st.selectbox(
        "Select Action",
        ["Deploy", "Restart Service", "Scale Container", "Update Config", "Rolling Update"]
    )
    
    if action == "Deploy":
        service = st.text_input("Service name", "app")
        version = st.text_input("New version", "v1.0.0")
        deployment_type = st.selectbox("Deployment strategy", ["rolling", "blue-green", "canary"])
        
        if st.button("Propose Deploy with AI", type="primary", use_container_width=True):
            llm_service = st.session_state.get("llm_service")
            if llm_service:
                response = llm_service.propose_deployment(
                    service=service,
                    current_version="stable",
                    new_version=version,
                    deployment_type=deployment_type
                )
                
                if response.get("success"):
                    # Extract commands from LLM response
                    commands = response.get("commands", [])
                    
                    if commands:
                        for i, cmd_block in enumerate(commands):
                            if cmd_block.get("language") in ["bash", "shell"]:
                                st.session_state.pending_commands.append({
                                    "proposed": cmd_block["code"],
                                    "rollback": f"docker pull {service}:stable && docker restart {service}",
                                    "type": "deploy"
                                })
                        
                        st.success(f"✅ {len(commands)} deployment commands proposed!")
                        st.info(response.get("explanation", ""))
                        st.rerun()
            else:
                # Fallback without LLM
                proposed = f"docker pull repo/{service}:{version} && docker restart {service}"
                rollback = f"docker pull repo/{service}:stable && docker restart {service}"
                st.session_state.pending_commands.append({
                    "proposed": proposed,
                    "rollback": rollback,
                    "type": "deploy"
                })
                st.success("Command proposed!")
                st.rerun()
    
    elif action == "Restart Service":
        service = st.text_input("Service name", "nginx")
        if st.button("Propose Restart", type="primary", use_container_width=True):
            proposed = f"systemctl restart {service}"
            st.session_state.pending_commands.append({
                "proposed": proposed,
                "rollback": f"systemctl restart {service}",
                "type": "restart"
            })
            st.success("Command proposed!")
            st.rerun()

def render_security_actions(server: dict):
    """Security action interface with threat response."""
    st.subheader("🛡️ Security Actions")
    
    action = st.selectbox(
        "Select Security Action",
        ["Scan for Malware", "Check Logs", "Enable Firewall", "NIAD Isolation", "Block IP"]
    )
    
    if action == "Scan for Malware":
        if st.button("Run ClamAV Scan", type="primary", use_container_width=True):
            proposed = "clamscan -r / --max-filesize=50M --log=/var/log/clamav-scan.log"
            st.session_state.pending_commands.append({
                "proposed": proposed,
                "rollback": "echo 'Scan complete - no rollback needed'",
                "type": "scan"
            })
            st.success("Scan command proposed!")
            st.rerun()
    
    elif action == "NIAD Isolation":
        st.info("Non-Invasive Adaptive Deception: Create honeypot for threat monitoring")
        container = st.text_input("Container ID/name to isolate")
        
        if st.button("Isolate & Monitor with Honeypot", type="primary", use_container_width=True):
            # NIAD commands: isolate + honeypot
            proposed = (
                f"docker network disconnect bridge {container} && "
                f"docker run -d --name honeypot-{container} --network none alpine sleep infinity && "
                f"echo 'Honeypot active - monitoring attacker'"
            )
            rollback = f"docker network connect bridge {container} && docker rm -f honeypot-{container}"
            
            st.session_state.pending_commands.append({
                "proposed": proposed,
                "rollback": rollback,
                "type": "niad"
            })
            st.success("NIAD honeypot command proposed!")
            st.rerun()

def render_actions_log():
    """Display full actions log with rollback capability."""
    st.subheader("📋 Actions Log")
    
    if not st.session_state.actions_log:
        st.info("No actions logged yet")
        return
    
    # Display actions in reverse chronological order
    for i, action in enumerate(reversed(st.session_state.actions_log)):
        with st.container(border=True):
            col1, col2 = st.columns([4, 1])
            
            with col1:
                timestamp = action.get("timestamp", "")
                st.caption(f"⏰ {timestamp}")
                
                # Command
                st.code(action.get("command_executed", ""), language="bash")
                
                # Status
                status_icon = "✅" if action.get("status") == "success" else "❌"
                st.write(f"{status_icon} **Status:** {action.get('status')}")
                
                # Output (if any)
                if action.get("output"):
                    with st.expander("View Output"):
                        st.code(action.get("output", ""), language="bash")
            
            with col2:
                if action.get("rollback_command"):
                    if st.button("↩️ Rollback", key=f"rollback_{i}"):
                        st.info("Rollback initiated...")
                        st.rerun()

def execute_command_now(cmd: dict, server: dict):
    """Execute command immediately without queue."""
    try:
        ssh_manager = st.session_state.get('ssh_manager')
        if not ssh_manager:
            st.error("❌ SSH connection lost!")
            return

        proposed_cmd = cmd.get("proposed", "")

        with st.spinner(f"Executing: {proposed_cmd[:50]}..."):
            out, err, code = ssh_manager.execute_command(proposed_cmd)

        if code == 0:
            output_display = f"✅ SUCCESS\n$ {proposed_cmd}\n\n{out}"
            st.success("Command executed successfully!")
        else:
            output_display = f"❌ ERROR (code {code})\n$ {proposed_cmd}\n\n{err}"
            st.error(f"Command failed with exit code {code}")

        st.session_state.cli_output.append(output_display)

        st.session_state.actions_log.append({
            "timestamp": datetime.now().isoformat(),
            "command_executed": proposed_cmd,
            "rollback_command": cmd.get("rollback"),
            "status": "success" if code == 0 else "error",
            "output": out[:500] if code == 0 else err[:500]
        })

    except Exception as e:
        st.error(f"❌ Exception: {str(e)}")
        st.session_state.cli_output.append(f"❌ EXCEPTION\n{str(e)}")


def execute_command(cmd: dict, server: dict, index: int):
    """Execute approved command from queue."""
    try:
        ssh_manager = st.session_state.get('ssh_manager')
        if not ssh_manager:
            st.error("❌ SSH connection lost!")
            return

        proposed_cmd = cmd.get("proposed", "")
        out, err, code = ssh_manager.execute_command(proposed_cmd)

        if code == 0:
            output_display = f"✅ SUCCESS\n$ {proposed_cmd}\n\n{out}"
            status = "success"
        else:
            output_display = f"❌ ERROR (code {code})\n$ {proposed_cmd}\n\n{err}"
            status = "error"

        st.session_state.cli_output.append(output_display)

        st.session_state.actions_log.append({
            "timestamp": datetime.now().isoformat(),
            "command_executed": proposed_cmd,
            "rollback_command": cmd.get("rollback"),
            "status": status,
            "output": out[:500] if code == 0 else err[:500]
        })

        st.session_state.pending_commands.pop(index)

        st.success(f"✅ Executed: {status}")
        st.rerun()

    except Exception as e:
        st.error(f"❌ Execution error: {str(e)}")
        st.session_state.cli_output.append(f"❌ ERROR\n{str(e)}")
