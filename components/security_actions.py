"""
Production-Level Security Actions & AI Chat Interface
Real implementations, not dummies
"""

import streamlit as st
from datetime import datetime


def render_security_actions_pro(server: dict, monitor_data: dict):
    """Production-level security actions with tool detection."""

    st.subheader("🛡️ Security Actions")

    # Get security status to check what's available
    security = monitor_data.get('security', {}) if monitor_data else {}

    # Tool availability status
    with st.expander("🔧 Security Tools Status"):
        col1, col2, col3 = st.columns(3)
        with col1:
            clam_status = "🟢 Installed" if security.get('clamav_installed') else "🔴 Not Installed"
            st.metric("ClamAV", clam_status)
        with col2:
            crowdsec_status = "🟢 Installed" if security.get('crowdsec_installed') else "🔴 Not Installed"
            st.metric("CrowdSec", crowdsec_status)
        with col3:
            fw_status = f"🟢 Active ({security.get('firewall_type', 'none')})" if security.get('firewall_active') else "🔴 Inactive"
            st.metric("Firewall", fw_status)

    st.markdown("---")

    # Action selector
    action = st.selectbox(
        "Select Security Action",
        [
            "🦠 Scan for Malware (ClamAV)",
            "📋 View Security Logs",
            "🔥 Manage Firewall",
            "🎭 NIAD Honeypot Isolation",
            "🚫 Block Malicious IP",
            "🔍 Check for Rootkits",
            "📊 Security Audit",
            "🛡️ Harden System"
        ]
    )

    # === MALWARE SCANNING ===
    if action == "🦠 Scan for Malware (ClamAV)":
        if not security.get('clamav_installed'):
            st.warning("⚠️ ClamAV is not installed on this server")
            st.info("**Install ClamAV:**")
            install_cmd = """# Ubuntu/Debian
sudo apt-get update && sudo apt-get install -y clamav clamav-daemon
sudo freshclam

# CentOS/RHEL
sudo yum install -y clamav clamav-update
sudo freshclam"""
            st.code(install_cmd, language="bash")

            if st.button("📦 Generate Install Command", use_container_width=True):
                st.session_state.pending_commands.append({
                    "proposed": "apt-get update && apt-get install -y clamav clamav-daemon && freshclam",
                    "rollback": "apt-get remove -y clamav clamav-daemon",
                    "type": "install_clamav"
                })
                st.success("Install command proposed!")
                st.rerun()
        else:
            st.success("✅ ClamAV is installed and ready")

            scan_type = st.radio(
                "Scan Type",
                ["Quick Scan (/home, /tmp)", "Full System Scan", "Custom Path"]
            )

            if scan_type == "Custom Path":
                scan_path = st.text_input("Path to scan", "/var/www")
            elif scan_type == "Full System Scan":
                scan_path = "/"
            else:
                scan_path = "/home /tmp"

            col1, col2 = st.columns(2)
            with col1:
                recursive = st.checkbox("Recursive", value=True)
            with col2:
                infected_only = st.checkbox("Show infected only", value=False)

            if st.button("🦠 Run Malware Scan", type="primary", use_container_width=True):
                flags = "-r" if recursive else ""
                flags += " -i" if infected_only else ""
                proposed = f"clamscan {flags} {scan_path} --max-filesize=100M | tee /tmp/clamav-scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}.log"

                st.session_state.pending_commands.append({
                    "proposed": proposed,
                    "rollback": "echo 'Scan completed - no rollback needed'",
                    "type": "malware_scan"
                })
                st.success("Malware scan command proposed!")
                st.rerun()

    # === VIEW SECURITY LOGS ===
    elif action == "📋 View Security Logs":
        st.markdown("### Security Log Viewer")

        log_type = st.selectbox(
            "Select Log Type",
            ["SSH Authentication (/var/log/auth.log)",
             "System Log (/var/log/syslog)",
             "Firewall Log",
             "Docker Logs",
             "ClamAV Logs",
             "Custom Path"]
        )

        lines = st.slider("Number of lines", 10, 500, 100)

        if log_type == "Custom Path":
            log_path = st.text_input("Log file path", "/var/log/custom.log")
        elif log_type == "SSH Authentication (/var/log/auth.log)":
            log_path = "/var/log/auth.log"
        elif log_type == "System Log (/var/log/syslog)":
            log_path = "/var/log/syslog"
        elif log_type == "Firewall Log":
            log_path = "/var/log/ufw.log"  # or kern.log for iptables
        elif log_type == "Docker Logs":
            log_path = "/var/lib/docker/containers"
        else:
            log_path = "/var/log/clamav/clamav.log"

        search_term = st.text_input("Filter by keyword (optional)", "")

        if st.button("📖 View Logs", type="primary", use_container_width=True):
            if search_term:
                proposed = f"tail -n {lines} {log_path} | grep -i '{search_term}'"
            else:
                proposed = f"tail -n {lines} {log_path}"

            st.session_state.pending_commands.append({
                "proposed": proposed,
                "rollback": "echo 'Log viewing completed'",
                "type": "view_logs"
            })
            st.success("Log viewing command proposed!")
            st.rerun()

    # === MANAGE FIREWALL ===
    elif action == "🔥 Manage Firewall":
        fw_active = security.get('firewall_active', False)
        fw_type = security.get('firewall_type', 'none')

        st.markdown(f"**Current Status:** {'🟢 Active' if fw_active else '🔴 Inactive'}")
        if fw_active:
            st.markdown(f"**Firewall Type:** {fw_type.upper()}")

        fw_action = st.radio(
            "Firewall Action",
            ["Enable Firewall", "Disable Firewall", "Add Rule (Allow)", "Add Rule (Deny)", "View Rules", "Reset Firewall"]
        )

        if fw_action == "Enable Firewall":
            if fw_active:
                st.info(f"✅ Firewall is already active ({fw_type})")
            else:
                st.warning("⚠️ This will enable UFW firewall. Make sure SSH access is allowed!")

                if st.button("🔥 Enable UFW Firewall", type="primary", use_container_width=True):
                    proposed = "ufw --force enable && ufw allow 22/tcp && ufw status"
                    st.session_state.pending_commands.append({
                        "proposed": proposed,
                        "rollback": "ufw disable",
                        "type": "enable_firewall"
                    })
                    st.success("Firewall enable command proposed!")
                    st.rerun()

        elif fw_action == "Disable Firewall":
            st.error("⚠️ WARNING: Disabling firewall removes protection!")
            if st.button("⚠️ Disable Firewall", use_container_width=True):
                if fw_type == "ufw":
                    proposed = "ufw disable"
                elif fw_type == "firewalld":
                    proposed = "systemctl stop firewalld && systemctl disable firewalld"
                else:
                    proposed = "iptables -F && iptables -X"

                st.session_state.pending_commands.append({
                    "proposed": proposed,
                    "rollback": "ufw --force enable" if fw_type == "ufw" else "systemctl start firewalld",
                    "type": "disable_firewall"
                })
                st.success("Firewall disable command proposed!")
                st.rerun()

        elif fw_action == "Add Rule (Allow)":
            col1, col2 = st.columns(2)
            with col1:
                port = st.text_input("Port number", "80")
            with col2:
                protocol = st.selectbox("Protocol", ["tcp", "udp"])

            if st.button("➕ Add Allow Rule", type="primary", use_container_width=True):
                if fw_type == "ufw" or not fw_active:
                    proposed = f"ufw allow {port}/{protocol} && ufw status"
                elif fw_type == "firewalld":
                    proposed = f"firewall-cmd --permanent --add-port={port}/{protocol} && firewall-cmd --reload"
                else:
                    proposed = f"iptables -A INPUT -p {protocol} --dport {port} -j ACCEPT"

                st.session_state.pending_commands.append({
                    "proposed": proposed,
                    "rollback": f"ufw delete allow {port}/{protocol}",
                    "type": "firewall_allow"
                })
                st.success("Firewall rule proposed!")
                st.rerun()

        elif fw_action == "View Rules":
            if st.button("📋 View Firewall Rules", use_container_width=True):
                if fw_type == "ufw":
                    proposed = "ufw status numbered"
                elif fw_type == "firewalld":
                    proposed = "firewall-cmd --list-all"
                else:
                    proposed = "iptables -L -n -v"

                st.session_state.pending_commands.append({
                    "proposed": proposed,
                    "rollback": "echo 'Rules viewed'",
                    "type": "view_firewall"
                })
                st.success("View rules command proposed!")
                st.rerun()

    # === NIAD ISOLATION ===
    elif action == "🎭 NIAD Honeypot Isolation":
        st.info("**Non-Invasive Adaptive Deception**: Isolate suspicious containers and create honeypots")

        containers = monitor_data.get('containers', []) if monitor_data else []
        if containers:
            running_containers = [c['name'] for c in containers if c.get('state') == 'running']

            if running_containers:
                container = st.selectbox("Select container to isolate", running_containers)

                st.warning(f"⚠️ This will disconnect '{container}' from network and create a honeypot")

                if st.button("🎭 Deploy NIAD Honeypot", type="primary", use_container_width=True):
                    honeypot_name = f"honeypot-{container}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
                    proposed = (
                        f"docker network disconnect bridge {container} && "
                        f"docker run -d --name {honeypot_name} --network none alpine sh -c 'echo Honeypot Active && sleep infinity' && "
                        f"echo 'NIAD deployed: {honeypot_name}'"
                    )
                    rollback = f"docker network connect bridge {container} && docker rm -f {honeypot_name}"

                    st.session_state.pending_commands.append({
                        "proposed": proposed,
                        "rollback": rollback,
                        "type": "niad_honeypot"
                    })
                    st.success("NIAD honeypot command proposed!")
                    st.rerun()
            else:
                st.info("No running containers to isolate")
        else:
            st.info("No containers found. Update metrics to see containers.")

    # === BLOCK IP ===
    elif action == "🚫 Block Malicious IP":
        st.markdown("### Block IP Address")

        ip_address = st.text_input("IP Address to block", placeholder="192.168.1.100")
        reason = st.text_input("Reason (optional)", placeholder="Brute force attempt")

        if ip_address and st.button("🚫 Block IP", type="primary", use_container_width=True):
            if fw_type == "ufw" or not fw_active:
                proposed = f"ufw deny from {ip_address} && ufw status | grep {ip_address}"
            elif fw_type == "firewalld":
                proposed = f"firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address={ip_address} reject' && firewall-cmd --reload"
            else:
                proposed = f"iptables -A INPUT -s {ip_address} -j DROP"

            st.session_state.pending_commands.append({
                "proposed": proposed,
                "rollback": f"ufw delete deny from {ip_address}",
                "type": "block_ip"
            })
            st.success(f"Block IP '{ip_address}' command proposed!")
            st.rerun()

    # === CHECK ROOTKITS ===
    elif action == "🔍 Check for Rootkits":
        if security.get('rootkit_scanner'):
            st.success("✅ rkhunter is installed")

            if st.button("🔍 Run Rootkit Scan", type="primary", use_container_width=True):
                proposed = "rkhunter --check --skip-keypress --report-warnings-only"
                st.session_state.pending_commands.append({
                    "proposed": proposed,
                    "rollback": "echo 'Rootkit scan completed'",
                    "type": "rootkit_scan"
                })
                st.success("Rootkit scan command proposed!")
                st.rerun()
        else:
            st.warning("⚠️ rkhunter is not installed")
            if st.button("📦 Install rkhunter", use_container_width=True):
                proposed = "apt-get update && apt-get install -y rkhunter && rkhunter --update"
                st.session_state.pending_commands.append({
                    "proposed": proposed,
                    "rollback": "apt-get remove -y rkhunter",
                    "type": "install_rkhunter"
                })
                st.success("Install rkhunter command proposed!")
                st.rerun()

    # === SECURITY AUDIT ===
    elif action == "📊 Security Audit":
        st.markdown("### Comprehensive Security Audit")

        audit_checks = st.multiselect(
            "Select audit checks",
            [
                "List users with sudo access",
                "Check for users with empty passwords",
                "List all open ports",
                "Check SSH configuration",
                "List SUID/SGID files",
                "Check world-writable files",
                "Review cron jobs"
            ],
            default=["List users with sudo access", "Check SSH configuration"]
        )

        if st.button("📊 Run Security Audit", type="primary", use_container_width=True):
            commands = []
            if "List users with sudo access" in audit_checks:
                commands.append("grep '^sudo:.*$' /etc/group | cut -d: -f4")
            if "Check for users with empty passwords" in audit_checks:
                commands.append("awk -F: '($2 == \"\") {print $1}' /etc/shadow")
            if "List all open ports" in audit_checks:
                commands.append("netstat -tuln")
            if "Check SSH configuration" in audit_checks:
                commands.append("grep -E 'PermitRootLogin|PasswordAuthentication|PubkeyAuthentication' /etc/ssh/sshd_config")
            if "List SUID/SGID files" in audit_checks:
                commands.append("find / -perm /6000 -type f 2>/dev/null | head -20")
            if "Check world-writable files" in audit_checks:
                commands.append("find / -perm -002 -type f 2>/dev/null | head -20")
            if "Review cron jobs" in audit_checks:
                commands.append("crontab -l && ls -la /etc/cron.*")

            proposed = " && echo '---' && ".join(commands)

            st.session_state.pending_commands.append({
                "proposed": proposed,
                "rollback": "echo 'Audit completed'",
                "type": "security_audit"
            })
            st.success("Security audit command proposed!")
            st.rerun()

    # === HARDEN SYSTEM ===
    elif action == "🛡️ Harden System":
        st.markdown("### System Hardening")
        st.warning("⚠️ These changes may affect system behavior. Review carefully!")

        hardening_options = st.multiselect(
            "Select hardening measures",
            [
                "Disable root SSH login",
                "Disable password authentication (key-only)",
                "Install fail2ban",
                "Enable automatic security updates",
                "Configure secure kernel parameters",
                "Remove unnecessary packages"
            ]
        )

        if hardening_options and st.button("🛡️ Apply Hardening", type="primary", use_container_width=True):
            commands = []
            if "Disable root SSH login" in hardening_options:
                commands.append("sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl restart sshd")
            if "Install fail2ban" in hardening_options:
                commands.append("apt-get install -y fail2ban && systemctl enable fail2ban && systemctl start fail2ban")
            if "Enable automatic security updates" in hardening_options:
                commands.append("apt-get install -y unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades")

            proposed = " && ".join(commands)

            st.session_state.pending_commands.append({
                "proposed": proposed,
                "rollback": "echo 'Manual rollback required'",
                "type": "system_hardening"
            })
            st.success("System hardening commands proposed!")
            st.rerun()


def render_ai_chat_interface(server: dict):
    """AI-powered chat interface for natural language commands."""

    st.subheader("💬 AI Command Assistant")
    st.markdown("Describe what you want to do, and AI will generate the commands for you.")

    # Initialize chat history
    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []

    # Display chat history
    for i, msg in enumerate(st.session_state.chat_history):
        if msg["role"] == "user":
            with st.chat_message("user"):
                st.markdown(msg["content"])
        else:
            with st.chat_message("assistant"):
                st.markdown(msg["content"])
                if msg.get("commands"):
                    for cmd in msg["commands"]:
                        st.code(cmd, language="bash")

    # User input FORM (fixes the issue where response doesn't show)
    with st.form(key="ai_chat_form", clear_on_submit=True):
        user_input = st.text_area(
            "Your Request:",
            placeholder="e.g., 'Check if port 80 is open' or 'Find large files in /var'",
            height=100,
            key="chat_input_field"
        )
        submit_button = st.form_submit_button("🚀 Generate Command", use_container_width=True, type="primary")

    if submit_button and user_input:
        # Add user message
        st.session_state.chat_history.append({"role": "user", "content": user_input})

        # Generate AI response
        llm_service = st.session_state.get("llm_service")

        if not llm_service:
            st.error("❌ LLM Service not initialized! Go back and re-enter your API key.")
            st.session_state.chat_history.append({
                "role": "assistant",
                "content": "❌ Error: LLM service not available. Please check your API key in the setup.",
                "commands": []
            })
        else:
            with st.spinner("🤖 AI is thinking..."):
                try:
                    prompt = f"""You are a Linux system administrator. Generate shell commands for this request:

Request: {user_input}

Server info:
- OS: Linux
- IP: {server.get('ip', 'unknown')}
- User: {server.get('user', 'unknown')}

Provide:
1. Brief explanation (2-3 sentences)
2. The exact shell command(s) in markdown code blocks
3. Any warnings or considerations

Be concise and practical. Use ```bash code blocks for commands."""

                    response = llm_service.generate_response(prompt)

                    if response.get("success"):
                        explanation = response.get("explanation", "Here are the commands:")
                        commands = [cmd.get("code") for cmd in response.get("commands", [])]

                        # Add AI response
                        st.session_state.chat_history.append({
                            "role": "assistant",
                            "content": explanation,
                            "commands": commands
                        })

                        # Propose commands to CLI
                        for cmd in commands:
                            st.session_state.pending_commands.append({
                                "proposed": cmd,
                                "rollback": "echo 'Manual rollback if needed'",
                                "type": "ai_generated"
                            })

                        st.success(f"✅ Generated {len(commands)} command(s)! Check CLI panel to approve.")
                    else:
                        error_msg = response.get('error', 'Unknown error')
                        st.session_state.chat_history.append({
                            "role": "assistant",
                            "content": f"❌ Error: {error_msg}",
                            "commands": []
                        })
                        st.error(f"AI Error: {error_msg}")

                except Exception as e:
                    st.session_state.chat_history.append({
                        "role": "assistant",
                        "content": f"❌ Exception: {str(e)}",
                        "commands": []
                    })
                    st.error(f"Exception: {str(e)}")

        st.rerun()

    # Clear chat
    if st.session_state.chat_history:
        if st.button("🗑️ Clear Chat", use_container_width=True):
            st.session_state.chat_history = []
            st.rerun()
