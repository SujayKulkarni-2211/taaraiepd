"""
Comprehensive Real-time Dashboard
Shows containers, services, processes, network, resources
"""

import streamlit as st
from datetime import datetime
import pandas as pd


def render_comprehensive_dashboard(server: dict, monitor_data: dict):
    """Render comprehensive dashboard with real system data."""

    st.subheader("📊 Live System Dashboard")

    if not server:
        st.warning("No server connected.")
        return

    if not monitor_data:
        st.info("📊 Click **'🔄 Update All Metrics'** in the sidebar to collect monitoring data.")
        st.markdown("---")
        st.markdown("### What you'll see:")
        st.markdown("""
        - 🐳 **Docker Containers** - All containers with resource usage
        - 💻 **System Resources** - CPU, Memory, Load averages
        - 🔝 **Top Processes** - CPU-consuming processes
        - ⚙️ **System Services** - Active services
        - 🌐 **Network Status** - Port listeners and connections
        - 💾 **Disk Usage** - All partitions with usage
        - 🛡️ **Security Indicators** - SSH failures, firewall status, DNA score
        """)
        return

    # Header with refresh time
    col1, col2 = st.columns([3, 1])
    with col1:
        st.caption(f"🔄 Last updated: {monitor_data.get('timestamp', 'Never')[:19]}")
    with col2:
        if st.button("🔄 Refresh Now", use_container_width=True):
            st.rerun()

    # === RESOURCE OVERVIEW ===
    st.markdown("### 💻 Resource Usage")
    resources = monitor_data.get('resources', {})

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        cpu = resources.get('cpu_percent', 0)
        cpu_color = "🔴" if cpu > 80 else "🟡" if cpu > 60 else "🟢"
        st.metric(f"{cpu_color} CPU", f"{cpu:.1f}%")

    with col2:
        mem = resources.get('memory_percent', 0)
        mem_color = "🔴" if mem > 85 else "🟡" if mem > 70 else "🟢"
        st.metric(f"{mem_color} Memory", f"{mem:.1f}%")
        st.caption(f"{resources.get('memory_used_gb', 0):.1f}G / {resources.get('memory_total_gb', 0):.1f}G")

    with col3:
        load = resources.get('load_1min', 0)
        st.metric("⚙️ Load (1min)", f"{load:.2f}")
        st.caption(f"5m: {resources.get('load_5min', 0):.2f} | 15m: {resources.get('load_15min', 0):.2f}")

    with col4:
        procs = resources.get('process_count', 0)
        st.metric("🔢 Processes", f"{procs}")

    # Resource bar charts
    col1, col2 = st.columns(2)
    with col1:
        st.progress(cpu / 100, text=f"CPU: {cpu:.1f}%")
    with col2:
        st.progress(mem / 100, text=f"Memory: {mem:.1f}%")

    st.divider()

    # === DOCKER CONTAINERS ===
    st.markdown("### 🐳 Docker Containers")
    containers = monitor_data.get('containers', [])

    if containers:
        col1, col2, col3 = st.columns(3)
        running = len([c for c in containers if c.get('state') == 'running'])
        stopped = len([c for c in containers if c.get('state') == 'stopped'])
        total = len(containers)

        with col1:
            st.metric("🟢 Running", running)
        with col2:
            st.metric("🔴 Stopped", stopped)
        with col3:
            st.metric("📦 Total", total)

        # Container details table
        for container in containers:
            with st.expander(f"{container.get('status_color', '⚪')} {container.get('name', 'Unknown')} - {container.get('state', 'unknown').upper()}"):
                col1, col2 = st.columns([2, 1])

                with col1:
                    st.markdown(f"**Image:** `{container.get('image', 'N/A')}`")
                    st.markdown(f"**ID:** `{container.get('id', 'N/A')[:12]}`")
                    st.markdown(f"**Status:** {container.get('status', 'N/A')}")
                    ports = container.get('ports', '')
                    if ports:
                        st.markdown(f"**Ports:** `{ports}`")

                with col2:
                    if container.get('cpu'):
                        st.metric("CPU", container.get('cpu', 'N/A'))
                    if container.get('memory'):
                        st.metric("Memory", container.get('memory', 'N/A'))
                    if container.get('net_io'):
                        st.caption(f"Net I/O: {container.get('net_io', 'N/A')}")
                    if container.get('block_io'):
                        st.caption(f"Block I/O: {container.get('block_io', 'N/A')}")

                # Action buttons
                btn_col1, btn_col2, btn_col3 = st.columns(3)
                with btn_col1:
                    if st.button("📋 View Logs", key=f"logs_{container.get('id')}"):
                        st.session_state[f"show_logs_{container.get('id')}"] = True
                with btn_col2:
                    if container.get('state') == 'running':
                        if st.button("⏸️ Stop", key=f"stop_{container.get('id')}"):
                            st.session_state.pending_commands.append({
                                "proposed": f"docker stop {container.get('name')}",
                                "rollback": f"docker start {container.get('name')}",
                                "type": "container_stop"
                            })
                            st.rerun()
                    else:
                        if st.button("▶️ Start", key=f"start_{container.get('id')}"):
                            st.session_state.pending_commands.append({
                                "proposed": f"docker start {container.get('name')}",
                                "rollback": f"docker stop {container.get('name')}",
                                "type": "container_start"
                            })
                            st.rerun()
                with btn_col3:
                    if st.button("🔄 Restart", key=f"restart_{container.get('id')}"):
                        st.session_state.pending_commands.append({
                            "proposed": f"docker restart {container.get('name')}",
                            "rollback": "echo 'No rollback for restart'",
                            "type": "container_restart"
                        })
                        st.rerun()
    else:
        st.info("ℹ️ No Docker containers found. Install Docker or deploy containers to see them here.")

    st.divider()

    # === SYSTEM SERVICES ===
    st.markdown("### ⚙️ System Services (Top 10)")
    services = monitor_data.get('services', [])

    if services:
        for service in services[:10]:
            col1, col2, col3 = st.columns([3, 1, 1])
            with col1:
                st.markdown(f"{service.get('status_color', '⚪')} **{service.get('name', 'Unknown')}**")
            with col2:
                st.caption(f"State: {service.get('active', 'N/A')}")
            with col3:
                if st.button("📋 Logs", key=f"svc_logs_{service.get('name')}"):
                    st.session_state[f"show_svc_logs_{service.get('name')}"] = True
    else:
        st.info("ℹ️ No system services detected")

    st.divider()

    # === TOP PROCESSES ===
    st.markdown("### 🔝 Top Processes by CPU")
    processes = monitor_data.get('processes', [])

    if processes:
        # Create DataFrame for better display
        df = pd.DataFrame(processes)
        df = df[['user', 'pid', 'cpu', 'mem', 'command']]
        df.columns = ['User', 'PID', 'CPU %', 'MEM %', 'Command']
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("ℹ️ No process data available")

    st.divider()

    # === NETWORK CONNECTIONS ===
    st.markdown("### 🌐 Network Status")
    network = monitor_data.get('network', {})

    col1, col2 = st.columns(2)
    with col1:
        st.metric("🔌 Listening Ports", network.get('listening_ports', 0))
    with col2:
        st.metric("🔗 Established Connections", network.get('established_connections', 0))

    # Listening services
    listening = network.get('listening_services', [])
    if listening:
        st.markdown("**Active Listeners:**")
        for svc in listening[:10]:
            col1, col2, col3 = st.columns([1, 2, 2])
            with col1:
                st.caption(svc.get('proto', 'N/A'))
            with col2:
                st.code(f"{svc.get('local_address', 'N/A')}", language="text")
            with col3:
                st.caption(svc.get('program', 'unknown')[:30])

    st.divider()

    # === DISK USAGE ===
    st.markdown("### 💾 Disk Usage")
    disks = monitor_data.get('disk', [])

    if disks:
        for disk in disks:
            col1, col2, col3 = st.columns([2, 3, 1])
            with col1:
                st.markdown(f"{disk.get('status_color', '⚪')} **{disk.get('device', 'N/A')}**")
                st.caption(f"Mount: {disk.get('mount', 'N/A')}")
            with col2:
                usage = disk.get('usage_percent', 0)
                st.progress(usage / 100, text=f"{usage}% used ({disk.get('used', 'N/A')} / {disk.get('size', 'N/A')})")
            with col3:
                st.caption(f"{disk.get('available', 'N/A')} free")
    else:
        st.info("ℹ️ No disk data available")

    st.divider()

    # === SECURITY STATUS ===
    st.markdown("### 🛡️ Security Indicators")
    security = monitor_data.get('security', {})

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        ssh_fails = security.get('recent_ssh_failures', 0)
        fail_color = "🔴" if ssh_fails > 10 else "🟡" if ssh_fails > 5 else "🟢"
        st.metric(f"{fail_color} SSH Failures", ssh_fails)
        st.caption("Last 100 auth.log entries")

    with col2:
        fw_active = security.get('firewall_active', False)
        fw_icon = "🟢" if fw_active else "🔴"
        st.metric(f"{fw_icon} Firewall", "Active" if fw_active else "Inactive")

    with col3:
        rk_installed = security.get('rootkit_scanner', False)
        rk_icon = "🟢" if rk_installed else "🟡"
        st.metric(f"{rk_icon} RootKit Scanner", "Yes" if rk_installed else "No")

    with col4:
        dna_score = server.get('similarity_score', 1.0)
        dna_color = "🟢" if dna_score > 0.8 else "🟡" if dna_score > 0.6 else "🔴"
        st.metric(f"{dna_color} DNA Score", f"{dna_score*100:.1f}%")

    # Last login info
    last_login = security.get('last_login', 'Unknown')
    st.caption(f"📅 Last Login: {last_login}")

    # Threat alerts
    alerts = server.get("clamav_alerts", []) + server.get("crowdsec_alerts", [])
    if alerts:
        st.warning(f"⚠️ {len(alerts)} Active Security Alert(s)")
        for alert in alerts:
            with st.expander(f"🚨 {alert.get('type', 'Unknown').upper()}"):
                st.error(alert.get('message', 'No details'))
                st.caption(f"Severity: {alert.get('severity', 'unknown')} | Time: {alert.get('timestamp', 'N/A')}")
    else:
        st.success("✅ No active security threats detected")


def render_container_logs(container_id: str, monitor_agent):
    """Show container logs in a modal-like expander."""
    logs = monitor_agent.get_container_logs(container_id, lines=100)
    st.code(logs, language="log")


def render_service_logs(service_name: str, monitor_agent):
    """Show service logs in a modal-like expander."""
    logs = monitor_agent.get_service_logs(service_name, lines=100)
    st.code(logs, language="log")
