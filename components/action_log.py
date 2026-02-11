"""
Action Log Viewer with Rollback
=================================

Displays all actions taken by the TAARA system including:
- Agent actions (scans, detections, responses)
- Executed commands (with rollback capability)
- Training events
- TaaraWare deployments
- Analysis runs
- System events

One-click rollback: For any executed command, generates and runs a
reverse command to restore previous state.
"""

import streamlit as st
import json
import os
import time
from typing import Dict, List
from datetime import datetime


# Common rollback mappings for known command patterns
ROLLBACK_PATTERNS = {
    # File permission changes
    r'chmod (\d+) (.+)': 'stat -c "%a" {path} | xargs -I{{}} echo "chmod {{}} {path}"',
    # Service restarts
    r'systemctl restart (.+)': 'systemctl status {service}',
    # Package installs
    r'apt-get install -y (.+)': 'apt-get remove -y {package}',
    r'yum install -y (.+)': 'yum remove -y {package}',
    # Firewall rules
    r'ufw allow (.+)': 'ufw delete allow {rule}',
    r'ufw deny (.+)': 'ufw delete deny {rule}',
    r'iptables -A (.+)': 'iptables -D {rule}',
    # User modifications
    r'usermod (.+)': 'echo "Manual review required for usermod rollback"',
    # File moves/copies
    r'cp (.+) (.+)': 'rm {dest}',
    r'mv (.+) (.+)': 'mv {dest} {src}',
}


class ActionLogger:
    """Centralized action logger with rollback support."""

    def __init__(self, log_path: str = 'models/action_log.json'):
        self.log_path = log_path
        self.logs: List[Dict] = []
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        self._load()

    def log(self, category: str, action: str, details: str = '',
            severity: str = 'info', metadata: Dict = None):
        """Log an action with optional rollback information."""
        entry = {
            'id': f"act_{int(time.time() * 1000)}_{len(self.logs)}",
            'timestamp': time.time(),
            'datetime': datetime.now().isoformat(),
            'category': category,
            'action': action,
            'details': details,
            'severity': severity,
            'metadata': metadata or {},
            'rollback_status': None,  # None, 'available', 'rolled_back', 'failed'
        }

        # Check if this action has rollback info
        if metadata and metadata.get('command'):
            entry['rollback_status'] = 'available'
            if metadata.get('rollback_cmd'):
                entry['rollback_cmd'] = metadata['rollback_cmd']

        self.logs.append(entry)
        if len(self.logs) > 2000:
            self.logs = self.logs[-1000:]
        self._save()
        return entry['id']

    def get_logs(self, category: str = None, severity: str = None,
                 limit: int = 100) -> List[Dict]:
        """Get filtered logs."""
        filtered = self.logs
        if category:
            filtered = [l for l in filtered if l.get('category') == category]
        if severity:
            filtered = [l for l in filtered if l.get('severity') == severity]
        return filtered[-limit:][::-1]

    def get_categories(self) -> List[str]:
        """Get all log categories."""
        return list(set(l.get('category', 'unknown') for l in self.logs))

    def mark_rolled_back(self, log_id: str, rollback_result: Dict):
        """Mark a log entry as rolled back."""
        for entry in self.logs:
            if entry.get('id') == log_id:
                entry['rollback_status'] = 'rolled_back' if rollback_result.get('success') else 'rollback_failed'
                entry['rollback_result'] = rollback_result
                self._save()
                return True
        return False

    def get_rollbackable_actions(self, limit: int = 50) -> List[Dict]:
        """Get actions that can be rolled back."""
        rollbackable = [
            l for l in self.logs
            if l.get('rollback_status') == 'available'
            and l.get('metadata', {}).get('command')
        ]
        return rollbackable[-limit:][::-1]

    def clear(self):
        """Clear all logs."""
        self.logs = []
        self._save()

    def _save(self):
        try:
            with open(self.log_path, 'w') as f:
                json.dump(self.logs[-2000:], f)
        except Exception:
            pass

    def _load(self):
        if os.path.exists(self.log_path):
            try:
                with open(self.log_path, 'r') as f:
                    self.logs = json.load(f)
            except Exception:
                self.logs = []


def _generate_rollback_command(command: str) -> str:
    """Generate a rollback command for a given command."""
    import re

    cmd_stripped = command.strip()

    # chmod rollback: record original permissions
    m = re.match(r'chmod\s+(\d+)\s+(.+)', cmd_stripped)
    if m:
        return f'# Rollback: Restore original permissions\n# Check current: stat -c "%a" {m.group(2)}'

    # systemctl restart -> just note it
    m = re.match(r'systemctl\s+restart\s+(.+)', cmd_stripped)
    if m:
        return f'systemctl restart {m.group(1)}  # Re-restart to baseline'

    # apt install -> apt remove
    m = re.match(r'(?:apt-get|apt)\s+install\s+(?:-y\s+)?(.+)', cmd_stripped)
    if m:
        return f'apt-get remove -y {m.group(1)}'

    # yum install -> yum remove
    m = re.match(r'yum\s+install\s+(?:-y\s+)?(.+)', cmd_stripped)
    if m:
        return f'yum remove -y {m.group(1)}'

    # ufw allow -> ufw delete allow
    m = re.match(r'ufw\s+allow\s+(.+)', cmd_stripped)
    if m:
        return f'ufw delete allow {m.group(1)}'

    # ufw deny -> ufw delete deny
    m = re.match(r'ufw\s+deny\s+(.+)', cmd_stripped)
    if m:
        return f'ufw delete deny {m.group(1)}'

    # iptables -A -> iptables -D
    m = re.match(r'iptables\s+-A\s+(.+)', cmd_stripped)
    if m:
        return f'iptables -D {m.group(1)}'

    # cp -> rm destination
    m = re.match(r'cp\s+(?:-[a-zA-Z]+\s+)?(.+?)\s+(.+)', cmd_stripped)
    if m:
        return f'rm -f {m.group(2)}  # Remove copied file'

    # echo >> (append) -> sed to remove line
    m = re.match(r'echo\s+["\'](.+?)["\']\s*>>\s*(.+)', cmd_stripped)
    if m:
        content = m.group(1).replace('/', '\\/')
        return f'sed -i "/{content}/d" {m.group(2)}'

    # sed -i -> can't easily reverse, but flag it
    if 'sed -i' in cmd_stripped:
        return f'# Manual rollback needed for: {cmd_stripped[:100]}'

    # mkdir -> rmdir
    m = re.match(r'mkdir\s+(?:-p\s+)?(.+)', cmd_stripped)
    if m:
        return f'rmdir {m.group(1)}  # Only removes if empty'

    # Default: no auto-rollback
    return ''


def _execute_rollback(command: str, platform) -> Dict:
    """Execute a rollback command on the platform."""
    result = {'success': False, 'stdout': '', 'stderr': '', 'error': ''}

    if not platform or not platform.connected:
        result['error'] = 'No platform connected'
        return result

    try:
        if platform.platform_type == 'ssh':
            stdout, stderr, exit_code = platform.execute_command(command)
            result['stdout'] = stdout
            result['stderr'] = stderr
            result['exit_code'] = exit_code
            result['success'] = (exit_code == 0)
        else:
            result['stdout'] = f'Rollback staged for {platform.platform_type}: {command}'
            result['success'] = True
    except Exception as e:
        result['error'] = str(e)

    return result


def render_action_log(action_logger: ActionLogger, agent=None):
    """Render the action log viewer with rollback support."""

    st.markdown("""
    <div style="background: linear-gradient(135deg, #1a1a2e 0%, #2e2e1a 100%);
                padding: 30px; border-radius: 15px; margin-bottom: 20px;
                border: 1px solid #aaaa44;">
        <h1 style="color: #aaaa44; margin: 0; font-size: 2.2em;">
            Action Log
        </h1>
        <p style="color: #a0a0b0; margin: 5px 0 0 0; font-size: 1.1em;">
            Complete Audit Trail — With One-Click Rollback
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Merge logs from action_logger and agent
    all_logs = action_logger.get_logs(limit=200)
    if agent:
        agent_logs = agent.get_recent_log(100)
        for al in agent_logs:
            all_logs.append({
                'id': f"agent_{al.get('timestamp', 0)}",
                'timestamp': al.get('timestamp', 0),
                'datetime': al.get('datetime', ''),
                'category': 'agent',
                'action': al.get('action_type', ''),
                'details': al.get('description', ''),
                'severity': al.get('severity', 'info'),
                'metadata': al.get('details', {}),
                'rollback_status': None
            })

        # Include agent executed actions (these have rollback potential)
        for ea in getattr(agent, 'executed_actions', []):
            if ea.get('status') in ['success', 'failed']:
                rollback_cmd = _generate_rollback_command(ea.get('code', ''))
                all_logs.append({
                    'id': f"agent_exec_{ea.get('time', '')}_{hash(ea.get('code', '')[:50])}",
                    'timestamp': ea.get('executed_at', time.time()),
                    'datetime': ea.get('time', ''),
                    'category': 'agent_execution',
                    'action': f'{"Executed" if ea.get("status") == "success" else "Failed"}: {ea["code"][:60]}',
                    'details': ea.get('result', {}).get('stdout', '')[:200],
                    'severity': 'info' if ea.get('status') == 'success' else 'error',
                    'metadata': {
                        'command': ea.get('code', ''),
                        'result': ea.get('result', {}),
                        'rollback_cmd': rollback_cmd
                    },
                    'rollback_status': 'available' if ea.get('status') == 'success' and rollback_cmd else None
                })

    all_logs.sort(key=lambda x: x.get('timestamp', 0), reverse=True)

    # --- Summary Metrics ---
    total = len(all_logs)
    criticals = sum(1 for l in all_logs if l.get('severity') == 'critical')
    warnings = sum(1 for l in all_logs if l.get('severity') == 'warning')
    rollbackable = sum(1 for l in all_logs if l.get('rollback_status') == 'available')

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Total Events", total)
    with col2:
        st.metric("Critical", criticals)
    with col3:
        st.metric("Warnings", warnings)
    with col4:
        categories = list(set(l.get('category', 'unknown') for l in all_logs))
        st.metric("Categories", len(categories))
    with col5:
        st.metric("Rollbackable", rollbackable)

    st.markdown("---")

    # --- Rollback Section ---
    if rollbackable > 0:
        st.markdown("### Rollback Available Actions")
        st.caption("These executed commands can be rolled back to restore previous state.")

        rollback_actions = [l for l in all_logs if l.get('rollback_status') == 'available']

        for i, entry in enumerate(rollback_actions[:20]):
            cmd = entry.get('metadata', {}).get('command', '')
            rollback_cmd = entry.get('metadata', {}).get('rollback_cmd', '') or \
                           _generate_rollback_command(cmd)

            if not rollback_cmd or rollback_cmd.startswith('# Manual'):
                continue

            with st.expander(f"Rollback: {cmd[:80]}...", expanded=False):
                st.markdown("**Original Command:**")
                st.code(cmd, language='bash')
                st.markdown("**Rollback Command:**")
                st.code(rollback_cmd, language='bash')

                platform = st.session_state.get('platform')
                if st.button(f"Execute Rollback", key=f"rollback_{i}_{entry.get('id', i)}",
                            type="primary", use_container_width=True):
                    with st.spinner("Rolling back..."):
                        result = _execute_rollback(rollback_cmd, platform)
                        if result['success']:
                            st.success("Rollback successful!")
                            if result.get('stdout'):
                                st.code(result['stdout'][:1000], language='text')
                            action_logger.mark_rolled_back(entry.get('id', ''), result)
                            action_logger.log(
                                'rollback', 'rollback_success',
                                f'Rolled back: {cmd[:100]}',
                                severity='info',
                                metadata={'original_cmd': cmd, 'rollback_cmd': rollback_cmd}
                            )
                        else:
                            st.error(f"Rollback failed: {result.get('error', '')}")
                            if result.get('stderr'):
                                st.code(result['stderr'][:1000], language='text')
                            action_logger.log(
                                'rollback', 'rollback_failed',
                                f'Rollback failed: {cmd[:100]}',
                                severity='error',
                                metadata={'original_cmd': cmd, 'error': result.get('error', '')}
                            )
                        st.rerun()

        st.markdown("---")

    # --- Filters ---
    fcol1, fcol2, fcol3 = st.columns(3)
    with fcol1:
        filter_cat = st.selectbox("Category", ["All"] + sorted(categories), key="log_cat_filter")
    with fcol2:
        filter_sev = st.selectbox("Severity", ["All", "critical", "error", "warning", "info"],
                                  key="log_sev_filter")
    with fcol3:
        if st.button("Clear All Logs"):
            action_logger.clear()
            st.rerun()

    filtered = all_logs
    if filter_cat != "All":
        filtered = [l for l in filtered if l.get('category') == filter_cat]
    if filter_sev != "All":
        filtered = [l for l in filtered if l.get('severity') == filter_sev]

    # --- Log Entries ---
    severity_colors = {
        'critical': '#ff0000', 'error': '#ff4444',
        'warning': '#ff6600', 'info': '#4466ff'
    }

    rollback_icons = {
        'available': '🔄',
        'rolled_back': '↩️',
        'rollback_failed': '⚠️',
    }

    for entry in filtered[:100]:
        ts = ''
        if 'datetime' in entry and entry['datetime']:
            try:
                ts = datetime.fromisoformat(entry['datetime']).strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                ts = str(entry.get('timestamp', ''))

        sev = entry.get('severity', 'info')
        color = severity_colors.get(sev, '#888')
        cat = entry.get('category', 'system')
        rb_status = entry.get('rollback_status')
        rb_icon = rollback_icons.get(rb_status, '') if rb_status else ''
        details = entry.get('details', '')

        line = f"**\\[{sev.upper()}\\]** `{ts}` \\[{cat}\\] {entry.get('action', '')}"
        if rb_icon:
            line += f" {rb_icon}"
        if details:
            line += f"  \n  _{details}_"

        st.markdown(line)

    if not filtered:
        st.info("No log entries match the current filters.")
