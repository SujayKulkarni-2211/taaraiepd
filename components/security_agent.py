"""
Security Agent
===============

Autonomous security agent that:
- Scans systems and identifies vulnerabilities
- Autonomously generates remediation commands
- Shows commands for admin approval before execution
- Learns from past successes/failures
- Executes approved commands and reports results
- On failure, automatically generates corrective commands

The agent figures things out by itself and shows for approval.
AI Chat gives when asked — Agent proactively discovers.
"""

import streamlit as st
import time
import json
import os
import threading
import numpy as np
from typing import Dict, List, Optional
from datetime import datetime


class SecurityAgent:
    """Autonomous security agent connected to TAARA analysis."""

    def __init__(self, model_dir: str = 'models'):
        self.model_dir = model_dir
        self.agent_log: List[Dict] = []
        self.status = 'idle'
        self.current_task = None
        self.running = False
        self.stop_flag = threading.Event()

        # Autonomous action queue
        self.proposed_actions: List[Dict] = []
        self.executed_actions: List[Dict] = []
        self.learned_patterns: Dict = {}

        os.makedirs(model_dir, exist_ok=True)
        self._load_log()
        self._load_learned_patterns()

    def log_action(self, action_type: str, description: str, result: str = '',
                   severity: str = 'info', details: Dict = None):
        """Log an agent action."""
        entry = {
            'timestamp': time.time(),
            'datetime': datetime.now().isoformat(),
            'action_type': action_type,
            'description': description,
            'result': result,
            'severity': severity,
            'details': details or {}
        }
        self.agent_log.append(entry)
        if len(self.agent_log) > 500:
            self.agent_log = self.agent_log[-250:]
        self._save_log()

    def run_security_scan(self, platform, taara_analyzer, embedder=None,
                          detector=None) -> Dict:
        """Run a complete security scan and analysis."""
        self.status = 'scanning'
        self.current_task = 'Security Scan'
        self.log_action('scan_start', f'Starting security scan on {platform.platform_type}')

        result = {'success': False, 'findings': [], 'analysis': None}

        try:
            security_data = platform.collect_security_data()
            total = sum(security_data.get('summary', {}).values())
            critical = security_data.get('summary', {}).get('critical', 0)

            self.log_action('scan_complete', f'Security scan complete: {total} findings, {critical} critical',
                           severity='warning' if critical > 0 else 'info')

            features = security_data.get('features', {})
            feature_vector = np.array([float(v) for v in features.values()], dtype=np.float32)
            if len(feature_vector) < 4:
                feature_vector = np.pad(feature_vector, (0, max(0, 7 - len(feature_vector))))

            identity_id = f'{platform.platform_type}_system'
            has_baseline_alert = False

            if embedder and embedder.is_ready() and detector and detector.is_ready():
                padded = feature_vector[:19] if len(feature_vector) >= 19 else \
                    np.pad(feature_vector, (0, max(0, 19 - len(feature_vector))))
                embedding = embedder.embed(padded)
                detection = detector.detect(embedding)
                has_baseline_alert = detection.get('is_anomaly', False)
                if has_baseline_alert:
                    self.log_action('anomaly_detected', 'Baseline anomaly detector flagged this state',
                                   severity='warning')

            taara_result = taara_analyzer.analyze(identity_id, feature_vector,
                                                   baseline_alert=has_baseline_alert)

            if taara_result.get('is_quantum_confirmed'):
                self.log_action('quantum_novelty', 'Quantum-confirmed directional novelty detected!',
                               severity='critical',
                               details={'f_min': taara_result.get('quantum_validation', {}).get('f_min', 0)})
            elif taara_result.get('is_taara_novel'):
                self.log_action('novelty_detected', 'Behavioral novelty detected (reconstruction failure)',
                               severity='warning')
            else:
                self.log_action('normal', 'System behavior within known patterns', severity='info')

            result['success'] = True
            result['findings'] = security_data
            result['analysis'] = taara_result

        except Exception as e:
            self.log_action('error', f'Scan error: {str(e)[:200]}', severity='error')
            result['error'] = str(e)

        self.status = 'idle'
        self.current_task = None
        return result

    def autonomous_analyze(self, platform, taara_analyzer, llm_service,
                           embedder=None, detector=None) -> Dict:
        """
        Full autonomous analysis cycle:
        1. Scan the system
        2. Analyze findings with AI
        3. Generate remediation commands
        4. Add to proposed_actions for approval
        """
        self.status = 'autonomous_analysis'
        self.current_task = 'Autonomous Analysis'
        self.log_action('autonomous_start', 'Starting autonomous security analysis')

        scan_result = self.run_security_scan(platform, taara_analyzer, embedder, detector)

        if not scan_result.get('success'):
            return scan_result

        findings = scan_result.get('findings', {})
        analysis = scan_result.get('analysis', {})

        # Build findings summary for AI
        findings_text = self._summarize_findings(findings, analysis)

        if not llm_service:
            self.log_action('autonomous_skip', 'No LLM service - cannot generate remediation commands',
                           severity='warning')
            return scan_result

        # Get learned context
        learned_context = self._get_learned_context()

        prompt = f"""You are TAARA Security Agent — an autonomous security analysis system.

You have just completed a security scan. Based on the findings below, generate specific
remediation commands that should be executed on the target system.

IMPORTANT:
- Generate ONLY safe, non-destructive commands
- Each command should fix ONE specific issue
- Prioritize by severity (critical first)
- For each command, explain what it does and what it fixes
- Use proper code blocks with language tags (```bash for shell commands)
- Commands should be idempotent where possible

Platform: {platform.platform_type}
{learned_context}

=== SCAN FINDINGS ===
{findings_text}

=== TAARA ANALYSIS ===
Novel behavior detected: {analysis.get('is_taara_novel', False)}
Quantum confirmed: {analysis.get('is_quantum_confirmed', False)}

Generate remediation commands for the most critical issues found.
For each command, start with a comment explaining what it fixes.
"""

        self.status = 'generating_remediations'
        response = llm_service.generate_response(prompt)

        commands = []
        if response.get('success'):
            commands = response.get('commands', [])
            explanation = response.get('explanation', '')

            for cmd in commands:
                cmd['time'] = datetime.now().strftime('%H:%M:%S')
                cmd['source'] = 'agent_autonomous'
                cmd['scan_context'] = findings_text[:500]
                self.proposed_actions.append(cmd)

            self.log_action('remediation_generated',
                           f'Generated {len(commands)} remediation commands',
                           severity='info',
                           details={'command_count': len(commands)})
        else:
            self.log_action('llm_error', f'AI analysis failed: {response.get("error", "")}',
                           severity='warning')

        self.status = 'idle'
        self.current_task = None

        return {
            'success': True,
            'scan': scan_result,
            'commands': commands,
            'explanation': response.get('explanation', '') if response.get('success') else ''
        }

    def execute_approved_action(self, action_index: int, platform) -> Dict:
        """Execute an approved action from the proposed queue."""
        if action_index >= len(self.proposed_actions):
            return {'success': False, 'error': 'Invalid action index'}

        action = self.proposed_actions[action_index]
        result = self._execute_command(action, platform)

        action['status'] = 'success' if result['success'] else 'failed'
        action['result'] = result
        action['executed_at'] = time.time()

        self.executed_actions.append(action)
        self.proposed_actions.pop(action_index)

        # Learn from result
        self._learn_from_execution(action, result)

        severity = 'info' if result['success'] else 'error'
        self.log_action(
            'action_executed',
            f'{"SUCCESS" if result["success"] else "FAILED"}: {action["code"][:80]}',
            result=result.get('stdout', '')[:200],
            severity=severity,
            details={
                'command': action['code'][:200],
                'exit_code': result.get('exit_code', -1),
                'rollback_cmd': action.get('rollback_cmd', '')
            }
        )

        return result

    def get_failure_recovery(self, action: Dict, result: Dict, llm_service, platform) -> List[Dict]:
        """When a command fails, ask AI for corrective commands."""
        if not llm_service:
            return []

        prompt = f"""A security remediation command failed on {platform.platform_type}.

Failed command:
```{action.get('language', 'bash')}
{action['code']}
```

Exit code: {result.get('exit_code', 'N/A')}
Stdout: {result.get('stdout', '')[:800]}
Stderr: {result.get('stderr', '')[:800]}
Error: {result.get('error', '')}

Analyze the failure and provide corrective commands. If the issue is a missing package,
permission problem, or configuration issue, provide the specific fix.
"""

        response = llm_service.generate_response(prompt)
        commands = []
        if response.get('success'):
            commands = response.get('commands', [])
            for cmd in commands:
                cmd['time'] = datetime.now().strftime('%H:%M:%S')
                cmd['source'] = 'agent_recovery'
                cmd['original_failure'] = action['code'][:200]
                self.proposed_actions.append(cmd)

            self.log_action('recovery_generated',
                           f'Generated {len(commands)} recovery commands for failed action',
                           severity='info')

        return commands

    def _execute_command(self, cmd: Dict, platform) -> Dict:
        """Execute a command on the target platform."""
        result = {'success': False, 'stdout': '', 'stderr': '', 'error': ''}

        code = cmd.get('code', '')
        language = cmd.get('language', 'shell')

        try:
            if platform.platform_type == 'ssh':
                if language in ['bash', 'shell', 'sh']:
                    stdout, stderr, exit_code = platform.execute_command(code)
                    result['stdout'] = stdout
                    result['stderr'] = stderr
                    result['exit_code'] = exit_code
                    result['success'] = (exit_code == 0)
                elif language == 'python':
                    escaped = code.replace("'", "'\\''")
                    stdout, stderr, exit_code = platform.execute_command(
                        f"python3 -c '{escaped}'"
                    )
                    result['stdout'] = stdout
                    result['stderr'] = stderr
                    result['exit_code'] = exit_code
                    result['success'] = (exit_code == 0)
                else:
                    stdout, stderr, exit_code = platform.execute_command(code)
                    result['stdout'] = stdout
                    result['stderr'] = stderr
                    result['exit_code'] = exit_code
                    result['success'] = (exit_code == 0)
            else:
                result['stdout'] = f'[{platform.platform_type.upper()}] Command staged:\n{code}'
                result['success'] = True
        except Exception as e:
            result['error'] = str(e)

        return result

    def _summarize_findings(self, findings: Dict, analysis: Dict) -> str:
        """Summarize scan findings into text for AI consumption."""
        parts = []
        parts.append(f"Platform: {findings.get('platform', 'unknown')}")

        summary = findings.get('summary', {})
        parts.append(f"Critical: {summary.get('critical', 0)}, High: {summary.get('high', 0)}, "
                     f"Medium: {summary.get('medium', 0)}, Low: {summary.get('low', 0)}")

        for cat_name, cat_data in findings.get('categories', {}).items():
            cat_findings = cat_data.get('findings', [])
            if cat_findings:
                parts.append(f"\n--- {cat_data.get('name', cat_name)} ---")
                for f in cat_findings[:10]:
                    parts.append(f"  [{f.get('severity', 'info').upper()}] {f.get('title', '')}")
                    if f.get('remediation'):
                        parts.append(f"    Remediation: {f['remediation']}")

        return "\n".join(parts)

    def _learn_from_execution(self, action: Dict, result: Dict):
        """Learn from command execution results."""
        cmd_hash = hash(action.get('code', '')[:100])
        key = str(cmd_hash)

        if key not in self.learned_patterns:
            self.learned_patterns[key] = {
                'command_prefix': action.get('code', '')[:80],
                'successes': 0,
                'failures': 0,
                'last_outcome': None,
                'common_errors': []
            }

        pattern = self.learned_patterns[key]
        if result['success']:
            pattern['successes'] += 1
            pattern['last_outcome'] = 'success'
        else:
            pattern['failures'] += 1
            pattern['last_outcome'] = 'failed'
            error = result.get('stderr', '') or result.get('error', '')
            if error and error not in pattern['common_errors']:
                pattern['common_errors'].append(error[:200])
                if len(pattern['common_errors']) > 5:
                    pattern['common_errors'] = pattern['common_errors'][-5:]

        self._save_learned_patterns()

    def _get_learned_context(self) -> str:
        """Get learned patterns as context for AI."""
        if not self.learned_patterns:
            return ""

        parts = ["\n=== LEARNED PATTERNS FROM PAST EXECUTIONS ==="]
        for key, pattern in list(self.learned_patterns.items())[-10:]:
            if pattern['failures'] > 0:
                parts.append(
                    f"Command '{pattern['command_prefix']}...' - "
                    f"Success: {pattern['successes']}, Failures: {pattern['failures']}"
                )
                if pattern['common_errors']:
                    parts.append(f"  Common errors: {pattern['common_errors'][-1][:100]}")

        return "\n".join(parts) if len(parts) > 1 else ""

    def run_continuous_monitoring(self, platform, taara_analyzer, embedder,
                                  detector, interval: int = 60):
        """Start continuous monitoring in background."""
        self.running = True
        self.stop_flag.clear()
        self.status = 'monitoring'
        self.log_action('monitor_start', f'Continuous monitoring started (interval: {interval}s)')

        def _monitor_loop():
            while not self.stop_flag.is_set():
                try:
                    self.run_security_scan(platform, taara_analyzer, embedder, detector)
                except Exception as e:
                    self.log_action('monitor_error', str(e)[:200], severity='error')

                for _ in range(interval):
                    if self.stop_flag.is_set():
                        break
                    time.sleep(1)

            self.running = False
            self.status = 'idle'
            self.log_action('monitor_stop', 'Continuous monitoring stopped')

        thread = threading.Thread(target=_monitor_loop, daemon=True)
        thread.start()

    def stop_monitoring(self):
        """Stop continuous monitoring."""
        self.stop_flag.set()
        self.status = 'stopping'

    def get_recent_log(self, limit: int = 50) -> List[Dict]:
        return self.agent_log[-limit:][::-1]

    def get_stats(self) -> Dict:
        total = len(self.agent_log)
        critical = sum(1 for e in self.agent_log if e.get('severity') == 'critical')
        warnings = sum(1 for e in self.agent_log if e.get('severity') == 'warning')
        novelties = sum(1 for e in self.agent_log if 'novelty' in e.get('action_type', ''))

        return {
            'total_actions': total,
            'critical_events': critical,
            'warnings': warnings,
            'novelties_detected': novelties,
            'status': self.status,
            'running': self.running,
            'proposed_actions': len(self.proposed_actions),
            'executed_actions': len(self.executed_actions),
            'learned_patterns': len(self.learned_patterns)
        }

    def _save_log(self):
        path = os.path.join(self.model_dir, 'agent_log.json')
        try:
            with open(path, 'w') as f:
                json.dump(self.agent_log[-500:], f, indent=2)
        except Exception:
            pass

    def _load_log(self):
        path = os.path.join(self.model_dir, 'agent_log.json')
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    self.agent_log = json.load(f)
            except Exception:
                pass

    def _save_learned_patterns(self):
        path = os.path.join(self.model_dir, 'agent_learned_patterns.json')
        try:
            with open(path, 'w') as f:
                json.dump(self.learned_patterns, f, indent=2)
        except Exception:
            pass

    def _load_learned_patterns(self):
        path = os.path.join(self.model_dir, 'agent_learned_patterns.json')
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    self.learned_patterns = json.load(f)
            except Exception:
                pass


def render_agent_panel(agent, platform, taara_analyzer, embedder, detector):
    """Render the Security Agent panel with autonomous capabilities."""

    st.markdown("""
    <div style="background: linear-gradient(135deg, #1a1a2e 0%, #2e1a2e 100%);
                padding: 30px; border-radius: 15px; margin-bottom: 20px;
                border: 1px solid #aa44ff;">
        <h1 style="color: #aa44ff; margin: 0; font-size: 2.2em;">
            TAARA Agent
        </h1>
        <p style="color: #a0a0b0; margin: 5px 0 0 0; font-size: 1.1em;">
            Autonomous Security Analysis — Scan, Analyze, Remediate
        </p>
    </div>
    """, unsafe_allow_html=True)

    stats = agent.get_stats()
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Status", stats['status'].upper())
    with col2:
        st.metric("Total Actions", stats['total_actions'])
    with col3:
        st.metric("Critical Events", stats['critical_events'])
    with col4:
        st.metric("Pending Approval", stats['proposed_actions'])
    with col5:
        st.metric("Learned Patterns", stats['learned_patterns'])

    st.markdown("---")

    # --- Agent Controls ---
    col_a, col_b, col_c, col_d = st.columns(4)
    with col_a:
        if st.button("Quick Scan", type="primary", use_container_width=True):
            if platform and platform.connected:
                with st.spinner("Agent scanning..."):
                    result = agent.run_security_scan(platform, taara_analyzer, embedder, detector)
                    if result.get('success'):
                        analysis = result.get('analysis', {})
                        if analysis.get('is_quantum_confirmed'):
                            st.error("QUANTUM-CONFIRMED NOVELTY DETECTED!")
                        elif analysis.get('is_taara_novel'):
                            st.warning("Behavioral novelty detected")
                        else:
                            st.success("System behavior normal")
                    else:
                        st.error(f"Scan failed: {result.get('error', 'Unknown')}")
            else:
                st.warning("No platform connected")

    with col_b:
        llm_service = st.session_state.get('llm_service')
        if st.button("Autonomous Analysis", use_container_width=True):
            if platform and platform.connected:
                if llm_service:
                    with st.spinner("Agent performing autonomous analysis..."):
                        result = agent.autonomous_analyze(
                            platform, taara_analyzer, llm_service, embedder, detector
                        )
                        if result.get('commands'):
                            st.success(f"Generated {len(result['commands'])} remediation commands. "
                                     f"See Proposed Actions below.")
                        else:
                            st.info("No remediation commands generated.")
                        st.rerun()
                else:
                    st.warning("LLM service required for autonomous analysis")
            else:
                st.warning("No platform connected")

    with col_c:
        if not agent.running:
            if st.button("Start Monitor", use_container_width=True):
                if platform and platform.connected:
                    agent.run_continuous_monitoring(
                        platform, taara_analyzer, embedder, detector, interval=60
                    )
                    st.success("Continuous monitoring started")
                    st.rerun()
        else:
            if st.button("Stop Monitor", use_container_width=True):
                agent.stop_monitoring()
                st.info("Stopping monitoring...")
                st.rerun()

    with col_d:
        if st.button("Clear Log", use_container_width=True):
            agent.agent_log = []
            agent._save_log()
            st.rerun()

    # --- Proposed Actions (Approval Queue) ---
    st.markdown("### Proposed Actions — Awaiting Approval")

    if agent.proposed_actions:
        for i, action in enumerate(agent.proposed_actions):
            source_label = 'Autonomous' if action.get('source') == 'agent_autonomous' else 'Recovery'

            with st.expander(
                f"[{source_label}] {action.get('language', 'bash')}: {action['code'][:80]}...",
                expanded=True
            ):
                st.code(action['code'], language=action.get('language', 'bash'))
                st.caption(f"Generated at {action.get('time', '')} | Source: {action.get('source', 'agent')}")

                col_approve, col_reject = st.columns(2)
                with col_approve:
                    if st.button("Approve & Execute", key=f"agent_approve_{i}",
                                type="primary", use_container_width=True):
                        with st.spinner("Executing..."):
                            result = agent.execute_approved_action(i, platform)
                            if result['success']:
                                st.success("Executed successfully!")
                                if result.get('stdout'):
                                    st.code(result['stdout'][:2000], language='text')
                            else:
                                st.error(f"Failed! {result.get('error', '')}")
                                if result.get('stderr'):
                                    st.code(result['stderr'][:1000], language='text')

                                # Auto-generate recovery
                                if llm_service:
                                    st.info("Generating recovery commands...")
                                    recovery = agent.get_failure_recovery(
                                        action, result, llm_service, platform
                                    )
                                    if recovery:
                                        st.warning(f"Added {len(recovery)} recovery commands to queue")

                            st.rerun()
                with col_reject:
                    if st.button("Reject", key=f"agent_reject_{i}", use_container_width=True):
                        action['status'] = 'rejected'
                        agent.executed_actions.append(action)
                        agent.proposed_actions.pop(i)
                        st.rerun()
    else:
        st.info("No pending actions. Run 'Autonomous Analysis' to generate remediation commands.")

    # --- Executed Actions History ---
    if agent.executed_actions:
        st.markdown("### Execution History")
        for i, action in enumerate(agent.executed_actions[-10:][::-1]):
            status = action.get('status', 'unknown')
            icon = '✅' if status == 'success' else ('❌' if status == 'failed' else '🚫')

            with st.expander(f"{icon} {action['code'][:60]}...", expanded=False):
                st.code(action['code'], language=action.get('language', 'bash'))
                if action.get('result'):
                    res = action['result']
                    if res.get('stdout'):
                        st.text_area("Output", res['stdout'][:2000], height=80,
                                    key=f"agent_exec_out_{i}")
                    if res.get('stderr'):
                        st.text_area("Errors", res['stderr'][:1000], height=60,
                                    key=f"agent_exec_err_{i}")

    # --- Agent Log ---
    st.markdown("### Agent Activity Log")
    log = agent.get_recent_log(30)

    if not log:
        st.info("No agent actions recorded yet.")
        return

    severity_colors = {
        'critical': '#ff0000', 'error': '#ff4444',
        'warning': '#ff6600', 'info': '#4466ff', 'normal': '#00cc00'
    }

    for entry in log:
        ts = datetime.fromisoformat(entry['datetime']).strftime('%H:%M:%S') if 'datetime' in entry else ''
        sev = entry.get('severity', 'info')
        color = severity_colors.get(sev, '#888')

        st.markdown(f"""
        <div style="padding: 5px 10px; margin: 2px 0; border-left: 3px solid {color};
                    background: #111; border-radius: 3px; font-size: 0.85em;">
            <span style="color: {color}; font-weight: bold;">[{sev.upper()}]</span>
            <span style="color: #888;"> {ts}</span>
            <span style="color: #ccc;"> {entry.get('description', '')}</span>
            {f'<span style="color: #666;"> | {entry.get("result", "")}</span>' if entry.get('result') else ''}
        </div>
        """, unsafe_allow_html=True)
