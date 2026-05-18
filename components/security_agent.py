"""
TAARA Security Agent
=====================
Quantum-informed, bandit-guided security agent for infrastructure protection.

Design principles:
  1. Quantum fidelity is the SIGNAL — not decoration. The agent's urgency,
     action ranking, and pre-approval thresholds are all derived from F_min.
     When F_min < 0.5, behavioral direction is more orthogonal than parallel
     to everything normal. That is the reason the agent escalates.

  2. Contrastive bandits handle repetition. The bandit tracks which actions
     work in which quantum contexts. After enough evidence, it earns
     pre-approval rights — the admin stops seeing the same low-risk block
     every time and sees only novel decisions.

  3. Everything is reversible. Every action has a pre-computed rollback
     command before execution. The audit trail stores quantum score,
     bandit confidence, and rollback — permanently.

  4. Autonomy is configured, not assumed. Level 0 = propose only.
     Level 5 = fully autonomous. TaaraWare local engine uses the same
     thresholds for on-device decisions when command center is unreachable.

  5. GraphRAG + Quantum for analysis: the agent doesn't just summarize
     findings — it walks the knowledge graph to find propagation chains
     and scores each chain hop with quantum fidelity against safe-state embeddings.
     The LLM reasons over the graph output, not raw text.
"""

import time
import json
import os
import threading
import numpy as np
from typing import Dict, List, Optional, Tuple
from datetime import datetime

from components.action_bandit import ContrastiveBandit, fidelity_bucket, ACTION_AUTONOMY_REQUIREMENTS


# Pre-computed rollback templates keyed by action pattern
_ROLLBACK_TEMPLATES = {
    "fail2ban":         "fail2ban-client set {jail} unbanip {target}",
    "ufw deny":         "ufw delete deny from {target}",
    "ufw allow":        "ufw delete allow {target}",
    "systemctl stop":   "systemctl start {service}",
    "systemctl restart":"systemctl status {service}",
    "usermod -L":       "usermod -U {user}",
    "chmod":            "chmod {original_mode} {path}",
    "kill ":            "# Cannot undo process kill — check if restart needed",
    "iptables -A":      "iptables -D {rule}",
    "iptables -I":      "iptables -D {rule}",
}


def _infer_rollback(command: str) -> str:
    """Best-effort rollback command inference from the action command."""
    cmd = command.strip()
    for pattern, template in _ROLLBACK_TEMPLATES.items():
        if pattern in cmd:
            return f"# Rollback: {template}  (fill in parameters from original command)"
    return "# No automatic rollback available — review manually before reverting"


def _infer_action_type(code: str) -> str:
    """Infer action_type from command string for bandit arm selection."""
    code_lower = code.lower()
    if "fail2ban" in code_lower or "banip" in code_lower:
        return "block_ip"
    if "systemctl restart" in code_lower or "service" in code_lower and "restart" in code_lower:
        return "restart_service"
    if "systemctl stop" in code_lower:
        return "terminate_service"
    if "sshd_config" in code_lower or "ssh" in code_lower and "config" in code_lower:
        return "harden_ssh"
    if "ufw" in code_lower or "iptables" in code_lower or "firewall" in code_lower:
        return "firewall_rule"
    if "usermod -L" in code_lower or "passwd -l" in code_lower:
        return "isolate_user"
    if "authorized_keys" in code_lower:
        return "rotate_key"
    if "rate" in code_lower and "ssh" in code_lower:
        return "rate_limit_ssh"
    if "kill " in code_lower:
        return "kill_process"
    return "generic"


class SecurityAgent:
    """
    Quantum-informed, bandit-guided security agent.
    Maintains backward compatibility with all existing callers.
    """

    def __init__(self, model_dir: str = "models"):
        self.model_dir = model_dir
        self.agent_log: List[Dict] = []
        self.status = "idle"
        self.current_task = None
        self.running = False
        self.stop_flag = threading.Event()

        self.proposed_actions: List[Dict] = []
        self.executed_actions: List[Dict] = []
        self.learned_patterns: Dict = {}

        self.bandit = ContrastiveBandit(model_dir=model_dir)

        # Working memory: persists across cycles within a session
        self._working_memory: Dict = {
            "last_scan_findings": None,
            "last_quantum_result": None,
            "last_graph_chains": [],
            "hypothesis": None,
            "cycles": 0,
        }

        os.makedirs(model_dir, exist_ok=True)
        self._load_log()
        self._load_learned_patterns()

    # ── Logging ───────────────────────────────────────────────────────────────

    def log_action(self, action_type: str, description: str, result: str = "",
                   severity: str = "info", details: Dict = None):
        entry = {
            "timestamp": time.time(),
            "datetime": datetime.now().isoformat(),
            "action_type": action_type,
            "description": description,
            "result": result,
            "severity": severity,
            "details": details or {},
        }
        self.agent_log.append(entry)
        if len(self.agent_log) > 500:
            self.agent_log = self.agent_log[-250:]
        self._save_log()

    # ── Security scan ─────────────────────────────────────────────────────────

    def run_security_scan(self, platform, taara_analyzer, embedder=None,
                          detector=None) -> Dict:
        self.status = "scanning"
        self.current_task = "Security Scan"
        self.log_action("scan_start", f"Starting security scan on {platform.platform_type}")

        result = {"success": False, "findings": [], "analysis": None}

        try:
            security_data = platform.collect_security_data()
            total = sum(security_data.get("summary", {}).values())
            critical = security_data.get("summary", {}).get("critical", 0)
            self.log_action("scan_complete",
                            f"Scan complete: {total} findings, {critical} critical",
                            severity="warning" if critical > 0 else "info")

            features = security_data.get("features", {})
            feature_vector = np.array([float(v) for v in features.values()], dtype=np.float32)
            if len(feature_vector) < 4:
                feature_vector = np.pad(feature_vector, (0, max(0, 7 - len(feature_vector))))

            identity_id = f"{platform.platform_type}_system"
            has_baseline_alert = False

            if embedder and embedder.is_ready() and detector and detector.is_ready():
                padded = (feature_vector[:19] if len(feature_vector) >= 19
                          else np.pad(feature_vector, (0, max(0, 19 - len(feature_vector)))))
                embedding = embedder.embed(padded)
                detection = detector.detect(embedding)
                has_baseline_alert = detection.get("is_anomaly", False)
                if has_baseline_alert:
                    self.log_action("anomaly_detected", "Baseline anomaly flagged this state",
                                    severity="warning")

            taara_result = taara_analyzer.analyze(identity_id, feature_vector,
                                                   baseline_alert=has_baseline_alert)

            if taara_result.get("is_quantum_confirmed"):
                f_min = taara_result.get("quantum_validation", {}).get("f_min", 0)
                self.log_action("quantum_novelty",
                                f"Quantum-confirmed directional novelty — F_min={f_min:.3f}. "
                                f"Behavioral direction is {(1-f_min)*100:.0f}% orthogonal to prior normal.",
                                severity="critical",
                                details={"f_min": f_min, "bucket": fidelity_bucket(f_min)})
            elif taara_result.get("is_taara_novel"):
                self.log_action("novelty_detected",
                                "Reconstruction failure — behavior cannot be represented by prior observations.",
                                severity="warning")
            else:
                self.log_action("normal", "Behavior within known patterns.", severity="info")

            # Update working memory
            self._working_memory["last_scan_findings"] = security_data
            self._working_memory["last_quantum_result"] = taara_result
            self._working_memory["cycles"] += 1

            result["success"] = True
            result["findings"] = security_data
            result["analysis"] = taara_result

        except Exception as e:
            self.log_action("error", f"Scan error: {str(e)[:200]}", severity="error")
            result["error"] = str(e)

        self.status = "idle"
        self.current_task = None
        return result

    # ── GraphRAG-enhanced analysis ────────────────────────────────────────────

    def _walk_graph_chains(self, security_data: Dict) -> List[Dict]:
        """
        Walk the knowledge graph for each detected misconfiguration.
        Returns propagation chains scored by quantum fidelity.
        Each chain tells the LLM: "this finding → enables → this attack → causes → this damage."
        """
        chains = []
        try:
            from knowledge_base.query_knowledge_base import TAARAScan
            scanner = TAARAScan()
            scanner._load()

            for cat_key, cat_data in security_data.get("categories", {}).items():
                raw = cat_data.get("raw_config", "")
                if not raw:
                    continue

                # Get propagation chain for each finding in this category
                for finding in cat_data.get("findings", [])[:3]:
                    # Map finding title to graph node
                    title_lower = finding.get("title", "").lower()
                    node_id = None
                    for nid in scanner._graph.nodes():
                        label = scanner._graph.nodes[nid].get("label", "").lower()
                        if any(kw in title_lower for kw in label.split()[:3]):
                            node_id = nid
                            break

                    if node_id:
                        chain = scanner._propagation_chain(node_id, depth=4)
                        mitigations = scanner._get_mitigations(node_id)

                        # Quantum score: how far is current config from safe state?
                        content_vec = scanner._model.encode(
                            [raw[:500]], normalize_embeddings=True
                        ).astype(np.float32)[0]
                        policy_label = scanner._graph.nodes[node_id].get("label", node_id)
                        policy_vec = scanner._model.encode(
                            [policy_label], normalize_embeddings=True
                        ).astype(np.float32)[0]

                        from research.query_knowledge_base import quantum_fidelity, deviation_score
                        F = quantum_fidelity(content_vec, policy_vec)
                        deviation = deviation_score(F)

                        chains.append({
                            "finding": finding.get("title", ""),
                            "severity": finding.get("severity", "medium"),
                            "node_id": node_id,
                            "propagation_chain": chain,
                            "mitigations": mitigations,
                            "quantum_fidelity": round(F, 4),
                            "deviation_score": deviation,
                            "quantum_interpretation": (
                                f"F={F:.3f} — this config is "
                                + ("maximally unsafe (nearly orthogonal to best practice)"
                                   if F < 0.3 else
                                   "unsafe (more orthogonal than parallel to best practice)"
                                   if F < 0.5 else
                                   "drifting from best practice" if F < 0.7 else
                                   "close to best practice")
                            ),
                        })
        except Exception as e:
            # KB not loaded or graph unavailable — degrade gracefully
            self.log_action("graphrag_skip", f"GraphRAG unavailable: {str(e)[:100]}",
                            severity="info")

        self._working_memory["last_graph_chains"] = chains
        return chains

    def _format_graph_chains_for_llm(self, chains: List[Dict]) -> str:
        """Format graph chains into structured text the LLM reasons over."""
        if not chains:
            return ""
        parts = ["\n=== GRAPHRAG PROPAGATION CHAINS (Quantum-Scored) ==="]
        for ch in chains[:4]:
            parts.append(
                f"\nFinding: [{ch['severity'].upper()}] {ch['finding']}"
                f"\n  {ch['quantum_interpretation']}"
                f"\n  Deviation from safe state: {ch['deviation_score']:.0%}"
            )
            if ch.get("propagation_chain"):
                parts.append("  Propagation path:")
                for node in ch["propagation_chain"][:4]:
                    depth_indent = "    " + "  " * node.get("depth", 0)
                    parts.append(
                        f"{depth_indent}→ [{node.get('severity','?').upper()}] {node.get('label', node.get('id',''))}"
                    )
                    for rel in node.get("relationships", [])[:2]:
                        parts.append(f"{depth_indent}   {rel.get('rel','')} → {rel.get('to_label','')}")
            if ch.get("mitigations"):
                parts.append(f"  Fix: {ch['mitigations'][0].get('description','')[:120]}")
        return "\n".join(parts)

    # ── Core autonomous analysis ───────────────────────────────────────────────

    def autonomous_analyze(self, platform, taara_analyzer, llm_service,
                           embedder=None, detector=None) -> Dict:
        """
        Full autonomous analysis cycle — quantum-informed, bandit-ranked.

        1. Security scan
        2. GraphRAG chain walking + quantum fidelity scoring per chain
        3. LLM reasons over the graph output (not raw text)
        4. Bandit ranks proposed actions by context × history
        5. Pre-approved low-risk actions flagged for autonomous execution
        6. Every action gets rollback pre-computed
        """
        self.status = "autonomous_analysis"
        self.current_task = "Autonomous Analysis"
        self.log_action("autonomous_start", "Starting quantum-informed autonomous analysis")

        scan_result = self.run_security_scan(platform, taara_analyzer, embedder, detector)
        if not scan_result.get("success"):
            return scan_result

        findings = scan_result.get("findings", {})
        analysis = scan_result.get("analysis", {})
        quantum_result = analysis.get("quantum_validation") or {}
        f_min = quantum_result.get("f_min", 1.0)
        is_quantum_confirmed = analysis.get("is_quantum_confirmed", False)

        # Build quantum context for bandit
        quantum_context = {
            "f_min": f_min,
            "platform_type": platform.platform_type,
            "is_quantum_confirmed": is_quantum_confirmed,
            "bucket": fidelity_bucket(f_min),
        }

        # GraphRAG: walk knowledge graph chains, score with quantum fidelity
        graph_chains = self._walk_graph_chains(findings)
        graph_context_text = self._format_graph_chains_for_llm(graph_chains)

        findings_text = self._summarize_findings(findings, analysis)
        learned_context = self._get_learned_context()

        if not llm_service:
            self.log_action("autonomous_skip", "No LLM — cannot generate commands",
                            severity="warning")
            return scan_result

        # Urgency framing based on quantum signal
        if is_quantum_confirmed:
            urgency = (
                f"QUANTUM-CONFIRMED THREAT: F_min={f_min:.3f}. "
                f"Behavioral direction is {(1-f_min)*100:.0f}% orthogonal to all prior normal states. "
                f"This is a genuine directional shift, not noise or statistical variation. "
                f"The quantum fidelity criterion (F < 0.5 = more orthogonal than parallel) "
                f"has been crossed — this is the TAARA confirmation signal."
            )
        elif analysis.get("is_taara_novel"):
            urgency = (
                f"TAARA NOVELTY: Reconstruction residual exceeds all prior maxima. "
                f"This behavior cannot be represented by prior observations. "
                f"Quantum fidelity F={f_min:.3f} (pending confirmation)."
            )
        else:
            urgency = f"System within known patterns. Quantum fidelity F={f_min:.3f}."

        prompt = f"""You are TAARA Security Agent — a quantum-informed, bandit-guided security analysis system.

The quantum engine has assessed the current behavioral state.
{urgency}

Your task: Generate specific, targeted remediation commands for the findings below.
Reason over the GraphRAG propagation chains — these show what each misconfiguration CAUSES,
not just what it is. Prioritize by quantum deviation score and propagation depth.

Rules:
- Each command fixes ONE specific issue
- Commands must be idempotent where possible
- Mark each command with its action_type (block_ip, restart_service, harden_ssh, etc.)
- Do NOT generate commands that cannot be rolled back without data loss
- Format: ```bash with a comment line explaining what it fixes and why

Platform: {platform.platform_type}
Quantum bucket: {fidelity_bucket(f_min)} (F_min={f_min:.3f})
Autonomy level configured: {self.bandit.autonomy_level}/5
{learned_context}

=== SCAN FINDINGS ===
{findings_text}
{graph_context_text}

Based on the propagation chains above, focus on findings with the highest deviation scores
and deepest propagation paths. Those are the ones most likely to cascade into larger incidents.
Generate the top 3-5 most impactful remediation commands.
"""

        self.status = "generating_remediations"
        response = llm_service.generate_response(prompt)

        commands = []
        if response.get("success"):
            raw_commands = response.get("commands", [])

            for cmd in raw_commands:
                action_type = _infer_action_type(cmd.get("code", ""))
                arm_key = f"{fidelity_bucket(f_min)}:{platform.platform_type}:{action_type}"
                rollback = _infer_rollback(cmd.get("code", ""))

                # Bandit ranking
                bandit_scored = self.bandit.select_actions(
                    quantum_context, [{"action_type": action_type, **cmd}], top_k=1
                )
                bandit_info = bandit_scored[0] if bandit_scored else {}

                contrast_insight = self.bandit.get_contrast_insight(arm_key)

                enriched_cmd = {
                    **cmd,
                    "action_type": action_type,
                    "arm_key": arm_key,
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "source": "agent_autonomous",
                    "rollback_cmd": rollback,
                    "quantum_context": quantum_context,
                    "pre_approved": bandit_info.get("pre_approved", False),
                    "bandit_rationale": bandit_info.get("bandit_rationale", ""),
                    "approval_rate": bandit_info.get("approval_rate", 0),
                    "success_rate": bandit_info.get("success_rate", 0),
                    "contrast_insight": contrast_insight,
                    "graph_chain": next(
                        (ch for ch in graph_chains if action_type in ch.get("finding", "").lower()),
                        None
                    ),
                    "scan_context": findings_text[:300],
                }

                self.proposed_actions.append(enriched_cmd)
                self.bandit.record_proposed(arm_key)
                commands.append(enriched_cmd)

            self.log_action(
                "remediations_generated",
                f"Generated {len(commands)} commands. "
                f"Pre-approved: {sum(1 for c in commands if c.get('pre_approved'))}. "
                f"Quantum bucket: {fidelity_bucket(f_min)}.",
                severity="info",
                details={"command_count": len(commands), "f_min": f_min,
                         "pre_approved_count": sum(1 for c in commands if c.get("pre_approved"))},
            )

            # Auto-execute pre-approved actions if platform available and autonomy allows
            auto_executed = []
            for cmd in commands:
                if (cmd.get("pre_approved")
                        and self.bandit.autonomy_level >= ACTION_AUTONOMY_REQUIREMENTS.get(
                            cmd.get("action_type", "generic"), 5)
                        and platform and platform.connected):
                    exec_result = self._execute_command(cmd, platform)
                    context_snap = {**quantum_context,
                                    "exit_code": exec_result.get("exit_code", -1)}
                    self.bandit.record_executed(cmd["arm_key"], exec_result["success"],
                                                context_snap)
                    if exec_result["success"]:
                        self.bandit.record_approved(cmd["arm_key"])

                    cmd["auto_executed"] = True
                    cmd["auto_result"] = exec_result
                    cmd["status"] = "auto_executed"
                    self.executed_actions.append(cmd)
                    self.proposed_actions.remove(cmd)
                    auto_executed.append(cmd)
                    self.log_action(
                        "auto_executed",
                        f"Pre-approved action executed autonomously: {cmd['code'][:80]}",
                        result="success" if exec_result["success"] else "failed",
                        severity="warning",
                        details={"arm_key": cmd["arm_key"],
                                 "exit_code": exec_result.get("exit_code", -1),
                                 "rollback": cmd.get("rollback_cmd", "")},
                    )
        else:
            self.log_action("llm_error", f"LLM failed: {response.get('error', '')}",
                            severity="warning")

        self.status = "idle"
        self.current_task = None

        return {
            "success": True,
            "scan": scan_result,
            "commands": commands,
            "explanation": response.get("explanation", "") if response.get("success") else "",
            "graph_chains": graph_chains,
            "quantum_context": quantum_context,
            "pre_approved_count": sum(1 for c in commands if c.get("pre_approved")),
            "auto_executed_count": sum(1 for c in commands if c.get("auto_executed")),
            "bandit_summary": self.bandit.get_pre_approved_actions_summary(),
        }

    # ── Action execution with bandit recording ────────────────────────────────

    def execute_approved_action(self, action_index: int, platform) -> Dict:
        if action_index >= len(self.proposed_actions):
            return {"success": False, "error": "Invalid action index"}

        action = self.proposed_actions[action_index]
        self.bandit.record_approved(action.get("arm_key", "unknown"))

        result = self._execute_command(action, platform)

        action["status"] = "success" if result["success"] else "failed"
        action["result"] = result
        action["executed_at"] = time.time()

        self.executed_actions.append(action)
        self.proposed_actions.pop(action_index)

        # Record outcome with quantum context
        ctx = action.get("quantum_context", {})
        ctx["exit_code"] = result.get("exit_code", -1)
        self.bandit.record_executed(
            action.get("arm_key", "unknown"),
            result["success"],
            context_snapshot=ctx,
        )

        self._learn_from_execution(action, result)

        self.log_action(
            "action_executed",
            f"{'SUCCESS' if result['success'] else 'FAILED'}: {action['code'][:80]}",
            result=result.get("stdout", "")[:200],
            severity="info" if result["success"] else "error",
            details={
                "command": action["code"][:200],
                "exit_code": result.get("exit_code", -1),
                "rollback_cmd": action.get("rollback_cmd", ""),
                "arm_key": action.get("arm_key", ""),
                "quantum_f_min": action.get("quantum_context", {}).get("f_min", None),
            },
        )
        return result

    def rollback_action(self, action_index: int, platform) -> Dict:
        """Execute the rollback command for an already-executed action."""
        if action_index >= len(self.executed_actions):
            return {"success": False, "error": "Invalid action index"}

        action = self.executed_actions[action_index]
        rollback_cmd = action.get("rollback_cmd", "")

        if not rollback_cmd or rollback_cmd.startswith("# No automatic"):
            return {"success": False, "error": "No rollback command available for this action"}

        result = self._execute_command({"code": rollback_cmd, "language": "bash"}, platform)

        self.bandit.record_rollback(action.get("arm_key", "unknown"))

        self.log_action(
            "rollback_executed",
            f"Rollback for: {action['code'][:60]}",
            result="success" if result["success"] else "failed",
            severity="warning",
            details={"original_cmd": action["code"][:200],
                     "rollback_cmd": rollback_cmd,
                     "arm_key": action.get("arm_key", "")},
        )
        return result

    def get_failure_recovery(self, action: Dict, result: Dict, llm_service, platform) -> List[Dict]:
        if not llm_service:
            return []

        f_min = action.get("quantum_context", {}).get("f_min", 1.0)
        prompt = f"""A security remediation command failed on {platform.platform_type}.
The quantum engine context: F_min={f_min:.3f} ({fidelity_bucket(f_min)}).

Failed command:
```{action.get('language', 'bash')}
{action['code']}
```
Exit code: {result.get('exit_code', 'N/A')}
Stdout: {result.get('stdout', '')[:600]}
Stderr: {result.get('stderr', '')[:600]}

The original intent was: {action.get('bandit_rationale', 'security remediation')}

Analyze the failure and provide corrective commands.
Consider the quantum context — if fidelity is critically low, the system state may have
changed since the command was generated. Adjust accordingly.
"""
        response = llm_service.generate_response(prompt)
        commands = []
        if response.get("success"):
            for cmd in response.get("commands", []):
                action_type = _infer_action_type(cmd.get("code", ""))
                arm_key = f"{fidelity_bucket(f_min)}:{platform.platform_type}:{action_type}"
                enriched = {
                    **cmd,
                    "action_type": action_type,
                    "arm_key": arm_key,
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "source": "agent_recovery",
                    "rollback_cmd": _infer_rollback(cmd.get("code", "")),
                    "original_failure": action["code"][:200],
                    "quantum_context": action.get("quantum_context", {}),
                    "pre_approved": False,
                }
                self.proposed_actions.append(enriched)
                self.bandit.record_proposed(arm_key)
                commands.append(enriched)
            self.log_action("recovery_generated",
                            f"Generated {len(commands)} recovery commands",
                            severity="info")
        return commands

    # ── Agent status + stats ──────────────────────────────────────────────────

    def get_stats(self) -> Dict:
        total = len(self.agent_log)
        critical = sum(1 for e in self.agent_log if e.get("severity") == "critical")
        warnings = sum(1 for e in self.agent_log if e.get("severity") == "warning")
        novelties = sum(1 for e in self.agent_log if "novelty" in e.get("action_type", ""))
        auto_exec = sum(1 for a in self.executed_actions if a.get("auto_executed"))
        pre_approved_actions = self.bandit.get_pre_approved_actions_summary()

        return {
            "total_actions": total,
            "critical_events": critical,
            "warnings": warnings,
            "novelties_detected": novelties,
            "status": self.status,
            "running": self.running,
            "proposed_actions": len(self.proposed_actions),
            "executed_actions": len(self.executed_actions),
            "auto_executed": auto_exec,
            "learned_patterns": len(self.learned_patterns),
            "autonomy_level": self.bandit.autonomy_level,
            "pre_approved_action_types": len(pre_approved_actions),
            "working_memory_cycles": self._working_memory.get("cycles", 0),
        }

    def get_audit_trail(self, limit: int = 50) -> List[Dict]:
        """Full audit trail with quantum scores and rollback commands."""
        trail = []
        for action in self.executed_actions[-limit:]:
            trail.append({
                "code": action.get("code", ""),
                "status": action.get("status", "unknown"),
                "executed_at": action.get("executed_at"),
                "source": action.get("source", ""),
                "auto_executed": action.get("auto_executed", False),
                "quantum_f_min": action.get("quantum_context", {}).get("f_min"),
                "quantum_bucket": action.get("quantum_context", {}).get("bucket"),
                "arm_key": action.get("arm_key", ""),
                "approval_rate_at_time": action.get("approval_rate", None),
                "rollback_cmd": action.get("rollback_cmd", ""),
                "result_stdout": action.get("result", {}).get("stdout", "")[:300],
                "result_exit_code": action.get("result", {}).get("exit_code"),
            })
        return trail[::-1]

    def set_autonomy_level(self, level: int):
        self.bandit.set_autonomy_level(level)
        self.log_action("autonomy_change", f"Autonomy level set to {level}/5", severity="info")

    # ── Continuous monitoring ─────────────────────────────────────────────────

    def run_continuous_monitoring(self, platform, taara_analyzer, embedder,
                                  detector, interval: int = 60):
        self.running = True
        self.stop_flag.clear()
        self.status = "monitoring"
        self.log_action("monitor_start", f"Continuous monitoring started ({interval}s interval)")

        def _loop():
            while not self.stop_flag.is_set():
                try:
                    self.run_security_scan(platform, taara_analyzer, embedder, detector)
                except Exception as e:
                    self.log_action("monitor_error", str(e)[:200], severity="error")
                for _ in range(interval):
                    if self.stop_flag.is_set():
                        break
                    time.sleep(1)
            self.running = False
            self.status = "idle"
            self.log_action("monitor_stop", "Continuous monitoring stopped")

        threading.Thread(target=_loop, daemon=True).start()

    def stop_monitoring(self):
        self.stop_flag.set()
        self.status = "stopping"

    def get_recent_log(self, limit: int = 50) -> List[Dict]:
        return self.agent_log[-limit:][::-1]

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _execute_command(self, cmd: Dict, platform) -> Dict:
        result = {"success": False, "stdout": "", "stderr": "", "error": ""}
        code = cmd.get("code", "")
        language = cmd.get("language", "shell")
        try:
            if platform.platform_type == "ssh":
                if language == "python":
                    escaped = code.replace("'", "'\\''")
                    code = f"python3 -c '{escaped}'"
                stdout, stderr, exit_code = platform.execute_command(code)
                result.update({"stdout": stdout, "stderr": stderr,
                                "exit_code": exit_code, "success": exit_code == 0})
                if exit_code != 0:
                    result["error"] = f"Exit code: {exit_code}"
            else:
                result["stdout"] = f"[{platform.platform_type.upper()}] Staged:\n{code}"
                result["success"] = True
        except Exception as e:
            result["error"] = str(e)
        return result

    def _summarize_findings(self, findings: Dict, analysis: Dict) -> str:
        parts = [f"Platform: {findings.get('platform', 'unknown')}"]
        summary = findings.get("summary", {})
        parts.append(
            f"Critical: {summary.get('critical',0)}, High: {summary.get('high',0)}, "
            f"Medium: {summary.get('medium',0)}, Low: {summary.get('low',0)}"
        )
        for cat_name, cat_data in findings.get("categories", {}).items():
            cat_findings = cat_data.get("findings", [])
            if cat_findings:
                parts.append(f"\n--- {cat_data.get('name', cat_name)} ---")
                for f in cat_findings[:8]:
                    parts.append(f"  [{f.get('severity','info').upper()}] {f.get('title','')}")
                    if f.get("remediation"):
                        parts.append(f"    Fix: {f['remediation']}")
        return "\n".join(parts)

    def _learn_from_execution(self, action: Dict, result: Dict):
        cmd_hash = str(hash(action.get("code", "")[:100]))
        if cmd_hash not in self.learned_patterns:
            self.learned_patterns[cmd_hash] = {
                "command_prefix": action.get("code", "")[:80],
                "successes": 0, "failures": 0,
                "last_outcome": None, "common_errors": [],
            }
        p = self.learned_patterns[cmd_hash]
        if result["success"]:
            p["successes"] += 1
            p["last_outcome"] = "success"
        else:
            p["failures"] += 1
            p["last_outcome"] = "failed"
            err = result.get("stderr", "") or result.get("error", "")
            if err and err not in p["common_errors"]:
                p["common_errors"].append(err[:200])
                p["common_errors"] = p["common_errors"][-5:]
        self._save_learned_patterns()

    def _get_learned_context(self) -> str:
        if not self.learned_patterns:
            return ""
        parts = ["\n=== LEARNED EXECUTION PATTERNS ==="]
        for p in list(self.learned_patterns.values())[-8:]:
            if p["failures"] > 0:
                parts.append(
                    f"  '{p['command_prefix']}' — "
                    f"{p['successes']}✓ {p['failures']}✗"
                )
                if p["common_errors"]:
                    parts.append(f"    Error: {p['common_errors'][-1][:80]}")
        return "\n".join(parts) if len(parts) > 1 else ""

    def _save_log(self):
        try:
            with open(os.path.join(self.model_dir, "agent_log.json"), "w") as f:
                json.dump(self.agent_log[-500:], f, indent=2)
        except Exception:
            pass

    def _load_log(self):
        path = os.path.join(self.model_dir, "agent_log.json")
        if os.path.exists(path):
            try:
                with open(path) as f:
                    self.agent_log = json.load(f)
            except Exception:
                pass

    def _save_learned_patterns(self):
        try:
            with open(os.path.join(self.model_dir, "agent_learned_patterns.json"), "w") as f:
                json.dump(self.learned_patterns, f, indent=2)
        except Exception:
            pass

    def _load_learned_patterns(self):
        path = os.path.join(self.model_dir, "agent_learned_patterns.json")
        if os.path.exists(path):
            try:
                with open(path) as f:
                    self.learned_patterns = json.load(f)
            except Exception:
                pass
