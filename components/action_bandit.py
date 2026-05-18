"""
Contrastive Action Bandit
==========================
UCB-style contextual bandit that learns which security actions work
in which contexts — and earns pre-approval eligibility for repeat patterns.

Context = (quantum_fidelity_bucket, feature_cluster, platform_type)
Arm    = action_type (e.g. "block_ip", "restart_service", "harden_ssh")

For each (context, arm) pair we track:
  n_proposed       — times this action was surfaced to admin
  n_approved       — times admin approved
  n_executed       — times it was actually run
  n_success        — times execution succeeded (exit_code 0)
  n_rolled_back    — times admin hit rollback
  total_reward     — sum of reward signals

Reward signal:
  +1.0  execution success
  +0.5  admin approved (without rollback)
  -1.0  rollback triggered
  -0.5  execution failed

Pre-approval eligibility:
  approval_rate >= 0.90  AND  success_rate >= 0.85  AND  n_proposed >= 5
  AND  autonomy_level >= required_level_for_action

Contrastive learning:
  After each cycle we compare context pairs where the same action
  succeeded vs. failed. The difference in feature_cluster tells us
  which system states make an action dangerous vs. safe.
  This is stored as contrast_pairs and surfaced in the agent's reasoning.
"""

import json
import os
import time
import math
from typing import Dict, List, Optional, Tuple
from datetime import datetime


# Minimum autonomy level required for each action type to run without approval
ACTION_AUTONOMY_REQUIREMENTS = {
    "block_ip":          2,   # Block a single IP via fail2ban — low blast radius
    "restart_service":   2,   # Restart a known-safe monitoring service
    "rate_limit_ssh":    3,   # Add SSH rate limiting rule
    "kill_process":      3,   # Kill a specific PID (non-critical)
    "isolate_user":      4,   # Lock a user account
    "rotate_key":        4,   # Rotate SSH authorized_keys
    "harden_ssh":        4,   # Apply SSH config hardening
    "firewall_rule":     5,   # Broad firewall changes
    "terminate_service": 5,   # Stop a service entirely
}

# Quantum fidelity buckets — these are the "context" dimension
# F < 0.3: maximal divergence from safe behavior (critical)
# 0.3-0.5: unsafe direction (high)
# 0.5-0.7: drifting (medium)
# 0.7-1.0: normal (low / monitor)
def fidelity_bucket(f_min: float) -> str:
    if f_min < 0.3:
        return "critical_divergence"
    elif f_min < 0.5:
        return "unsafe_direction"
    elif f_min < 0.7:
        return "drifting"
    else:
        return "normal"


class ContrastiveBandit:
    """
    Contextual UCB bandit with contrastive learning for security action selection.

    The bandit answers: "Given what TAARA's quantum engine is telling us about
    the current behavioral direction, which action has the highest expected
    reward AND has earned the trust to run autonomously?"
    """

    def __init__(self, model_dir: str = "models"):
        self.model_dir = model_dir
        self.arm_stats: Dict[str, Dict] = {}
        self.contrast_pairs: List[Dict] = []
        self.autonomy_level: int = 1  # 0=off, 1=propose-only, 2=pre-approve-low, 5=full-auto
        self._load()

    # ── UCB arm selection ──────────────────────────────────────────────────────

    def select_actions(self, context: Dict, candidate_actions: List[Dict],
                       top_k: int = 5) -> List[Dict]:
        """
        Rank candidate actions by UCB score in the given context.
        Returns top_k actions with scores, pre-approval flags, and bandit rationale.
        """
        f_min = context.get("f_min", 1.0)
        bucket = fidelity_bucket(f_min)
        platform = context.get("platform_type", "ssh")
        total_rounds = max(sum(
            s.get("n_proposed", 0)
            for s in self.arm_stats.values()
        ), 1)

        scored = []
        for action in candidate_actions:
            action_type = action.get("action_type", action.get("code", "")[:30])
            arm_key = f"{bucket}:{platform}:{action_type}"

            stats = self.arm_stats.get(arm_key, {
                "n_proposed": 0, "n_approved": 0, "n_executed": 0,
                "n_success": 0, "n_rolled_back": 0, "total_reward": 0.0,
            })

            ucb_score = self._ucb_score(stats, total_rounds)
            approval_rate = (stats["n_approved"] / max(stats["n_proposed"], 1))
            success_rate = (stats["n_success"] / max(stats["n_executed"], 1))

            required_level = ACTION_AUTONOMY_REQUIREMENTS.get(action_type, 5)
            pre_approved = (
                approval_rate >= 0.90
                and success_rate >= 0.85
                and stats["n_proposed"] >= 5
                and self.autonomy_level >= required_level
            )

            # Urgency boost: quantum says this is critical AND we've seen it work
            urgency_boost = 0.0
            if bucket == "critical_divergence" and success_rate > 0.8:
                urgency_boost = 0.3

            action_copy = dict(action)
            action_copy.update({
                "arm_key": arm_key,
                "ucb_score": round(ucb_score + urgency_boost, 4),
                "approval_rate": round(approval_rate, 3),
                "success_rate": round(success_rate, 3),
                "times_seen": stats["n_proposed"],
                "pre_approved": pre_approved,
                "required_autonomy_level": required_level,
                "quantum_context": bucket,
                "bandit_rationale": self._rationale(stats, bucket, pre_approved, action_type),
            })
            scored.append(action_copy)

        scored.sort(key=lambda x: x["ucb_score"], reverse=True)
        return scored[:top_k]

    def _ucb_score(self, stats: Dict, total_rounds: int) -> float:
        n = stats.get("n_proposed", 0)
        if n == 0:
            return 2.0  # Unexplored — high UCB to encourage trying

        reward = stats.get("total_reward", 0.0)
        mean_reward = reward / n
        exploration_bonus = math.sqrt(2 * math.log(total_rounds) / n)
        return mean_reward + exploration_bonus

    def _rationale(self, stats: Dict, bucket: str, pre_approved: bool, action_type: str) -> str:
        n = stats.get("n_proposed", 0)
        if n == 0:
            return f"First time seeing this action in {bucket} context — exploring."
        ar = stats["n_approved"] / max(n, 1)
        sr = stats["n_success"] / max(stats["n_executed"], 1)
        rb = stats["n_rolled_back"]
        base = f"Seen {n}× in {bucket} context. Approval {ar:.0%}, success {sr:.0%}"
        if rb > 0:
            base += f", {rb} rollback(s)"
        if pre_approved:
            base += f". Pre-approved at autonomy level {self.autonomy_level}."
        return base + "."

    # ── Reward recording ───────────────────────────────────────────────────────

    def record_proposed(self, arm_key: str):
        s = self._get_or_create(arm_key)
        s["n_proposed"] += 1
        self._save()

    def record_approved(self, arm_key: str):
        s = self._get_or_create(arm_key)
        s["n_approved"] += 1
        s["total_reward"] += 0.5
        self._save()

    def record_executed(self, arm_key: str, success: bool, context_snapshot: Dict = None):
        s = self._get_or_create(arm_key)
        s["n_executed"] += 1
        if success:
            s["n_success"] += 1
            s["total_reward"] += 1.0
        else:
            s["total_reward"] -= 0.5
        if context_snapshot:
            self._record_contrast(arm_key, success, context_snapshot)
        self._save()

    def record_rollback(self, arm_key: str):
        s = self._get_or_create(arm_key)
        s["n_rolled_back"] += 1
        s["total_reward"] -= 1.0
        self._save()

    # ── Contrastive learning ───────────────────────────────────────────────────

    def _record_contrast(self, arm_key: str, success: bool, context_snapshot: Dict):
        """
        Store (context, outcome) pairs.
        When we have a success and failure for the same arm, the difference
        in context tells us WHAT makes this action safe vs. dangerous.
        """
        self.contrast_pairs.append({
            "arm_key": arm_key,
            "success": success,
            "context": context_snapshot,
            "timestamp": time.time(),
        })
        if len(self.contrast_pairs) > 500:
            self.contrast_pairs = self.contrast_pairs[-250:]
        self._save()

    def get_contrast_insight(self, arm_key: str) -> Optional[str]:
        """
        Find the most informative contrast for this arm.
        Returns a human-readable insight about when this action is safe vs. dangerous.
        """
        relevant = [p for p in self.contrast_pairs if p["arm_key"] == arm_key]
        successes = [p for p in relevant if p["success"]]
        failures = [p for p in relevant if not p["success"]]

        if not successes or not failures:
            return None

        # Compare quantum fidelity distributions
        success_f = [p["context"].get("f_min", 1.0) for p in successes]
        failure_f = [p["context"].get("f_min", 1.0) for p in failures]

        avg_success_f = sum(success_f) / len(success_f)
        avg_failure_f = sum(failure_f) / len(failure_f)

        if abs(avg_success_f - avg_failure_f) > 0.15:
            direction = "lower" if avg_success_f < avg_failure_f else "higher"
            return (
                f"This action succeeds when quantum fidelity is {direction} "
                f"(avg F={avg_success_f:.2f} on success vs F={avg_failure_f:.2f} on failure). "
                f"Quantum signal is the reliable predictor here."
            )
        return None

    def get_pre_approved_actions_summary(self) -> List[Dict]:
        """Return all actions that have earned pre-approval in any context."""
        results = []
        for arm_key, stats in self.arm_stats.items():
            n = stats.get("n_proposed", 0)
            if n < 5:
                continue
            ar = stats["n_approved"] / n
            sr = stats["n_success"] / max(stats["n_executed"], 1)
            if ar >= 0.90 and sr >= 0.85:
                parts = arm_key.split(":", 2)
                results.append({
                    "arm_key": arm_key,
                    "quantum_context": parts[0] if len(parts) > 0 else "",
                    "platform": parts[1] if len(parts) > 1 else "",
                    "action_type": parts[2] if len(parts) > 2 else "",
                    "approval_rate": round(ar, 3),
                    "success_rate": round(sr, 3),
                    "times_seen": n,
                    "rollbacks": stats.get("n_rolled_back", 0),
                })
        return results

    def set_autonomy_level(self, level: int):
        """0=off, 1=propose-only, 2=block-ip+restart, 3=rate-limit+kill, 4=isolate+rotate, 5=full"""
        self.autonomy_level = max(0, min(5, level))
        self._save()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _get_or_create(self, arm_key: str) -> Dict:
        if arm_key not in self.arm_stats:
            self.arm_stats[arm_key] = {
                "n_proposed": 0, "n_approved": 0, "n_executed": 0,
                "n_success": 0, "n_rolled_back": 0, "total_reward": 0.0,
            }
        return self.arm_stats[arm_key]

    def _save(self):
        path = os.path.join(self.model_dir, "action_bandit.json")
        try:
            with open(path, "w") as f:
                json.dump({
                    "arm_stats": self.arm_stats,
                    "contrast_pairs": self.contrast_pairs[-100:],
                    "autonomy_level": self.autonomy_level,
                }, f, indent=2)
        except Exception:
            pass

    def _load(self):
        path = os.path.join(self.model_dir, "action_bandit.json")
        if not os.path.exists(path):
            return
        try:
            with open(path) as f:
                data = json.load(f)
            self.arm_stats = data.get("arm_stats", {})
            self.contrast_pairs = data.get("contrast_pairs", [])
            self.autonomy_level = data.get("autonomy_level", 1)
        except Exception:
            pass
