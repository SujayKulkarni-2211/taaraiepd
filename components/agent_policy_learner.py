"""
Agent Policy Learner (Contextual Bandit)
=========================================

REAL learning - not rules.

Implements ε-greedy contextual bandit for action selection.

Context:
    - DNA embedding (64 dims)
    - Anomaly score (1 dim)
    - Gemini reasoning category (encoded)

Actions:
    1. ignore: Do nothing (benign)
    2. notify: Alert admin only
    3. enhanced_monitoring: Safe auto-action (tcpdump, verbose logging)

Rewards:
    - From admin feedback in dashboard
    - Positive reward: Admin approves action
    - Negative reward: Admin marks as false positive
    - Neutral: Admin ignores

CRITICAL SAFETY:
    - Agent can ONLY automate actions previously approved by admin
    - No action invention
    - Fallback to notify-only if uncertain
"""

import numpy as np
import json
import os
from typing import Dict, List, Tuple, Optional
from collections import defaultdict


class ContextualBandit:
    """ε-greedy contextual bandit for action learning."""

    ACTIONS = ['ignore', 'notify', 'enhanced_monitoring']

    # Action risk levels
    ACTION_RISK = {
        'ignore': 'low',                    # No action - safe
        'notify': 'low',                     # Just alert - safe
        'enhanced_monitoring': 'medium'      # Executes commands - needs approval first time
    }

    def __init__(self, epsilon=0.1, learning_rate=0.1, model_path='models/bandit_policy.json'):
        self.epsilon = epsilon  # Exploration rate
        self.learning_rate = learning_rate
        self.model_path = model_path

        # Create directory
        os.makedirs(os.path.dirname(model_path), exist_ok=True)

        # Q-table approximation: action -> {context_signature -> Q-value}
        # We'll use discrete context signatures (bucketed embeddings)
        self.q_table = {action: defaultdict(float) for action in self.ACTIONS}

        # Action counts (for uncertainty tracking)
        self.action_counts = {action: defaultdict(int) for action in self.ACTIONS}

        # Approved actions memory
        # Maps context_signature -> action (only if admin approved)
        self.approved_actions = {}

        # Statistics
        self.total_rewards = {action: 0.0 for action in self.ACTIONS}
        self.total_selections = {action: 0 for action in self.ACTIONS}

        # Load existing policy
        self.load()

    def select_action(self, context: Dict, safe_mode: bool = True) -> str:
        """
        Select action based on context.

        Args:
            context: {
                'embedding': np.ndarray (64,),
                'anomaly_score': float,
                'gemini_category': str ('ignore'/'notify'/'monitor')
            }
            safe_mode: If True, only allow actions previously approved by admin

        Returns:
            str: Selected action ('ignore', 'notify', 'enhanced_monitoring')
        """
        context_sig = self._get_context_signature(context)

        # SAFETY: In safe mode, only use previously approved actions
        if safe_mode and context_sig in self.approved_actions:
            action = self.approved_actions[context_sig]
            self.total_selections[action] += 1
            return action

        # ε-greedy: Explore vs Exploit
        if np.random.random() < self.epsilon:
            # Explore: Random action
            if safe_mode:
                # In safe mode, only explore between ignore and notify
                action = np.random.choice(['ignore', 'notify'])
            else:
                action = np.random.choice(self.ACTIONS)
        else:
            # Exploit: Choose best Q-value
            q_values = {action: self.q_table[action][context_sig] for action in self.ACTIONS}

            # If safe mode, exclude enhanced_monitoring unless approved
            if safe_mode and context_sig not in self.approved_actions:
                q_values['enhanced_monitoring'] = -np.inf

            action = max(q_values, key=q_values.get)

        self.total_selections[action] += 1
        return action

    def needs_approval(self, action: str, context: Dict) -> bool:
        """
        Check if action needs admin approval before execution.

        Args:
            action: Action to check
            context: Context dict

        Returns:
            bool: True if approval needed
        """
        # Low-risk actions never need approval
        if self.ACTION_RISK.get(action, 'high') == 'low':
            return False

        # Medium-risk actions need approval unless already approved for this context
        context_sig = self._get_context_signature(context)
        if context_sig in self.approved_actions and self.approved_actions[context_sig] == action:
            return False  # Already learned/approved

        return True  # Needs approval

    def update(self, context: Dict, action: str, reward: float, admin_approved: bool = False):
        """
        Update Q-value based on reward.

        Args:
            context: Context dict (same as select_action)
            action: Action taken
            reward: Reward received (positive, negative, or zero)
            admin_approved: If True, mark this action as approved for future automation
        """
        context_sig = self._get_context_signature(context)

        # Q-learning update: Q(s,a) = Q(s,a) + α * [R - Q(s,a)]
        current_q = self.q_table[action][context_sig]
        self.q_table[action][context_sig] = current_q + self.learning_rate * (reward - current_q)

        # Update statistics
        self.total_rewards[action] += reward
        self.action_counts[action][context_sig] += 1

        # If admin approved, remember this action for automation
        if admin_approved and action != 'ignore':
            self.approved_actions[context_sig] = action
            print(f"[Bandit] Learned: {action} for context {context_sig[:16]}...")

        # Save policy
        self.save()

    def _get_context_signature(self, context: Dict) -> str:
        """
        Convert context to discrete signature for Q-table.

        Uses bucketing to generalize similar contexts.
        """
        # Discretize embedding (cluster into buckets)
        embedding = context['embedding']
        anomaly_score = context['anomaly_score']
        gemini_category = context.get('gemini_category', 'unknown')

        # Bucket embedding: Hash of top-5 dimensions
        top_indices = np.argsort(np.abs(embedding))[-5:]
        top_values = [f"{i}:{int(embedding[i]*10)}" for i in top_indices]

        # Bucket anomaly score
        anomaly_bucket = 'low' if anomaly_score > -0.1 else 'medium' if anomaly_score > -0.3 else 'high'

        # Create signature
        signature = f"{gemini_category}_{anomaly_bucket}_{'_'.join(top_values)}"

        return signature

    def get_statistics(self) -> Dict:
        """Get bandit statistics."""
        avg_rewards = {}
        for action in self.ACTIONS:
            count = self.total_selections[action]
            avg_rewards[action] = self.total_rewards[action] / max(count, 1)

        return {
            'total_selections': self.total_selections,
            'average_rewards': avg_rewards,
            'approved_actions_count': len(self.approved_actions),
            'epsilon': self.epsilon,
            'q_table_size': {action: len(self.q_table[action]) for action in self.ACTIONS}
        }

    def save(self):
        """Save policy to disk."""
        try:
            data = {
                'q_table': {action: dict(values) for action, values in self.q_table.items()},
                'action_counts': {action: dict(counts) for action, counts in self.action_counts.items()},
                'approved_actions': self.approved_actions,
                'total_rewards': self.total_rewards,
                'total_selections': self.total_selections,
                'epsilon': self.epsilon,
                'learning_rate': self.learning_rate
            }

            with open(self.model_path, 'w') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            print(f"[Bandit] Save error: {e}")

    def load(self):
        """Load policy from disk."""
        try:
            if not os.path.exists(self.model_path):
                print(f"[Bandit] No saved policy found, starting fresh")
                return

            with open(self.model_path, 'r') as f:
                data = json.load(f)

            self.q_table = {action: defaultdict(float, values) for action, values in data['q_table'].items()}
            self.action_counts = {action: defaultdict(int, counts) for action, counts in data['action_counts'].items()}
            self.approved_actions = data['approved_actions']
            self.total_rewards = data['total_rewards']
            self.total_selections = data['total_selections']
            self.epsilon = data.get('epsilon', self.epsilon)
            self.learning_rate = data.get('learning_rate', self.learning_rate)

            print(f"[Bandit] Loaded policy: {len(self.approved_actions)} approved actions")

        except Exception as e:
            print(f"[Bandit] Load error: {e}")


class RewardCalculator:
    """Calculates rewards from admin feedback."""

    @staticmethod
    def compute_reward(feedback: str, actual_threat: bool = False) -> float:
        """
        Compute reward based on admin feedback.

        Args:
            feedback: 'approve', 'reject', 'mark_benign', 'mark_suspicious', 'ignore'
            actual_threat: Whether this was actually a threat (from admin marking)

        Returns:
            float: Reward value
        """
        rewards = {
            'approve': 1.0,           # Admin approved action
            'mark_benign': 0.5,       # Admin marked as benign (reduce false positives)
            'mark_suspicious': 1.0,   # Admin confirmed threat
            'reject': -0.5,           # Admin rejected action (false positive)
            'ignore': 0.0             # No feedback
        }

        base_reward = rewards.get(feedback, 0.0)

        # Bonus if actual threat was correctly identified
        if actual_threat and feedback in ['approve', 'mark_suspicious']:
            base_reward += 0.5

        return base_reward

    @staticmethod
    def compute_reward_from_outcome(predicted_action: str, admin_action: str) -> float:
        """
        Compute reward by comparing predicted vs actual admin action.

        Args:
            predicted_action: What agent suggested
            admin_action: What admin actually did

        Returns:
            float: Reward value
        """
        if predicted_action == admin_action:
            return 1.0  # Perfect match
        elif predicted_action == 'ignore' and admin_action != 'ignore':
            return -1.0  # Missed a threat
        elif predicted_action != 'ignore' and admin_action == 'ignore':
            return -0.5  # False positive
        else:
            return 0.0  # Partial credit
