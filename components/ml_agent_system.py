"""
ML-Powered Agent System
========================

Unified controller for the entire ML + Agent learning loop.

Integrates:
    - Atomic DNA Collector
    - DNA Autoencoder
    - Isolation Forest Anomaly Detector
    - Quantum Fidelity Similarity
    - Behavior Memory
    - Contextual Bandit Policy
    - Agent Orchestrator
    - Safe Executor
    - Training Manager

Provides simple API for dashboard integration.
"""

from typing import Dict, Any, Optional
import numpy as np
from .atomic_dna_collector import AtomicDNACollector
from .dna_autoencoder import DNAEmbedder
from .ml_anomaly_detector import MLAnomalyDetector, QuantumFidelity, BehaviorMemory
from .agent_policy_learner import ContextualBandit, RewardCalculator
from .agent_orchestrator import AgentOrchestrator, AgentState
from .safe_executor import SafeExecutor
from .training_manager import TrainingManager
from .action_suggester import ActionSuggester


class MLAgentSystem:
    """
    Unified ML-powered agent system.

    Usage:
        # Initialize
        system = MLAgentSystem(ssh_manager, llm_service)

        # Training (one-time or periodic)
        system.run_training(quick_mode=True)

        # Monitoring (continuous)
        result = system.analyze_current_state()

        # Learning (from admin feedback)
        system.learn_from_feedback(result_id, feedback='approve')
    """

    def __init__(self, ssh_manager, llm_service):
        """
        Initialize all ML components.

        Args:
            ssh_manager: SSH connection manager
            llm_service: LLM service (Gemini)
        """
        self.ssh_manager = ssh_manager
        self.llm_service = llm_service

        # Initialize all components
        print("[MLAgentSystem] Initializing ML components...")

        self.dna_collector = AtomicDNACollector(ssh_manager)
        self.embedder = DNAEmbedder()
        self.anomaly_detector = MLAnomalyDetector()
        self.memory = BehaviorMemory()
        self.bandit = ContextualBandit()
        self.safe_executor = SafeExecutor()
        self.action_suggester = ActionSuggester(self.memory, llm_service)

        self.orchestrator = AgentOrchestrator(
            dna_collector=self.dna_collector,
            embedder=self.embedder,
            anomaly_detector=self.anomaly_detector,
            memory=self.memory,
            bandit=self.bandit,
            llm_service=llm_service,
            safe_executor=self.safe_executor
        )

        self.training_manager = TrainingManager(
            dna_collector=self.dna_collector,
            embedder=self.embedder,
            anomaly_detector=self.anomaly_detector,
            memory=self.memory
        )

        # State cache
        self.recent_states = {}  # result_id -> AgentState
        self.next_result_id = 1

        print("[MLAgentSystem] Initialization complete")

    # ========================================================================
    # TRAINING API
    # ========================================================================

    def run_training(self, quick_mode: bool = False) -> Dict[str, Any]:
        """
        Run complete training workflow.

        Args:
            quick_mode: If True, use shorter collection time (for testing)

        Returns:
            dict: Training results
        """
        return self.training_manager.quick_start(self.ssh_manager, quick_mode=quick_mode)

    def is_trained(self) -> bool:
        """Check if system is trained and ready."""
        return self.training_manager.is_ready()

    def get_training_status(self) -> Dict[str, Any]:
        """Get current training status."""
        return self.training_manager.get_status()

    # ========================================================================
    # MONITORING API
    # ========================================================================

    def analyze_current_state(self, safe_mode: bool = True) -> Dict[str, Any]:
        """
        Analyze current system state using ML + Agent pipeline.

        Args:
            safe_mode: If True, only allow previously approved actions

        Returns:
            dict: Analysis result with action recommendation
        """
        print("[MLAgentSystem] Analyzing current state...")

        # Run agent pipeline
        state = self.orchestrator.run_pipeline(self.ssh_manager, safe_mode=safe_mode)

        # Assign result ID for tracking
        result_id = f"result_{self.next_result_id}"
        self.next_result_id += 1

        # Cache state for later feedback
        self.recent_states[result_id] = state

        # Check if action needs approval
        context = {
            'embedding': state['embedding'] if state['embedding'] is not None else np.zeros(64),
            'anomaly_score': state.get('anomaly_result', {}).get('anomaly_score', 0.0),
            'gemini_category': state.get('reasoning_category', 'unknown')
        }
        needs_approval = self.bandit.needs_approval(state['selected_action'], context)

        # Build result dict for dashboard
        exec_result = state.get('execution_result') or {}
        result = {
            'result_id': result_id,
            'timestamp': exec_result.get('timestamp', 0),

            # DNA
            'raw_features': state['raw_features'],
            'embedding': state['embedding'].tolist() if state['embedding'] is not None else [],
            'reconstruction_error': state.get('reconstruction_error', 0.0),

            # Detection
            'is_anomaly': state['is_anomaly'],
            'anomaly_score': (state.get('anomaly_result') or {}).get('anomaly_score', 0.0),
            'confidence': (state.get('anomaly_result') or {}).get('confidence', 0.0),

            # Memory
            'known_benign': state['known_benign'],
            'known_suspicious': state['known_suspicious'],
            'similar_pattern': state.get('similar_pattern'),

            # Reasoning
            'gemini_reasoning': state.get('gemini_reasoning'),
            'reasoning_category': state.get('reasoning_category'),

            # Action
            'selected_action': state['selected_action'],
            'action_rationale': state['action_rationale'],
            'needs_approval': needs_approval,
            'action_risk': self.bandit.ACTION_RISK.get(state['selected_action'], 'unknown'),

            # Execution
            'execution_result': state.get('execution_result'),

            # Meta
            'errors': state['errors'],
            'safe_mode': state['safe_mode'],

            # System status
            'system_trained': self.is_trained(),
            'fallback_mode': self.training_manager.get_fallback_mode()
        }

        # If not trained, override action
        if not self.is_trained():
            result['selected_action'] = 'notify'
            result['action_rationale'] = 'System not trained - notify-only mode'

        return result

    def execute_action(self, result_id: str) -> Dict[str, Any]:
        """
        Execute the selected action (after admin approval).

        Args:
            result_id: ID from analyze_current_state()

        Returns:
            dict: Execution result
        """
        if result_id not in self.recent_states:
            return {'status': 'error', 'message': 'Result ID not found'}

        state = self.recent_states[result_id]

        # Execute
        state = self.orchestrator.execute_action(state)

        # Update cached state
        self.recent_states[result_id] = state

        return state.get('execution_result', {})

    # ========================================================================
    # LEARNING API
    # ========================================================================

    def learn_from_feedback(self, result_id: str, feedback: str, actual_threat: bool = False) -> Dict[str, Any]:
        """
        Update models based on admin feedback.

        Args:
            result_id: ID from analyze_current_state()
            feedback: 'approve', 'reject', 'mark_benign', 'mark_suspicious', 'ignore'
            actual_threat: Whether admin confirmed this was a real threat

        Returns:
            dict: Learning results
        """
        if result_id not in self.recent_states:
            return {'status': 'error', 'message': 'Result ID not found'}

        state = self.recent_states[result_id]

        # Learn
        state = self.orchestrator.learn_from_feedback(state, feedback, actual_threat)

        # Update cached state
        self.recent_states[result_id] = state

        # Online model update (if benign samples accumulated)
        if feedback == 'mark_benign' and state['embedding'] is not None:
            # Add to online learning queue
            # For now, we'll do immediate update (could batch later)
            self.training_manager.online_update(
                new_samples=[state['feature_vector']],
                labels=['benign']
            )

        return {
            'status': 'success',
            'feedback': feedback,
            'reward': state.get('reward', 0.0),
            'message': f"Learned from feedback: {feedback}"
        }

    # ========================================================================
    # STATISTICS API
    # ========================================================================

    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive system statistics."""
        return {
            'training': self.training_manager.get_status(),
            'memory': self.memory.get_stats(),
            'bandit': self.bandit.get_statistics(),
            'system_ready': self.is_trained()
        }

    def get_feature_names(self) -> list:
        """Get list of atomic DNA feature names."""
        return self.dna_collector.get_feature_names()

    # ========================================================================
    # MANUAL ACTIONS (for dashboard)
    # ========================================================================

    def mark_as_benign(self, result_id: str, notes: str = "") -> Dict[str, Any]:
        """Manually mark a pattern as benign."""
        return self.learn_from_feedback(result_id, 'mark_benign', actual_threat=False)

    def mark_as_suspicious(self, result_id: str, notes: str = "") -> Dict[str, Any]:
        """Manually mark a pattern as suspicious."""
        return self.learn_from_feedback(result_id, 'mark_suspicious', actual_threat=True)

    def approve_action(self, result_id: str) -> Dict[str, Any]:
        """Approve and execute the recommended action."""
        # First execute
        exec_result = self.execute_action(result_id)

        # Then learn
        learn_result = self.learn_from_feedback(result_id, 'approve', actual_threat=True)

        return {
            'execution': exec_result,
            'learning': learn_result
        }

    def reject_action(self, result_id: str) -> Dict[str, Any]:
        """Reject the recommended action (false positive)."""
        return self.learn_from_feedback(result_id, 'reject', actual_threat=False)
