"""
Agent Orchestrator (LangGraph)
===============================

Orchestrates the ML + Agent learning loop.

Flow:
    observe → embed → detect → reason → select_action → execute → learn

State:
    - raw_features: Atomic DNA features
    - embedding: Autoencoder embedding
    - anomaly_result: Isolation Forest output
    - similar_patterns: Memory search result
    - gemini_reasoning: LLM explanation (if needed)
    - selected_action: Bandit policy output
    - execution_result: Safe execution output
    - admin_feedback: Human feedback for learning
"""

from typing import Dict, Any, Optional, TypedDict, List
import numpy as np
import operator


class AgentState(TypedDict):
    """State passed between agent nodes."""
    # Input
    ssh_manager: Any
    llm_service: Any

    # Observation
    raw_features: Optional[Dict[str, float]]
    feature_vector: Optional[np.ndarray]

    # Embedding
    embedding: Optional[np.ndarray]
    reconstruction_error: Optional[float]

    # Detection
    anomaly_result: Optional[Dict]
    is_anomaly: bool

    # Memory
    similar_pattern: Optional[Dict]
    known_benign: bool
    known_suspicious: bool

    # Reasoning
    gemini_reasoning: Optional[Dict]
    reasoning_category: Optional[str]

    # Action Selection
    selected_action: str
    action_rationale: str

    # Execution
    execution_result: Optional[Dict]

    # Learning
    admin_feedback: Optional[str]
    reward: Optional[float]

    # Meta
    errors: List[str]
    safe_mode: bool


class AgentOrchestrator:
    """
    Orchestrates the ML + Agent pipeline.

    Simple sequential flow (no complex branching needed for MVP).
    """

    def __init__(self, dna_collector, embedder, anomaly_detector, memory, bandit, llm_service, safe_executor):
        self.dna_collector = dna_collector
        self.embedder = embedder
        self.anomaly_detector = anomaly_detector
        self.memory = memory
        self.bandit = bandit
        self.llm_service = llm_service
        self.safe_executor = safe_executor

    def run_pipeline(self, ssh_manager, safe_mode: bool = True) -> AgentState:
        """
        Run full agent pipeline.

        Args:
            ssh_manager: SSH connection to monitored system
            safe_mode: If True, only allow previously approved actions

        Returns:
            AgentState: Final state with all results
        """
        state = AgentState(
            ssh_manager=ssh_manager,
            llm_service=self.llm_service,
            raw_features=None,
            feature_vector=None,
            embedding=None,
            reconstruction_error=None,
            anomaly_result=None,
            is_anomaly=False,
            similar_pattern=None,
            known_benign=False,
            known_suspicious=False,
            gemini_reasoning=None,
            reasoning_category=None,
            selected_action='notify',
            action_rationale='',
            execution_result=None,
            admin_feedback=None,
            reward=None,
            errors=[],
            safe_mode=safe_mode
        )

        # Step 1: Observe (collect atomic DNA)
        state = self._observe(state)

        # Step 2: Embed (autoencoder)
        state = self._embed(state)

        # Step 3: Detect (Isolation Forest)
        state = self._detect(state)

        # Step 4: Check Memory (similarity search)
        state = self._check_memory(state)

        # If known benign, skip reasoning and return
        if state['known_benign']:
            state['selected_action'] = 'ignore'
            state['action_rationale'] = 'Known benign pattern (auto-suppressed)'
            return state

        # If known suspicious, use stored action
        if state['known_suspicious']:
            state['selected_action'] = state['similar_pattern']['action']
            state['action_rationale'] = f"Known suspicious pattern (auto-action: {state['selected_action']})"
            return state

        # Step 5: Reason (Gemini - only if anomaly detected)
        if state['is_anomaly']:
            state = self._reason(state)

        # Step 6: Select Action (Contextual Bandit)
        state = self._select_action(state)

        return state

    def execute_action(self, state: AgentState) -> AgentState:
        """Execute the selected action (called after admin approval)."""
        state = self._execute(state)
        return state

    def learn_from_feedback(self, state: AgentState, feedback: str, actual_threat: bool = False):
        """Update models based on admin feedback."""
        state = self._learn(state, feedback, actual_threat)
        return state

    # ========================================================================
    # PIPELINE STEPS
    # ========================================================================

    def _observe(self, state: AgentState) -> AgentState:
        """Step 1: Collect atomic DNA features."""
        try:
            raw_features = self.dna_collector.collect()
            feature_vector = self.dna_collector.get_feature_vector()

            state['raw_features'] = raw_features
            state['feature_vector'] = feature_vector

        except Exception as e:
            state['errors'].append(f"Observation error: {e}")

        return state

    def _embed(self, state: AgentState) -> AgentState:
        """Step 2: Embed features using autoencoder."""
        try:
            if state['feature_vector'] is None:
                state['errors'].append("No feature vector to embed")
                return state

            if not self.embedder.is_ready():
                state['errors'].append("Embedder not trained - skipping embedding")
                state['embedding'] = np.zeros(64)
                state['reconstruction_error'] = 0.0
                return state

            embedding = self.embedder.embed(state['feature_vector'])
            reconstruction_error = self.embedder.reconstruction_error(state['feature_vector'])

            state['embedding'] = embedding
            state['reconstruction_error'] = reconstruction_error

        except Exception as e:
            state['errors'].append(f"Embedding error: {e}")
            state['embedding'] = np.zeros(64)

        return state

    def _detect(self, state: AgentState) -> AgentState:
        """Step 3: Detect anomalies using Isolation Forest."""
        try:
            if state['embedding'] is None or not self.anomaly_detector.is_ready():
                state['errors'].append("Anomaly detector not ready")
                state['is_anomaly'] = False
                return state

            anomaly_result = self.anomaly_detector.detect(state['embedding'])

            state['anomaly_result'] = anomaly_result
            state['is_anomaly'] = anomaly_result.get('is_anomaly', False)

        except Exception as e:
            state['errors'].append(f"Detection error: {e}")
            state['is_anomaly'] = False

        return state

    def _check_memory(self, state: AgentState) -> AgentState:
        """Step 4: Check if similar pattern exists in memory."""
        try:
            if state['embedding'] is None:
                return state

            # STRICT threshold - need 95% similarity to be "known"
            similar = self.memory.find_similar(state['embedding'], threshold=0.95)

            state['similar_pattern'] = similar

            if similar:
                if similar['category'] == 'benign':
                    state['known_benign'] = True
                elif similar['category'] == 'suspicious':
                    state['known_suspicious'] = True

        except Exception as e:
            state['errors'].append(f"Memory search error: {e}")

        return state

    def _reason(self, state: AgentState) -> AgentState:
        """Step 5: Use Gemini to reason about anomaly (only if anomaly detected)."""
        try:
            if not state['is_anomaly']:
                state['reasoning_category'] = 'ignore'
                return state

            # Prepare context for Gemini
            context = {
                'anomaly_score': state['anomaly_result']['anomaly_score'],
                'confidence': state['anomaly_result']['confidence'],
                'reconstruction_error': state['reconstruction_error'],
                'raw_features': state['raw_features']
            }

            # Call Gemini for reasoning (lightweight prompt)
            prompt = f"""Analyze this system behavior anomaly:

Anomaly Score: {context['anomaly_score']:.4f} (negative = more anomalous)
Confidence: {context['confidence']:.2%}
Reconstruction Error: {context['reconstruction_error']:.6f}

Key Features:
- Process spawn rate: {context['raw_features'].get('proc_spawn_rate', 0):.1f}/min
- Outbound connections: {context['raw_features'].get('net_outbound_conn_rate', 0):.0f}
- Unique dst IPs: {context['raw_features'].get('net_unique_dst_ips', 0):.0f}
- Sensitive file access: {context['raw_features'].get('fs_sensitive_access', 0)}
- Exec from tmp: {context['raw_features'].get('fs_exec_from_tmp', 0)}

Is this behavior:
1. Benign / normal variation (respond: "ignore")
2. Suspicious but needs admin review (respond: "notify")
3. Suspicious and worth enhanced monitoring (respond: "monitor")

Respond with ONLY one word: ignore, notify, or monitor.
Then on a new line, briefly explain why (max 50 words)."""

            response = self.llm_service.generate_response(prompt, context={})

            # Parse response
            lines = response.strip().split('\n')
            category = lines[0].strip().lower()

            if category not in ['ignore', 'notify', 'monitor']:
                category = 'notify'  # Default to safe option

            explanation = '\n'.join(lines[1:]).strip() if len(lines) > 1 else "No explanation provided"

            state['gemini_reasoning'] = {
                'category': category,
                'explanation': explanation,
                'raw_response': response
            }
            state['reasoning_category'] = category

        except Exception as e:
            state['errors'].append(f"Reasoning error: {e}")
            state['reasoning_category'] = 'notify'  # Fail-safe to notify

        return state

    def _select_action(self, state: AgentState) -> AgentState:
        """Step 6: Select action using contextual bandit."""
        try:
            context = {
                'embedding': state['embedding'],
                'anomaly_score': state['anomaly_result'].get('anomaly_score', 0.0),
                'gemini_category': state.get('reasoning_category', 'unknown')
            }

            action = self.bandit.select_action(context, safe_mode=state['safe_mode'])

            state['selected_action'] = action

            # Generate rationale
            if action == 'ignore':
                state['action_rationale'] = 'Low risk - no action needed'
            elif action == 'notify':
                state['action_rationale'] = 'Requires admin review'
            elif action == 'enhanced_monitoring':
                state['action_rationale'] = 'Automated safe monitoring enabled'

        except Exception as e:
            state['errors'].append(f"Action selection error: {e}")
            state['selected_action'] = 'notify'  # Fail-safe

        return state

    def _execute(self, state: AgentState) -> AgentState:
        """Step 7: Execute action (only enhanced_monitoring is automated)."""
        try:
            action = state['selected_action']

            if action == 'ignore':
                state['execution_result'] = {'status': 'skipped', 'message': 'No action taken'}

            elif action == 'notify':
                state['execution_result'] = {'status': 'notified', 'message': 'Admin notified'}

            elif action == 'enhanced_monitoring':
                # Execute safe monitoring
                result = self.safe_executor.execute_enhanced_monitoring(state['ssh_manager'])
                state['execution_result'] = result

        except Exception as e:
            state['errors'].append(f"Execution error: {e}")
            state['execution_result'] = {'status': 'error', 'message': str(e)}

        return state

    def _learn(self, state: AgentState, feedback: str, actual_threat: bool) -> AgentState:
        """Step 8: Learn from admin feedback."""
        try:
            from .agent_policy_learner import RewardCalculator

            # Compute reward
            reward = RewardCalculator.compute_reward(feedback, actual_threat)

            # Update bandit
            context = {
                'embedding': state['embedding'],
                'anomaly_score': state['anomaly_result'].get('anomaly_score', 0.0),
                'gemini_category': state.get('reasoning_category', 'unknown')
            }

            admin_approved = feedback in ['approve', 'mark_suspicious']

            self.bandit.update(context, state['selected_action'], reward, admin_approved)

            # Update memory
            if feedback == 'mark_benign':
                self.memory.add_benign(state['embedding'], notes=feedback)
            elif feedback == 'mark_suspicious':
                self.memory.add_suspicious(state['embedding'], state['selected_action'], notes=feedback)

            state['admin_feedback'] = feedback
            state['reward'] = reward

        except Exception as e:
            state['errors'].append(f"Learning error: {e}")

        return state
