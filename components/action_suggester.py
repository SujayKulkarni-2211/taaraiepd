"""
Action Suggester
================

Intelligent action suggestion system that combines:
1. ML-based pattern matching (behavior memory)
2. LLM reasoning (when pattern is unknown)
3. Confidence-based execution policy

NOT just "execute LLM output" - this is a real decision engine.
"""

import numpy as np
from typing import Dict, List, Tuple, Optional


class ActionSuggester:
    """Suggests actions based on context, ML patterns, and LLM reasoning."""

    # Predefined safe actions (VPS-safe only)
    SAFE_ACTIONS = {
        'ignore': {
            'description': 'No action needed - benign behavior',
            'risk': 'none',
            'auto_executable': True
        },
        'notify': {
            'description': 'Alert admin for review',
            'risk': 'none',
            'auto_executable': True
        },
        'enhanced_monitoring': {
            'description': 'Capture detailed system state (tcpdump, ps, ss, lsof)',
            'risk': 'low',
            'auto_executable': True  # Safe, read-only
        },
        'snapshot_state': {
            'description': 'Take full system snapshot (no changes)',
            'risk': 'low',
            'auto_executable': True
        },
        'log_verbose': {
            'description': 'Enable verbose logging temporarily',
            'risk': 'low',
            'auto_executable': False  # Requires approval (changes config)
        }
    }

    def __init__(self, behavior_memory, llm_service):
        self.memory = behavior_memory
        self.llm = llm_service

    def suggest_actions(
        self,
        context: Dict,
        anomaly_detected: bool,
        known_pattern: Optional[Dict] = None
    ) -> Dict:
        """
        Suggest actions based on context.

        Args:
            context: {
                'embedding': np.ndarray,
                'anomaly_score': float,
                'raw_features': dict,
                'is_anomaly': bool
            }
            anomaly_detected: bool
            known_pattern: Optional dict from behavior memory

        Returns:
            dict: {
                'suggestions': List[Dict],  # [{action, confidence, reason}, ...]
                'source': 'memory' | 'llm' | 'ml',
                'auto_executable': bool,
                'requires_approval': bool
            }
        """
        # Case 1: Known benign pattern
        if known_pattern and known_pattern['category'] == 'benign':
            return {
                'suggestions': [{
                    'action': 'ignore',
                    'confidence': 1.0,
                    'reason': f"Known benign pattern (fidelity: {known_pattern['fidelity']:.2f})"
                }],
                'source': 'memory',
                'auto_executable': True,
                'requires_approval': False
            }

        # Case 2: Known suspicious pattern with learned action
        if known_pattern and known_pattern['category'] == 'suspicious':
            learned_action = known_pattern.get('action', 'notify')
            return {
                'suggestions': [{
                    'action': learned_action,
                    'confidence': 0.9,
                    'reason': f"Learned response for similar pattern (fidelity: {known_pattern['fidelity']:.2f})"
                }],
                'source': 'memory',
                'auto_executable': self.SAFE_ACTIONS[learned_action]['auto_executable'],
                'requires_approval': not self.SAFE_ACTIONS[learned_action]['auto_executable']
            }

        # Case 3: No anomaly detected
        if not anomaly_detected:
            return {
                'suggestions': [{
                    'action': 'ignore',
                    'confidence': 0.95,
                    'reason': 'Normal behavior detected by ML'
                }],
                'source': 'ml',
                'auto_executable': True,
                'requires_approval': False
            }

        # Case 4: Anomaly detected, unknown pattern - query LLM
        return self._query_llm_for_suggestions(context)

    def _query_llm_for_suggestions(self, context: Dict) -> Dict:
        """
        Query LLM for action suggestions on unknown anomaly.

        Returns suggestions with confidence levels.
        """
        try:
            # Build prompt for LLM
            prompt = self._build_llm_prompt(context)

            # Query LLM
            response = self.llm.generate_response(prompt, context={})

            # Parse LLM response into structured suggestions
            suggestions = self._parse_llm_response(response)

            # Determine if auto-executable based on confidence
            max_confidence = max([s['confidence'] for s in suggestions]) if suggestions else 0.0

            return {
                'suggestions': suggestions,
                'source': 'llm',
                'auto_executable': max_confidence >= 0.85 and all(
                    self.SAFE_ACTIONS.get(s['action'], {}).get('auto_executable', False)
                    for s in suggestions
                ),
                'requires_approval': max_confidence < 0.85 or any(
                    not self.SAFE_ACTIONS.get(s['action'], {}).get('auto_executable', True)
                    for s in suggestions
                )
            }

        except Exception as e:
            print(f"[ActionSuggester] LLM query failed: {e}")
            # Fallback to ML-only
            return self._fallback_suggestions(context)

    def _build_llm_prompt(self, context: Dict) -> str:
        """Build prompt for LLM."""
        features = context['raw_features']
        anomaly_score = context.get('anomaly_score', 0)

        return f"""Analyze this system behavior anomaly and suggest appropriate actions.

**Anomaly Details:**
- Anomaly Score: {anomaly_score:.4f} (negative = more anomalous)
- Process spawn rate: {features.get('proc_spawn_rate', 0):.1f}/min
- Short-lived processes: {features.get('proc_short_lived_ratio', 0):.1%}
- Outbound connections: {features.get('net_outbound_conn_rate', 0):.0f}
- Unique dst IPs: {features.get('net_unique_dst_ips', 0):.0f}
- Sensitive file access: {'Yes' if features.get('fs_sensitive_access', 0) > 0 else 'No'}
- Exec from /tmp: {'Yes' if features.get('fs_exec_from_tmp', 0) > 0 else 'No'}

**Available Safe Actions:**
1. ignore - No action (benign behavior)
2. notify - Alert admin only
3. enhanced_monitoring - Capture system state (tcpdump, ps, ss, lsof)
4. snapshot_state - Take full system snapshot
5. log_verbose - Enable verbose logging

**Your Task:**
Suggest 1-3 actions from the list above.
For each action, provide:
- Action name (exactly as listed)
- Confidence (0.0-1.0): How certain are you this is the right action?
- Reason (one sentence): Why this action?

**Response Format:**
action: <action_name>
confidence: <0.0-1.0>
reason: <brief explanation>

---

action: <action_name>
confidence: <0.0-1.0>
reason: <brief explanation>

Respond now:"""

    def _parse_llm_response(self, response: str) -> List[Dict]:
        """Parse LLM response into structured suggestions."""
        suggestions = []

        # Split by action blocks
        blocks = response.strip().split('---')

        for block in blocks:
            lines = block.strip().split('\n')
            suggestion = {}

            for line in lines:
                line = line.strip()
                if line.startswith('action:'):
                    action = line.split(':', 1)[1].strip()
                    if action in self.SAFE_ACTIONS:
                        suggestion['action'] = action
                elif line.startswith('confidence:'):
                    try:
                        conf = float(line.split(':', 1)[1].strip())
                        suggestion['confidence'] = min(max(conf, 0.0), 1.0)
                    except ValueError:
                        suggestion['confidence'] = 0.5
                elif line.startswith('reason:'):
                    suggestion['reason'] = line.split(':', 1)[1].strip()

            # Only add if we have all required fields
            if 'action' in suggestion and 'confidence' in suggestion:
                if 'reason' not in suggestion:
                    suggestion['reason'] = 'No explanation provided'
                suggestions.append(suggestion)

        # If parsing failed, return safe default
        if not suggestions:
            suggestions = [{
                'action': 'notify',
                'confidence': 0.5,
                'reason': 'LLM response unclear - defaulting to notify'
            }]

        return suggestions

    def _fallback_suggestions(self, context: Dict) -> Dict:
        """Fallback suggestions when LLM fails."""
        anomaly_score = context.get('anomaly_score', 0)

        # High anomaly = more aggressive monitoring
        if anomaly_score < -0.3:
            action = 'enhanced_monitoring'
            confidence = 0.7
            reason = 'High anomaly score - ML suggests detailed monitoring'
        else:
            action = 'notify'
            confidence = 0.6
            reason = 'Moderate anomaly - ML suggests admin review'

        return {
            'suggestions': [{
                'action': action,
                'confidence': confidence,
                'reason': reason
            }],
            'source': 'ml_fallback',
            'auto_executable': False,  # Be conservative on fallback
            'requires_approval': True
        }

    def get_action_info(self, action: str) -> Dict:
        """Get information about an action."""
        return self.SAFE_ACTIONS.get(action, {
            'description': 'Unknown action',
            'risk': 'unknown',
            'auto_executable': False
        })
