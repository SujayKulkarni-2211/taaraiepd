"""
TAARA Core: Trajectory-Aware Adaptive Residual Analysis
========================================================

Implements the reconstruction-based novelty detection system from the TAARA paper.

Key concepts:
1. Per-identity memory basis construction (Section 3.3.1)
2. Least-squares reconstruction (Section 3.3.2)
3. Threshold-free novelty criterion (Section 3.3.3)
4. Integration with quantum validation layer (Section 3.4)

This is NOT deviation detection - it is novelty detection through representational failure.
TAARA asks: "Can this behavior be represented by prior observations?" not "Is this unusual?"
"""

import numpy as np
import json
import os
import time
from typing import Dict, List, Optional, Tuple
from components.quantum_engine import QuantumValidator


class IdentityMemoryBasis:
    """
    Per-identity memory basis (paper Section 3.3.1).

    Maintains M_u = {m_1, m_2, ..., m_k} of previously observed behavioral states.
    Bootstrap phase: first 3 observations initialize the basis without detection.
    Memory updates: non-novel states are added to accommodate behavioral evolution.
    """

    def __init__(self, identity_id: str, bootstrap_size: int = 3):
        self.identity_id = identity_id
        self.bootstrap_size = bootstrap_size
        self.basis_vectors: List[np.ndarray] = []
        self.max_residual_norm: float = 0.0
        self.observation_count: int = 0
        self.residual_history: List[float] = []
        self.timestamps: List[float] = []

    def add_observation(self, state: np.ndarray):
        """Add a non-novel observation to the memory basis."""
        self.basis_vectors.append(state.copy())
        self.observation_count += 1
        self.timestamps.append(time.time())

    def is_bootstrapping(self) -> bool:
        """Check if still in bootstrap phase."""
        return len(self.basis_vectors) < self.bootstrap_size

    def get_basis_matrix(self) -> Optional[np.ndarray]:
        """Get memory basis as matrix M (columns = basis vectors)."""
        if not self.basis_vectors:
            return None
        return np.column_stack(self.basis_vectors)

    def reconstruct(self, x_t: np.ndarray) -> Tuple[np.ndarray, np.ndarray, float]:
        """
        Reconstruct x_t using memory basis via least-squares projection.

        From paper Eq. 3-5:
        x_hat = M(M^T M)^{-1} M^T x_t
        Δ_t = x_t - x_hat
        """
        M = self.get_basis_matrix()
        if M is None:
            return x_t, x_t, float(np.linalg.norm(x_t))

        try:
            MtM = M.T @ M
            reg = 1e-8 * np.eye(MtM.shape[0])
            MtM_inv = np.linalg.inv(MtM + reg)
            x_hat = M @ MtM_inv @ M.T @ x_t
        except np.linalg.LinAlgError:
            alpha, _, _, _ = np.linalg.lstsq(M, x_t, rcond=None)
            x_hat = M @ alpha

        residual = x_t - x_hat
        residual_norm = float(np.linalg.norm(residual))

        return x_hat, residual, residual_norm

    def check_novelty(self, x_t: np.ndarray) -> Dict:
        """
        Check if x_t is novel using threshold-free criterion.

        From paper Eq. 6:
        ||Δ_t|| > max_{i<t} ||Δ_i||

        This is threshold-free: novelty is defined purely relative to
        the identity's own history.
        """
        if self.is_bootstrapping():
            self.add_observation(x_t)
            return {
                'is_novel': False,
                'status': 'bootstrap',
                'residual_norm': 0.0,
                'max_prior_residual': 0.0,
                'observation_count': self.observation_count,
                'basis_size': len(self.basis_vectors)
            }

        x_hat, residual, residual_norm = self.reconstruct(x_t)

        is_novel = residual_norm > self.max_residual_norm if self.max_residual_norm > 0 else False

        result = {
            'is_novel': is_novel,
            'status': 'novel' if is_novel else 'known',
            'residual_norm': residual_norm,
            'max_prior_residual': self.max_residual_norm,
            'residual_vector': residual,
            'reconstruction': x_hat,
            'observation_count': self.observation_count,
            'basis_size': len(self.basis_vectors),
            'novelty_margin': residual_norm - self.max_residual_norm if self.max_residual_norm > 0 else residual_norm
        }

        self.residual_history.append(residual_norm)

        if not is_novel:
            self.add_observation(x_t)
            if residual_norm > self.max_residual_norm:
                self.max_residual_norm = residual_norm

        return result

    def to_dict(self) -> Dict:
        """Serialize for persistence."""
        return {
            'identity_id': self.identity_id,
            'bootstrap_size': self.bootstrap_size,
            'basis_vectors': [v.tolist() for v in self.basis_vectors],
            'max_residual_norm': self.max_residual_norm,
            'observation_count': self.observation_count,
            'residual_history': self.residual_history,
            'timestamps': self.timestamps
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'IdentityMemoryBasis':
        """Deserialize from persistence."""
        obj = cls(data['identity_id'], data.get('bootstrap_size', 3))
        obj.basis_vectors = [np.array(v) for v in data.get('basis_vectors', [])]
        obj.max_residual_norm = data.get('max_residual_norm', 0.0)
        obj.observation_count = data.get('observation_count', 0)
        obj.residual_history = data.get('residual_history', [])
        obj.timestamps = data.get('timestamps', [])
        return obj


class TAARAnalyzer:
    """
    Main TAARA analysis engine.

    Combines:
    - Per-identity memory basis construction
    - Reconstruction-based novelty detection
    - Quantum fidelity validation
    - Ensemble baseline detection (Isolation Forest + Autoencoder)
    """

    def __init__(self, model_dir: str = 'models'):
        self.model_dir = model_dir
        self.memory_bases: Dict[str, IdentityMemoryBasis] = {}
        self.quantum_validator = QuantumValidator()
        self.detection_log: List[Dict] = []
        self.stats = {
            'total_windows': 0,
            'baseline_alerts': 0,
            'taara_novelty': 0,
            'taara_only': 0,
            'quantum_confirmed': 0
        }
        os.makedirs(model_dir, exist_ok=True)
        self._load_state()

    def get_or_create_basis(self, identity_id: str) -> IdentityMemoryBasis:
        """Get or create a memory basis for an identity."""
        if identity_id not in self.memory_bases:
            self.memory_bases[identity_id] = IdentityMemoryBasis(identity_id)
        return self.memory_bases[identity_id]

    def analyze(self, identity_id: str, feature_vector: np.ndarray,
                baseline_alert: bool = False) -> Dict:
        """
        Full TAARA analysis pipeline.

        Steps:
        1. Get/create per-identity memory basis
        2. Check novelty via reconstruction failure
        3. If novel, run quantum validation
        4. Track detection funnel statistics
        """
        self.stats['total_windows'] += 1

        basis = self.get_or_create_basis(identity_id)

        novelty_result = basis.check_novelty(feature_vector)

        if baseline_alert:
            self.stats['baseline_alerts'] += 1

        quantum_result = None
        is_taara_novel = novelty_result['is_novel']

        if is_taara_novel:
            self.stats['taara_novelty'] += 1

            if not baseline_alert:
                self.stats['taara_only'] += 1

            residual = novelty_result.get('residual_vector')
            if residual is not None:
                quantum_result = self.quantum_validator.validate_novelty(
                    residual, is_classically_novel=True
                )

                if quantum_result.get('quantum_novel', False):
                    self.stats['quantum_confirmed'] += 1

                    self.quantum_validator.add_to_memory(residual)

        result = {
            'identity_id': identity_id,
            'timestamp': time.time(),
            'novelty': novelty_result,
            'baseline_alert': baseline_alert,
            'quantum_validation': quantum_result,
            'is_taara_novel': is_taara_novel,
            'is_quantum_confirmed': (
                quantum_result.get('quantum_novel', False)
                if quantum_result else False
            ),
            'is_taara_only': is_taara_novel and not baseline_alert,
            'stats': self.stats.copy()
        }

        self.detection_log.append({
            'identity_id': identity_id,
            'timestamp': result['timestamp'],
            'is_novel': is_taara_novel,
            'is_quantum_confirmed': result['is_quantum_confirmed'],
            'residual_norm': novelty_result.get('residual_norm', 0),
            'f_min': quantum_result.get('f_min', None) if quantum_result else None
        })

        if len(self.detection_log) > 10000:
            self.detection_log = self.detection_log[-5000:]

        return result

    def get_quantum_risk_assessment(self, feature_vector: np.ndarray,
                                     identity_id: str = 'system') -> Dict:
        """
        Compute comprehensive quantum risk assessment for a feature vector.
        Used by TaaraAnalysis for OHA scanning.
        """
        basis = self.get_or_create_basis(identity_id)

        if basis.is_bootstrapping():
            basis.add_observation(feature_vector)
            return {
                'risk_score': 0,
                'severity': 'BOOTSTRAPPING',
                'quantum_novelty': 0,
                'magnitude_score': 0,
                'f_min': 1.0,
                'is_directionally_novel': False,
                'note': f'Collecting baseline ({len(basis.basis_vectors)}/{basis.bootstrap_size})'
            }

        x_hat, residual, residual_norm = basis.reconstruct(feature_vector)

        risk = self.quantum_validator.get_quantum_risk_score(
            residual,
            memory_basis=[r for r in self.quantum_validator.memory_residuals] if self.quantum_validator.memory_residuals else None
        )

        risk['residual_norm'] = round(residual_norm, 4)
        risk['max_prior_residual'] = round(basis.max_residual_norm, 4)
        risk['basis_size'] = len(basis.basis_vectors)
        risk['identity_id'] = identity_id

        return risk

    def get_detection_summary(self) -> Dict:
        """Get summary statistics matching the paper's detection funnel."""
        total = max(self.stats['total_windows'], 1)
        return {
            'total_windows': self.stats['total_windows'],
            'baseline_alerts': self.stats['baseline_alerts'],
            'baseline_alert_rate': round(self.stats['baseline_alerts'] / total * 100, 1),
            'taara_novelty': self.stats['taara_novelty'],
            'taara_novelty_rate': round(self.stats['taara_novelty'] / total * 100, 1),
            'taara_only': self.stats['taara_only'],
            'taara_only_rate': round(self.stats['taara_only'] / total * 100, 1),
            'quantum_confirmed': self.stats['quantum_confirmed'],
            'quantum_confirmation_rate': (
                round(self.stats['quantum_confirmed'] / max(self.stats['taara_only'], 1) * 100, 1)
            ),
            'identities_tracked': len(self.memory_bases),
            'mean_basis_size': round(
                np.mean([len(b.basis_vectors) for b in self.memory_bases.values()])
                if self.memory_bases else 0, 1
            )
        }

    def save_state(self):
        """Persist all memory bases and state."""
        state = {
            'memory_bases': {
                k: v.to_dict() for k, v in self.memory_bases.items()
            },
            'stats': self.stats,
            'quantum_memory_residuals': [
                r.tolist() for r in self.quantum_validator.memory_residuals
            ]
        }
        path = os.path.join(self.model_dir, 'taara_state.json')
        with open(path, 'w') as f:
            json.dump(state, f, indent=2)

    def _load_state(self):
        """Load persisted state."""
        path = os.path.join(self.model_dir, 'taara_state.json')
        if not os.path.exists(path):
            return
        try:
            with open(path, 'r') as f:
                state = json.load(f)
            for k, v in state.get('memory_bases', {}).items():
                self.memory_bases[k] = IdentityMemoryBasis.from_dict(v)
            self.stats = state.get('stats', self.stats)
            for r in state.get('quantum_memory_residuals', []):
                self.quantum_validator.add_to_memory(np.array(r))
        except Exception as e:
            print(f"[TAARAnalyzer] Error loading state: {e}")

    def reset(self):
        """Reset all state for fresh analysis."""
        self.memory_bases = {}
        self.quantum_validator.clear_memory()
        self.detection_log = []
        self.stats = {
            'total_windows': 0,
            'baseline_alerts': 0,
            'taara_novelty': 0,
            'taara_only': 0,
            'quantum_confirmed': 0
        }
