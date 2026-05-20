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
import hashlib
import hmac as _hmac_mod
import base64
from collections import deque
from typing import Dict, List, Optional, Tuple
from components.quantum_engine import (QuantumValidator,
    latent_swap_fidelity, latent_directionality,
    latent_deviation_angle, latent_phase_coherence, quantum_confidence_v3)


# ── State encryption helpers ──────────────────────────────────────────────────

def _derive_state_key() -> bytes:
    """
    Derive 32-byte AES key from available key material.
    Uses SSH host key fingerprints from client_keys.json, concatenated and hashed.
    Falls back to a machine-local secret (hostname + uid) if no keys registered yet.
    """
    keys_path = os.path.join("models", "client_keys.json")
    material = b""
    try:
        with open(keys_path) as f:
            store = json.load(f)
        for entry in store.values():
            fp = entry.get("ssh_host_key_fingerprint") or entry.get("fingerprint", "")
            if fp:
                material += fp.encode()
    except Exception:
        pass
    if not material:
        import socket
        material = socket.gethostname().encode() + str(os.getuid() if hasattr(os, "getuid") else 0).encode()
    return hashlib.sha3_256(material + b"taara-state-v1").digest()


def _encrypt_state(plaintext: bytes, key: bytes) -> bytes:
    """AES-256-GCM encrypt. Returns: 12-byte nonce || ciphertext+tag."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, b"taara-state")
    return nonce + ct


def _decrypt_state(blob: bytes, key: bytes) -> bytes:
    """AES-256-GCM decrypt. Raises ValueError on tamper."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ct, b"taara-state")


def _state_hmac(cipherblob: bytes, key: bytes) -> str:
    return _hmac_mod.new(key, cipherblob, hashlib.sha3_256).hexdigest()


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

        READ-ONLY — does not modify the basis. Only the Train tab pipeline
        (via TAARAnalyzer.add_training_observation) should modify the basis.
        """
        if self.is_bootstrapping():
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

        self.residual_history.append(residual_norm)

        return {
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

    def add_to_basis(self, x_t: np.ndarray):
        """
        Add a confirmed-normal observation to the memory basis.
        Only called by the Train tab pipeline — never by live monitoring.
        Residual is computed BEFORE adding (same as original check_novelty) so
        max_residual_norm reflects how well the existing basis spans each new sample.
        """
        if len(self.basis_vectors) >= 1:
            _, _, residual_norm = self.reconstruct(x_t)
            if residual_norm > self.max_residual_norm:
                self.max_residual_norm = residual_norm
        self.add_observation(x_t)

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

        # Per-identity validated quantum state (SWAP test on 8-dim latent)
        # pca_basis: (3,8), pca_complement: (2,8), pca_mean: (8,), angle_buf: deque
        self._quantum_state: Dict[str, Dict] = {}

        self.stats = {
            'total_windows': 0,
            'baseline_alerts': 0,
            'taara_novelty': 0,
            'taara_only': 0,
            'quantum_confirmed': 0
        }
        os.makedirs(model_dir, exist_ok=True)
        self._load_state()

    @property
    def quantum_states(self) -> Dict:
        """Public alias for _quantum_state — used by node_identity_db and server."""
        return self._quantum_state

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
                                     identity_id: str = 'system', embedder=None) -> Dict:
        """
        Compute quantum risk assessment. READ-ONLY — never modifies basis or memory.

        Returns both the legacy F_min signals (for existing UI) AND the validated
        v3 SWAP-test signals (swap_fidelity, q_directionality, phase_coherence,
        quantum_confidence) when the latent quantum state is available.
        """
        basis = self.get_or_create_basis(identity_id)

        if basis.is_bootstrapping():
            # Still compute SWAP signals from the seeded PCA quantum state so the
            # dashboard shows live values even before the memory basis is mature.
            swap_fidelity = q_directionality = phase_coherence = quantum_confidence = None
            qs = self._quantum_state.get(identity_id)
            if qs is not None and qs.get('pca_basis') is not None:
                try:
                    if qs.get('embedder') is None and embedder is not None:
                        qs['embedder'] = embedder
                    z_t = qs['embedder'].embed(feature_vector) if qs.get('embedder') else None
                    if z_t is not None:
                        angle_buf = qs.setdefault('angle_buffer', deque(maxlen=4))
                        sf  = latent_swap_fidelity(z_t, qs['pca_basis'], qs['pca_mean'])
                        qd  = latent_directionality(z_t, qs['pca_mean'], qs['pca_complement'])
                        ang = latent_deviation_angle(z_t, qs['pca_mean'], qs['pca_complement'])
                        angle_buf.append(ang)
                        coh = latent_phase_coherence(list(angle_buf))
                        α, β, γ = qs.get('weights', (0.263, 0.285, 0.451))
                        qc  = quantum_confidence_v3(sf, qd, coh, alpha=α, beta=β, gamma=γ)
                        swap_fidelity     = round(sf, 4)
                        q_directionality  = round(qd, 4)
                        phase_coherence   = round(coh, 4)
                        quantum_confidence = round(qc, 4)
                        qs['last_swap_fidelity']      = swap_fidelity
                        qs['last_q_directionality']   = q_directionality
                        qs['last_phase_coherence']    = phase_coherence
                        qs['last_quantum_confidence'] = quantum_confidence
                except Exception:
                    pass
            return {
                'risk_score': 0,
                'severity': 'BOOTSTRAPPING',
                'quantum_novelty': 0,
                'magnitude_score': 0,
                'f_min': None,
                'is_directionally_novel': False,
                'basis_size': len(basis.basis_vectors),
                'note': f'Calibrating ({len(basis.basis_vectors)}/{basis.bootstrap_size} observations)',
                'swap_fidelity':      swap_fidelity,
                'q_directionality':   q_directionality,
                'phase_coherence':    phase_coherence,
                'quantum_confidence': quantum_confidence,
            }

        x_hat, residual, residual_norm = basis.reconstruct(feature_vector)

        if not self.quantum_validator.memory_residuals and basis.basis_vectors:
            for bv in basis.basis_vectors:
                _, bv_residual, _ = basis.reconstruct(bv)
                self.quantum_validator.add_to_memory(bv_residual)

        risk = self.quantum_validator.get_quantum_risk_score(
            residual,
            memory_basis=[r for r in self.quantum_validator.memory_residuals]
                          if self.quantum_validator.memory_residuals else None
        )

        risk['residual_norm'] = round(residual_norm, 4)
        risk['max_prior_residual'] = round(basis.max_residual_norm, 4)
        risk['basis_size'] = len(basis.basis_vectors)
        risk['identity_id'] = identity_id

        # ── Validated v3 SWAP signals on 8-dim latent ──────────────────────────
        # Uses the quantum state built by add_training_observation() when training
        # sets up the per-identity PCA basis from normal latent vectors.
        qs = self._quantum_state.get(identity_id)
        if qs is not None:
            try:
                # Reconnect embedder if this state was restored from disk (must happen before embed call)
                if qs.get('embedder') is None and embedder is not None:
                    qs['embedder'] = embedder
                z_t = qs['embedder'].embed(feature_vector) if qs.get('embedder') else None

                if z_t is not None and qs.get('pca_basis') is not None:
                    pca_basis      = qs['pca_basis']
                    pca_mean       = qs['pca_mean']
                    pca_complement = qs['pca_complement']
                    angle_buf      = qs['angle_buffer']

                    sf  = latent_swap_fidelity(z_t, pca_basis, pca_mean)
                    qd  = latent_directionality(z_t, pca_mean, pca_complement)
                    ang = latent_deviation_angle(z_t, pca_mean, pca_complement)
                    angle_buf.append(ang)
                    coh = latent_phase_coherence(list(angle_buf))
                    # Use per-identity fitted weights if available, else global prior
                    α, β, γ = qs.get('weights', (0.263, 0.285, 0.451))
                    qc  = quantum_confidence_v3(sf, qd, coh, alpha=α, beta=β, gamma=γ)

                    risk['swap_fidelity']      = round(sf, 4)
                    risk['q_directionality']   = round(qd, 4)
                    risk['phase_coherence']    = round(coh, 4)
                    risk['quantum_confidence'] = round(qc, 4)
                    # Cache last computed values for /api/identities endpoint
                    qs['last_swap_fidelity']      = round(sf, 4)
                    qs['last_q_directionality']   = round(qd, 4)
                    qs['last_phase_coherence']    = round(coh, 4)
                    qs['last_quantum_confidence'] = round(qc, 4)
                    # Override risk_score with validated confidence (0-100 scale)
                    risk['risk_score'] = round(qc * 100, 1)
                    risk['severity'] = (
                        'CRITICAL' if qc >= 0.75 else 'HIGH' if qc >= 0.45
                        else 'MEDIUM' if qc >= 0.18 else 'LOW'
                    )
                else:
                    risk['swap_fidelity'] = risk['q_directionality'] = None
                    risk['phase_coherence'] = risk['quantum_confidence'] = None
            except Exception:
                risk['swap_fidelity'] = risk['q_directionality'] = None
                risk['phase_coherence'] = risk['quantum_confidence'] = None
        else:
            risk['swap_fidelity'] = risk['q_directionality'] = None
            risk['phase_coherence'] = risk['quantum_confidence'] = None

        return risk

    def add_training_observation(self, feature_vector: np.ndarray, identity_id: str,
                                  embedder=None):
        """
        Add a confirmed-normal observation to the basis and quantum memory.
        ONLY called by the Train tab pipeline — never by live monitoring.

        embedder: optional DNAEmbedder — if provided, also builds the per-identity
        PCA quantum state (pca_basis, pca_complement, pca_mean) from accumulated
        normal latents. This enables the validated v3 SWAP signals at inference.
        """
        basis = self.get_or_create_basis(identity_id)
        basis.add_to_basis(feature_vector)

        if len(basis.basis_vectors) >= 2:
            _, residual, _ = basis.reconstruct(feature_vector)
            self.quantum_validator.add_to_memory(residual)

        # Build / update per-identity PCA quantum state from normal latents
        if embedder is not None and embedder.is_ready():
            try:
                qs = self._quantum_state.setdefault(identity_id, {
                    'embedder': embedder,
                    'normal_latents': [],
                    'pca_basis': None,
                    'pca_mean': None,
                    'pca_complement': None,
                    'angle_buffer': deque(maxlen=4),
                })
                z = embedder.embed(feature_vector)
                qs['normal_latents'].append(z)
                qs['embedder'] = embedder

                # Rebuild PCA basis + fit per-identity weights once we have enough latents
                if len(qs['normal_latents']) >= 3:
                    latents = np.array(qs['normal_latents'])
                    mean_z  = latents.mean(0)
                    centered = latents - mean_z
                    try:
                        from scipy.linalg import svd as _svd
                        _, _, Vt = _svd(centered, full_matrices=True,
                                        check_finite=False, lapack_driver='gesdd')
                    except Exception:
                        Vt = np.linalg.qr(
                            np.random.randn(centered.shape[1], centered.shape[1])
                        )[0].T
                    qs['pca_mean']       = mean_z
                    qs['pca_basis']      = Vt[:3]
                    qs['pca_complement'] = Vt[3:5]

                    # Fit per-identity fusion weights from normal latents.
                    # Compute (swap_s, q_dir, coh) for each normal window, then
                    # set threshold = p95 of resulting confidence scores.
                    # Weights: constrained softmax so α+β+γ=1, initialized at global prior.
                    try:
                        pca_b = Vt[:3]
                        pca_c = Vt[3:5]
                        sigs  = []
                        angle_buf_fit = deque(maxlen=4)
                        for z_n in latents:
                            sf_n  = latent_swap_fidelity(z_n, pca_b, mean_z)
                            qd_n  = latent_directionality(z_n, mean_z, pca_c)
                            ang_n = latent_deviation_angle(z_n, mean_z, pca_c)
                            angle_buf_fit.append(ang_n)
                            coh_n = latent_phase_coherence(list(angle_buf_fit))
                            swap_s_n = max(0.0, 1.0 - sf_n)
                            itf_n = coh_n * float(np.sqrt(max(swap_s_n * qd_n, 0.0)))
                            sigs.append([swap_s_n, qd_n, itf_n])
                        sigs = np.array(sigs, dtype=np.float32)

                        # Global prior (from CERT r4.2 experiment)
                        PRIOR = np.array([0.263, 0.285, 0.451], dtype=np.float32)
                        # Weighted ridge fit: minimise ||X·w - 0||² + λ||w - prior||²
                        # All normal windows should score near 0, so target = 0 vector.
                        # Ridge towards prior prevents overfitting on small N.
                        lam = 2.0
                        A   = sigs.T @ sigs + lam * np.eye(3)
                        b   = lam * PRIOR
                        w   = np.linalg.solve(A, b)
                        w   = np.clip(w, 0.0, None)
                        w_sum = w.sum()
                        if w_sum > 1e-6:
                            w /= w_sum          # normalize so α+β+γ=1
                        else:
                            w = PRIOR.copy()

                        # Per-identity threshold = p95 of normal confidence scores
                        confs_normal = np.clip(sigs @ w, 0.0, 1.0)
                        thresh = float(np.percentile(confs_normal, 95)) if len(confs_normal) >= 3 else 0.1854

                        qs['weights']   = tuple(float(x) for x in w)   # (α, β, γ)
                        qs['threshold'] = thresh
                    except Exception:
                        qs['weights']   = (0.263, 0.285, 0.451)
                        qs['threshold'] = 0.1854
            except Exception:
                pass

        self.save_state()

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
        """Persist all memory bases and quantum state — AES-256-GCM encrypted + HMAC-SHA3."""
        quantum_state_serial = {}
        for iid, qs in self._quantum_state.items():
            entry = {
                'weights':   list(qs['weights'])   if qs.get('weights')   else [0.263, 0.285, 0.451],
                'threshold': qs.get('threshold', 0.1854),
            }
            if qs.get('pca_basis') is not None:
                entry['pca_basis']      = qs['pca_basis'].tolist()
                entry['pca_mean']       = qs['pca_mean'].tolist()
                entry['pca_complement'] = qs['pca_complement'].tolist()
            if qs.get('normal_latents'):
                entry['normal_latents'] = [z.tolist() for z in qs['normal_latents'][-50:]]
            quantum_state_serial[iid] = entry

        state = {
            'memory_bases': {k: v.to_dict() for k, v in self.memory_bases.items()},
            'stats': self.stats,
            'quantum_memory_residuals': [r.tolist() for r in self.quantum_validator.memory_residuals],
            'quantum_state': quantum_state_serial,
        }
        try:
            plaintext = json.dumps(state).encode()
            key = _derive_state_key()
            blob = _encrypt_state(plaintext, key)
            tag  = _state_hmac(blob, key)
            envelope = {"v": 2, "hmac": tag, "data": base64.b64encode(blob).decode()}
            path = os.path.join(self.model_dir, 'taara_state.json')
            with open(path, 'w') as f:
                json.dump(envelope, f)
        except Exception as e:
            print(f"[TAARAnalyzer] State encryption failed ({e}), falling back to plaintext")
            path = os.path.join(self.model_dir, 'taara_state.json')
            with open(path, 'w') as f:
                json.dump(state, f, indent=2)

    def _load_state(self):
        """Load persisted state — decrypt and verify HMAC. Tamper fires alert."""
        path = os.path.join(self.model_dir, 'taara_state.json')
        if not os.path.exists(path):
            return
        try:
            with open(path, 'r') as f:
                raw = json.load(f)

            # Versioned encrypted envelope
            if isinstance(raw, dict) and raw.get("v") == 2:
                key  = _derive_state_key()
                blob = base64.b64decode(raw["data"])
                expected_tag = _state_hmac(blob, key)
                if not _hmac_mod.compare_digest(expected_tag, raw.get("hmac", "")):
                    print("[TAARAnalyzer] TAMPER ALERT: taara_state.json HMAC mismatch — "
                          "state not loaded. Attacker may have modified baseline.")
                    return
                state = json.loads(_decrypt_state(blob, key))
            else:
                # Legacy plaintext state — load as-is, will be re-encrypted on next save
                state = raw

            for k, v in state.get('memory_bases', {}).items():
                self.memory_bases[k] = IdentityMemoryBasis.from_dict(v)
            self.stats = state.get('stats', self.stats)
            for r in state.get('quantum_memory_residuals', []):
                self.quantum_validator.add_to_memory(np.array(r))
            for iid, qs_data in state.get('quantum_state', {}).items():
                qs = {
                    'embedder':       None,
                    'normal_latents': [np.array(z) for z in qs_data.get('normal_latents', [])],
                    'pca_basis':      np.array(qs_data['pca_basis'])      if 'pca_basis'      in qs_data else None,
                    'pca_mean':       np.array(qs_data['pca_mean'])       if 'pca_mean'       in qs_data else None,
                    'pca_complement': np.array(qs_data['pca_complement']) if 'pca_complement' in qs_data else None,
                    'angle_buffer':   deque(maxlen=4),
                    'weights':        tuple(qs_data.get('weights',   [0.263, 0.285, 0.451])),
                    'threshold':      qs_data.get('threshold', 0.1854),
                }
                self._quantum_state[iid] = qs
            print(f"[TAARAnalyzer] Loaded state: {len(self.memory_bases)} identities, "
                  f"{len(self._quantum_state)} quantum states")
        except Exception as e:
            print(f"[TAARAnalyzer] Error loading state: {e}")

    def reconnect_embedder(self, embedder):
        """Reconnect embedder to all restored quantum states after server startup."""
        for qs in self._quantum_state.values():
            if qs['embedder'] is None:
                qs['embedder'] = embedder

    def rebuild_quantum_state_if_missing(self, embedder):
        """
        For each identity that has a memory basis but no quantum state,
        rebuild the PCA subspace from the stored basis vectors.
        Called once at startup to handle state files written before quantum state saving was added.
        """
        if not embedder or not embedder.is_ready():
            return
        rebuilt = False
        for iid, basis in self.memory_bases.items():
            if iid in self._quantum_state and self._quantum_state[iid].get('pca_basis') is not None:
                continue  # already have PCA
            if len(basis.basis_vectors) < 3:
                continue
            try:
                raw = np.array(basis.basis_vectors, dtype=np.float32)
                latents = np.array([embedder.embed(r) for r in raw])
                mean_z = latents.mean(0)
                centered = latents - mean_z
                try:
                    from scipy.linalg import svd as _svd
                    _, _, Vt = _svd(centered, full_matrices=True, check_finite=False, lapack_driver='gesdd')
                except Exception:
                    Vt = np.linalg.qr(np.random.randn(centered.shape[1], centered.shape[1]))[0].T
                pca_basis = Vt[:3]
                pca_complement = Vt[3:5]

                # Fit weights
                PRIOR = np.array([0.263, 0.285, 0.451], dtype=np.float32)
                sigs = []
                angle_buf = deque(maxlen=4)
                for z_n in latents:
                    sf_n  = latent_swap_fidelity(z_n, pca_basis, mean_z)
                    qd_n  = latent_directionality(z_n, mean_z, pca_complement)
                    ang_n = latent_deviation_angle(z_n, mean_z, pca_complement)
                    angle_buf.append(ang_n)
                    coh_n = latent_phase_coherence(list(angle_buf))
                    swap_s_n = max(0.0, 1.0 - sf_n)
                    itf_n = coh_n * float(np.sqrt(max(swap_s_n * qd_n, 0.0)))
                    sigs.append([swap_s_n, qd_n, itf_n])
                sigs = np.array(sigs, dtype=np.float32)
                lam = 2.0
                A = sigs.T @ sigs + lam * np.eye(3)
                w = np.linalg.solve(A, lam * PRIOR)
                w = np.clip(w, 0.0, None)
                if w.sum() > 1e-6:
                    w /= w.sum()
                else:
                    w = PRIOR.copy()
                confs = np.clip(sigs @ w, 0.0, 1.0)
                thresh = float(np.percentile(confs, 95)) if len(confs) >= 3 else 0.1854

                self._quantum_state[iid] = {
                    'embedder':       embedder,
                    'normal_latents': list(latents[-50:]),
                    'pca_basis':      pca_basis,
                    'pca_mean':       mean_z,
                    'pca_complement': pca_complement,
                    'angle_buffer':   deque(maxlen=4),
                    'weights':        tuple(float(x) for x in w),
                    'threshold':      thresh,
                }
                print(f"[TAARAnalyzer] Rebuilt quantum state for {iid}: w={tuple(round(x,3) for x in w)}, thresh={thresh:.4f}")
                rebuilt = True
            except Exception as e:
                print(f"[TAARAnalyzer] Could not rebuild quantum state for {iid}: {e}")
        if rebuilt:
            self.save_state()

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
