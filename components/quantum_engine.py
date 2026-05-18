"""
Quantum Validation Engine (PennyLane)
=====================================

Implements the quantum validation layer from the TAARA paper (Section 3.4).

Architecture — dual-encoding pipeline:
    1. Amplitude encoding: encodes residual magnitude + direction as quantum amplitudes
       → captures the "how far" dimension of behavioral drift
    2. Angle encoding: encodes each feature as a rotation angle (Rx gate)
       → entanglement layer after angle encoding creates interference between correlated
          features, detecting non-linear relationships amplitude encoding treats independently
    3. Fidelity computed from angle-encoded circuit (richer signal)
       Amplitude circuit available for magnitude-only baseline
    4. Quantum-confirmed novelty: F_min(t) < 0.5 (geometric midpoint of Hilbert space)

Why angle encoding adds value over amplitude alone:
    Amplitude encoding maps features to a superposition state — features interact only
    through global normalization. Angle encoding maps feature_i → Rx(θ_i) on qubit_i,
    then the ring-CNOT entanglement creates CX interference between adjacent features.
    If features A and B both rotate when an attack is in progress (correlated change),
    the entangled state diverges more strongly from baseline than either rotation alone.
    Amplitude encoding cannot see this correlation; angle encoding can.

Uses PennyLane default.qubit simulator (no real quantum hardware).
Keeps circuits to 4 qubits for laptop GPU compatibility.
"""

import numpy as np
import pennylane as qml
from typing import List, Dict, Tuple, Optional
import math
import hashlib


N_QUBITS = 4
STATE_DIM = 2 ** N_QUBITS  # 16 dimensions

dev = qml.device("default.qubit", wires=N_QUBITS)
dev_angle = qml.device("default.qubit", wires=N_QUBITS)


def _prepare_amplitude_vector(vector: np.ndarray) -> np.ndarray:
    """
    Prepare a vector for amplitude encoding into 4-qubit state.

    From paper Section 3.4.1:
    - Extract normalized direction: Δ_hat = Δ / ||Δ||
    - Zero-pad to 16 dimensions
    - Normalize to unit L2 norm
    """
    v = np.array(vector, dtype=np.float64).flatten()

    if np.linalg.norm(v) < 1e-12:
        result = np.zeros(STATE_DIM, dtype=np.float64)
        result[0] = 1.0
        return result

    v = v / np.linalg.norm(v)

    if len(v) < STATE_DIM:
        padded = np.zeros(STATE_DIM, dtype=np.float64)
        padded[:len(v)] = v
        v = padded
    elif len(v) > STATE_DIM:
        v = v[:STATE_DIM]

    norm = np.linalg.norm(v)
    if norm < 1e-12:
        v = np.zeros(STATE_DIM, dtype=np.float64)
        v[0] = 1.0
    else:
        v = v / norm

    return v


def _prepare_angle_vector(vector: np.ndarray) -> np.ndarray:
    """
    Prepare a vector for angle encoding into N_QUBITS rotation angles.

    Each feature is mapped to [0, π] via arctan normalization so that:
    - Zero → π/2 (|+⟩ state, maximally uncertain)
    - Large positive → π (|1⟩ direction)
    - Large negative → 0 (|0⟩ direction)
    This means deviations from normal (= 0) push qubits toward poles,
    and the entanglement layer then captures correlated pole-pushes.
    """
    v = np.array(vector, dtype=np.float64).flatten()

    # Take first N_QUBITS features (or pad with zeros)
    if len(v) < N_QUBITS:
        padded = np.zeros(N_QUBITS, dtype=np.float64)
        padded[:len(v)] = v
        v = padded
    else:
        # Downsample by averaging groups — preserves global deviation signal
        chunk = len(v) // N_QUBITS
        v = np.array([np.mean(v[i*chunk:(i+1)*chunk]) for i in range(N_QUBITS)])

    # Map ℝ → [0, π] via scaled arctan
    angles = np.pi / 2 + np.arctan(v)  # arctan ∈ (-π/2, π/2) → result ∈ (0, π)
    return angles.astype(np.float64)


@qml.qnode(dev)
def _quantum_circuit(features: np.ndarray):
    """
    TAARA amplitude-encoding validation circuit (paper Section 3.4.2).

    Circuit design:
    1. Amplitude embedding - encodes residual direction into quantum state
    2. Hadamard gates - create superposition on all qubits
    3. Ring entanglement - CNOT gates in ring topology (0→1, 1→2, 2→3, 3→0)
    4. Parameterized rotations - RX, RY, RZ on each qubit (angles fixed at π/4)
    5. Return full statevector for fidelity computation

    Circuit depth: 5 gate layers
    """
    qml.AmplitudeEmbedding(features=features, wires=range(N_QUBITS), normalize=True)

    for i in range(N_QUBITS):
        qml.Hadamard(wires=i)

    for i in range(N_QUBITS):
        qml.CNOT(wires=[i, (i + 1) % N_QUBITS])

    angle = np.pi / 4
    for i in range(N_QUBITS):
        qml.RX(angle, wires=i)
        qml.RY(angle, wires=i)
        qml.RZ(angle, wires=i)

    return qml.state()


@qml.qnode(dev_angle)
def _angle_encoding_circuit(angles: np.ndarray):
    """
    TAARA angle-encoding circuit for relational feature detection.

    Circuit design:
    1. AngleEmbedding(rotation='X') — Rx(θ_i) on each qubit_i
       Each feature's deviation from zero becomes a rotation angle.
       Normal behavior (all zeros) → all qubits at π/2 → uniform superposition.
    2. Ring CNOT entanglement — creates CX correlations between adjacent qubits.
       Correlated feature changes (f_i and f_{i+1} both deviating) produce
       constructive/destructive interference not present without entanglement.
    3. Second AngleEmbedding layer (rotation='Y') — encodes the same features
       again as Y-rotations, giving the circuit depth to detect 2nd-order correlations.
    4. Ring CNOT again — captures correlations after Y-rotation layer.
    5. Return statevector.

    Why this catches what amplitude encoding misses:
    If proc_count and cpu_entropy both spike (correlated attack signal), the Rx-CNOT
    layer produces a specific interference pattern distinct from either spiking alone.
    Amplitude encoding would see a slightly larger ||Δ|| but miss the correlation geometry.
    Angle encoding + entanglement sees the specific joint rotation — a fingerprint of
    correlated multi-feature behavioral change.

    Circuit depth: 4 gate layers | Qubits: 4 | Encodes: N_QUBITS features
    """
    # Layer 1: Angle encode as X-rotations
    qml.AngleEmbedding(features=angles, wires=range(N_QUBITS), rotation='X')

    # Entanglement: ring CNOT captures pairwise correlations after X-layer
    for i in range(N_QUBITS):
        qml.CNOT(wires=[i, (i + 1) % N_QUBITS])

    # Layer 2: Angle encode again as Y-rotations (cross-basis, 2nd-order signal)
    qml.AngleEmbedding(features=angles, wires=range(N_QUBITS), rotation='Y')

    # Second entanglement: ring CNOT in reverse direction for full correlation coverage
    for i in range(N_QUBITS - 1, -1, -1):
        qml.CNOT(wires=[i, (i + 1) % N_QUBITS])

    return qml.state()


@qml.qnode(dev)
def _quantum_circuit_bare(features: np.ndarray):
    """Bare amplitude encoding without processing - for pure fidelity computation."""
    qml.AmplitudeEmbedding(features=features, wires=range(N_QUBITS), normalize=True)
    return qml.state()


class QuantumValidator:
    """
    Quantum validation layer for TAARA novelty detection.

    Implements Section 3.4 of the paper with dual-encoding:
    - Amplitude encoding: captures magnitude + direction of residual
    - Angle encoding: captures correlational relationships between features
    - F_min computed from angle-encoded states (richer signal)
    - Both are available for comparison and reporting
    """

    def __init__(self):
        self.memory_states: List[np.ndarray] = []          # amplitude-encoded
        self.memory_angle_states: List[np.ndarray] = []    # angle-encoded
        self.memory_residuals: List[np.ndarray] = []
        self.encoding_mode: str = "angle"  # "angle" | "amplitude" | "both"

    def encode_residual(self, residual: np.ndarray) -> np.ndarray:
        """
        Encode a residual vector into a quantum state (amplitude encoding).

        From paper Eq. 7-8:
        Δ_hat = Δ / ||Δ||
        |ψ_t⟩ = Σ Δ_hat[i] |i⟩
        """
        amplitude_vec = _prepare_amplitude_vector(residual)
        state = _quantum_circuit(amplitude_vec)
        return np.array(state, dtype=np.complex128)

    def encode_residual_angle(self, residual: np.ndarray) -> np.ndarray:
        """
        Encode a residual vector using angle encoding for relational detection.

        Maps each feature to a rotation angle — entanglement then captures
        which features are changing together vs. independently.
        """
        angles = _prepare_angle_vector(residual)
        state = _angle_encoding_circuit(angles)
        return np.array(state, dtype=np.complex128)

    def encode_residual_bare(self, residual: np.ndarray) -> np.ndarray:
        """Encode without circuit processing - pure amplitude state."""
        amplitude_vec = _prepare_amplitude_vector(residual)
        state = _quantum_circuit_bare(amplitude_vec)
        return np.array(state, dtype=np.complex128)

    def compute_fidelity(self, state1: np.ndarray, state2: np.ndarray) -> float:
        """
        Compute quantum fidelity between two states.

        From paper Eq. 9:
        F(|ψ_t⟩, |ψ_m⟩) = |⟨ψ_t|ψ_m⟩|²
        """
        inner_product = np.vdot(state1, state2)
        fidelity = float(np.abs(inner_product) ** 2)
        return min(max(fidelity, 0.0), 1.0)

    def compute_minimum_fidelity(self, current_residual: np.ndarray) -> Dict:
        """
        Compute minimum fidelity against all memory states using angle encoding.

        F_min(t) = min_{m ∈ M_u} F(|ψ_t⟩, |ψ_m⟩)

        Angle encoding used as primary: captures correlated multi-feature changes
        that amplitude encoding treats independently. Amplitude F_min included as
        a secondary signal for comparison and reporting.

        Quantum-confirmed novelty: F_min < 0.5 (geometric midpoint, parameter-free)
        """
        # First observation — no memory to compare against
        if not self.memory_angle_states and not self.memory_states:
            return {
                'f_min': 0.0,
                'is_quantum_novel': True,
                'fidelities': [],
                'fidelities_amplitude': [],
                'note': 'No memory states - first observation',
                'encoding': 'angle+amplitude',
            }

        # Angle-encoded fidelities (primary signal)
        angle_fidelities = []
        if self.memory_angle_states:
            current_angle_state = self.encode_residual_angle(current_residual)
            for mem_state in self.memory_angle_states:
                f = self.compute_fidelity(current_angle_state, mem_state)
                angle_fidelities.append(f)

        # Amplitude-encoded fidelities (secondary / baseline)
        amp_fidelities = []
        if self.memory_states:
            current_amp_state = self.encode_residual(current_residual)
            for mem_state in self.memory_states:
                f = self.compute_fidelity(current_amp_state, mem_state)
                amp_fidelities.append(f)

        # Primary F_min comes from angle encoding (if available)
        if angle_fidelities:
            f_min = min(angle_fidelities)
            primary_fidelities = angle_fidelities
        else:
            f_min = min(amp_fidelities)
            primary_fidelities = amp_fidelities

        f_min_amp = min(amp_fidelities) if amp_fidelities else None

        return {
            'f_min': f_min,
            'is_quantum_novel': f_min < 0.5,
            'fidelities': primary_fidelities,
            'fidelities_amplitude': amp_fidelities,
            'mean_fidelity': float(np.mean(primary_fidelities)),
            'max_fidelity': float(max(primary_fidelities)),
            'quantum_confidence': 1.0 - f_min,
            'f_min_amplitude': round(f_min_amp, 4) if f_min_amp is not None else None,
            'encoding': 'angle+amplitude',
            # If angle F_min < amplitude F_min, angle encoding caught a correlation
            # that amplitude encoding's global normalization masked
            'correlation_signal_detected': (
                f_min_amp is not None and f_min < f_min_amp - 0.05
            ),
        }

    def compute_minimum_fidelity_keyed(self, current_residual: np.ndarray,
                                        shared_secret_hex: str, hostname: str) -> Dict:
        """
        PQC-keyed fidelity computation. Applies per-client Kyber768 transform before encoding.
        Attacker cannot compute client's normal without the Kyber private key.
        """
        keyed_residual = apply_client_transform(current_residual, shared_secret_hex, hostname)
        result = self.compute_minimum_fidelity(keyed_residual)
        result['keyed'] = True
        return result

    def add_to_memory(self, residual: np.ndarray):
        """Add a residual direction to both amplitude and angle quantum memory."""
        # Amplitude memory (magnitude baseline)
        amp_state = self.encode_residual(residual)
        self.memory_states.append(amp_state)

        # Angle memory (relational baseline)
        angle_state = self.encode_residual_angle(residual)
        self.memory_angle_states.append(angle_state)

        self.memory_residuals.append(residual.copy())

    def clear_memory(self):
        """Clear all quantum memory."""
        self.memory_states = []
        self.memory_angle_states = []
        self.memory_residuals = []

    def validate_novelty(self, residual: np.ndarray,
                         is_classically_novel: bool) -> Dict:
        """
        Full quantum validation pipeline.

        Called only when classical detection flags novelty.
        Returns quantum-confirmed or quantum-rejected status.
        """
        if not is_classically_novel:
            return {
                'status': 'not_novel',
                'classical_novel': False,
                'quantum_novel': False,
                'f_min': 1.0,
                'quantum_confidence': 0.0
            }

        result = self.compute_minimum_fidelity(residual)

        status = 'quantum_confirmed' if result['is_quantum_novel'] else 'magnitude_only'

        return {
            'status': status,
            'classical_novel': True,
            'quantum_novel': result['is_quantum_novel'],
            'f_min': result['f_min'],
            'quantum_confidence': result['quantum_confidence'],
            'fidelities': result['fidelities'],
            'interpretation': (
                'Genuine directional behavioral shift detected - '
                'new behavioral dimension orthogonal to prior observations'
                if result['is_quantum_novel'] else
                'Magnitude variation only - same behavioral direction, different scale'
            )
        }

    def get_quantum_risk_score(self, features: np.ndarray,
                                memory_basis: Optional[List[np.ndarray]] = None) -> Dict:
        """
        Compute quantum-enhanced risk score (0-100).

        Combines:
        - Angle-encoded fidelity (primary — detects correlated feature changes)
        - Amplitude-encoded fidelity (secondary — detects magnitude/direction)
        - Residual magnitude
        """
        if memory_basis and len(memory_basis) > 0:
            old_amp = self.memory_states
            old_angle = self.memory_angle_states
            self.memory_states = [self.encode_residual(m) for m in memory_basis]
            self.memory_angle_states = [self.encode_residual_angle(m) for m in memory_basis]
            result = self.compute_minimum_fidelity(features)
            self.memory_states = old_amp
            self.memory_angle_states = old_angle
        else:
            result = self.compute_minimum_fidelity(features)

        f_min = result['f_min']
        quantum_novelty = 1.0 - f_min

        residual_magnitude = float(np.linalg.norm(features))
        magnitude_score = min(residual_magnitude / 2.0, 1.0)

        # Correlation bonus: if angle encoding caught something amplitude missed,
        # bump risk score slightly — this is a multi-feature correlated attack pattern
        correlation_bonus = 0.05 if result.get('correlation_signal_detected') else 0.0

        risk_score = (0.6 * quantum_novelty + 0.4 * magnitude_score + correlation_bonus) * 100
        risk_score = min(max(risk_score, 0), 100)

        if risk_score >= 75:
            severity = 'CRITICAL'
        elif risk_score >= 50:
            severity = 'HIGH'
        elif risk_score >= 25:
            severity = 'MEDIUM'
        else:
            severity = 'LOW'

        correlation_note = ""
        if result.get('correlation_signal_detected'):
            correlation_note = (
                "Angle encoding detected correlated multi-feature deviation — "
                "this pattern is only visible to the relational quantum circuit."
            )

        return {
            'risk_score': round(risk_score, 1),
            'severity': severity,
            'quantum_novelty': round(quantum_novelty * 100, 1),
            'magnitude_score': round(magnitude_score * 100, 1),
            'f_min': round(f_min, 4),
            'f_min_amplitude': result.get('f_min_amplitude'),
            'is_directionally_novel': f_min < 0.5,
            'correlation_signal_detected': result.get('correlation_signal_detected', False),
            'correlation_note': correlation_note,
            'encoding': 'angle+amplitude',
        }


def draw_circuit_text() -> str:
    """Generate a text representation of the TAARA dual-encoding quantum circuits."""
    return """
    TAARA Quantum Validation — Dual Encoding (4 Qubits)
    ====================================================

    CIRCUIT A: Amplitude Encoding (magnitude + direction baseline)
    ─────────────────────────────────────────────────────────────
    |q3> ─ |ψ⟩ ─ H ─ ● ─────── ⊕ ─ RX ─ RY ─ RZ ─ ⟨state⟩
                      │         │
    |q2> ─ |ψ⟩ ─ H ─ ⊕ ─ ● ─── │ ─ RX ─ RY ─ RZ ─ ⟨state⟩
                          │     │
    |q1> ─ |ψ⟩ ─ H ────── ⊕ ─ ● ─ RX ─ RY ─ RZ ─ ⟨state⟩
                                │
    |q0> ─ |ψ⟩ ─ H ─────────── ● ─ RX ─ RY ─ RZ ─ ⟨state⟩

    |ψ⟩ : AmplitudeEmbedding(Δ̂)    H : Hadamard
    ●/⊕ : Ring CNOT                 RX/RY/RZ : Fixed rotations (π/4)

    CIRCUIT B: Angle Encoding (feature correlation detector — primary F_min)
    ─────────────────────────────────────────────────────────────────────────
    |q3> ─ Rx(θ₃) ─ ● ─────── ⊕ ─ Ry(θ₃) ─ ⊕ ─────── ● ─ ⟨state⟩
                     │         │             │           │
    |q2> ─ Rx(θ₂) ─ ⊕ ─ ● ─── │ ─ Ry(θ₂) ─ │ ─ ● ─── │ ─ ⟨state⟩
                         │     │             │   │     │
    |q1> ─ Rx(θ₁) ─────── ⊕ ─ ● ─ Ry(θ₁) ─ ● ─ ⊕ ─── │ ─ ⟨state⟩
                                │                       │
    |q0> ─ Rx(θ₀) ─────────── ● ─ Ry(θ₀) ─────────── ● ─ ⟨state⟩

    θᵢ = π/2 + arctan(feature_i)   → 0 if zero, poles if deviant
    Rx(θᵢ) : AngleEmbedding(rotation='X')
    Ry(θᵢ) : AngleEmbedding(rotation='Y')  [2nd layer — 2nd-order correlations]
    ●/⊕    : Ring CNOT (forward then reverse — full pairwise coverage)

    WHY ANGLE ENCODING MATTERS:
    If two features deviate together (correlated attack pattern), the Rx-CNOT
    layer creates constructive interference. Amplitude encoding only sees ||Δ||.
    Angle encoding sees WHICH features changed together — the attack fingerprint.

    Primary F_min: Angle circuit  |  Baseline F_min: Amplitude circuit
    Correlation signal detected if: F_angle < F_amplitude − 0.05
    Quantum-confirmed novelty: F_min < 0.5 (parameter-free geometric midpoint)

    Circuit Depth: A=5 layers, B=4 layers | Qubits: 4 each | Total states: 2 × 16-dim
    """


def compute_bloch_coordinates(state: np.ndarray, qubit: int = 0) -> Dict:
    """
    Compute Bloch sphere coordinates for a specific qubit.
    Returns (θ, φ, x, y, z) for visualization.
    """
    n_qubits = int(np.log2(len(state)))

    rho = np.outer(state, np.conj(state))

    dims = 2 ** n_qubits
    rho_qubit = np.zeros((2, 2), dtype=complex)

    for i in range(dims):
        for j in range(dims):
            bi = (i >> (n_qubits - 1 - qubit)) & 1
            bj = (j >> (n_qubits - 1 - qubit)) & 1
            rest_i = i & ~(1 << (n_qubits - 1 - qubit))
            rest_j = j & ~(1 << (n_qubits - 1 - qubit))
            if rest_i == rest_j:
                rho_qubit[bi, bj] += rho[i, j]

    sigma_x = np.array([[0, 1], [1, 0]])
    sigma_y = np.array([[0, -1j], [1j, 0]])
    sigma_z = np.array([[1, 0], [0, -1]])

    x = float(np.real(np.trace(rho_qubit @ sigma_x)))
    y = float(np.real(np.trace(rho_qubit @ sigma_y)))
    z = float(np.real(np.trace(rho_qubit @ sigma_z)))

    r = np.sqrt(x**2 + y**2 + z**2)
    theta = np.arccos(np.clip(z / max(r, 1e-10), -1, 1))
    phi = np.arctan2(y, x)

    return {
        'x': round(x, 4),
        'y': round(y, 4),
        'z': round(z, 4),
        'theta': round(float(theta), 4),
        'phi': round(float(phi), 4),
        'purity': round(float(r), 4)
    }


# ── Validated quantum signals (from v3 benchmark, latent-space SWAP test) ─────
#
# These operate on the 8-dim AE latent z_t, NOT raw features.
# The PCA basis is built from normal training latents per identity.
# Results confirmed on real SSH benchmark: SWAP gap=+0.683, dir gap=+0.218,
# coherence gap=+0.339. Formula: conf = α·swap_s + β·q_dir + γ·coh·√(swap_s·q_dir)
# See experiments/taara_experiment.py for full benchmark methodology.

_dev_swap = qml.device("default.qubit", wires=3)

@qml.qnode(_dev_swap)
def _amp_state_3q_swap(vec):
    qml.AmplitudeEmbedding(vec, wires=range(3), normalize=True, pad_with=0.0)
    return qml.state()

def latent_swap_fidelity(z_t: np.ndarray, pca_basis: np.ndarray,
                          pca_mean: np.ndarray, K: int = 3) -> float:
    """
    Quantum subspace projection fidelity on 8-dim latent.
    F_sub = Σ_{k=1}^{K} |<ψ_t|ψ_k>|²   K=3 PCA components of normal latents.
    swap_s = 1 - F_sub  (high = outside normal subspace = anomalous).
    """
    z_centered = z_t - pca_mean
    if np.linalg.norm(z_centered) < 1e-10:
        return 1.0
    a = z_centered.astype(complex)
    psi_t = _amp_state_3q_swap(a / np.linalg.norm(a))
    total = 0.0
    for k in range(min(K, len(pca_basis))):
        b = pca_basis[k].astype(complex)
        b_norm = np.linalg.norm(b)
        if b_norm < 1e-10:
            continue
        psi_k = _amp_state_3q_swap(b / b_norm)
        total += float(abs(np.dot(np.conj(psi_t), psi_k)) ** 2)
    return min(total, 1.0)

def latent_directionality(z_t: np.ndarray, pca_mean: np.ndarray,
                           pca_complement: np.ndarray) -> float:
    """
    Complement-subspace alignment: how much is z_t pointing into directions
    that normal behavior never explores?
    q_dir = Σ_{c} |<ψ_t|ψ_c>|²  over complement vectors Vt[K:K+2].
    """
    z_centered = z_t - pca_mean
    if np.linalg.norm(z_centered) < 1e-10:
        return 0.0
    a = z_centered.astype(complex)
    psi_t = _amp_state_3q_swap(a / np.linalg.norm(a))
    total = 0.0
    for c_vec in pca_complement:
        b = c_vec.astype(complex)
        b_norm = np.linalg.norm(b)
        if b_norm < 1e-10:
            continue
        psi_c = _amp_state_3q_swap(b / b_norm)
        total += float(abs(np.dot(np.conj(psi_t), psi_c)) ** 2)
    return min(total, 1.0)

def latent_deviation_angle(z_t: np.ndarray, pca_mean: np.ndarray,
                            pca_complement: np.ndarray) -> float:
    """Phase angle of z_t in the complement subspace. Used for coherence tracking."""
    z_centered = z_t - pca_mean
    if np.linalg.norm(z_centered) < 1e-10:
        return 0.0
    c0 = pca_complement[0] if len(pca_complement) > 0 else np.zeros(len(z_t))
    c1 = pca_complement[1] if len(pca_complement) > 1 else np.zeros(len(z_t))
    proj0 = float(np.dot(z_centered, c0) / (np.linalg.norm(c0) + 1e-10))
    proj1 = float(np.dot(z_centered, c1) / (np.linalg.norm(c1) + 1e-10))
    return float(np.arctan2(proj1, proj0))

def latent_phase_coherence(angles: list) -> float:
    """
    |mean(exp(i·φ))| over W consecutive windows.
    0 = random phase (noise), 1 = sustained directional drift (attack).
    """
    if not angles:
        return 0.0
    return float(abs(np.mean(np.exp(1j * np.array(angles)))))

def quantum_confidence_v3(swap_fidelity: float, q_dir: float, coherence: float,
                           alpha: float = 0.263, beta: float = 0.285,
                           gamma: float = 0.451) -> float:
    """
    Validated v3 fusion formula. Default weights are mean across 293 identities
    from the real SSH benchmark run.
    conf = α·swap_s + β·q_dir + γ·coh·√(swap_s·q_dir)
    """
    swap_s = max(0.0, 1.0 - swap_fidelity)
    interference = coherence * math.sqrt(max(swap_s * q_dir, 0.0))
    return float(np.clip(alpha * swap_s + beta * q_dir + gamma * interference, 0.0, 1.0))


def apply_client_transform(feature_vec: np.ndarray, shared_secret_hex: str, hostname: str) -> np.ndarray:
    """
    Apply a per-client PQC-keyed additive offset to the feature vector before quantum encoding.

    Derived from Kyber768 shared secret — lattice-hard to reverse without the private key.
    Attacker who knows the full TAARA architecture still cannot compute what "normal"
    looks like for this client without the shared secret.

    Algorithm:
      seed = SHA3-256(shared_secret_bytes + hostname_bytes)
      Expand seed via repeated SHA3-256 hashing to cover feature_vec length
      Normalize expanded bytes to [-0.5, 0.5] float range → offset
      Add offset to feature_vec → project result to unit sphere
    """
    secret_bytes = bytes.fromhex(shared_secret_hex)
    hostname_bytes = hostname.encode('utf-8')

    n = len(feature_vec)
    offset_bytes = bytearray()
    counter = 0
    while len(offset_bytes) < n * 8:
        h = hashlib.sha3_256(secret_bytes + hostname_bytes + counter.to_bytes(4, 'big')).digest()
        offset_bytes.extend(h)
        counter += 1

    offset = np.frombuffer(bytes(offset_bytes[:n * 8]), dtype=np.uint64).astype(np.float64)
    offset = (offset / np.iinfo(np.uint64).max) - 0.5

    transformed = feature_vec + offset[:n]
    norm = np.linalg.norm(transformed)
    if norm < 1e-12:
        return feature_vec
    return transformed / norm
