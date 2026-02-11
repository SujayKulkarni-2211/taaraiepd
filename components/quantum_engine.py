"""
Quantum Validation Engine (PennyLane)
=====================================

Implements the quantum validation layer from the TAARA paper (Section 3.4).

Architecture:
    1. Amplitude encoding of residual direction vectors
    2. 4-qubit circuit: AmplitudeEmbedding → Hadamard → Ring CNOT → RX/RY/RZ rotations
    3. Quantum fidelity computation: F(|ψ_t⟩, |ψ_m⟩) = |⟨ψ_t|ψ_m⟩|²
    4. Quantum-confirmed novelty: F_min(t) < 0.5

Uses PennyLane default.qubit simulator (no real quantum hardware).
Keeps circuits to 4 qubits for laptop GPU compatibility.
"""

import numpy as np
import pennylane as qml
from typing import List, Dict, Tuple, Optional
import math


N_QUBITS = 4
STATE_DIM = 2 ** N_QUBITS  # 16 dimensions

dev = qml.device("default.qubit", wires=N_QUBITS)


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


@qml.qnode(dev)
def _quantum_circuit(features: np.ndarray):
    """
    TAARA quantum validation circuit (paper Section 3.4.2).

    Circuit design:
    1. Amplitude embedding - encodes residual direction into quantum state
    2. Hadamard gates - create superposition on all qubits
    3. Ring entanglement - CNOT gates in ring topology (0→1, 1→2, 2→3, 3→0)
    4. Parameterized rotations - RX, RY, RZ on each qubit (angles fixed at π/4)
    5. Return full statevector for fidelity computation

    Circuit depth: 5 gates
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


@qml.qnode(dev)
def _quantum_circuit_bare(features: np.ndarray):
    """Bare amplitude encoding without processing - for pure fidelity computation."""
    qml.AmplitudeEmbedding(features=features, wires=range(N_QUBITS), normalize=True)
    return qml.state()


class QuantumValidator:
    """
    Quantum validation layer for TAARA novelty detection.

    Implements Section 3.4 of the paper:
    - Encodes residual direction vectors into quantum states
    - Computes quantum fidelity between states
    - Confirms if classical novelty detections represent genuine directional shifts
    """

    def __init__(self):
        self.memory_states: List[np.ndarray] = []
        self.memory_residuals: List[np.ndarray] = []

    def encode_residual(self, residual: np.ndarray) -> np.ndarray:
        """
        Encode a residual vector into a quantum state.

        From paper Eq. 7-8:
        Δ_hat = Δ / ||Δ||
        |ψ_t⟩ = Σ Δ_hat[i] |i⟩
        """
        amplitude_vec = _prepare_amplitude_vector(residual)
        state = _quantum_circuit(amplitude_vec)
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
        Compute minimum fidelity against all memory states.

        From paper Section 3.4.3:
        F_min(t) = min_{m ∈ M_u} F(|ψ_t⟩, |ψ_m⟩)

        Quantum-confirmed novelty if F_min < 0.5
        """
        if not self.memory_states:
            return {
                'f_min': 0.0,
                'is_quantum_novel': True,
                'fidelities': [],
                'note': 'No memory states - first observation'
            }

        current_state = self.encode_residual(current_residual)

        fidelities = []
        for mem_state in self.memory_states:
            f = self.compute_fidelity(current_state, mem_state)
            fidelities.append(f)

        f_min = min(fidelities)

        return {
            'f_min': f_min,
            'is_quantum_novel': f_min < 0.5,
            'fidelities': fidelities,
            'mean_fidelity': float(np.mean(fidelities)),
            'max_fidelity': float(max(fidelities)),
            'quantum_confidence': 1.0 - f_min
        }

    def add_to_memory(self, residual: np.ndarray):
        """Add a residual direction to quantum memory."""
        state = self.encode_residual(residual)
        self.memory_states.append(state)
        self.memory_residuals.append(residual.copy())

    def clear_memory(self):
        """Clear quantum memory."""
        self.memory_states = []
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
        - Reconstruction residual magnitude
        - Quantum fidelity (directional novelty)
        - Number of novel dimensions detected
        """
        if memory_basis and len(memory_basis) > 0:
            temp_states = []
            for m in memory_basis:
                temp_states.append(self.encode_residual(m))
            old_states = self.memory_states
            self.memory_states = temp_states
            result = self.compute_minimum_fidelity(features)
            self.memory_states = old_states
        else:
            result = self.compute_minimum_fidelity(features)

        f_min = result['f_min']
        quantum_novelty = 1.0 - f_min

        residual_magnitude = float(np.linalg.norm(features))
        magnitude_score = min(residual_magnitude / 2.0, 1.0)

        risk_score = (0.6 * quantum_novelty + 0.4 * magnitude_score) * 100
        risk_score = min(max(risk_score, 0), 100)

        if risk_score >= 75:
            severity = 'CRITICAL'
        elif risk_score >= 50:
            severity = 'HIGH'
        elif risk_score >= 25:
            severity = 'MEDIUM'
        else:
            severity = 'LOW'

        return {
            'risk_score': round(risk_score, 1),
            'severity': severity,
            'quantum_novelty': round(quantum_novelty * 100, 1),
            'magnitude_score': round(magnitude_score * 100, 1),
            'f_min': round(f_min, 4),
            'is_directionally_novel': f_min < 0.5
        }


def draw_circuit_text() -> str:
    """Generate a text representation of the TAARA quantum circuit."""
    return """
    TAARA Quantum Validation Circuit (4 Qubits)
    =============================================

    |q3> ─ |ψ⟩ ─ H ─ ● ─────── ⊕ ─ RX ─ RY ─ RZ ─ ⟨M⟩
                      │         │
    |q2> ─ |ψ⟩ ─ H ─ ⊕ ─ ● ─── │ ─ RX ─ RY ─ RZ ─ ⟨M⟩
                          │     │
    |q1> ─ |ψ⟩ ─ H ────── ⊕ ─ ● ─ RX ─ RY ─ RZ ─ ⟨M⟩
                                │
    |q0> ─ |ψ⟩ ─ H ─────────── ● ─ RX ─ RY ─ RZ ─ ⟨M⟩

    |ψ⟩ : Amplitude Embedding    H : Hadamard Gate
    ●/⊕ : Ring CNOT Entanglement  RX/RY/RZ : Parameterized Rotations (π/4)
    ⟨M⟩ : Computational Basis Measurement

    Circuit Depth: 5 | Qubits: 4 | Parameters: 12 (fixed)
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
