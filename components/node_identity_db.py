"""
Node Identity DB
================

Persistent per-node storage tied to the PQC Kyber768 key fingerprint.

Each monitored node gets a permanent folder:
  models/nodes/<host>_<pqc_fingerprint>/

Contents:
  meta.json          — host, fingerprint, first_seen, last_seen, connect_count
  ae_model.pt        — finetuned autoencoder for this node (updated after every training run)
  baseline.npy       — accumulated baseline feature samples (appended on each training run)
  quantum_state.json — PCA basis, weights, threshold, angle buffer (snapshotted on disconnect)
  action_log.json    — all commands executed on this node
  training_log.json  — training history: timestamp, mode, samples, final_loss

On connect:  load ae_model.pt → embedder, restore quantum_state.json → taara_analyzer
On training: append to baseline.npy, save ae_model.pt, update training_log.json
On disconnect: snapshot quantum_state.json, flush action_log additions
"""

import os
import json
import time
import numpy as np

try:
    import torch
except ImportError:
    torch = None


_NODES_DIR = os.path.join("models", "nodes")


def _safe_host(host: str) -> str:
    return host.replace(".", "_").replace(":", "_").replace("/", "_")


def _pqc_fingerprint(host: str) -> str:
    """Read the PQC fingerprint for this host from models/client_keys.json."""
    keys_path = os.path.join("models", "client_keys.json")
    try:
        with open(keys_path) as f:
            keys = json.load(f)
        entry = keys.get(host, {})
        return entry.get("fingerprint", "nopqc")
    except Exception:
        return "nopqc"


def node_id(host: str) -> str:
    """Stable unique identifier for a node: <safe_host>_<pqc_fingerprint>."""
    return f"{_safe_host(host)}_{_pqc_fingerprint(host)}"


def node_dir(host: str) -> str:
    nid = node_id(host)
    path = os.path.join(_NODES_DIR, nid)
    os.makedirs(path, exist_ok=True)
    return path


# ── Meta ──────────────────────────────────────────────────────────────────────

def load_meta(host: str) -> dict:
    p = os.path.join(node_dir(host), "meta.json")
    if os.path.exists(p):
        try:
            with open(p) as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "host": host,
        "node_id": node_id(host),
        "pqc_fingerprint": _pqc_fingerprint(host),
        "first_seen": None,
        "last_seen": None,
        "connect_count": 0,
        "total_samples": 0,
        "training_runs": 0,
    }


def save_meta(host: str, meta: dict):
    with open(os.path.join(node_dir(host), "meta.json"), "w") as f:
        json.dump(meta, f, indent=2)


def record_connect(host: str):
    meta = load_meta(host)
    now = time.time()
    if meta["first_seen"] is None:
        meta["first_seen"] = now
    meta["last_seen"] = now
    meta["connect_count"] = meta.get("connect_count", 0) + 1
    save_meta(host, meta)


# ── Autoencoder model ─────────────────────────────────────────────────────────

def ae_model_path(host: str) -> str:
    return os.path.join(node_dir(host), "ae_model.pt")


def load_node_model(host: str, embedder) -> bool:
    """
    Load the node-specific finetuned AE into embedder.
    Returns True if a node model was found and loaded.
    Falls back gracefully — embedder keeps the global pretrained model.
    """
    path = ae_model_path(host)
    if not os.path.exists(path):
        return False
    if torch is None:
        return False
    try:
        checkpoint = torch.load(path, weights_only=True)
        from components.dna_autoencoder import DNAAutoencoder
        embedder.model = DNAAutoencoder(
            input_dim=checkpoint["input_dim"],
            embedding_dim=checkpoint["embedding_dim"],
            hidden_dim=checkpoint["hidden_dim"],
        )
        embedder.model.load_state_dict(checkpoint["model_state_dict"])
        embedder.is_trained = True
        print(f"[NodeDB] Loaded node model for {host} ({node_id(host)})")
        return True
    except Exception as e:
        print(f"[NodeDB] Failed to load node model for {host}: {e}")
        return False


def save_node_model(host: str, embedder):
    """Persist the current embedder weights as this node's finetuned model."""
    if torch is None or not embedder.is_trained:
        return
    try:
        path = ae_model_path(host)
        torch.save({
            "model_state_dict": embedder.model.state_dict(),
            "input_dim": embedder.model.input_dim,
            "embedding_dim": embedder.model.embedding_dim,
            "hidden_dim": embedder.model.hidden_dim,
            "is_trained": True,
        }, path)
        print(f"[NodeDB] Saved node model for {host} → {path}")
    except Exception as e:
        print(f"[NodeDB] Save node model error: {e}")


# ── Baseline samples ──────────────────────────────────────────────────────────

def baseline_path(host: str) -> str:
    return os.path.join(node_dir(host), "baseline.npy")


def load_baseline(host: str) -> np.ndarray:
    p = baseline_path(host)
    if os.path.exists(p):
        try:
            return np.load(p)
        except Exception:
            pass
    return np.empty((0, 19), dtype=np.float32)


def append_baseline(host: str, new_samples: np.ndarray):
    """Append new baseline samples to the node's persistent baseline store."""
    if new_samples is None or len(new_samples) == 0:
        return
    existing = load_baseline(host)
    combined = np.vstack([existing, new_samples]) if len(existing) > 0 else new_samples
    # Keep last 500 samples — enough for quantum subspace, avoids unbounded growth
    if len(combined) > 500:
        combined = combined[-500:]
    np.save(baseline_path(host), combined)
    meta = load_meta(host)
    meta["total_samples"] = len(combined)
    save_meta(host, meta)


# ── Quantum state snapshot ────────────────────────────────────────────────────

def quantum_state_path(host: str) -> str:
    return os.path.join(node_dir(host), "quantum_state.json")


def snapshot_quantum_state(host: str, taara_analyzer):
    """
    Save this node's quantum state (PCA basis, weights, threshold, angle buffer)
    from taara_analyzer into the node folder.
    """
    identity = f"taaraware_{host}"
    qs = taara_analyzer.quantum_states.get(identity)
    if not qs:
        return
    try:
        snap = {}
        if qs.get("pca_basis") is not None:
            b = qs["pca_basis"]
            snap["pca_basis"] = b.tolist() if hasattr(b, "tolist") else list(b)
        if qs.get("pca_mean") is not None:
            m = qs["pca_mean"]
            snap["pca_mean"] = m.tolist() if hasattr(m, "tolist") else list(m)
        if qs.get("pca_complement") is not None:
            c = qs["pca_complement"]
            snap["pca_complement"] = c.tolist() if hasattr(c, "tolist") else list(c)
        snap["weights"] = list(qs["weights"]) if qs.get("weights") else None
        snap["threshold"] = qs.get("threshold")
        # Angle buffer: convert deque to list
        ab = qs.get("angle_buffer")
        if ab is not None:
            snap["angle_buffer"] = list(ab)
        # Normal latents used for subspace (last 50)
        nl = qs.get("normal_latents", [])
        if nl:
            snap["normal_latents"] = [
                v.tolist() if hasattr(v, "tolist") else list(v)
                for v in nl[-50:]
            ]
        # Memory basis vectors from IdentityMemoryBasis object
        basis_obj = taara_analyzer.memory_bases.get(identity)
        if basis_obj is not None and hasattr(basis_obj, "basis_vectors") and basis_obj.basis_vectors:
            snap["basis_vectors"] = [
                v.tolist() if hasattr(v, "tolist") else list(v)
                for v in basis_obj.basis_vectors[-50:]
            ]
        with open(quantum_state_path(host), "w") as f:
            json.dump(snap, f)
        print(f"[NodeDB] Quantum state snapshotted for {host}")
    except Exception as e:
        print(f"[NodeDB] Quantum state snapshot error: {e}")


def restore_quantum_state(host: str, taara_analyzer, embedder):
    """
    Restore this node's quantum state into taara_analyzer.
    Priority:
      1. Node-specific quantum_state.json (saved on last disconnect)
      2. Seed from normal_latent.json using the loaded embedder (pretrained or finetuned)
    Returns True if any state was restored/seeded.
    """
    from collections import deque

    identity = f"taaraware_{host}"
    p = quantum_state_path(host)

    # ── Path 1: restore saved state ───────────────────────────────────────────
    if os.path.exists(p):
        try:
            with open(p) as f:
                snap = json.load(f)

            qs = taara_analyzer.quantum_states.get(identity, {})
            if snap.get("pca_basis"):
                qs["pca_basis"] = np.array(snap["pca_basis"], dtype=np.float32)
            if snap.get("pca_mean"):
                qs["pca_mean"] = np.array(snap["pca_mean"], dtype=np.float32)
            if snap.get("pca_complement"):
                qs["pca_complement"] = np.array(snap["pca_complement"], dtype=np.float32)
            if snap.get("weights"):
                w = snap["weights"]
                qs["weights"] = tuple(float(x) for x in w)
                # Legacy keys kept for older code paths
                if len(w) >= 3:
                    qs["alpha"], qs["beta"], qs["gamma"] = float(w[0]), float(w[1]), float(w[2])
            if snap.get("threshold") is not None:
                qs["threshold"] = snap["threshold"]
            if snap.get("angle_buffer") is not None:
                qs["angle_buffer"] = deque(snap["angle_buffer"], maxlen=4)
            else:
                qs.setdefault("angle_buffer", deque(maxlen=4))
            # Normal latents
            if snap.get("normal_latents"):
                qs["normal_latents"] = [np.array(v, dtype=np.float32) for v in snap["normal_latents"]]
            qs["embedder"] = embedder
            taara_analyzer.quantum_states[identity] = qs

            # Re-seed IdentityMemoryBasis with saved basis vectors
            if snap.get("basis_vectors"):
                from components.taara_core import IdentityMemoryBasis
                if identity not in taara_analyzer.memory_bases:
                    taara_analyzer.memory_bases[identity] = IdentityMemoryBasis(identity)
                basis_obj = taara_analyzer.memory_bases[identity]
                if len(basis_obj.basis_vectors) == 0:
                    for v in snap["basis_vectors"]:
                        basis_obj.basis_vectors.append(np.array(v, dtype=np.float32))
                    basis_obj.observation_count = len(basis_obj.basis_vectors)

            print(f"[NodeDB] Quantum state restored for {host} (pca={'yes' if qs.get('pca_basis') is not None else 'no'})")
            return True
        except Exception as e:
            print(f"[NodeDB] Quantum state restore error: {e}")
            # Fall through to seeding

    # ── Path 2: no saved state — seed from normal_latent.json ────────────────
    # This gives the quantum engine a starting subspace immediately,
    # so the dashboard shows real signals from the first live observation.
    if embedder and embedder.is_ready():
        try:
            normal_latent_path = os.path.join("models", "normal_latent.json")
            if not os.path.exists(normal_latent_path):
                return False

            with open(normal_latent_path) as f:
                mean_latent = np.array(json.load(f), dtype=np.float32)

            # Build a synthetic set of normal latents around the mean
            # (small Gaussian noise) to bootstrap the PCA subspace
            rng = np.random.default_rng(42)
            n_synthetic = 20
            noise = rng.normal(0, 0.05, size=(n_synthetic, len(mean_latent))).astype(np.float32)
            latents = mean_latent + noise

            # PCA subspace via SVD
            centered = latents - latents.mean(0)
            try:
                from scipy.linalg import svd as _svd
                _, _, Vt = _svd(centered, full_matrices=True, check_finite=False)
            except Exception:
                Vt = np.linalg.qr(np.random.randn(centered.shape[1], centered.shape[1]))[0].T

            from components.quantum_engine import (latent_swap_fidelity, latent_directionality,
                                                    latent_deviation_angle, latent_phase_coherence,
                                                    quantum_confidence_v3)

            pca_basis = Vt[:3].astype(np.float32)
            pca_complement = Vt[3:5].astype(np.float32)
            pca_mean = latents.mean(0).astype(np.float32)

            # Fit V3 weights from synthetic normals
            PRIOR = np.array([0.263, 0.285, 0.451], dtype=np.float32)
            sigs = []
            angle_buf = deque(maxlen=4)
            for z_n in latents:
                sf  = latent_swap_fidelity(z_n, pca_basis, pca_mean)
                qd  = latent_directionality(z_n, pca_mean, pca_complement)
                ang = latent_deviation_angle(z_n, pca_mean, pca_complement)
                angle_buf.append(ang)
                coh = latent_phase_coherence(list(angle_buf))
                swap_s = max(0.0, 1.0 - sf)
                itf = coh * float(np.sqrt(max(swap_s * qd, 0.0)))
                sigs.append([swap_s, qd, itf])
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

            taara_analyzer.quantum_states[identity] = {
                "embedder": embedder,
                "pca_basis": pca_basis,
                "pca_mean": pca_mean,
                "pca_complement": pca_complement,
                "normal_latents": list(latents),
                "weights": tuple(float(x) for x in w),
                "alpha": float(w[0]), "beta": float(w[1]), "gamma": float(w[2]),
                "threshold": thresh,
                "angle_buffer": deque(maxlen=4),
            }

            # Seed memory basis with synthetic normals (raw-feature space)
            # We don't have real feature vectors, so just seed with zero vectors
            # — enough to let reconstruction run; real data fills it in live
            from components.taara_core import IdentityMemoryBasis
            if identity not in taara_analyzer.memory_bases:
                taara_analyzer.memory_bases[identity] = IdentityMemoryBasis(identity)
            basis_obj = taara_analyzer.memory_bases[identity]
            if len(basis_obj.basis_vectors) == 0:
                # Use node baseline if available
                bl = load_baseline(host)
                if len(bl) >= 3:
                    for fv in bl[-10:]:
                        basis_obj.basis_vectors.append(fv.astype(np.float32))
                    basis_obj.observation_count = len(basis_obj.basis_vectors)

            model_src = "finetuned" if os.path.exists(ae_model_path(host)) else "pretrained"
            print(f"[NodeDB] Quantum state seeded from normal_latent.json ({model_src} model, thresh={thresh:.4f})")
            return True
        except Exception as e:
            print(f"[NodeDB] Quantum state seed error: {e}")

    return False


# ── Action log ────────────────────────────────────────────────────────────────

def action_log_path(host: str) -> str:
    return os.path.join(node_dir(host), "action_log.json")


def append_action_log(host: str, entries: list):
    """Append new action log entries to the node's persistent action log."""
    p = action_log_path(host)
    existing = []
    if os.path.exists(p):
        try:
            with open(p) as f:
                existing = json.load(f)
        except Exception:
            existing = []
    existing.extend(entries)
    # Keep last 1000 entries
    if len(existing) > 1000:
        existing = existing[-1000:]
    with open(p, "w") as f:
        json.dump(existing, f, indent=2)


def load_action_log(host: str) -> list:
    p = action_log_path(host)
    if not os.path.exists(p):
        return []
    try:
        with open(p) as f:
            return json.load(f)
    except Exception:
        return []


# ── Training log ──────────────────────────────────────────────────────────────

def training_log_path(host: str) -> str:
    return os.path.join(node_dir(host), "training_log.json")


def record_training(host: str, mode: str, samples: int, result: dict):
    p = training_log_path(host)
    existing = []
    if os.path.exists(p):
        try:
            with open(p) as f:
                existing = json.load(f)
        except Exception:
            existing = []
    existing.append({
        "timestamp": time.time(),
        "mode": mode,
        "samples": samples,
        "result": result,
    })
    with open(p, "w") as f:
        json.dump(existing, f, indent=2)
    meta = load_meta(host)
    meta["training_runs"] = len(existing)
    save_meta(host, meta)


def load_training_log(host: str) -> list:
    p = training_log_path(host)
    if not os.path.exists(p):
        return []
    try:
        with open(p) as f:
            return json.load(f)
    except Exception:
        return []


# ── Convenience: full restore on connect ─────────────────────────────────────

def restore_node_session(host: str, embedder, taara_analyzer) -> dict:
    """
    Called on connect. Restores everything known about this node:
    - Finetuned AE model
    - Quantum state (PCA basis, weights, threshold)
    Returns a summary dict for logging.
    """
    record_connect(host)
    meta = load_meta(host)
    model_loaded = load_node_model(host, embedder)
    qs_restored   = restore_quantum_state(host, taara_analyzer, embedder)
    baseline_size = len(load_baseline(host))
    return {
        "node_id": meta["node_id"],
        "connect_count": meta["connect_count"],
        "model_loaded": model_loaded,
        "quantum_state_restored": qs_restored,
        "baseline_samples": baseline_size,
        "training_runs": meta.get("training_runs", 0),
    }


# ── Convenience: full snapshot on disconnect ──────────────────────────────────

def snapshot_node_session(host: str, embedder, taara_analyzer, action_logger=None):
    """
    Called on disconnect. Snapshots everything:
    - Finetuned AE model
    - Quantum state
    - Any new action log entries since last snapshot
    """
    save_node_model(host, embedder)
    snapshot_quantum_state(host, taara_analyzer)
    if action_logger is not None:
        try:
            recent = action_logger.get_log(limit=200) if hasattr(action_logger, "get_log") else []
            if recent:
                append_action_log(host, recent)
        except Exception:
            pass
    meta = load_meta(host)
    meta["last_seen"] = time.time()
    save_meta(host, meta)
    print(f"[NodeDB] Session snapshotted for {host} ({meta['node_id']})")
