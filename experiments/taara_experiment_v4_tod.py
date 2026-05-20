#!/usr/bin/env python3
"""
TAARA T1078 Benchmark — Quantum Subspace Projection Detection v4 (ToD)
=======================================================================
Extends v3. AE stays 19-dim (unchanged). ToD added ONLY to fusion formula.

Fusion formula (v4):
  conf = α·swap_s + β·q_dir + δ·tod_dev + γ·coh·√(swap_s·q_dir·(1+tod_dev))

  swap_s  = 1 - swap_fidelity        (is z_t outside normal subspace?)
  q_dir   = directionality            (is it pointing into complement?)
  tod_dev = circular hour deviation   (is this window at an unusual hour for this user?)
  coh·√(swap_s·q_dir·(1+tod_dev)) = interference: fires only when BOTH quantum
      signals are active AND coherence is sustained. (1+tod_dev) amplifies the
      interference when the hour is also unusual — but only if the quantum signals
      already fired. If swap_s·q_dir≈0 (legit user), tod_dev contributes nothing
      to the interference term.

Why ToD stays OUT of the AE:
  Confirmed in failed 22-dim run: SWAP gap dropped +0.683→+0.439, Prec=0.278.
  8-dim bottleneck shared between behavioral DNA and ToD crowds out pure signal.

Real benchmark results (this file):
  TAARA v4:  Prec=0.525  Rec=0.992  F1=0.686  AUC=0.990  TP=872  FP=790  FN=7
  IF global: Prec=0.763  Rec=0.995  F1=0.864  AUC=0.995  TP=875  FP=272  FN=4
  v3 ref:    Prec=0.689  Rec=0.942  F1=0.796  AUC=0.980

Recall improves 0.942→0.992 (51 FNs→7). Precision cost accepted.
Design choice: for T1078/credential theft, missing 7 attacks vs 51 is worth the
extra FPs — a human analyst reviews alerts, a missed breach is unrecoverable.

Signal separation confirmed real:
  SWAP:        normal=0.938  attack=0.309  gap=+0.629
  Direction:   normal=0.052  attack=0.360  gap=+0.308
  Coherence:   normal=0.630  attack=0.964  gap=+0.334
  ToD dev:     normal=0.274  attack=0.804  gap=+0.529

Do NOT touch experiments/taara_experiment.py — preserves v3 results.
"""

import re, json, time, copy, warnings
from pathlib import Path
from scipy.linalg import svd as scipy_svd
from collections import defaultdict, deque

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
import pennylane as qml
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (precision_score, recall_score, f1_score,
                              confusion_matrix, roc_auc_score)

warnings.filterwarnings("ignore")

ROOT        = Path(__file__).parent.parent
SSH_LOG     = ROOT / "benchmark" / "datasets" / "SSH.log"
AUTH_LOG    = ROOT / "benchmark" / "datasets" / "auth.log"
ELASTIC_LOG = ROOT / "benchmark" / "datasets" / "elastic_auth.log"
RESULTS_DIR = Path(__file__).parent / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

WINDOW  = 5
PCA_K   = 3
COH_W   = 4

ALPHA_PRIOR = 0.30
BETA_PRIOR  = 0.12
GAMMA_PRIOR = 0.58
DELTA_PRIOR = 0.25

# ── Parsers ────────────────────────────────────────────────────────────────────

MONTHS = {"Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,
          "Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12}

def to_sec(mn, d, h, mi, s):
    return MONTHS.get(mn,1)*30*86400+int(d)*86400+int(h)*3600+int(mi)*60+int(s)

AUTH_FAIL = re.compile(
    r"(\w{3})\s+(\d+)\s+(\d+):(\d+):(\d+)\s+\S+\s+sshd\[(\d+)\].*?"
    r"(?:Failed password|Invalid user|Connection closed|error: maximum authentication).*?from\s+([\d.]+)")
AUTH_SUCCESS = re.compile(
    r"(\w{3})\s+(\d+)\s+(\d+):(\d+):(\d+)\s+\S+\s+sshd\[(\d+)\].*?"
    r"Accepted (?:password|publickey) for \S+ from ([\d.]+)")
AUTH_LINE = re.compile(
    r"(\w{3})\s+(\d+)\s+(\d+):(\d+):(\d+)\s+\S+\s+sshd\[(\d+)\].*?from\s+([\d.]+)")

def parse_ssh_log(filepath):
    d = defaultdict(list)
    with open(filepath, errors="ignore") as f:
        for line in f:
            m = AUTH_FAIL.search(line)
            if m:
                mn,dy,h,mi,s,_,ip = m.groups()
                d[ip].append((to_sec(mn,dy,h,mi,s), 0)); continue
            m = AUTH_SUCCESS.search(line)
            if m:
                mn,dy,h,mi,s,_,ip = m.groups()
                d[ip].append((to_sec(mn,dy,h,mi,s), 1))
    for ip in d: d[ip].sort(key=lambda x: x[0])
    return d

def parse_generic(filepath):
    d = defaultdict(list)
    with open(filepath, errors="ignore") as f:
        for line in f:
            m = AUTH_LINE.search(line)
            if m:
                mn,dy,h,mi,s,_,ip = m.groups()
                d[ip].append((to_sec(mn,dy,h,mi,s), 1 if "Accepted" in line else 0))
    for ip in d: d[ip].sort(key=lambda x: x[0])
    return d


# ── Feature Extraction (19-dim — identical to v3) ─────────────────────────────

INPUT_DIM = 19

def make_features(events):
    if not events: return np.zeros(INPUT_DIM, dtype=np.float32)
    ts = [e[0] for e in events]; ty = [e[1] for e in events]
    fails = sum(1 for t in ty if t==0)
    succs = sum(1 for t in ty if t==1)
    total = len(events); dur = max(ts[-1]-ts[0], 1)
    if len(ts) > 1:
        ivs = [ts[i+1]-ts[i] for i in range(len(ts)-1)]
        avg_iv,std_iv,min_iv,max_iv = (float(np.mean(ivs)),float(np.std(ivs)),
                                       float(np.min(ivs)),float(np.max(ivs)))
    else:
        avg_iv=std_iv=min_iv=max_iv=0.0
    bursts = sum(1 for i in range(len(ts))
                 if sum(1 for t in ts if ts[i]<=t<=ts[i]+30)>3)
    return np.array([
        float(fails), float(succs), float(total),
        float(fails/max(total,1)), float(fails/max(succs+1,1)), float(bursts),
        float(fails/max(dur,1)*100), float(avg_iv), float(std_iv),
        float(min_iv), float(max_iv), float(std_iv/max(avg_iv,1)),
        float(dur), float(bursts/max(dur/3600,1)),
        float(total/max(dur,1)*60), float(len(set(ts))),
        float(min_iv<1.0), float(min_iv<0.1), float(std_iv/max(dur,1)),
    ], dtype=np.float32)

def extract_windows(ip_events, step=2):
    return [make_features(evs[i:i+WINDOW])
            for evs in ip_events.values()
            for i in range(0, len(evs)-WINDOW, step)]


# ── ToD deviation (fusion signal only, not AE input) ──────────────────────────

def compute_tod_deviation(events, mean_hour, hour_spread):
    """
    Circular distance of this window's mean hour from user's established mean hour.
    Normalized by user's own spread. Returns [0, 1].
    0 = window at user's normal hour. 1 = maximally unusual hour for this user.
    """
    if not events: return 0.0
    ts = [e[0] for e in events]
    hours = [(t % 86400) / 3600.0 for t in ts]
    angles = np.array([2 * np.pi * h / 24.0 for h in hours])
    w_sin = float(np.mean(np.sin(angles)))
    w_cos = float(np.mean(np.cos(angles)))
    window_hour = float(np.arctan2(w_sin, w_cos) * 24 / (2 * np.pi) % 24)
    diff_rad = abs(np.arctan2(
        np.sin((window_hour - mean_hour) * 2 * np.pi / 24),
        np.cos((window_hour - mean_hour) * 2 * np.pi / 24)
    ))
    diff_hours = diff_rad * 24 / (2 * np.pi)
    spread = max(hour_spread, 0.5)
    return float(np.clip(diff_hours / (spread * 3.0), 0.0, 1.0))


# ── Autoencoder 19→64→8→64→19 (identical to v3) ───────────────────────────────

class BehavioralAE(nn.Module):
    def __init__(self, input_dim=INPUT_DIM, latent_dim=8, hidden_dim=64):
        super().__init__()
        self.latent_dim = latent_dim
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim), nn.ReLU(), nn.Dropout(0.1),
            nn.Linear(hidden_dim, latent_dim), nn.Tanh()
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, hidden_dim), nn.ReLU(), nn.Dropout(0.1),
            nn.Linear(hidden_dim, input_dim)
        )
    def forward(self, x): z=self.encoder(x); return self.decoder(z), z
    def encode(self, x): return self.encoder(x)

def train_ae(feats, scaler, epochs=80, lr=0.001, bs=32, model=None, patience=10):
    X = torch.FloatTensor(scaler.transform(feats))
    if model is None: model = BehavioralAE()
    opt = optim.Adam(model.parameters(), lr=lr)
    crit = nn.MSELoss()
    best, cnt = float('inf'), 0
    model.train()
    for _ in range(epochs):
        idx = torch.randperm(len(X))
        ls = 0.0; nb = 0
        for i in range(0, len(X), bs):
            b = X[idx[i:i+bs]]
            r, _ = model(b); l = crit(r, b)
            opt.zero_grad(); l.backward(); opt.step()
            ls += l.item(); nb += 1
        avg = ls / max(nb, 1)
        if avg < best: best = avg; cnt = 0
        else: cnt += 1
        if cnt >= patience: break
    model.eval()
    return model

def get_latent(model, scaler, feat):
    x = torch.FloatTensor(scaler.transform(feat.reshape(1,-1)))
    with torch.no_grad(): return model.encode(x).numpy()[0]

def get_recon_error(model, scaler, feat):
    x = torch.FloatTensor(scaler.transform(feat.reshape(1,-1)))
    with torch.no_grad():
        r, _ = model(x)
        return float(torch.mean((r-x)**2).item())


# ── Quantum signals (identical to v3) ─────────────────────────────────────────

dev3 = qml.device("default.qubit", wires=3)

@qml.qnode(dev3)
def _amp_state_3q(vec):
    qml.AmplitudeEmbedding(vec, wires=range(3), normalize=True, pad_with=0.0)
    return qml.state()

def quantum_subspace_fidelity(z_t, pca_basis, pca_mean, K=PCA_K):
    z_centered = z_t - pca_mean
    if np.linalg.norm(z_centered) < 1e-10: return 1.0
    a = z_centered.astype(complex)
    psi_t = _amp_state_3q(a / np.linalg.norm(a))
    total = 0.0
    for k in range(min(K, len(pca_basis))):
        b = pca_basis[k].astype(complex)
        b_norm = np.linalg.norm(b)
        if b_norm < 1e-10: continue
        psi_k = _amp_state_3q(b / b_norm)
        total += float(abs(np.dot(np.conj(psi_t), psi_k))**2)
    return min(total, 1.0)

def quantum_directionality(z_t, pca_basis, pca_mean, pca_complement):
    z_centered = z_t - pca_mean
    if np.linalg.norm(z_centered) < 1e-10: return 0.0
    a = z_centered.astype(complex)
    psi_t = _amp_state_3q(a / np.linalg.norm(a))
    total = 0.0
    for c_vec in pca_complement:
        b = c_vec.astype(complex)
        b_norm = np.linalg.norm(b)
        if b_norm < 1e-10: continue
        psi_c = _amp_state_3q(b / b_norm)
        total += float(abs(np.dot(np.conj(psi_t), psi_c))**2)
    return min(total, 1.0)

def deviation_angle(z_t, pca_mean, pca_complement):
    z_centered = z_t - pca_mean
    if np.linalg.norm(z_centered) < 1e-10: return 0.0
    c0 = pca_complement[0] if len(pca_complement) > 0 else np.zeros(len(z_t))
    c1 = pca_complement[1] if len(pca_complement) > 1 else np.zeros(len(z_t))
    proj0 = float(np.dot(z_centered, c0) / (np.linalg.norm(c0) + 1e-10))
    proj1 = float(np.dot(z_centered, c1) / (np.linalg.norm(c1) + 1e-10))
    return float(np.arctan2(proj1, proj0))

def phase_coherence(angles):
    if len(angles) == 0: return 0.0
    return float(abs(np.mean(np.exp(1j * np.array(angles)))))


# ── V4 Fusion formula ─────────────────────────────────────────────────────────

def qconf_v4(swap_f, q_dir, coherence, tod_dev, alpha, beta, gamma, delta):
    """
    conf = α·swap_s + β·q_dir + δ·tod_dev + γ·coh·√(swap_s·q_dir·(1+tod_dev))

    The (1+tod_dev) inside the interference term amplifies the cross-signal
    only when the hour is unusual AND both quantum signals already fired.
    If swap_s·q_dir≈0, tod_dev contributes nothing to interference — the δ·tod_dev
    additive term is the only ToD contribution for clean quantum windows.
    """
    swap_s = max(0.0, 1.0 - swap_f)
    tod_boost = 1.0 + float(tod_dev)
    interference = coherence * np.sqrt(max(swap_s * q_dir * tod_boost, 0.0))
    raw = alpha * swap_s + beta * q_dir + delta * tod_dev + gamma * interference
    return float(np.clip(raw, 0.0, 2.0))


# ── Per-identity learnable weights (4: α, β, γ, δ) ───────────────────────────

def fit_fusion_weights(train_latents, pca_basis, pca_mean, pca_complement,
                       angle_history, train_raw_wins, mean_hour, hour_spread):
    """
    Fit α, β, γ, δ per identity on normal training windows.
    Features: [swap_s, q_dir, coh·√(swap_s·q_dir·(1+tod)), tod_dev]
    Labels: all 0 (normal). Regularized toward global prior via C=2.0.
    """
    rows = []
    for i, z in enumerate(train_latents):
        sf     = quantum_subspace_fidelity(z, pca_basis, pca_mean)
        qd     = quantum_directionality(z, pca_basis, pca_mean, pca_complement)
        coh    = phase_coherence(angle_history[i])
        swap_s = max(0.0, 1.0 - sf)
        evs    = train_raw_wins[i] if i < len(train_raw_wins) else []
        tod    = compute_tod_deviation(evs, mean_hour, hour_spread)
        tod_boost = 1.0 + tod
        itf = coh * np.sqrt(max(swap_s * qd * tod_boost, 0.0))
        rows.append([swap_s, qd, itf, tod])

    if len(rows) < 4:
        return ALPHA_PRIOR, BETA_PRIOR, GAMMA_PRIOR, DELTA_PRIOR

    X = np.array(rows, dtype=np.float32)
    y = np.zeros(len(X), dtype=int)
    X_anom = np.clip(1.0 - X + 0.1 * np.random.randn(*X.shape), 0, 1)
    X_fit  = np.vstack([X, X_anom])
    y_fit  = np.hstack([y, np.ones(len(X_anom), dtype=int)])

    try:
        lr = LogisticRegression(C=2.0, fit_intercept=False, max_iter=200,
                                random_state=42, solver='lbfgs')
        lr.fit(X_fit, y_fit)
        w = np.clip(lr.coef_[0], 0.05, 2.0)
        total_prior = ALPHA_PRIOR + BETA_PRIOR + GAMMA_PRIOR + DELTA_PRIOR
        w = w / (w.sum() + 1e-10) * total_prior
        return float(w[0]), float(w[1]), float(w[2]), float(w[3])
    except Exception:
        return ALPHA_PRIOR, BETA_PRIOR, GAMMA_PRIOR, DELTA_PRIOR


# ── Identity profile (stores mean_hour + hour_spread for ToD) ─────────────────

def extract_identity_profile(events):
    if len(events) < 5: return None
    ts  = [e[0] for e in events]
    ivs = [ts[i+1]-ts[i] for i in range(len(ts)-1)] if len(ts)>1 else [3600.0]
    hours  = [(t % 86400) / 3600.0 for t in ts]
    angles = np.array([2 * np.pi * h / 24.0 for h in hours])
    mean_hour = float(np.arctan2(float(np.mean(np.sin(angles))),
                                  float(np.mean(np.cos(angles)))) * 24 / (2*np.pi) % 24)
    R = float(np.clip(abs(np.mean(np.exp(1j * angles))), 1e-6, 1.0-1e-6))
    hour_spread = float(np.sqrt(-2 * np.log(R)) * 24 / (2*np.pi))
    return {
        'avg_iv':      float(np.mean(ivs)),
        'std_iv':      float(np.std(ivs)) + 1.0,
        'fail_rate':   sum(1 for _,t in events if t==0) / max(len(events), 1),
        'mean_hour':   mean_hour,
        'hour_spread': max(hour_spread, 0.5),
    }


# ── T1078 injection (behavioral perturbation + unusual-hour shift) ─────────────

def inject_t1078(legit_profile, rng, t_start, n=WINDOW):
    avg_iv    = legit_profile['avg_iv']
    std_iv    = legit_profile['std_iv']
    fail_rate = legit_profile['fail_rate']
    mean_hour = legit_profile.get('mean_hour', 12.0)

    hour_shift_sec = rng.choice([-1, 1]) * rng.uniform(6, 10) * 3600
    current_hour   = (t_start % 86400) / 3600.0
    target_hour    = (mean_hour + hour_shift_sec / 3600.0) % 24
    tod_offset     = ((target_hour - current_hour) % 24) * 3600
    t = t_start + tod_offset

    perturbed_avg_iv = max(60.0, avg_iv * (1.0 + rng.uniform(0.20, 0.40) * rng.choice([-1,1])))
    perturbed_std_iv = std_iv * rng.uniform(1.3, 1.8)
    perturbed_fail   = min(fail_rate + rng.uniform(0.08, 0.15), 0.40)

    events = []
    for _ in range(n):
        iv = max(30.0, rng.normal(perturbed_avg_iv, perturbed_std_iv))
        t += iv
        events.append((t, 0 if rng.random() < perturbed_fail else 1))
    return events


# ── Metrics ────────────────────────────────────────────────────────────────────

def compute_metrics(name, preds, labels):
    p  = precision_score(labels, preds, zero_division=0)
    r  = recall_score(labels, preds, zero_division=0)
    f  = f1_score(labels, preds, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(labels, preds, labels=[0,1]).ravel()
    return {'method': name,
            'precision': round(float(p),4), 'recall': round(float(r),4),
            'f1': round(float(f),4),
            'tp':int(tp), 'fp':int(fp), 'tn':int(tn), 'fn':int(fn)}


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print("="*70)
    print("TAARA T1078 Benchmark v4 (ToD-fusion) — 19-dim AE + ToD in fusion only")
    print("  conf = α·swap_s + β·q_dir + δ·tod_dev + γ·coh·√(swap_s·q_dir·(1+tod_dev))")
    print("  AE input: 19-dim (pure behavioral, unchanged from v3)")
    print("="*70)
    rng = np.random.default_rng(42)

    # ── 1. Load ────────────────────────────────────────────────────────────────
    print("\nStep 1: Loading datasets...")
    ssh_events     = parse_ssh_log(SSH_LOG)
    legit_ips      = {ip:e for ip,e in ssh_events.items()
                      if any(t==1 for _,t in e) and len(e)>=5}
    auth_events    = parse_generic(AUTH_LOG)    if AUTH_LOG.exists() else {}
    elastic_events = parse_generic(ELASTIC_LOG) if ELASTIC_LOG.exists() else {}
    print(f"  SSH.log legit: {len(legit_ips)} | auth: {len(auth_events)} | elastic: {len(elastic_events)}")

    # ── 2. Pretrain AE ─────────────────────────────────────────────────────────
    print("\nStep 2: Pretraining AE (19-dim)...")
    pretrain_feats = np.array(
        extract_windows(legit_ips) +
        extract_windows(auth_events) +
        extract_windows(elastic_events), dtype=np.float32)
    print(f"  Pretrain windows: {len(pretrain_feats)}")
    pretrain_scaler = StandardScaler()
    pretrain_scaler.fit(pretrain_feats)
    ae_pretrained = train_ae(pretrain_feats, pretrain_scaler, epochs=80)
    print(f"  Done.")

    # ── 3. Per-identity finetuning + quantum memory + weight fitting ───────────
    print("\nStep 3: Per-identity finetuning + quantum memory + weight fitting...")
    all_sources = {
        **{f"ssh_{ip}":     e for ip,e in legit_ips.items()},
        **{f"auth_{ip}":    e for ip,e in auth_events.items()},
        **{f"elastic_{ip}": e for ip,e in elastic_events.items()},
    }

    identity_ae      = {}
    identity_pca     = {}
    identity_if      = {}
    identity_test    = {}
    identity_test_raw= {}
    identity_thresh  = {}
    identity_weights = {}
    identity_profile = {}
    all_train_feats  = []

    for iid, evs in all_sources.items():
        wins     = [make_features(evs[i:i+WINDOW]) for i in range(0, len(evs)-WINDOW, 2)]
        raw_wins = [evs[i:i+WINDOW]                for i in range(0, len(evs)-WINDOW, 2)]
        if len(wins) < 6: continue
        split = max(4, len(wins)*3//4)
        train_w     = np.array(wins[:split], dtype=np.float32)
        train_raw_w = raw_wins[:split]
        test_w      = wins[split:]
        test_raw_w  = raw_wins[split:]
        all_train_feats.extend(train_w)

        ae_ft = train_ae(train_w, pretrain_scaler, epochs=30, lr=5e-4,
                         model=copy.deepcopy(ae_pretrained), patience=8)

        normal_z = np.array([get_latent(ae_ft, pretrain_scaler, f) for f in train_w])
        mean_z   = normal_z.mean(0)
        centered = normal_z - mean_z
        try:
            _, _, Vt = scipy_svd(centered, full_matrices=True, check_finite=False,
                                  lapack_driver='gesdd')
        except Exception:
            try:
                _, _, Vt = scipy_svd(centered, full_matrices=True, check_finite=False,
                                      lapack_driver='gesvd')
            except Exception:
                Vt = np.linalg.qr(np.random.randn(centered.shape[1],
                                                    centered.shape[1]))[0].T
        pca_basis      = Vt[:PCA_K]
        pca_complement = Vt[PCA_K:PCA_K+2]

        if_model = IsolationForest(contamination=0.05, n_estimators=100, random_state=42)
        if_model.fit(pretrain_scaler.transform(train_w))

        errs  = [get_recon_error(ae_ft, pretrain_scaler, f) for f in train_w]
        thresh = float(np.percentile(errs, 95))

        profile     = extract_identity_profile(evs)
        mean_hour   = profile['mean_hour']   if profile else 12.0
        hour_spread = profile['hour_spread'] if profile else 3.0

        train_angles = [deviation_angle(z, mean_z, pca_complement) for z in normal_z]
        angle_history = [train_angles[max(0,i-COH_W+1):i+1]
                         for i in range(len(train_angles))]

        alpha, beta, gamma, delta = fit_fusion_weights(
            normal_z, pca_basis, mean_z, pca_complement,
            angle_history, train_raw_w, mean_hour, hour_spread)

        train_scores = []
        for i, f in enumerate(train_w):
            z   = normal_z[i]
            sf  = quantum_subspace_fidelity(z, pca_basis, mean_z)
            qd  = quantum_directionality(z, pca_basis, mean_z, pca_complement)
            coh = phase_coherence(angle_history[i])
            tod = compute_tod_deviation(train_raw_w[i], mean_hour, hour_spread)
            train_scores.append(qconf_v4(sf, qd, coh, tod, alpha, beta, gamma, delta))
        identity_thresh[iid + '_train_scores'] = train_scores

        identity_ae[iid]       = ae_ft
        identity_pca[iid]      = {'basis': pca_basis, 'mean': mean_z,
                                   'complement': pca_complement,
                                   'angle_buffer': deque(train_angles[-COH_W:], maxlen=COH_W)}
        identity_if[iid]       = if_model
        identity_test[iid]     = test_w
        identity_test_raw[iid] = test_raw_w
        identity_thresh[iid]   = thresh
        identity_weights[iid]  = (alpha, beta, gamma, delta)
        identity_profile[iid]  = profile

    all_train_feats = np.array(all_train_feats, dtype=np.float32)
    n_ids = len(identity_ae)
    print(f"  Finetuned identities: {n_ids}")

    all_train_scores = []
    for iid in identity_ae:
        all_train_scores.extend(identity_thresh.get(iid + '_train_scores', []))
    global_conf_thresh = float(np.percentile(all_train_scores, 95)) if all_train_scores else 0.10
    print(f"  Global threshold (p95 normal training): {global_conf_thresh:.4f}")

    w_arr = np.array(list(identity_weights.values()))
    print(f"  Weights mean — α={w_arr[:,0].mean():.3f}(swap) β={w_arr[:,1].mean():.3f}(dir) "
          f"γ={w_arr[:,2].mean():.3f}(itf) δ={w_arr[:,3].mean():.3f}(tod)")
    print(f"  Prior         — α={ALPHA_PRIOR} β={BETA_PRIOR} γ={GAMMA_PRIOR} δ={DELTA_PRIOR}")

    # ── 4. Run detectors ───────────────────────────────────────────────────────
    print("\nStep 4: Running detectors...")
    results = []

    for iid, test_windows in identity_test.items():
        ae      = identity_ae[iid]
        pca     = identity_pca[iid]
        ifc     = identity_if[iid]
        alpha, beta, gamma, delta = identity_weights[iid]
        profile     = identity_profile.get(iid)
        mean_hour   = profile['mean_hour']   if profile else 12.0
        hour_spread = profile['hour_spread'] if profile else 3.0
        angle_buf   = deque(pca['angle_buffer'], maxlen=COH_W)
        raw_wins    = identity_test_raw[iid]

        for i, feat in enumerate(test_windows):
            raw_evs = raw_wins[i] if i < len(raw_wins) else []
            z   = get_latent(ae, pretrain_scaler, feat)
            sf  = quantum_subspace_fidelity(z, pca['basis'], pca['mean'])
            qd  = quantum_directionality(z, pca['basis'], pca['mean'], pca['complement'])
            ang = deviation_angle(z, pca['mean'], pca['complement'])
            angle_buf.append(ang)
            coh = phase_coherence(list(angle_buf))
            tod = compute_tod_deviation(raw_evs, mean_hour, hour_spread)
            conf = qconf_v4(sf, qd, coh, tod, alpha, beta, gamma, delta)
            re_err = get_recon_error(ae, pretrain_scaler, feat)
            if_sc  = float(ifc.score_samples(
                        pretrain_scaler.transform(feat.reshape(1,-1)))[0])
            results.append({
                'label': 0, 'feat': feat,
                'confidence': round(conf,4), 'swap_fidelity': round(sf,4),
                'q_directionality': round(qd,4), 'phase_coherence': round(coh,4),
                'tod_deviation': round(tod,4), 'recon_err': round(re_err,4),
                'if_score': round(if_sc,4), 'anomalous': conf > global_conf_thresh,
                'alpha':round(alpha,3),'beta':round(beta,3),
                'gamma':round(gamma,3),'delta':round(delta,3),
            })

    all_ids = list(identity_ae.keys())
    n_t1078 = 0
    for idx, iid in enumerate(all_ids):
        ae      = identity_ae[iid]
        pca     = identity_pca[iid]
        ifc     = identity_if[iid]
        alpha, beta, gamma, delta = identity_weights[iid]
        profile = identity_profile.get(iid)
        if profile is None: continue
        mean_hour   = profile['mean_hour']
        hour_spread = profile['hour_spread']
        t_start = (max(t for t,_ in all_sources[iid]) + 3600
                   if all_sources.get(iid) else 1_000_000 + idx*86400)
        atk_angle_buf = deque(maxlen=COH_W)

        for j in range(3):
            evs  = inject_t1078(profile, rng, t_start + j*7200, n=WINDOW)
            feat = make_features(evs)
            z    = get_latent(ae, pretrain_scaler, feat)
            sf   = quantum_subspace_fidelity(z, pca['basis'], pca['mean'])
            qd   = quantum_directionality(z, pca['basis'], pca['mean'], pca['complement'])
            ang  = deviation_angle(z, pca['mean'], pca['complement'])
            atk_angle_buf.append(ang)
            coh  = phase_coherence(list(atk_angle_buf))
            tod  = compute_tod_deviation(evs, mean_hour, hour_spread)
            conf = qconf_v4(sf, qd, coh, tod, alpha, beta, gamma, delta)
            re_err = get_recon_error(ae, pretrain_scaler, feat)
            if_sc  = float(ifc.score_samples(
                        pretrain_scaler.transform(feat.reshape(1,-1)))[0])
            results.append({
                'label': 1, 'feat': feat,
                'confidence': round(conf,4), 'swap_fidelity': round(sf,4),
                'q_directionality': round(qd,4), 'phase_coherence': round(coh,4),
                'tod_deviation': round(tod,4), 'recon_err': round(re_err,4),
                'if_score': round(if_sc,4), 'anomalous': conf > global_conf_thresh,
                'alpha':round(alpha,3),'beta':round(beta,3),
                'gamma':round(gamma,3),'delta':round(delta,3),
            })
            n_t1078 += 1

    print(f"  Test: {sum(1 for r in results if r['label']==0)} normal + {n_t1078} T1078 attacks")

    # ── 5. Metrics ─────────────────────────────────────────────────────────────
    labels      = np.array([r['label']      for r in results])
    taara_preds = np.array([1 if r['anomalous'] else 0 for r in results])
    all_feats   = np.array([r['feat']       for r in results], dtype=np.float32)
    conf_scores = np.array([r['confidence'] for r in results])

    global_if = IsolationForest(contamination=0.05, n_estimators=200, random_state=42)
    global_if.fit(pretrain_scaler.transform(all_train_feats))
    global_if_preds = np.where(
        global_if.predict(pretrain_scaler.transform(all_feats)) == -1, 1, 0)

    taara_m = compute_metrics("TAARA v4-ToD (19-dim AE + ToD fusion)", taara_preds, labels)
    if_m    = compute_metrics("IsolationForest global (Splunk/Sentinel)", global_if_preds, labels)
    auc_taara = roc_auc_score(labels, np.clip(conf_scores, 0, 10))
    auc_if    = roc_auc_score(labels, -global_if.score_samples(
                    pretrain_scaler.transform(all_feats)))

    sf_n  = [r['swap_fidelity']    for r in results if r['label']==0]
    sf_a  = [r['swap_fidelity']    for r in results if r['label']==1]
    qd_n  = [r['q_directionality'] for r in results if r['label']==0]
    qd_a  = [r['q_directionality'] for r in results if r['label']==1]
    coh_n = [r['phase_coherence']  for r in results if r['label']==0]
    coh_a = [r['phase_coherence']  for r in results if r['label']==1]
    tod_n = [r['tod_deviation']    for r in results if r['label']==0]
    tod_a = [r['tod_deviation']    for r in results if r['label']==1]
    cn_n  = [r['confidence']       for r in results if r['label']==0]
    cn_a  = [r['confidence']       for r in results if r['label']==1]

    # ── 6. Print ───────────────────────────────────────────────────────────────
    print("\n" + "="*70)
    print("RESULTS")
    print("="*70)
    print(f"\n{'Method':<46} {'Prec':>6} {'Rec':>6} {'F1':>6} {'AUC':>6} "
          f"{'TP':>4} {'FP':>4} {'FN':>4}")
    print("-"*80)
    for m, auc in [(taara_m, auc_taara), (if_m, auc_if)]:
        print(f"{m['method']:<46} {m['precision']:>6.3f} {m['recall']:>6.3f} "
              f"{m['f1']:>6.3f} {auc:>6.3f} {m['tp']:>4} {m['fp']:>4} {m['fn']:>4}")

    print(f"\nF1 delta  (TAARA vs IF): {taara_m['f1']-if_m['f1']:+.4f}")
    print(f"AUC delta (TAARA vs IF): {auc_taara-auc_if:+.4f}")
    print(f"\nv3 reference:  Prec=0.689  Rec=0.942  F1=0.796  AUC=0.980")

    print(f"\nSignal separation on REAL data:")
    print(f"  SWAP fidelity:   normal={np.mean(sf_n):.4f}  attack={np.mean(sf_a):.4f}  gap={np.mean(sf_n)-np.mean(sf_a):+.4f}")
    print(f"  Directionality:  normal={np.mean(qd_n):.4f}  attack={np.mean(qd_a):.4f}  gap={np.mean(qd_a)-np.mean(qd_n):+.4f}")
    print(f"  Phase coherence: normal={np.mean(coh_n):.4f}  attack={np.mean(coh_a):.4f}  gap={np.mean(coh_a)-np.mean(coh_n):+.4f}")
    print(f"  ToD deviation:   normal={np.mean(tod_n):.4f}  attack={np.mean(tod_a):.4f}  gap={np.mean(tod_a)-np.mean(tod_n):+.4f}")
    print(f"  Confidence:      normal={np.mean(cn_n):.4f}  attack={np.mean(cn_a):.4f}  gap={np.mean(cn_a)-np.mean(cn_n):+.4f}")
    print(f"  Threshold: {global_conf_thresh:.4f}")

    print(f"\nWeights mean across {n_ids} identities:")
    print(f"  α={w_arr[:,0].mean():.3f}(swap) β={w_arr[:,1].mean():.3f}(dir) "
          f"γ={w_arr[:,2].mean():.3f}(itf) δ={w_arr[:,3].mean():.3f}(tod)")

    # ── 7. Save ────────────────────────────────────────────────────────────────
    output = {
        'benchmark': 'MITRE ATT&CK T1078 — Valid Account credential theft',
        'version': '4.0 — 19-dim AE (unchanged) + ToD as additive+interference fusion signal',
        'fusion_formula': 'conf = α·swap_s + β·q_dir + δ·tod_dev + γ·coh·√(swap_s·q_dir·(1+tod_dev))',
        'global_prior': {'alpha':ALPHA_PRIOR,'beta':BETA_PRIOR,
                         'gamma':GAMMA_PRIOR,'delta':DELTA_PRIOR},
        'fit_weights': {
            'alpha_mean': round(float(w_arr[:,0].mean()),4),
            'beta_mean':  round(float(w_arr[:,1].mean()),4),
            'gamma_mean': round(float(w_arr[:,2].mean()),4),
            'delta_mean': round(float(w_arr[:,3].mean()),4),
        },
        'datasets': {
            'pretrain_ae': 'SSH.log legit + auth.log + elastic_auth.log',
            'finetune': 'Per-identity on same sources',
            't1078_injection': '±20-40% interval shift, 1.3-1.8x jitter, +8-15% fail rate + 6-10h hour shift',
        },
        'results': {
            'taara': taara_m, 'iforest_global': if_m,
            'auc_taara': round(auc_taara,4), 'auc_iforest': round(auc_if,4),
            'f1_delta': round(taara_m['f1']-if_m['f1'],4),
            'auc_delta': round(auc_taara-auc_if,4),
        },
        'signal_separation': {
            'swap_normal':  round(float(np.mean(sf_n)),4),
            'swap_attack':  round(float(np.mean(sf_a)),4),
            'swap_gap':     round(float(np.mean(sf_n)-np.mean(sf_a)),4),
            'dir_normal':   round(float(np.mean(qd_n)),4),
            'dir_attack':   round(float(np.mean(qd_a)),4),
            'dir_gap':      round(float(np.mean(qd_a)-np.mean(qd_n)),4),
            'coh_normal':   round(float(np.mean(coh_n)),4),
            'coh_attack':   round(float(np.mean(coh_a)),4),
            'coh_gap':      round(float(np.mean(coh_a)-np.mean(coh_n)),4),
            'tod_normal':   round(float(np.mean(tod_n)),4),
            'tod_attack':   round(float(np.mean(tod_a)),4),
            'tod_gap':      round(float(np.mean(tod_a)-np.mean(tod_n)),4),
            'conf_normal':  round(float(np.mean(cn_n)),4),
            'conf_attack':  round(float(np.mean(cn_a)),4),
            'conf_gap':     round(float(np.mean(cn_a)-np.mean(cn_n)),4),
            'threshold':    round(global_conf_thresh,4),
        },
        'v3_reference': {'precision':0.689,'recall':0.942,'f1':0.796,'auc':0.980},
    }
    out = RESULTS_DIR / "experiment_results_v4_tod.json"
    with open(out, "w") as f: json.dump(output, f, indent=2)
    print(f"\nSaved: {out}")
    print("="*70)


if __name__ == "__main__":
    t0 = time.time()
    main()
    print(f"\nTotal time: {time.time()-t0:.1f}s")
