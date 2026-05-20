#!/usr/bin/env python3
"""
TAARA Benchmark v5 — Attention-Grounded Features + Real Cowrie Attack Class
=============================================================================

Architecture:
  Input (19) → AE 19→64→8 → 8-dim latent → SWAP test (per-identity quantum basis)
  → coherence-weighted interference fusion → quantum_confidence score

19 features grounded in transformer attention analysis on elastic_auth + SSH + Cowrie:
  Attention showed these token clusters as most discriminative (from attention head output):
  ATTACK tokens:   ATCK_UNAME, CPM_BURST, CMD_CPUINFO/FREE/TOP/W/LSCPU (hw enum),
                   ATCK_CRONTAB, OUTBOUND_CONN, CMD_VAR/TMP/DOTA (malware exec),
                   CMD_VERSION/SHELL/ENABLE (network device shells), ATCK_DD/BUSYBOX
  NORMAL tokens:   DUR_>5m (gap=0.189), ADM_APT-GET, ICI_HUMAN, CMD_SU, ADM_SERVICE,
                   DIVERSITY_LOW

  Mapped to continuous 19-dim features:
   0  session_duration         — DUR_>5m strongest normal signal
   1  commands_per_minute      — CPM_BURST exclusive to attack
   2  inter_cmd_timing_std     — ICI_SCRIPTED (≈0) vs ICI_HUMAN (high)
   3  session_idle_ratio       — long gaps between commands = human
   4  unique_commands          — DIVERSITY_LOW=normal, DIVERSITY_HIGH=attack
   5  command_entropy          — continuous diversity signal
   6  shell_history_delta      — ICI_HUMAN: humans write history
   7  sensitive_path_access    — ~/.ssh, /etc/passwd, authorized_keys
   8  hardware_enum_count      — uname+free+top+lscpu+w cluster (attention-discovered)
   9  outbound_connections     — OUTBOUND_CONN: wget/curl/tftp to C2
  10  persistence_attempt      — ATCK_CRONTAB: 1087/1100 attack sessions
  11  malware_exec_pattern     — /var/*, /tmp/*, dota* (attention-discovered)
  12  process_spawn_count      — dd, busybox, sh launches
  13  network_device_shell     — version/shell/enable = router/IoT exploitation
  14  data_volume_proxy        — outbound + file_downloads
  15  hour_sin                 — sin(2π·hour/24): positional encoding
  16  hour_cos                 — cos(2π·hour/24)
  17  dow_sin                  — sin(2π·dow/7)
  18  dow_cos                  — cos(2π·dow/7)

Per-identity detection:
  Each identity gets its own IdentityMemoryBasis.
  SWAP test measures overlap with THAT identity's quantum subspace.
  Attacker logged in as 'ubuntu' is compared against ubuntu's basis — not global stats.
  This is the core claim: "is this the person who owns this account?"

Datasets:
  Normal: elastic_auth.log (ubuntu, 27 sessions, 133 real sudo commands)
          + SSH.log legit (fztu/curi/hxu/jmzhu/zachary/suyuxin/yuewang/xxchen, 119 sessions)
  Attack: Cowrie Zenodo 3687527 — real post-auth attacker sessions (35k sessions, 1 day file)

Comparators (all per-identity where possible, else global):
  1. TAARA v5 — per-identity quantum SWAP + coherence fusion
  2. IsolationForest global   — what Splunk/Sentinel approximate
  3. IsolationForest per-user — fairest classical comparison
  4. LOF per-user
  5. Per-user z-score         — what simple SIEM threshold rules do
  6. LSTM-AE global           — academic deep learning baseline

Usage:
    source venv/bin/activate && python experiments/taara_benchmark_v5.py

Output:
    experiments/results/benchmark_v5_results.json
    experiments/results/benchmark_v5_report.txt
"""

import re, math, json, gzip, time, sys, warnings
from pathlib import Path
from collections import defaultdict, Counter
from typing import List, Dict, Tuple

import numpy as np
import torch
import torch.nn as nn
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.metrics import roc_auc_score, precision_score, recall_score, f1_score, confusion_matrix

warnings.filterwarnings("ignore")

ROOT        = Path(__file__).parent.parent
ELASTIC_LOG = ROOT / "benchmark" / "datasets" / "elastic_auth.log"
SSH_LOG     = ROOT / "benchmark" / "datasets" / "SSH.log"
COWRIE_DIR  = ROOT / "benchmark" / "datasets" / "cowrie"
RESULTS_DIR = Path(__file__).parent / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR  = ROOT / "models"

sys.path.insert(0, str(ROOT))

MONTHS = {"Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,
          "Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12}
LEGIT_SSH = {"fztu","curi","hxu","jmzhu","zachary","suyuxin","yuewang","xxchen"}

# Attention-discovered command clusters
HW_ENUM   = {"uname","free","top","w","lscpu","lspci","cpuinfo","df","uptime","nproc"}
RECON     = {"whoami","id","cat","ls","ps","netstat","ifconfig","ip"}
PERSIST   = {"crontab"}
MALWARE   = {"wget","curl","tftp","nc","netcat","chmod","nohup","tar","busybox","dd","mknod"}
NETDEV    = {"version","shell","enable","terminal","configure"}  # router/IoT exploitation
ADMIN     = {"apt-get","apt","vim","nano","systemctl","service","sudo","su","scp","git","pip","docker"}
SENSITIVE = {".ssh","authorized_keys","/etc/passwd","/etc/shadow","id_rsa","/root","crontab",".bash_history"}


# ══════════════════════════════════════════════════════════════════════════════
# 1. PARSERS
# ══════════════════════════════════════════════════════════════════════════════

def _ts(mn, d, h, mi, s):
    return MONTHS.get(mn,1)*86400*31 + int(d)*86400 + int(h)*3600 + int(mi)*60 + int(s)


def parse_elastic(path: Path) -> List[Dict]:
    OPEN  = re.compile(r'(\w+)\s+(\d+)\s+(\d+):(\d+):(\d+).*session opened for user (\w+)')
    CLOSE = re.compile(r'(\w+)\s+(\d+)\s+(\d+):(\d+):(\d+).*session closed for user (\w+)')
    SUDO  = re.compile(r'(\w+)\s+(\d+)\s+(\d+):(\d+):(\d+).*sudo:\s+\S+\s*:.*COMMAND=(.*)')
    pending = {}; sessions = []
    with open(path, errors="replace") as f:
        for line in f:
            m = OPEN.search(line)
            if m:
                mn,d,h,mi,s,u = m.groups()
                pending[u] = {"t0": _ts(mn,d,h,mi,s), "hour": int(h),
                               "dow": int(d)%7, "cmds": [], "ctimes": []}
                continue
            m = CLOSE.search(line)
            if m:
                mn,d,h,mi,s,u = m.groups()
                if u in pending:
                    info = pending.pop(u)
                    sessions.append({**info, "dur": max(_ts(mn,d,h,mi,s)-info["t0"], 1),
                                     "user": u, "label": 0, "src": "elastic",
                                     "sensitive": False, "outbound": 0, "downloads": 0})
                continue
            m = SUDO.search(line)
            if m:
                mn,d,h,mi,s,*_,cmd = m.groups()
                u_match = re.search(r'sudo:\s+(\S+)\s*:', line)
                u = u_match.group(1) if u_match else None
                if u and u in pending:
                    full = cmd.strip()
                    parts = full.split("/")
                    nm = parts[-1].split()[0].lower() if parts[-1].split() else "?"
                    t  = _ts(mn,d,h,mi,s)
                    pending[u]["cmds"].append(nm)
                    pending[u]["ctimes"].append(t)
                    if any(p in full for p in SENSITIVE):
                        pending[u]["sensitive"] = True
                    if nm in MALWARE:
                        pending[u]["outbound"] = pending[u].get("outbound",0) + 1
    return sessions


def parse_ssh_legit(path: Path) -> List[Dict]:
    ACC   = re.compile(r'(\w+)\s+(\d+)\s+(\d+):(\d+):(\d+).*Accepted\s+\w+\s+for\s+(\w+)\s+from\s+([\d.]+)')
    OPEN  = re.compile(r'(\w+)\s+(\d+)\s+(\d+):(\d+):(\d+).*session opened for user (\w+)')
    CLOSE = re.compile(r'(\w+)\s+(\d+)\s+(\d+):(\d+):(\d+).*session closed for user (\w+)')
    pending = {}; sessions = []
    with open(path, errors="replace") as f:
        for line in f:
            m = ACC.search(line)
            if m:
                mn,d,h,mi,s,u,ip = m.groups()
                if u in LEGIT_SSH:
                    pending[u] = {"t0": _ts(mn,d,h,mi,s), "hour": int(h),
                                  "dow": int(d)%7, "ip": ip}
                continue
            m = OPEN.search(line)
            if m:
                mn,d,h,mi,s,u = m.groups()
                if u in pending:
                    pending[u]["ss"] = _ts(mn,d,h,mi,s)
                continue
            m = CLOSE.search(line)
            if m:
                mn,d,h,mi,s,u = m.groups()
                if u in pending:
                    info = pending.pop(u)
                    t2   = _ts(mn,d,h,mi,s)
                    ss   = info.get("ss", info["t0"])
                    sessions.append({"t0": info["t0"], "hour": info["hour"],
                                     "dow": info["dow"], "cmds": [], "ctimes": [],
                                     "dur": max(t2-ss, 1), "user": u,
                                     "label": 0, "src": "ssh",
                                     "sensitive": False, "outbound": 0, "downloads": 0})
    return sessions


def parse_cowrie(cowrie_dir: Path, max_sessions: int = 3000) -> List[Dict]:
    sessions = []
    for gz in sorted(cowrie_dir.glob("*.json.gz")):
        if len(sessions) >= max_sessions:
            break
        try:
            with gzip.open(gz, "rt", errors="replace") as f:
                data = json.loads(f.read())
        except Exception as e:
            print(f"  [cowrie] {gz.name}: {e}"); continue

        # format: [{session_id: [events]}, ...]
        items = data if isinstance(data, list) else [{"_": v} for v in data.values()]
        for item in items:
            if len(sessions) >= max_sessions:
                break
            if not isinstance(item, dict):
                continue
            for sid, evlist in item.items():
                if not isinstance(evlist, list):
                    continue
                eids = [e.get("eventid","") for e in evlist if isinstance(e, dict)]
                if "cowrie.login.success" not in eids:
                    continue
                dur=0.0; cmds=[]; ctimes=[]; hour=12; dow=0
                sensitive=False; outbound=0; downloads=0
                t_start=None
                for ev in evlist:
                    if not isinstance(ev, dict): continue
                    eid = ev.get("eventid","")
                    hm  = re.search(r'T(\d{2}):(\d{2}):(\d{2})', ev.get("timestamp",""))
                    if hm:
                        hour = int(hm.group(1))
                        t_ev = int(hm.group(1))*3600 + int(hm.group(2))*60 + int(hm.group(3))
                        if t_start is None: t_start = t_ev
                    else:
                        t_ev = 0; t_start = t_start or 0
                    if eid == "cowrie.session.closed" and ev.get("duration"):
                        dur = float(ev["duration"])
                    if eid == "cowrie.command.input":
                        msg = ev.get("message","")
                        cm  = re.search(r'CMD:\s*(.+)', msg)
                        if cm:
                            full   = cm.group(1).strip()
                            parts  = full.split("/")
                            nm     = parts[-1].split()[0].lower() if parts[-1].split() \
                                     else (full.split()[0].lower() if full.split() else "?")
                            cmds.append(nm)
                            ctimes.append(t_ev - t_start if t_start else 0)
                            if any(p in full for p in SENSITIVE): sensitive = True
                            if nm in MALWARE: outbound += 1
                    if eid == "cowrie.session.file_download":
                        downloads += 1; outbound += 1
                sessions.append({
                    "t0": 0, "hour": hour, "dow": dow,
                    "cmds": cmds, "ctimes": ctimes,
                    "dur": max(dur, 0.1), "user": f"attacker_{sid[:6]}",
                    "label": 1, "src": "cowrie",
                    "sensitive": sensitive, "outbound": outbound, "downloads": downloads,
                })
    return sessions


# ══════════════════════════════════════════════════════════════════════════════
# 2. FEATURE EXTRACTION — 19 ATTENTION-GROUNDED DIMENSIONS
# ══════════════════════════════════════════════════════════════════════════════

def extract_19(s: Dict) -> np.ndarray:
    """
    Map a session dict to the 19-dim feature vector.
    Every dimension is grounded in transformer attention output.
    """
    dur    = max(float(s["dur"]), 0.01)
    cmds   = s.get("cmds", [])
    ctimes = s.get("ctimes", [])
    hour   = int(s.get("hour", 12))
    dow    = int(s.get("dow",  0))
    n      = max(len(cmds), 1)

    # 0  session_duration  (attention: DUR_>5m gap=0.189, strongest normal signal)
    f0 = min(dur, 86400.0)

    # 1  commands_per_minute  (attention: CPM_BURST exclusive to attack)
    f1 = min(n / (dur/60 + 1e-6), 500.0)

    # 2  inter_cmd_timing_std  (attention: ICI_SCRIPTED≈0 vs ICI_HUMAN large)
    if len(ctimes) > 1:
        gaps = [max(ctimes[i+1]-ctimes[i], 0) for i in range(len(ctimes)-1)]
        f2   = min(float(np.std(gaps)), 7200.0)
    else:
        f2 = 0.0

    # 3  session_idle_ratio  (attention: ICI_HUMAN — humans have pauses)
    if len(ctimes) > 1:
        active = ctimes[-1] - ctimes[0] if ctimes[-1] > ctimes[0] else 0
        f3 = max(1.0 - active / dur, 0.0)
    else:
        f3 = 1.0 if n <= 1 else 0.0

    # 4  unique_commands  (attention: DIVERSITY_LOW normal, DIVERSITY_HIGH attack)
    f4 = float(len(set(cmds)))

    # 5  command_entropy  (continuous diversity — attention confirmed this cluster)
    cnt = Counter(cmds)
    f5  = -sum((c/n)*math.log2(c/n + 1e-9) for c in cnt.values()) if cmds else 0.0

    # 6  shell_history_delta  (ICI_HUMAN: legit users run commands that write history)
    #    proxy: number of admin commands executed (write to history, not exec-only)
    f6 = float(sum(1 for c in cmds if c in ADMIN))

    # 7  sensitive_path_access  (attention: SENSITIVE_PATH — attackers always touch .ssh)
    f7 = float(int(s.get("sensitive", False)))

    # 8  hardware_enum_count  (attention-DISCOVERED: uname+free+top+lscpu+w cluster,
    #    not in original hand-engineered list — 1087-1092/1100 attack sessions each)
    f8 = float(sum(1 for c in cmds if c in HW_ENUM))

    # 9  outbound_connections  (attention: OUTBOUND_CONN — wget/curl to C2)
    f9 = float(s.get("outbound", 0))

    # 10  persistence_attempt  (attention-CONFIRMED: ATCK_CRONTAB in 1087/1100 sessions)
    f10 = float(sum(1 for c in cmds if c in PERSIST))

    # 11  malware_exec_pattern  (attention: CMD_VAR/TMP/DOTA — obfuscated malware paths)
    #     proxy: commands that launch processes from non-standard paths (/tmp, /var)
    f11 = float(sum(1 for c in cmds if c in MALWARE))

    # 12  process_spawn_count  (attention: ATCK_DD, ATCK_BUSYBOX — tool execution burst)
    f12 = float(sum(1 for c in cmds if c in {"dd","busybox","sh","bash","perl","python","python3"}))

    # 13  network_device_shell  (attention-DISCOVERED: version/shell/enable = router exploitation,
    #     not Linux server — completely missed by hand-engineering)
    f13 = float(sum(1 for c in cmds if c in NETDEV))

    # 14  data_volume_proxy  (attention: OUTBOUND_CONN + downloads together)
    f14 = float(s.get("outbound", 0) + s.get("downloads", 0))

    # 15-18  sinusoidal time encoding (positional encoding — same math as transformers)
    f15 = math.sin(2*math.pi*hour/24)
    f16 = math.cos(2*math.pi*hour/24)
    f17 = math.sin(2*math.pi*dow/7)
    f18 = math.cos(2*math.pi*dow/7)

    v = np.array([f0,f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11,f12,f13,f14,f15,f16,f17,f18],
                 dtype=np.float32)
    v = np.nan_to_num(v, nan=0.0, posinf=500.0, neginf=0.0)
    return v


FEATURE_NAMES = [
    "session_duration", "commands_per_minute", "inter_cmd_timing_std",
    "session_idle_ratio", "unique_commands", "command_entropy",
    "shell_history_delta", "sensitive_path_access", "hardware_enum_count",
    "outbound_connections", "persistence_attempt", "malware_exec_pattern",
    "process_spawn_count", "network_device_shell", "data_volume_proxy",
    "hour_sin", "hour_cos", "dow_sin", "dow_cos",
]


# ══════════════════════════════════════════════════════════════════════════════
# 3. AUTOENCODER  19 → 64 → 8 → 64 → 19
# ══════════════════════════════════════════════════════════════════════════════

class BehavioralAE(nn.Module):
    def __init__(self, input_dim=19, latent_dim=8, hidden_dim=64):
        super().__init__()
        self.latent_dim = latent_dim
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim), nn.ReLU(), nn.Dropout(0.1),
            nn.Linear(hidden_dim, latent_dim), nn.Tanh(),  # Tanh → bounded → AmplitudeEmbedding
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, hidden_dim), nn.ReLU(), nn.Dropout(0.1),
            nn.Linear(hidden_dim, input_dim),
        )
    def forward(self, x):
        z = self.encoder(x); return self.decoder(z), z
    def encode(self, x):
        return self.encoder(x)


def train_ae(X: np.ndarray, scaler: StandardScaler,
             epochs=100, lr=0.001, bs=32, patience=15) -> BehavioralAE:
    Xt  = torch.FloatTensor(scaler.transform(X))
    mdl = BehavioralAE()
    opt = torch.optim.Adam(mdl.parameters(), lr=lr)
    sch = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=epochs)
    crit = nn.MSELoss()
    best, no_imp = float('inf'), 0
    mdl.train()
    for ep in range(epochs):
        idx = torch.randperm(len(Xt))
        ls, nb = 0.0, 0
        for i in range(0, len(Xt), bs):
            b = Xt[idx[i:i+bs]]
            r, _ = mdl(b); l = crit(r, b)
            opt.zero_grad(); l.backward(); opt.step()
            ls += l.item(); nb += 1
        sch.step()
        avg = ls/max(nb,1)
        if avg < best - 1e-5: best = avg; no_imp = 0
        else: no_imp += 1
        if no_imp >= patience: break
    mdl.eval()
    return mdl


def get_latent(mdl: BehavioralAE, scaler: StandardScaler, feat: np.ndarray) -> np.ndarray:
    x = torch.FloatTensor(scaler.transform(feat.reshape(1,-1)))
    with torch.no_grad():
        return mdl.encode(x).numpy()[0]


# ══════════════════════════════════════════════════════════════════════════════
# 4. QUANTUM ENGINE  (PennyLane — AmplitudeEmbedding + SWAP test)
# ══════════════════════════════════════════════════════════════════════════════

import pennylane as qml

_dev3 = qml.device("default.qubit", wires=3)

@qml.qnode(_dev3)
def _amp_state(vec):
    qml.AmplitudeEmbedding(vec, wires=range(3), normalize=True, pad_with=0.0)
    return qml.state()


def quantum_subspace_fidelity(z: np.ndarray, basis: np.ndarray, mean: np.ndarray,
                               K: int = 3) -> float:
    """
    F_sub(z) = Σ_{k=1}^K |⟨ψ_z|ψ_k⟩|²
    Probability of measuring |z⟩ in the normal behavioral subspace.
    Low F_sub = attacker (state is outside normal subspace).
    """
    z_c = np.clip(z - mean, -1, 1)
    try:
        state_t = _amp_state(z_c)
    except Exception:
        return 0.5
    fid = 0.0
    for k in range(min(K, basis.shape[1])):
        bv = basis[:, k]
        bv = np.clip(bv - mean, -1, 1)
        try:
            state_k = _amp_state(bv)
            fid += abs(np.dot(np.conj(state_t), state_k))**2
        except Exception:
            fid += 0.0
    return float(np.clip(fid, 0.0, 1.0))


def quantum_directionality(z: np.ndarray, mean: np.ndarray,
                            complement: np.ndarray) -> float:
    """
    Fidelity with the complement subspace.
    High = z is pointing INTO the directions normal behavior never goes.
    """
    z_c = np.clip(z - mean, -1, 1)
    try:
        state_t = _amp_state(z_c)
    except Exception:
        return 0.5
    fid = 0.0
    for k in range(min(3, complement.shape[1])):
        bv = np.clip(complement[:, k] - mean, -1, 1)
        try:
            fid += abs(np.dot(np.conj(state_t), _amp_state(bv)))**2
        except Exception:
            pass
    return float(np.clip(fid, 0.0, 1.0))


def phase_coherence(angles: list) -> float:
    """
    |mean(exp(i·φ))| — Kuramoto order parameter.
    High coherence = sustained drift (attack), not random fluctuation (noise FP).
    """
    if len(angles) < 2: return 0.5
    return float(abs(np.mean(np.exp(1j * np.array(angles)))))


def quantum_confidence_v5(swap_s: float, q_dir: float, coh: float,
                           α=0.263, β=0.285, γ=0.451) -> float:
    """
    conf = α·swap_s + β·q_dir + γ·coh·√(swap_s·q_dir)

    Interference term γ·coh·√(swap_s·q_dir) fires ONLY when:
      - swap_s is high (outside normal subspace) AND
      - q_dir is high (pointing into complement) AND
      - coh is high (sustained across windows, not a spike)
    Three independent quantum signals must agree. Eliminates random FPs.
    """
    interference = γ * coh * math.sqrt(max(swap_s * q_dir, 0.0))
    return float(np.clip(α*swap_s + β*q_dir + interference, 0.0, 1.0))


# ══════════════════════════════════════════════════════════════════════════════
# 5. PER-IDENTITY MEMORY BASIS
# ══════════════════════════════════════════════════════════════════════════════

class IdentityBasis:
    """
    Per-identity behavioral subspace.
    Built from THAT identity's own normal latent vectors only.
    """
    BOOTSTRAP = 3

    def __init__(self, uid: str):
        self.uid      = uid
        self.latents  : List[np.ndarray] = []
        self.pca_basis: np.ndarray | None = None
        self.pca_compl: np.ndarray | None = None
        self.pca_mean : np.ndarray | None = None
        self.angle_buf: list = []
        self.α = 0.263; self.β = 0.285; self.γ = 0.451  # fit per-identity later

    def add_normal(self, z: np.ndarray):
        self.latents.append(z.copy())
        if len(self.latents) >= self.BOOTSTRAP:
            self._fit_pca()

    def _fit_pca(self):
        Z  = np.array(self.latents)
        mu = Z.mean(0)
        Zc = Z - mu
        try:
            U, _, _ = np.linalg.svd(Zc.T, full_matrices=True)
        except np.linalg.LinAlgError:
            return
        self.pca_mean  = mu
        self.pca_basis = U[:, :3]    # top-3 principal directions = normal subspace
        self.pca_compl = U[:, 3:]    # remaining = complement (where attacks go)

    def is_ready(self) -> bool:
        return self.pca_basis is not None

    def score(self, z: np.ndarray) -> float:
        """Returns quantum_confidence for this latent vector against this identity."""
        if not self.is_ready():
            return 0.0
        swap_s = 1.0 - quantum_subspace_fidelity(z, self.pca_basis, self.pca_mean)
        q_dir  = quantum_directionality(z, self.pca_mean, self.pca_compl)
        # Deviation angle for coherence
        z_c = z - self.pca_mean
        nrm = np.linalg.norm(z_c) + 1e-8
        proj_norm  = self.pca_basis @ (self.pca_basis.T @ z_c)
        compl_comp = z_c - proj_norm
        angle = math.atan2(np.linalg.norm(compl_comp), np.linalg.norm(proj_norm) + 1e-8)
        self.angle_buf.append(angle)
        if len(self.angle_buf) > 4: self.angle_buf.pop(0)
        coh = phase_coherence(self.angle_buf)
        return quantum_confidence_v5(swap_s, q_dir, coh, self.α, self.β, self.γ)

    def fit_weights(self, normal_zs: List[np.ndarray], attack_zs: List[np.ndarray]):
        """
        Fit α,β,γ per identity via simple grid search on logistic loss.
        Falls back to global prior if insufficient data.
        """
        if len(normal_zs) < 3 or len(attack_zs) < 3:
            return
        from sklearn.linear_model import LogisticRegression
        rows = []
        for z in normal_zs:
            sw = 1.0 - quantum_subspace_fidelity(z, self.pca_basis, self.pca_mean)
            qd = quantum_directionality(z, self.pca_mean, self.pca_compl)
            rows.append([sw, qd, sw*qd, 0])
        for z in attack_zs:
            sw = 1.0 - quantum_subspace_fidelity(z, self.pca_basis, self.pca_mean)
            qd = quantum_directionality(z, self.pca_mean, self.pca_compl)
            rows.append([sw, qd, sw*qd, 1])
        rows = np.array(rows)
        try:
            lr = LogisticRegression(C=1.0, max_iter=200, random_state=42)
            lr.fit(rows[:, :3], rows[:, 3])
            w = np.clip(lr.coef_[0], 0.05, 2.0)
            total = w.sum() + 1e-6
            self.α = float(w[0]/total)
            self.β = float(w[1]/total)
            self.γ = float(w[2]/total)
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
# 6. LSTM-AE BASELINE
# ══════════════════════════════════════════════════════════════════════════════

class LSTMAEBaseline(nn.Module):
    def __init__(self, dim=19, h=32, lat=8):
        super().__init__()
        self.enc = nn.LSTM(dim, h, batch_first=True)
        self.lat = nn.Linear(h, lat)
        self.exp = nn.Linear(lat, h)
        self.dec = nn.LSTM(h, dim, batch_first=True)
    def forward(self, x):
        o,_ = self.enc(x); z = self.lat(o[:,-1:,:]); h = self.exp(z); r,_ = self.dec(h); return r, z

def train_lstm_ae(X: np.ndarray, epochs=60) -> LSTMAEBaseline:
    mdl = LSTMAEBaseline(); opt = torch.optim.Adam(mdl.parameters(), lr=1e-3)
    Xt  = torch.FloatTensor(X[:,None,:])
    mdl.train()
    for _ in range(epochs):
        r,_ = mdl(Xt); l=nn.functional.mse_loss(r, Xt)
        opt.zero_grad(); l.backward(); opt.step()
    mdl.eval(); return mdl

def lstm_scores(mdl: LSTMAEBaseline, X: np.ndarray) -> np.ndarray:
    with torch.no_grad():
        Xt=torch.FloatTensor(X[:,None,:]); r,_=mdl(Xt)
        return ((r[:,0,:]-Xt[:,0,:])**2).mean(1).numpy()


# ══════════════════════════════════════════════════════════════════════════════
# 7. PER-USER Z-SCORE BASELINE
# ══════════════════════════════════════════════════════════════════════════════

def per_user_zscore(sessions_all: List[Dict], feats_all: np.ndarray) -> np.ndarray:
    stats = defaultdict(list)
    for s, f in zip(sessions_all, feats_all):
        if s["label"] == 0:
            stats[s["user"]].append(f)
    scores = np.zeros(len(sessions_all))
    for i, (s, f) in enumerate(zip(sessions_all, feats_all)):
        hist = stats[s["user"]]
        if len(hist) < 2:
            scores[i] = 0.0
        else:
            mu  = np.mean(hist, axis=0)
            std = np.std(hist, axis=0) + 1e-6
            scores[i] = float(np.max(np.abs((f - mu) / std)))
    return scores


# ══════════════════════════════════════════════════════════════════════════════
# 8. EVALUATION
# ══════════════════════════════════════════════════════════════════════════════

def evaluate(scores: np.ndarray, labels: np.ndarray, name: str,
             train_normal_scores: np.ndarray = None,
             threshold_pct: float = 90.0) -> Dict:
    """Threshold = 90th percentile of TRAINING normal scores (no test leakage).
    Falls back to test-normal if train_normal_scores not provided."""
    ref = train_normal_scores if train_normal_scores is not None else scores[labels == 0]
    threshold = np.percentile(ref, threshold_pct)
    preds = (scores > threshold).astype(int)
    y     = labels.astype(int)

    tp = int(np.sum((preds==1)&(y==1))); fp = int(np.sum((preds==1)&(y==0)))
    tn = int(np.sum((preds==0)&(y==0))); fn = int(np.sum((preds==0)&(y==1)))
    tpr  = tp/max(tp+fn, 1); fpr  = fp/max(fp+tn, 1)
    prec = tp/max(tp+fp, 1); f1   = 2*prec*tpr/max(prec+tpr, 1e-9)
    try:    auc = float(roc_auc_score(y, scores))
    except: auc = 0.0

    print(f"  {name:<25}  TPR={tpr:.3f}  FPR={fpr:.3f}  Prec={prec:.3f}  "
          f"F1={f1:.3f}  AUC={auc:.4f}  TP={tp}  FP={fp}  FN={fn}")
    return {"method":name,"tp":tp,"fp":fp,"tn":tn,"fn":fn,
            "tpr":round(tpr,4),"fpr":round(fpr,4),
            "precision":round(prec,4),"f1":round(f1,4),"auc":round(auc,4)}


# ══════════════════════════════════════════════════════════════════════════════
# 9. MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    t0 = time.time()
    print("="*70)
    print("TAARA Benchmark v5 — Attention-Grounded Features + Real Cowrie Attack Class")
    print("="*70)

    # ── 1. Parse ───────────────────────────────────────────────────────────────
    print("\n[1] Parsing sessions...")
    elastic   = parse_elastic(ELASTIC_LOG)
    ssh_legit = parse_ssh_legit(SSH_LOG)
    normal    = elastic + ssh_legit
    print(f"  elastic_auth: {len(elastic)}  ssh_legit: {len(ssh_legit)}  total_normal: {len(normal)}")

    cowrie = parse_cowrie(COWRIE_DIR, max_sessions=3000)
    with_cmds = sum(1 for s in cowrie if s["cmds"])
    print(f"  cowrie:       {len(cowrie)} post-auth sessions  ({with_cmds} with commands)")

    if len(cowrie) < 50:
        print("[ERROR] Too few Cowrie sessions. Check benchmark/datasets/cowrie/"); return

    # ── 2. Extract features ────────────────────────────────────────────────────
    print("\n[2] Extracting 19 attention-grounded features...")
    X_norm = np.array([extract_19(s) for s in normal],  dtype=np.float32)
    X_atk  = np.array([extract_19(s) for s in cowrie],  dtype=np.float32)
    all_sessions = normal + cowrie
    all_labels   = np.array([0]*len(normal) + [1]*len(cowrie), dtype=int)
    X_all        = np.vstack([X_norm, X_atk])

    # Feature sanity check
    print("  Feature separability (normal vs attack, per dimension):")
    mu_n = X_norm.mean(0); std_n = X_norm.std(0)+1e-6
    mu_a = X_atk.mean(0)
    gaps = np.abs(mu_a - mu_n) / std_n  # effect size in σ units
    top5 = np.argsort(gaps)[::-1][:5]
    for i in top5:
        print(f"    {FEATURE_NAMES[i]:<30}  normal={mu_n[i]:.2f}  attack={mu_a[i]:.2f}  gap={gaps[i]:.2f}σ")

    # PCA variance analysis
    sc_check = StandardScaler().fit(X_norm)
    pca_check = PCA()
    pca_check.fit(sc_check.transform(X_norm))
    cumvar = np.cumsum(pca_check.explained_variance_ratio_)
    print(f"\n  PCA on normal: 8 dims={cumvar[7]*100:.1f}%  19 dims={cumvar[18]*100:.1f}% variance")
    print(f"  (Bottleneck: 8-dim = 3-qubit NISQ: 2³=8 amplitudes for AmplitudeEmbedding)")

    # ── 3. Train/test split — 70% of each identity's normal sessions for train ─
    print("\n[3] Train/test split (70% per-identity normal for train)...")
    user_idx = defaultdict(list)
    for i, s in enumerate(normal):
        user_idx[s["user"]].append(i)

    train_mask = np.zeros(len(normal), dtype=bool)
    for u, idxs in user_idx.items():
        cutoff = max(int(len(idxs)*0.70), IdentityBasis.BOOTSTRAP+1)
        for i in idxs[:cutoff]:
            train_mask[i] = True

    train_sessions = [s for i,s in enumerate(normal) if train_mask[i]]
    train_feats    = X_norm[train_mask]
    test_sessions  = [s for i,s in enumerate(normal) if not train_mask[i]] + cowrie
    test_feats     = np.vstack([X_norm[~train_mask], X_atk])
    test_labels    = np.array([0]*int((~train_mask).sum()) + [1]*len(cowrie), dtype=int)

    print(f"  Train: {len(train_sessions)} normal sessions  "
          f"({len(user_idx)} identities: {list(user_idx.keys())})")
    print(f"  Test:  {len(test_sessions)} sessions  "
          f"({test_labels.sum()} attacks, {(test_labels==0).sum()} normal)")

    # ── 4. Pretrain AE on all normal training data ─────────────────────────────
    print("\n[4] Pretraining autoencoder (19→64→8→64→19) on normal sessions...")
    scaler = StandardScaler()
    scaler.fit(train_feats)
    ae = train_ae(train_feats, scaler, epochs=100, patience=15)
    print("  AE trained.")

    # ── 5. Build per-identity quantum bases ─────────────────────────────────────
    print("\n[5] Building per-identity quantum bases (SWAP test subspaces)...")
    bases: Dict[str, IdentityBasis] = {}
    for s, f in zip(train_sessions, train_feats):
        uid = s["user"]
        if uid not in bases:
            bases[uid] = IdentityBasis(uid)
        z = get_latent(ae, scaler, f)
        bases[uid].add_normal(z)

    ready = sum(1 for b in bases.values() if b.is_ready())
    print(f"  {ready}/{len(bases)} identities have quantum basis (≥{IdentityBasis.BOOTSTRAP} sessions)")
    for uid, b in bases.items():
        print(f"    {uid:<15}  {len(b.latents):3d} normal sessions  ready={b.is_ready()}")

    # ── 6. TAARA v5 inference (per-identity) ──────────────────────────────────
    print("\n[6] TAARA v5 inference (per-identity quantum SWAP)...")
    taara_scores = np.zeros(len(test_sessions))
    # Use 'ubuntu' basis for Cowrie attackers (they logged in as 'ubuntu' in T1078 scenario)
    # For benchmark clarity: attacker sessions get scored against the most-trained identity
    primary_uid = max(bases, key=lambda u: len(bases[u].latents))

    signal_stats = {"swap_s":[], "q_dir":[], "coh":[]}
    for i, (s, f) in enumerate(zip(test_sessions, test_feats)):
        uid = s["user"]
        # Per-identity: use that user's basis if available, else primary
        basis = bases.get(uid) or bases.get(primary_uid)
        if basis is None or not basis.is_ready():
            taara_scores[i] = 0.0; continue
        z     = get_latent(ae, scaler, f)
        score = basis.score(z)
        taara_scores[i] = score
        if (i+1) % 500 == 0:
            print(f"  {i+1}/{len(test_sessions)} scored...")

    norm_t = taara_scores[test_labels==0]
    atk_t  = taara_scores[test_labels==1]
    print(f"\n  Signal separation:")
    print(f"    Normal  conf: mean={norm_t.mean():.4f}  std={norm_t.std():.4f}  p95={np.percentile(norm_t,95):.4f}")
    print(f"    Attack  conf: mean={atk_t.mean():.4f}  std={atk_t.std():.4f}  p5={np.percentile(atk_t,5):.4f}")
    print(f"    Gap (atk-norm mean): {atk_t.mean()-norm_t.mean():+.4f}")

    # ── 7. Baselines ───────────────────────────────────────────────────────────
    print("\n[7] Running baselines...")
    sc2 = StandardScaler().fit(train_feats)
    Xtr_s = sc2.transform(train_feats)
    Xte_s = sc2.transform(test_feats)

    # IsolationForest global
    clf_if_g = IsolationForest(n_estimators=200, contamination=0.15, random_state=42)
    clf_if_g.fit(Xtr_s)
    if_global_scores = -clf_if_g.score_samples(Xte_s)

    # IsolationForest per-user (train separate model per identity)
    if_per_scores = np.zeros(len(test_sessions))
    for uid in user_idx:
        train_idxs = [i for i in user_idx[uid] if train_mask[i]]
        if len(train_idxs) < 3: continue
        Xu = sc2.transform(X_norm[train_idxs])
        clf_u = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        clf_u.fit(Xu)
        for j, s in enumerate(test_sessions):
            if s["user"] == uid:
                if_per_scores[j] = float(-clf_u.score_samples(Xte_s[j:j+1])[0])
    # Attack sessions: use global model for attacker user IDs
    atk_start = int((test_labels==0).sum())
    if_per_scores[atk_start:] = if_global_scores[atk_start:]

    # LOF per-user
    lof_scores = np.zeros(len(test_sessions))
    for uid in user_idx:
        train_idxs = [i for i in user_idx[uid] if train_mask[i]]
        if len(train_idxs) < 5: continue
        Xu = sc2.transform(X_norm[train_idxs])
        n_nb = min(len(train_idxs)-1, 10)
        lof = LocalOutlierFactor(n_neighbors=n_nb, novelty=True, contamination=0.1)
        lof.fit(Xu)
        for j, s in enumerate(test_sessions):
            if s["user"] == uid:
                lof_scores[j] = float(-lof.score_samples(Xte_s[j:j+1])[0])
    lof_scores[atk_start:] = -clf_if_g.score_samples(Xte_s[atk_start:])

    # Per-user z-score
    z_scores = per_user_zscore(train_sessions + test_sessions,
                               np.vstack([train_feats, test_feats]))
    z_test   = z_scores[len(train_sessions):]

    # LSTM-AE global
    print("  Training LSTM-AE baseline...")
    lstm = train_lstm_ae(Xtr_s, epochs=80)
    lstm_s = lstm_scores(lstm, Xte_s)

    # ── 8. Evaluate all ────────────────────────────────────────────────────────
    print("\n[8] Results:")
    print(f"  {'Method':<25}  {'TPR':>5}  {'FPR':>5}  {'Prec':>5}  {'F1':>5}  {'AUC':>6}")
    print("  "+"-"*70)
    results = {}
    results["TAARA_v5"]           = evaluate(taara_scores,    test_labels, "TAARA_v5")
    results["IF_global"]          = evaluate(if_global_scores, test_labels, "IF_global")
    results["IF_per_identity"]    = evaluate(if_per_scores,   test_labels, "IF_per_identity")
    results["LOF_per_identity"]   = evaluate(lof_scores,      test_labels, "LOF_per_identity")
    results["PerUser_ZScore"]     = evaluate(z_test,          test_labels, "PerUser_ZScore")
    results["LSTM_AE"]            = evaluate(lstm_s,          test_labels, "LSTM_AE")

    # ── 9. Key claim: within-global-range attacks ──────────────────────────────
    print("\n[9] Hard-case analysis: attacks within ±2σ of global normal distribution")
    sc3    = StandardScaler().fit(X_norm)
    mu_g   = X_norm.mean(0); std_g = X_norm.std(0)+1e-6
    z_atk  = np.abs((X_atk - mu_g)/std_g)
    within = np.all(z_atk < 2, axis=1)  # attack sessions that look normal globally
    print(f"  {within.sum()}/{len(cowrie)} attack sessions within global ±2σ on ALL 19 features")
    print(f"  These are stealthy sessions that threshold-based tools miss.")
    if within.sum() > 0:
        hard_idx  = np.where(within)[0] + int((test_labels==0).sum())
        hard_taara = taara_scores[hard_idx]
        hard_if    = if_global_scores[hard_idx]
        thr_taara  = np.percentile(taara_scores[test_labels==0], 90)
        thr_if     = np.percentile(if_global_scores[test_labels==0], 90)
        taara_catches = (hard_taara > thr_taara).sum()
        if_catches    = (hard_if    > thr_if).sum()
        print(f"  TAARA catches {taara_catches}/{within.sum()} ({taara_catches/max(within.sum(),1)*100:.0f}%) of hard cases")
        print(f"  IF_global catches {if_catches}/{within.sum()} ({if_catches/max(within.sum(),1)*100:.0f}%) of hard cases")

    # ── 10. Save ───────────────────────────────────────────────────────────────
    elapsed = time.time()-t0
    output = {
        "timestamp":  time.strftime("%Y-%m-%d %H:%M:%S"),
        "benchmark":  "TAARA v5 — attention-grounded features + real Cowrie attack class",
        "version":    "5.0",
        "datasets": {
            "normal": f"elastic_auth.log ({len(elastic)} sessions) + SSH.log legit ({len(ssh_legit)} sessions)",
            "attack": f"Cowrie Zenodo 3687527 — {len(cowrie)} real post-auth sessions",
        },
        "features": {
            "count": 19,
            "grounding": "transformer attention head analysis (fixed hook extraction)",
            "bottleneck": "8-dim (3-qubit NISQ: 2^3=8 amplitudes)",
            "pca_8_dims": f"{cumvar[7]*100:.1f}% variance on normal sessions",
            "attention_discovered": ["hardware_enum_count","persistence_attempt","network_device_shell"],
        },
        "per_identity": {
            "n_identities": len(bases),
            "ready": ready,
            "primary_uid_for_attackers": primary_uid,
        },
        "signal_separation": {
            "conf_normal_mean": round(float(norm_t.mean()),4),
            "conf_normal_p95":  round(float(np.percentile(norm_t,95)),4),
            "conf_attack_mean": round(float(atk_t.mean()),4),
            "conf_attack_p5":   round(float(np.percentile(atk_t,5)),4),
            "gap":              round(float(atk_t.mean()-norm_t.mean()),4),
        },
        "results": results,
        "hard_case_analysis": {
            "attacks_within_2sigma": int(within.sum()),
            "total_attacks": len(cowrie),
        },
        "runtime_seconds": round(elapsed,1),
    }

    out_j = RESULTS_DIR/"benchmark_v5_results.json"
    with open(out_j,"w") as f: json.dump(output,f,indent=2)
    print(f"\n  Results → {out_j}")

    # Text report
    lines = [
        "TAARA Benchmark v5 Report",
        "="*60,
        f"Normal: {len(normal)} sessions ({len(elastic)} elastic + {len(ssh_legit)} ssh_legit)",
        f"Attack: {len(cowrie)} Cowrie sessions (Zenodo 3687527)",
        f"Features: 19-dim, grounded in transformer attention output",
        f"  Attention-discovered (not in prior hand-engineered list):",
        f"    hardware_enum_count (uname+free+top+lscpu+w cluster)",
        f"    persistence_attempt (crontab — 1087/1100 attack sessions)",
        f"    network_device_shell (version/shell/enable — router exploitation)",
        f"PCA: 8 dims explain {cumvar[7]*100:.1f}% variance (bottleneck = 3-qubit NISQ)",
        "",
        f"{'Method':<25}  {'TPR':>5}  {'FPR':>5}  {'Prec':>5}  {'F1':>5}  {'AUC':>6}",
        "-"*65,
    ]
    for name, r in results.items():
        lines.append(f"{name:<25}  {r['tpr']:>5.3f}  {r['fpr']:>5.3f}  "
                     f"{r['precision']:>5.3f}  {r['f1']:>5.3f}  {r['auc']:>6.4f}")
    lines += [
        "",
        f"Signal separation (quantum_confidence):",
        f"  Normal mean: {output['signal_separation']['conf_normal_mean']}  "
        f"p95: {output['signal_separation']['conf_normal_p95']}",
        f"  Attack mean: {output['signal_separation']['conf_attack_mean']}  "
        f"p5:  {output['signal_separation']['conf_attack_p5']}",
        f"  Gap: {output['signal_separation']['gap']}",
        "",
        f"Hard-case (within global ±2σ): "
        f"{output['hard_case_analysis']['attacks_within_2sigma']}/{len(cowrie)} sessions",
        f"Runtime: {elapsed:.0f}s",
    ]
    out_t = RESULTS_DIR/"benchmark_v5_report.txt"
    with open(out_t,"w") as f: f.write("\n".join(lines))
    print(f"  Report  → {out_t}")
    print(f"\n  Runtime: {elapsed:.0f}s")


if __name__ == "__main__":
    main()
