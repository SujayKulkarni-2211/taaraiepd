#!/usr/bin/env python3
"""
TAARA Transformer Feature Discovery
=====================================
Learns what raw log tokens matter for behavioral anomaly detection,
without hand-engineering features.

Pipeline:
  1. Parse raw logs → token sequences per session
  2. Build vocabulary from real log tokens
  3. Train small transformer (masked token prediction) on normal sessions
  4. Extract attention weights → which tokens get attended to during reconstruction
  5. Cluster attention patterns → discover N natural feature dimensions
  6. Validate: do discovered dimensions separate normal (elastic_auth + SSH) from attack (Cowrie)?
  7. Report: how many dimensions explain 90%+ variance? (justifies N=19 or adjusts it)

Datasets:
  Normal: elastic_auth.log (real admin sessions, real commands)
          SSH.log legitimate user sessions (fztu, curi, hxu, jmzhu, zachary, suyuxin, yuewang, xxchen)
  Attack: Cowrie Zenodo 3687527 (real attacker post-auth sessions)

Output:
  experiments/results/feature_discovery_report.json
  experiments/results/feature_discovery_report.txt
  models/transformer_features.json  — discovered feature extractors

Usage:
  python experiments/transformer_feature_discovery.py
"""

import re
import json
import gzip
import math
import time
import warnings
from pathlib import Path
from collections import defaultdict, Counter
from typing import List, Dict, Tuple, Optional

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score, classification_report

warnings.filterwarnings("ignore")

ROOT        = Path(__file__).parent.parent
ELASTIC_LOG = ROOT / "benchmark" / "datasets" / "elastic_auth.log"
SSH_LOG     = ROOT / "benchmark" / "datasets" / "SSH.log"
COWRIE_DIR  = ROOT / "benchmark" / "datasets" / "cowrie"
RESULTS_DIR = Path(__file__).parent / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR  = ROOT / "models"

# ── Config ─────────────────────────────────────────────────────────────────────
MAX_SEQ_LEN    = 64      # tokens per session window
VOCAB_SIZE     = 512     # top tokens kept
D_MODEL        = 128     # transformer hidden dim — wider for richer 19-dim PCA space
N_HEADS        = 4       # attention heads
N_LAYERS       = 3       # transformer layers
MASK_PROB      = 0.15    # masked LM probability
TRAIN_EPOCHS   = 40
BATCH_SIZE     = 64
LR             = 1e-3
TARGET_DIMS    = 19      # final feature dimensions to produce
PCA_EXPLAIN    = 0.92    # how much variance to explain (target: ≥92%)
DEVICE         = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# ── Tokenizer ──────────────────────────────────────────────────────────────────

SENSITIVE_PATHS = {
    "authorized_keys": "SENSITIVE_AUTHORIZED_KEYS",
    "/.ssh": "SENSITIVE_SSH_DIR",
    "/etc/passwd": "SENSITIVE_ETC_PASSWD",
    "/etc/shadow": "SENSITIVE_ETC_SHADOW",
    "id_rsa": "SENSITIVE_KEY_FILE",
    "/root": "SENSITIVE_ROOT_DIR",
    "crontab": "SENSITIVE_CRONTAB",
    ".bash_history": "SENSITIVE_HISTORY",
}

ATTACKER_COMMANDS = {
    "uname", "whoami", "id", "wget", "curl", "chmod", "nohup", "tar",
    "bash", "sh", "perl", "python", "python3", "nc", "netcat", "xmrig",
    "masscan", "nmap", "chattr", "history", "rm", "pkill", "kill",
}

ADMIN_COMMANDS = {
    "apt-get", "apt", "vim", "nano", "systemctl", "service", "sudo",
    "grep", "awk", "sed", "cat", "ls", "cp", "mv", "mkdir", "echo",
    "tee", "hostname", "ip", "ifconfig", "ping", "ssh", "scp",
    "git", "python3", "pip", "docker",
}


def tokenize_line(line: str) -> List[str]:
    """Convert a raw log line into semantic tokens."""
    tokens = []
    line_lower = line.lower()

    # Event type token
    if "session opened" in line_lower:
        tokens.append("EVT_SESSION_OPEN")
    elif "session closed" in line_lower:
        tokens.append("EVT_SESSION_CLOSE")
    elif "accepted publickey" in line_lower:
        tokens.append("AUTH_PUBKEY")
    elif "accepted password" in line_lower:
        tokens.append("AUTH_PASSWORD")
    elif "failed password" in line_lower:
        tokens.append("AUTH_FAIL")
    elif "invalid user" in line_lower:
        tokens.append("AUTH_INVALID_USER")
    elif "command=" in line_lower:
        tokens.append("EVT_SUDO_CMD")
    elif "cowrie.command.input" in line_lower or '"input"' in line:
        tokens.append("EVT_CMD_INPUT")
    elif "cowrie.session.file_download" in line_lower or "file_download" in line_lower:
        tokens.append("EVT_FILE_DOWNLOAD")
    elif "cowrie.login.success" in line_lower:
        tokens.append("COWRIE_LOGIN_SUCCESS")
    elif "cowrie.login.failed" in line_lower:
        tokens.append("COWRIE_LOGIN_FAIL")
    else:
        tokens.append("EVT_OTHER")

    # Command token
    cmd_match = re.search(r'COMMAND=(/[^\s;]+)', line)
    if cmd_match:
        cmd = cmd_match.group(1).split("/")[-1].lower()
        if cmd in ATTACKER_COMMANDS:
            tokens.append(f"CMD_ATTACK_{cmd.upper()}")
        elif cmd in ADMIN_COMMANDS:
            tokens.append(f"CMD_ADMIN_{cmd.upper()}")
        else:
            tokens.append("CMD_OTHER")

    # Cowrie command input token — commands appear in "message": "CMD: <cmd>" field
    cmd_msg_match = re.search(r'"CMD:\s*([^"\\]+)"', line)
    if cmd_msg_match:
        cmd_str = cmd_msg_match.group(1).strip().split()[0].lower() if cmd_msg_match.group(1).strip() else ""
        if cmd_str in ATTACKER_COMMANDS:
            tokens.append(f"CMD_ATTACK_{cmd_str.upper()}")
        elif cmd_str in ADMIN_COMMANDS:
            tokens.append(f"CMD_ADMIN_{cmd_str.upper()}")
        elif cmd_str:
            tokens.append(f"CMD_OTHER_{cmd_str[:12].upper()}")  # keep first 12 chars for diversity

    # Sensitive path token
    for path, token in SENSITIVE_PATHS.items():
        if path in line:
            tokens.append(token)
            break

    # IP token
    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
    if ip_match:
        ip = ip_match.group(1)
        octets = ip.split(".")
        # Classify by /8 range (heuristic)
        try:
            first = int(octets[0])
            if first in (10, 172, 192):
                tokens.append("IP_PRIVATE")
            elif first in (127,):
                tokens.append("IP_LOOPBACK")
            else:
                tokens.append("IP_PUBLIC")
        except:
            tokens.append("IP_PUBLIC")

    # Time token (hour of day → coarse bucket)
    time_match = re.search(r'(\d{2}):(\d{2}):\d{2}', line)
    if time_match:
        hour = int(time_match.group(1))
        if 0 <= hour < 6:
            tokens.append("TIME_NIGHT")
        elif 6 <= hour < 12:
            tokens.append("TIME_MORNING")
        elif 12 <= hour < 18:
            tokens.append("TIME_AFTERNOON")
        else:
            tokens.append("TIME_EVENING")

    # Duration token (from Cowrie closed events)
    dur_match = re.search(r'"duration":\s*([\d.]+)', line)
    if dur_match:
        dur = float(dur_match.group(1))
        if dur < 5:
            tokens.append("DUR_VERY_SHORT")     # attacker pattern: <5s
        elif dur < 60:
            tokens.append("DUR_SHORT")
        elif dur < 600:
            tokens.append("DUR_MEDIUM")
        else:
            tokens.append("DUR_LONG")

    # TTY token
    if "TTY=pts" in line:
        tokens.append("TTY_INTERACTIVE")
    elif "TTY=unknown" in line or "tty=ssh" in line.lower():
        tokens.append("TTY_NON_INTERACTIVE")

    # Download/upload token
    if "wget" in line_lower or "curl" in line_lower:
        tokens.append("NET_DOWNLOAD")
    if "file_upload" in line_lower:
        tokens.append("NET_UPLOAD")

    # Reconnaissance commands (attacker enumeration pattern)
    recon_cmds = {"uname", "whoami", "id", "cat", "w", "top", "free", "lscpu", "ls", "which"}
    if cmd_msg_match:
        cmd = cmd_msg_match.group(1).strip().split()[0].lower()
        if cmd in recon_cmds:
            tokens.append("CMD_RECON")
    if cmd_match:
        cmd = cmd_match.group(1).split("/")[-1].lower()
        if cmd in {"cat", "ls", "grep", "find", "ps"}:
            tokens.append("CMD_RECON")

    # C2 indicators (reverse shell patterns)
    if any(x in line for x in ["nohup", "0<&", ">&", "/dev/tcp", "exec 5<>"]):
        tokens.append("C2_REVERSE_SHELL")

    # Crontab persistence
    if "crontab" in line_lower:
        tokens.append("PERSISTENCE_CRON")

    # Anti-forensics (cleanup)
    if any(x in line_lower for x in ["rm -rf", "history -c", "unset histfile"]):
        tokens.append("ANTIFORENSICS_CLEANUP")

    return tokens if tokens else ["EVT_OTHER"]


# ── Log Parsers ────────────────────────────────────────────────────────────────

MONTHS = {"Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,
          "Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12}

def parse_elastic_sessions(path: Path) -> List[Dict]:
    """Parse elastic_auth.log into per-session token sequences."""
    sessions = []
    current_session = None
    session_tokens = []
    session_start = 0.0

    SESS_OPEN  = re.compile(r'session opened for user (\w+)')
    SESS_CLOSE = re.compile(r'session closed for user (\w+)')
    SUDO_CMD   = re.compile(r'sudo:\s+(\w+)\s*:.*COMMAND=(.*)')
    ACCEPTED   = re.compile(r'Accepted\s+(\w+)\s+for\s+(\w+)\s+from\s+([\d.]+)')
    TS_RE      = re.compile(r'^(\w+)\s+(\d+)\s+(\d+:\d+:\d+)')

    def parse_ts(line):
        m = TS_RE.match(line)
        if m:
            mn, d, hms = m.groups()
            h, mi, s = hms.split(":")
            return float(MONTHS.get(mn, 1)*30*86400 + int(d)*86400 + int(h)*3600 + int(mi)*60 + int(s))
        return 0.0

    with open(path, errors="replace") as f:
        for line in f:
            ts = parse_ts(line)

            # Session open
            m = SESS_OPEN.search(line)
            if m:
                if current_session and session_tokens:
                    sessions.append({
                        "user": current_session,
                        "tokens": session_tokens[:],
                        "duration": ts - session_start,
                        "label": 0,
                        "source": "elastic",
                    })
                current_session = m.group(1)
                session_tokens = [tokenize_line(line)]
                session_start = ts
                continue

            # Session close
            m = SESS_CLOSE.search(line)
            if m and current_session == m.group(1):
                if session_tokens:
                    session_tokens.append(tokenize_line(line))
                    sessions.append({
                        "user": current_session,
                        "tokens": session_tokens[:],
                        "duration": ts - session_start,
                        "label": 0,
                        "source": "elastic",
                    })
                current_session = None
                session_tokens = []
                continue

            # Commands and auth within session
            if current_session:
                toks = tokenize_line(line)
                if toks:
                    session_tokens.append(toks)

    return sessions


def parse_ssh_legit_sessions(path: Path) -> List[Dict]:
    """Extract legitimate user sessions from SSH.log (the 8 known users)."""
    LEGIT_USERS = {"fztu", "curi", "hxu", "jmzhu", "zachary", "suyuxin", "yuewang", "xxchen"}
    ACCEPTED_RE = re.compile(r'Accepted\s+\w+\s+for\s+(\w+)\s+from\s+([\d.]+)')
    SESS_OPEN   = re.compile(r'session opened for user (\w+)')
    SESS_CLOSE  = re.compile(r'session closed for user (\w+)')
    TS_RE       = re.compile(r'^(\w+)\s+(\d+)\s+(\d+):(\d+):(\d+)')

    def parse_ts(line):
        m = TS_RE.match(line)
        if m:
            mn, d, h, mi, s = m.groups()
            return float(MONTHS.get(mn, 1)*30*86400 + int(d)*86400 + int(h)*3600 + int(mi)*60 + int(s))
        return 0.0

    sessions = []
    pending = {}   # user → {src_ip, start_ts, tokens}

    with open(path, errors="replace") as f:
        for line in f:
            ts = parse_ts(line)

            m = ACCEPTED_RE.search(line)
            if m:
                user, src_ip = m.groups()
                if user in LEGIT_USERS:
                    pending[user] = {"src_ip": src_ip, "start_ts": ts, "tokens": [tokenize_line(line)]}
                continue

            m = SESS_OPEN.search(line)
            if m:
                user = m.group(1)
                if user in pending:
                    pending[user]["tokens"].append(tokenize_line(line))
                continue

            m = SESS_CLOSE.search(line)
            if m:
                user = m.group(1)
                if user in pending:
                    info = pending.pop(user)
                    info["tokens"].append(tokenize_line(line))
                    sessions.append({
                        "user": user,
                        "tokens": info["tokens"],
                        "duration": ts - info["start_ts"],
                        "label": 0,
                        "source": "ssh_legit",
                    })
                continue

    return sessions


def parse_cowrie_sessions(cowrie_dir: Path, max_sessions: int = 2000) -> List[Dict]:
    """Parse Cowrie honeypot sessions as attack class."""
    sessions = []
    gz_files = sorted(cowrie_dir.glob("*.json.gz"))
    if not gz_files:
        print(f"[transformer] WARNING: No Cowrie files in {cowrie_dir}")
        return []

    print(f"[transformer] Parsing Cowrie from {len(gz_files)} file(s)...")

    for gz_path in gz_files:
        if len(sessions) >= max_sessions:
            break
        try:
            with gzip.open(gz_path, "rt", encoding="utf-8", errors="replace") as f:
                raw = f.read()

            # Format: [{session_id: [{...events...}]}, ...]
            # Parse as one big JSON structure
            data = json.loads(raw)
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                # Top-level is {session_id: [events]}
                items = [{"session_id": k, "events": v} for k, v in data.items()]
            else:
                continue

            for item in items:
                if len(sessions) >= max_sessions:
                    break
                if isinstance(item, dict):
                    # Could be {session_id: "...", other_key: [...events...]}
                    # Or {session_id: "...", events: [...]}
                    # Find the event list
                    events = None
                    for k, v in item.items():
                        if isinstance(v, list) and v and isinstance(v[0], dict) and "eventid" in v[0]:
                            events = v
                            break
                    if events is None:
                        continue

                    # Only sessions with login.success (real post-auth sessions)
                    event_ids = [e.get("eventid", "") for e in events]
                    if "cowrie.login.success" not in event_ids:
                        continue

                    # Build token sequence from events
                    tokens = []
                    duration = 0.0
                    for ev in events:
                        # Build a synthetic line that tokenize_line can understand
                        ev_type = ev.get("eventid", "")
                        msg = ev.get("message", "") or ""
                        ts_str = ev.get("timestamp", "")
                        # Reconstruct as a log-like string for the tokenizer
                        # Include the message field directly (contains "CMD: ..." etc.)
                        synthetic = f'{ts_str} {ev_type} "{msg}" '
                        if ev.get("duration") is not None:
                            synthetic += f'"duration": {ev["duration"]} '
                        if ev.get("src_ip_identifier"):
                            synthetic += f'"src_ip_identifier": "{ev["src_ip_identifier"]}" '
                        toks = tokenize_line(synthetic)
                        if toks:
                            tokens.append(toks)
                        if ev_type == "cowrie.session.closed" and ev.get("duration"):
                            duration = float(ev["duration"])

                    if tokens:
                        sessions.append({
                            "user": "attacker",
                            "tokens": tokens,
                            "duration": duration,
                            "label": 1,
                            "source": "cowrie",
                        })

        except Exception as e:
            print(f"[transformer]   Warning: {gz_path.name}: {e}")
            continue

    return sessions


# ── Vocabulary ─────────────────────────────────────────────────────────────────

class Vocabulary:
    PAD = 0
    UNK = 1
    MASK = 2
    CLS = 3

    def __init__(self):
        self.token2id = {"<PAD>": 0, "<UNK>": 1, "<MASK>": 2, "<CLS>": 3}
        self.id2token = {0: "<PAD>", 1: "<UNK>", 2: "<MASK>", 3: "<CLS>"}
        self.counter  = Counter()

    def build(self, sessions: List[Dict], max_size: int = VOCAB_SIZE):
        for sess in sessions:
            for token_list in sess["tokens"]:
                self.counter.update(token_list)
        # Add top tokens
        for token, _ in self.counter.most_common(max_size - 4):
            idx = len(self.token2id)
            self.token2id[token] = idx
            self.id2token[idx] = token
        print(f"[transformer] Vocabulary: {len(self.token2id)} tokens")
        print(f"  Top tokens: {[t for t,_ in self.counter.most_common(20)]}")

    def encode(self, token_lists: List[List[str]], max_len: int = MAX_SEQ_LEN) -> List[int]:
        """Flatten token lists for a session into a single padded sequence."""
        flat = [self.CLS]
        for tl in token_lists:
            for t in tl:
                flat.append(self.token2id.get(t, self.UNK))
        # Truncate or pad
        flat = flat[:max_len]
        flat += [self.PAD] * (max_len - len(flat))
        return flat

    def __len__(self):
        return len(self.token2id)


# ── Transformer Model ──────────────────────────────────────────────────────────

class LogTransformer(nn.Module):
    """
    Small transformer for log token sequences.
    Returns:
      - token logits (for masked LM training)
      - cls_embedding (sequence summary for anomaly scoring)
      - attention_weights (for feature discovery)
    """

    def __init__(self, vocab_size: int, d_model: int = D_MODEL, n_heads: int = N_HEADS,
                 n_layers: int = N_LAYERS, max_len: int = MAX_SEQ_LEN):
        super().__init__()
        self.d_model = d_model

        self.embedding = nn.Embedding(vocab_size, d_model, padding_idx=Vocabulary.PAD)
        self.pos_embed  = nn.Embedding(max_len, d_model)

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model, nhead=n_heads, dim_feedforward=d_model * 4,
            dropout=0.1, batch_first=True, norm_first=True,
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=n_layers)
        self.mlm_head = nn.Linear(d_model, vocab_size)
        self.norm     = nn.LayerNorm(d_model)

        # Store attention weights during forward
        self._attn_weights: List[torch.Tensor] = []
        self._register_hooks()

    def _register_hooks(self):
        """Register hooks to capture attention weights from each layer."""
        def make_hook(layer_idx):
            def hook(module, input, output):
                # output is (attn_output, attn_weights) when need_weights=True
                # TransformerEncoderLayer output is just the hidden state
                # We'll capture via the self_attn sub-module
                pass
            return hook

        for i, layer in enumerate(self.transformer.layers):
            # Patch self_attn to return weights
            orig_forward = layer.self_attn.forward
            layer_idx = i
            attn_list = self._attn_weights

            def patched_forward(orig=orig_forward, idx=layer_idx, lst=attn_list):
                def forward(*args, **kwargs):
                    kwargs["need_weights"] = True
                    kwargs["average_attn_weights"] = False
                    out, weights = orig(*args, **kwargs)
                    if len(lst) <= idx:
                        lst.append(weights.detach())
                    else:
                        lst[idx] = weights.detach()
                    return out
                return forward

            layer.self_attn.forward = patched_forward()

    def forward(self, input_ids: torch.Tensor,
                padding_mask: Optional[torch.Tensor] = None) -> Tuple:
        """
        Args:
            input_ids: (B, L)
            padding_mask: (B, L) bool, True = ignore

        Returns:
            logits: (B, L, V)
            cls_emb: (B, d_model)
            attn_weights: list of (B, H, L, L) per layer
        """
        self._attn_weights.clear()
        B, L = input_ids.shape
        pos  = torch.arange(L, device=input_ids.device).unsqueeze(0).expand(B, -1)
        x    = self.embedding(input_ids) + self.pos_embed(pos)
        x    = self.transformer(x, src_key_padding_mask=padding_mask)
        x    = self.norm(x)
        logits  = self.mlm_head(x)
        cls_emb = x[:, 0, :]   # CLS token
        return logits, cls_emb, list(self._attn_weights)


# ── Dataset ────────────────────────────────────────────────────────────────────

class LogDataset(torch.utils.data.Dataset):
    def __init__(self, sessions: List[Dict], vocab: Vocabulary, mask_prob: float = MASK_PROB):
        self.samples = []
        self.mask_prob = mask_prob
        self.vocab = vocab
        for sess in sessions:
            ids = vocab.encode(sess["tokens"])
            self.samples.append({
                "input_ids": torch.tensor(ids, dtype=torch.long),
                "label":     sess["label"],
            })

    def __len__(self): return len(self.samples)

    def __getitem__(self, idx):
        item = self.samples[idx]
        ids  = item["input_ids"].clone()
        # Masked LM: randomly replace tokens with <MASK>
        labels = ids.clone()
        mask   = (torch.rand(ids.shape) < self.mask_prob) & (ids != Vocabulary.PAD) & (ids != Vocabulary.CLS)
        ids[mask] = Vocabulary.MASK
        labels[~mask] = -100   # only compute loss on masked positions
        padding_mask = (item["input_ids"] == Vocabulary.PAD)
        return ids, labels, padding_mask, item["label"]


# ── Training ───────────────────────────────────────────────────────────────────

def train_transformer(model: LogTransformer, normal_sessions: List[Dict],
                      vocab: Vocabulary) -> None:
    """Train via masked LM on normal sessions only."""
    dataset = LogDataset(normal_sessions, vocab)
    loader  = torch.utils.data.DataLoader(dataset, batch_size=BATCH_SIZE, shuffle=True)
    optim   = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optim, T_max=TRAIN_EPOCHS)
    criterion = nn.CrossEntropyLoss(ignore_index=-100)

    model.train()
    print(f"\n[transformer] Training on {len(normal_sessions)} normal sessions "
          f"({len(dataset)} samples), {TRAIN_EPOCHS} epochs, device={DEVICE}")

    for epoch in range(TRAIN_EPOCHS):
        total_loss = 0.0
        n_batches  = 0
        for ids, labels, pad_mask, _ in loader:
            ids       = ids.to(DEVICE)
            labels    = labels.to(DEVICE)
            pad_mask  = pad_mask.to(DEVICE)

            logits, _, _ = model(ids, padding_mask=pad_mask)
            loss = criterion(logits.view(-1, len(vocab)), labels.view(-1))
            optim.zero_grad()
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optim.step()
            total_loss += loss.item()
            n_batches  += 1

        scheduler.step()
        if (epoch + 1) % 5 == 0 or epoch == 0:
            print(f"  Epoch {epoch+1:3d}/{TRAIN_EPOCHS}  loss={total_loss/n_batches:.4f}  "
                  f"lr={scheduler.get_last_lr()[0]:.5f}")


# ── Attention-Based Feature Extraction ────────────────────────────────────────

def extract_session_embedding(model: LogTransformer, session: Dict,
                               vocab: Vocabulary) -> Tuple[np.ndarray, np.ndarray]:
    """
    Run one session through the transformer.
    Returns:
      cls_emb:        (d_model,) — summary embedding
      attn_profile:   (n_layers × n_heads × n_vocab_positions,) — attention heat
    """
    model.eval()
    ids = vocab.encode(session["tokens"])
    id_tensor  = torch.tensor([ids], dtype=torch.long, device=DEVICE)
    pad_mask   = (id_tensor == Vocabulary.PAD)

    with torch.no_grad():
        logits, cls_emb, attn_weights = model(id_tensor, padding_mask=pad_mask)

    cls_np = cls_emb[0].cpu().numpy()

    # Attention profile: for each layer×head, mean attention FROM CLS TO each position
    # Shape: (n_layers, n_heads, seq_len)
    if attn_weights:
        # attn_weights[layer]: (1, n_heads, seq_len, seq_len)
        # Take row 0 (attention from CLS token, position 0)
        head_attns = []
        for layer_attn in attn_weights:
            # (1, H, L, L) → (H, L)
            cls_row = layer_attn[0, :, 0, :].cpu().numpy()  # H × L
            head_attns.append(cls_row)
        attn_profile = np.concatenate(head_attns, axis=0).flatten()  # (n_layers×H×L,)
    else:
        attn_profile = np.zeros(N_LAYERS * N_HEADS * MAX_SEQ_LEN)

    return cls_np, attn_profile


def build_attention_feature_matrix(model: LogTransformer, sessions: List[Dict],
                                   vocab: Vocabulary) -> np.ndarray:
    """Extract CLS embeddings for all sessions → (N, d_model) matrix."""
    embeddings = []
    for i, sess in enumerate(sessions):
        cls_emb, _ = extract_session_embedding(model, sess, vocab)
        embeddings.append(cls_emb)
        if (i + 1) % 200 == 0:
            print(f"  Embedded {i+1}/{len(sessions)} sessions...")
    return np.array(embeddings, dtype=np.float32)


# ── Feature Discovery ─────────────────────────────────────────────────────────

def discover_features(model: LogTransformer, normal_sessions: List[Dict],
                      attack_sessions: List[Dict], vocab: Vocabulary) -> Dict:
    """
    Core analysis:
    1. Embed all sessions via transformer CLS token
    2. PCA on normal sessions → find how many components explain ≥92% variance
    3. Project attacks → measure separation
    4. Map top PCA components back to vocabulary tokens via attention analysis
    """
    print("\n[transformer] Extracting embeddings for all sessions...")
    all_sessions = normal_sessions + attack_sessions
    all_labels   = [0] * len(normal_sessions) + [1] * len(attack_sessions)

    X_all = build_attention_feature_matrix(model, all_sessions, vocab)
    X_norm = X_all[:len(normal_sessions)]
    X_atk  = X_all[len(normal_sessions):]

    # Normalize
    scaler = StandardScaler()
    X_norm_s = scaler.fit_transform(X_norm)
    X_all_s  = scaler.transform(X_all)

    # PCA on normal sessions
    pca = PCA(n_components=min(X_norm_s.shape[1], X_norm_s.shape[0] - 1))
    pca.fit(X_norm_s)
    cumvar = np.cumsum(pca.explained_variance_ratio_)

    # Find number of components for each variance threshold
    n_for_90 = int(np.searchsorted(cumvar, 0.90)) + 1
    n_for_92 = int(np.searchsorted(cumvar, 0.92)) + 1
    n_for_95 = int(np.searchsorted(cumvar, 0.95)) + 1

    print(f"\n[transformer] PCA on normal sessions ({X_norm_s.shape[0]} samples, {X_norm_s.shape[1]} dims)")
    print(f"  Components for 90% variance: {n_for_90}")
    print(f"  Components for 92% variance: {n_for_92}  ← target")
    print(f"  Components for 95% variance: {n_for_95}")
    print(f"  Confirmed TARGET_DIMS={TARGET_DIMS}: explains {cumvar[TARGET_DIMS-1]*100:.1f}% variance")

    # Project all into n_for_92-dim space
    X_proj_norm = pca.transform(X_norm_s)[:, :n_for_92]
    X_proj_all  = pca.transform(X_all_s)[:, :n_for_92]
    X_proj_atk  = X_proj_all[len(normal_sessions):]

    # Separation metric: how far are attack projections from normal centroid?
    norm_centroid = X_proj_norm.mean(axis=0)
    norm_std      = X_proj_norm.std(axis=0)
    atk_z_scores  = np.abs((X_proj_atk - norm_centroid) / (norm_std + 1e-8))
    norm_z_scores = np.abs((X_proj_norm - norm_centroid) / (norm_std + 1e-8))

    atk_mean_z  = float(atk_z_scores.mean())
    norm_mean_z = float(norm_z_scores.mean())
    separation_ratio = atk_mean_z / max(norm_mean_z, 1e-6)

    print(f"\n[transformer] Separation analysis:")
    print(f"  Normal mean z-score (should be ~1): {norm_mean_z:.3f}")
    print(f"  Attack mean z-score (should be >2): {atk_mean_z:.3f}")
    print(f"  Separation ratio: {separation_ratio:.2f}x  ({'GOOD ≥2x' if separation_ratio >= 2 else 'WEAK <2x'})")

    # AUC on projected features with IsolationForest
    y_all = np.array(all_labels)
    clf_if = IsolationForest(n_estimators=100, contamination=0.2, random_state=42)
    clf_if.fit(X_proj_all[y_all == 0])
    scores_if = -clf_if.score_samples(X_proj_all)  # higher = more anomalous
    auc_if = float(roc_auc_score(y_all, scores_if))
    print(f"  IsolationForest AUC on transformer features: {auc_if:.4f}")

    # Map top PCA components to vocabulary dimensions
    print("\n[transformer] Mapping PCA components to vocabulary tokens...")
    component_interpretations = []
    for comp_idx in range(min(n_for_92, 10)):
        comp = pca.components_[comp_idx]  # (d_model,)
        # Find which basis dimensions (d_model directions) load most
        top_dims = np.argsort(np.abs(comp))[::-1][:5]
        # The component explains variance in d_model space —
        # map back via attention: which vocab tokens caused high activation in those dims?
        # We use the embedding weight matrix: E (vocab × d_model)
        E = model.embedding.weight.detach().cpu().numpy()  # (V, d_model)
        proj_scores = E @ comp  # (V,) — how much each token aligns with this PC
        top_token_ids = np.argsort(np.abs(proj_scores))[::-1][:8]
        top_tokens = [(vocab.id2token.get(int(i), f"<{i}>"), float(proj_scores[i]))
                      for i in top_token_ids]
        var_explained = float(pca.explained_variance_ratio_[comp_idx]) * 100

        component_interpretations.append({
            "component": comp_idx + 1,
            "variance_explained_pct": round(var_explained, 2),
            "cumulative_variance_pct": round(float(cumvar[comp_idx]) * 100, 2),
            "top_tokens": top_tokens[:5],
        })
        print(f"  PC{comp_idx+1} ({var_explained:.1f}%): "
              f"{[t for t,_ in top_tokens[:4]]}")

    return {
        "n_normal_sessions": len(normal_sessions),
        "n_attack_sessions": len(attack_sessions),
        "d_model": D_MODEL,
        "pca_dims_for_90pct": n_for_90,
        "pca_dims_for_92pct": n_for_92,
        "pca_dims_for_95pct": n_for_95,
        "variance_at_target_dims": round(float(cumvar[TARGET_DIMS - 1]) * 100, 2),
        "separation_ratio": round(separation_ratio, 3),
        "attack_mean_z": round(atk_mean_z, 3),
        "normal_mean_z": round(norm_mean_z, 3),
        "if_auc_on_transformer_features": round(auc_if, 4),
        "cumulative_variance": [round(float(v) * 100, 2) for v in cumvar[:30]],
        "component_interpretations": component_interpretations,
    }


# ── Attention Head Specialization Analysis ────────────────────────────────────

def analyze_attention_heads(model: LogTransformer, normal_sessions: List[Dict],
                              attack_sessions: List[Dict], vocab: Vocabulary) -> Dict:
    """
    Find which attention heads specialize in different behavioral dimensions.
    An "attack-sensitive" head has high attention to different tokens in attack sessions.
    """
    print("\n[transformer] Analyzing attention head specialization...")

    def get_head_attn_patterns(sessions: List[Dict], label: str, max_n: int = 300) -> np.ndarray:
        """For each session, get mean attention weight per vocab token per head."""
        head_token_attn = defaultdict(lambda: defaultdict(list))
        for sess in sessions[:max_n]:
            ids = vocab.encode(sess["tokens"])
            id_tensor = torch.tensor([ids], dtype=torch.long, device=DEVICE)
            pad_mask  = (id_tensor == Vocabulary.PAD)
            with torch.no_grad():
                _, _, attn_weights = model(id_tensor, padding_mask=pad_mask)
            if not attn_weights:
                continue
            # For each layer, for each head: which token positions get most attention from CLS?
            for layer_idx, layer_attn in enumerate(attn_weights):
                # layer_attn: (1, H, L, L)
                for head_idx in range(layer_attn.shape[1]):
                    cls_attn = layer_attn[0, head_idx, 0, :].cpu().numpy()  # (L,)
                    # Map positions back to vocab tokens
                    for pos, token_id in enumerate(ids):
                        if token_id not in (Vocabulary.PAD, Vocabulary.CLS):
                            key = f"L{layer_idx}H{head_idx}"
                            head_token_attn[key][vocab.id2token.get(token_id, "<UNK>")].append(
                                float(cls_attn[pos])
                            )
        return head_token_attn

    normal_heads = get_head_attn_patterns(normal_sessions, "normal")
    attack_heads = get_head_attn_patterns(attack_sessions, "attack")

    head_analysis = {}
    for head_key in normal_heads:
        if head_key not in attack_heads:
            continue
        n_tokens = set(normal_heads[head_key].keys()) | set(attack_heads[head_key].keys())
        diffs = {}
        for tok in n_tokens:
            n_mean = np.mean(normal_heads[head_key].get(tok, [0.0]))
            a_mean = np.mean(attack_heads[head_key].get(tok, [0.0]))
            if n_mean > 0.001 or a_mean > 0.001:
                diffs[tok] = round(float(a_mean - n_mean), 4)
        # Sort by absolute difference
        top_diffs = sorted(diffs.items(), key=lambda x: abs(x[1]), reverse=True)[:5]
        head_analysis[head_key] = {
            "top_discriminative_tokens": top_diffs,
            "attack_attends_more": [(t, d) for t, d in top_diffs if d > 0],
            "normal_attends_more": [(t, d) for t, d in top_diffs if d < 0],
        }

    # Report most discriminative heads
    head_scores = {
        k: sum(abs(d) for _, d in v["top_discriminative_tokens"])
        for k, v in head_analysis.items()
    }
    top_heads = sorted(head_scores.items(), key=lambda x: x[1], reverse=True)[:8]
    print("  Top discriminative heads (attack vs normal attention):")
    for head_key, score in top_heads:
        analysis = head_analysis[head_key]
        print(f"  {head_key}: score={score:.4f}")
        for tok, diff in analysis["top_discriminative_tokens"][:3]:
            direction = "↑attack" if diff > 0 else "↑normal"
            print(f"    {tok}: {diff:+.4f} {direction}")

    return {
        "top_discriminative_heads": [
            {"head": k, "score": round(v, 4), "tokens": head_analysis[k]["top_discriminative_tokens"]}
            for k, v in top_heads
        ]
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    t0 = time.time()
    print("=" * 70)
    print("TAARA Transformer Feature Discovery")
    print(f"Device: {DEVICE}")
    print("=" * 70)

    # 1. Parse sessions
    print("\n[transformer] Parsing normal sessions...")
    elastic_sessions = parse_elastic_sessions(ELASTIC_LOG)
    ssh_sessions     = parse_ssh_legit_sessions(SSH_LOG)
    normal_sessions  = elastic_sessions + ssh_sessions
    print(f"  elastic_auth.log: {len(elastic_sessions)} sessions")
    print(f"  SSH.log legit:    {len(ssh_sessions)} sessions")
    print(f"  Total normal:     {len(normal_sessions)} sessions")

    print("\n[transformer] Parsing attack sessions (Cowrie)...")
    attack_sessions = parse_cowrie_sessions(COWRIE_DIR, max_sessions=1000)
    print(f"  Cowrie attacks: {len(attack_sessions)} post-auth sessions")

    if len(attack_sessions) < 10:
        print("[ERROR] Too few attack sessions. Check Cowrie data in benchmark/datasets/cowrie/")
        return

    # 2. Build vocabulary from all sessions
    vocab = Vocabulary()
    vocab.build(normal_sessions + attack_sessions, max_size=VOCAB_SIZE)

    # 3. Train transformer on normal sessions only
    model = LogTransformer(
        vocab_size=len(vocab),
        d_model=D_MODEL,
        n_heads=N_HEADS,
        n_layers=N_LAYERS,
        max_len=MAX_SEQ_LEN,
    ).to(DEVICE)

    print(f"\n[transformer] Model parameters: {sum(p.numel() for p in model.parameters()):,}")
    train_transformer(model, normal_sessions, vocab)

    # 4. Feature discovery analysis
    discovery = discover_features(model, normal_sessions, attack_sessions, vocab)

    # 5. Attention head specialization
    head_analysis = analyze_attention_heads(model, normal_sessions, attack_sessions, vocab)

    # 6. Print summary
    print("\n" + "=" * 70)
    print("FEATURE DISCOVERY SUMMARY")
    print("=" * 70)
    print(f"Normal sessions:  {discovery['n_normal_sessions']}")
    print(f"Attack sessions:  {discovery['n_attack_sessions']}")
    print(f"Transformer dim:  {discovery['d_model']}")
    print()
    print(f"PCA variance analysis (after transformer embedding):")
    print(f"  Dims for 90% variance: {discovery['pca_dims_for_90pct']}")
    print(f"  Dims for 92% variance: {discovery['pca_dims_for_92pct']}  ← use this as feature count")
    print(f"  Dims for 95% variance: {discovery['pca_dims_for_95pct']}")
    print(f"  Variance at TARGET_DIMS={TARGET_DIMS}: {discovery['variance_at_target_dims']}%")
    print()
    print(f"Separation (attack vs normal in transformer feature space):")
    print(f"  Separation ratio: {discovery['separation_ratio']}x")
    print(f"  IsolationForest AUC: {discovery['if_auc_on_transformer_features']}")
    print()
    print("PCA component → token mapping (what each dimension represents):")
    for c in discovery["component_interpretations"]:
        tokens = [t for t, _ in c["top_tokens"]]
        print(f"  PC{c['component']:2d} ({c['variance_explained_pct']:4.1f}%, cum {c['cumulative_variance_pct']:4.1f}%): "
              f"{tokens}")

    # 7. Save results
    output = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "config": {
            "d_model": D_MODEL, "n_heads": N_HEADS, "n_layers": N_LAYERS,
            "max_seq_len": MAX_SEQ_LEN, "vocab_size": len(vocab),
            "train_epochs": TRAIN_EPOCHS, "target_dims": TARGET_DIMS,
        },
        "discovery": discovery,
        "head_analysis": head_analysis,
    }

    out_json = RESULTS_DIR / "feature_discovery_report.json"
    with open(out_json, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n[transformer] Results saved to {out_json}")

    # Text report
    report_lines = [
        "TAARA Transformer Feature Discovery Report",
        "=" * 50,
        f"Dataset: elastic_auth.log + SSH.log (normal), Cowrie Zenodo 3687527 (attack)",
        f"Normal sessions: {discovery['n_normal_sessions']}",
        f"Attack sessions: {discovery['n_attack_sessions']}",
        "",
        "Key Finding:",
        f"  Transformer-discovered features ({discovery['d_model']}-dim CLS embedding)",
        f"  need {discovery['pca_dims_for_92pct']} PCA components to explain 92% variance.",
        f"  This {'confirms' if discovery['pca_dims_for_92pct'] <= TARGET_DIMS else 'suggests adjusting'} "
        f"our TARGET_DIMS={TARGET_DIMS} choice.",
        f"  Variance at {TARGET_DIMS} dims: {discovery['variance_at_target_dims']}%",
        "",
        "Separation (attack vs normal in transformer space):",
        f"  Ratio: {discovery['separation_ratio']}x  (IsolationForest AUC: {discovery['if_auc_on_transformer_features']})",
        "",
        "Component interpretations (what each PCA dimension represents):",
    ]
    for c in discovery["component_interpretations"]:
        tokens = [t for t, _ in c["top_tokens"]]
        report_lines.append(
            f"  PC{c['component']:2d} ({c['variance_explained_pct']:.1f}%): {tokens}"
        )
    report_lines.extend([
        "",
        "Top discriminative attention heads:",
    ])
    for h in head_analysis.get("top_discriminative_heads", [])[:5]:
        report_lines.append(
            f"  {h['head']}: {h['tokens'][:3]}"
        )
    report_lines.append(f"\nRuntime: {time.time()-t0:.1f}s")

    out_txt = RESULTS_DIR / "feature_discovery_report.txt"
    with open(out_txt, "w") as f:
        f.write("\n".join(report_lines))
    print(f"[transformer] Text report saved to {out_txt}")


if __name__ == "__main__":
    main()
