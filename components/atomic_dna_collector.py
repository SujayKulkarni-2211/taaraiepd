"""
Atomic Digital DNA Collector
=============================

Collects session-behavioral features from a remote system via SSH.
Features match exactly the 19-dimensional vector used in TAARA v8 benchmark
(experiments/taara_benchmark_v8.py :: extract_19).

The AE was trained on these 19 features — the order must never change.

Feature index map:
  0  session_duration          — seconds since login (from /proc/uptime - last login delta)
  1  commands_per_minute       — cmd count / elapsed minutes
  2  inter_cmd_timing_std      — std of gaps between commands (from history timestamps)
  3  session_idle_ratio        — fraction of session with no commands
  4  unique_commands           — number of distinct command names
  5  command_entropy           — Shannon entropy over command frequencies
  6  shell_history_delta       — admin command count (writes, config, service mgmt)
  7  sensitive_path_access     — 1 if .ssh/authorized_keys/shadow/id_rsa touched recently
  8  hardware_enum_count       — uname/free/top/w/lscpu/lspci/cpuinfo/df/uptime/nproc calls
  9  outbound_connections      — established outbound TCP connections (wget/curl proxy)
  10 persistence_attempt       — crontab command calls
  11 malware_exec_pattern      — wget/curl/nc/chmod/nohup/busybox/mknod calls
  12 process_spawn_count       — dd/busybox/sh/bash/perl/python runs in history
  13 network_device_shell      — router/IoT exploitation commands (version/shell/enable/configure)
  14 data_volume_proxy         — outbound + download proxies combined
  15 sin(2π·hour/24)           — sinusoidal hour of day
  16 cos(2π·hour/24)
  17 sin(2π·dow/7)             — sinusoidal day of week
  18 cos(2π·dow/7)
"""

import time
import math
import re
import hmac
import hashlib
import json
import os
from typing import Dict, List, Tuple, Any, Optional
from collections import Counter
import numpy as np


_KEYS_PATH = os.path.join("models", "client_keys.json")


def _get_hmac_key(host: str) -> Optional[bytes]:
    """Return the HMAC key for this host (SHA3-256 of the Kyber shared secret + host)."""
    try:
        with open(_KEYS_PATH) as f:
            store = json.load(f)
        entry = store.get(host, {})
        # Use the shared_secret if present, else fingerprint as fallback key material
        secret_hex = entry.get("shared_secret") or entry.get("ssh_host_key_fingerprint")
        if not secret_hex:
            return None
        raw = bytes.fromhex(secret_hex) if len(secret_hex) >= 32 else secret_hex.encode()
        return hashlib.sha3_256(raw + host.encode()).digest()
    except Exception:
        return None


def sign_vector(vec: np.ndarray, host: str) -> str:
    """Return HMAC-SHA256 hex of the feature vector bytes, keyed per-host."""
    key = _get_hmac_key(host)
    if key is None:
        return ""
    return hmac.new(key, vec.astype(np.float32).tobytes(), hashlib.sha256).hexdigest()


def verify_vector(vec: np.ndarray, tag: str, host: str) -> bool:
    """Return True if tag matches expected HMAC. Empty tag = key not configured (pass-through)."""
    if not tag:
        return True
    key = _get_hmac_key(host)
    if key is None:
        return True
    expected = hmac.new(key, vec.astype(np.float32).tobytes(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, tag)


# ── Command cluster sets (must match benchmark exactly) ───────────────────────
HW_ENUM  = {"uname", "free", "top", "w", "lscpu", "lspci", "cpuinfo", "df", "uptime", "nproc"}
RECON    = {"whoami", "id", "cat", "ls", "ps", "netstat", "ifconfig", "ip"}
PERSIST  = {"crontab"}
MALWARE  = {"wget", "curl", "tftp", "nc", "netcat", "chmod", "nohup", "tar", "busybox", "dd", "mknod"}
NETDEV   = {"version", "shell", "enable", "terminal", "configure"}
ADMIN    = {"apt-get", "apt", "vim", "nano", "systemctl", "service", "sudo", "su",
            "scp", "git", "pip", "docker"}
SENSITIVE_PATHS = {".ssh", "authorized_keys", "/etc/passwd", "/etc/shadow",
                   "id_rsa", "/root", "crontab", ".bash_history"}
SPAWN_CMDS = {"dd", "busybox", "sh", "bash", "perl", "python", "python3"}

FEATURE_NAMES = [
    "session_duration", "commands_per_minute", "inter_cmd_timing_std",
    "session_idle_ratio", "unique_commands", "command_entropy",
    "shell_history_delta", "sensitive_path_access", "hardware_enum_count",
    "outbound_connections", "persistence_attempt", "malware_exec_pattern",
    "process_spawn_count", "network_device_shell", "data_volume_proxy",
    "time_sin_hour", "time_cos_hour", "time_sin_dow", "time_cos_dow",
]


class AtomicDNACollector:
    """Collects session-behavioral DNA from a remote machine via SSH."""

    def __init__(self, ssh_manager, host: str = ""):
        self.ssh_manager = ssh_manager
        self.host = host  # used for HMAC signing
        self.session_start = time.time()
        self._cmd_log: List[Tuple[float, str]] = []  # (timestamp, cmd)
        self._last_history_len = 0
        self._baseline_history: List[str] = []  # history at session start
        self.history: List[Dict] = []
        self.last_collection_time: float = 0.0

    # ── Public API ──────────────────────────────────────────────────────────────

    def collect(self) -> Dict[str, float]:
        """Collect all features, update cmd_log from remote history."""
        self._sync_remote_history()
        features = self._compute_features()
        ts = time.time()
        self.history.append({"timestamp": ts, "features": features.copy()})
        if len(self.history) > 60:
            self.history = self.history[-60:]
        self.last_collection_time = ts
        return features

    def get_feature_vector(self) -> np.ndarray:
        features = self.collect()
        vec = np.array([features.get(n, 0.0) for n in FEATURE_NAMES], dtype=np.float32)
        vec = np.nan_to_num(vec, nan=0.0, posinf=500.0, neginf=0.0)
        return vec

    def get_signed_vector(self) -> Tuple[np.ndarray, str]:
        """Return (feature_vector, hmac_tag). Tag is '' if no key configured."""
        vec = self.get_feature_vector()
        tag = sign_vector(vec, self.host) if self.host else ""
        return vec, tag

    def get_feature_names(self) -> List[str]:
        return list(FEATURE_NAMES)

    # ── Remote history sync ────────────────────────────────────────────────────

    def _sync_remote_history(self):
        """Read ~/.bash_history from remote and update cmd_log with new entries."""
        try:
            stdout, _, _ = self.ssh_manager.execute_command(
                "cat ~/.bash_history 2>/dev/null | tail -200"
            )
            if not stdout:
                return
            lines = [l.strip() for l in stdout.strip().splitlines() if l.strip()]

            # On first call, record the baseline so we only track *new* commands
            if not self._baseline_history:
                self._baseline_history = lines
                return

            # New commands = anything beyond the baseline length
            if len(lines) > len(self._baseline_history):
                new_cmds = lines[len(self._baseline_history):]
                now = time.time()
                # Spread new commands evenly between last collection and now
                n = len(new_cmds)
                for i, cmd in enumerate(new_cmds):
                    t = self.last_collection_time + (now - self.last_collection_time) * (i + 1) / n
                    self._cmd_log.append((t, cmd.strip()))
        except Exception as e:
            print(f"[AtomicDNA] history sync error: {e}")

    # ── Feature computation ────────────────────────────────────────────────────

    def _compute_features(self) -> Dict[str, float]:
        now = time.time()
        dur = max(now - self.session_start, 0.01)
        cmds = [c for _, c in self._cmd_log]
        ctimes = [t for t, _ in self._cmd_log]
        cmd_names = [c.split()[0] for c in cmds if c.split()]
        n = max(len(cmd_names), 1)

        # 0 — session_duration
        f0 = min(dur, 86400.0)

        # 1 — commands_per_minute
        f1 = min(n / (dur / 60 + 1e-6), 500.0)

        # 2 — inter_cmd_timing_std
        if len(ctimes) > 1:
            gaps = [max(ctimes[i+1] - ctimes[i], 0) for i in range(len(ctimes) - 1)]
            f2 = min(float(np.std(gaps)), 7200.0)
        else:
            f2 = 0.0

        # 3 — session_idle_ratio
        if len(ctimes) > 1:
            active = ctimes[-1] - ctimes[0] if ctimes[-1] > ctimes[0] else 0
            f3 = max(1.0 - active / dur, 0.0)
        else:
            f3 = 1.0 if len(cmd_names) <= 1 else 0.0

        # 4 — unique_commands
        f4 = float(len(set(cmd_names)))

        # 5 — command_entropy
        cnt = Counter(cmd_names)
        f5 = -sum((c / n) * math.log2(c / n + 1e-9) for c in cnt.values()) if cmd_names else 0.0

        # 6 — shell_history_delta (admin command count)
        f6 = float(sum(1 for c in cmd_names if c in ADMIN))

        # 7 — sensitive_path_access
        sensitive_hit = any(
            any(p in cmd for p in SENSITIVE_PATHS) for cmd in cmds
        )
        # Also probe filesystem for recent access
        if not sensitive_hit:
            sensitive_hit = self._probe_sensitive_paths()
        f7 = float(int(sensitive_hit))

        # 8 — hardware_enum_count
        f8 = float(sum(1 for c in cmd_names if c in HW_ENUM))

        # 9 — outbound_connections (live network state)
        f9 = float(self._count_outbound())

        # 10 — persistence_attempt
        f10 = float(sum(1 for c in cmd_names if c in PERSIST))

        # 11 — malware_exec_pattern
        f11 = float(sum(1 for c in cmd_names if c in MALWARE))

        # 12 — process_spawn_count
        f12 = float(sum(1 for c in cmd_names if c in SPAWN_CMDS))

        # 13 — network_device_shell
        f13 = float(sum(1 for c in cmd_names if c in NETDEV))

        # 14 — data_volume_proxy (outbound + wget/curl count as download proxy)
        downloads = sum(1 for c in cmd_names if c in {"wget", "curl", "tftp"})
        f14 = float(f9 + downloads)

        # 15-18 — sinusoidal time encoding
        lt = time.localtime(now)
        hour = lt.tm_hour
        dow = lt.tm_wday
        f15 = math.sin(2 * math.pi * hour / 24)
        f16 = math.cos(2 * math.pi * hour / 24)
        f17 = math.sin(2 * math.pi * dow / 7)
        f18 = math.cos(2 * math.pi * dow / 7)

        return {
            "session_duration": f0,
            "commands_per_minute": f1,
            "inter_cmd_timing_std": f2,
            "session_idle_ratio": f3,
            "unique_commands": f4,
            "command_entropy": f5,
            "shell_history_delta": f6,
            "sensitive_path_access": f7,
            "hardware_enum_count": f8,
            "outbound_connections": f9,
            "persistence_attempt": f10,
            "malware_exec_pattern": f11,
            "process_spawn_count": f12,
            "network_device_shell": f13,
            "data_volume_proxy": f14,
            "time_sin_hour": f15,
            "time_cos_hour": f16,
            "time_sin_dow": f17,
            "time_cos_dow": f18,
        }

    # ── SSH probes ─────────────────────────────────────────────────────────────

    def _probe_sensitive_paths(self) -> bool:
        """Check if sensitive files were accessed in the last 5 minutes."""
        try:
            for path in ["/root/.ssh", "/home/*/.ssh", "/etc/passwd", "/etc/shadow"]:
                out, _, _ = self.ssh_manager.execute_command(
                    f"find {path} -type f -mmin -5 2>/dev/null | head -1"
                )
                if out and out.strip():
                    return True
        except Exception:
            pass
        return False

    def _count_outbound(self) -> int:
        """Count established outbound TCP connections."""
        try:
            out, _, _ = self.ssh_manager.execute_command(
                "ss -tn state established 2>/dev/null | grep -v '127.0.0.1' | wc -l"
            )
            val = int(out.strip()) if out.strip().isdigit() else 0
            return max(val - 1, 0)  # subtract the TAARA SSH connection itself
        except Exception:
            return 0
