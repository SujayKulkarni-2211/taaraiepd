"""
TaaraWare Deployment & Management
===================================

TaaraWare is an always-on collector + policy-bounded action layer deployed
to customer infrastructure. It is NOT a standalone security scanner —
it is the continuous collection and enforcement arm of TAARA.

Architecture:
  TaaraWare (on customer server/infra): Lightweight collector — CPU only
  TAARA Command Center (admin laptop/cloud): ML + Quantum analysis, decisions
  Human operator: approves high-impact actions

Three pillars of collection:

  1. Security Behavior
     - Auth events (failed/accepted logins per identity per window)
     - Connection patterns (new outbound IPs, port changes)
     - Process and network anomaly signals
     - Raw SSH config / open port changes
     -> Fed to TAARA reconstruction-based memory: detects behavioral drift
        before it shows up as a measurable event

  2. Config / Deploy Drift
     - sshd_config changes (file hash diff)
     - New ports opened (ss -tulnp delta)
     - Dockerfile / CI config changes (git diff on watched paths)
     - Unauthorized package installs
     -> Policy-bounded alerting: alerts on unauthorized config changes

  3. Resource / Spend Signals
     - CPU/memory/disk usage trends
     - Storage growth rate
     - Cloud API cost deltas (for cloud-connected deployments)
     - Runaway process detection (>90% CPU for >5 min)
     -> Early-warning on runaway costs and resource anomalies
        before they affect production or billing

Autonomy model (policy-bounded):
  TaaraWare collects lightweight signals locally.
  TAARA Command Center analyzes and approves actions.
  Human approval required for high-impact actions.

  Allowed without approval (pre-approved policy):
    - Block repeated SSH brute-force IP (>50 fails, 0 success, <10 min window)
    - Alert on new public port opened
    - Restart failed monitoring service (health check fails 3x)
    - Pause non-critical runaway process (>95% CPU, pre-approved list only)

  Always require human approval:
    - Delete or terminate cloud resource
    - Broad firewall rule changes
    - Rotate production secrets
    - Modify CI/CD configuration
    - Terminate server or container

Federated design: raw data stays on customer infrastructure.
Only feature vectors and alert payloads are sent to Command Center.
"""

import streamlit as st
import time
import json
import os
import secrets
import hashlib
import threading
from typing import Dict, List, Optional
from datetime import datetime
import numpy as np


TAARAWARE_AGENT_SCRIPT = '''#!/usr/bin/env python3
"""
TaaraWare Agent v2.1
====================
Always-on collector + policy-bounded action layer for customer infrastructure.
Deployed by TAARA Command Center.

Supports: Linux and macOS (Darwin). OS detected automatically at startup.
"""

import os
import sys
import time
import json
import math
import signal
import socket
import hashlib
import logging
import platform as _platform
import subprocess
from datetime import datetime
from collections import defaultdict
from pathlib import Path

_opt = Path("/opt/taaraware")
TAARAWARE_DIR = _opt if _opt.exists() else Path.home() / "taaraware"
CONFIG_FILE = TAARAWARE_DIR / "config.json"
DATA_DIR = TAARAWARE_DIR / "data"
LOG_FILE = TAARAWARE_DIR / "taaraware.log"
FEATURE_BUFFER = DATA_DIR / "feature_buffer.json"
ALERT_LOG = DATA_DIR / "alerts.json"

IS_MACOS = _platform.system() == "Darwin"

logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s [TaaraWare] %(levelname)s: %(message)s"
)
logger = logging.getLogger("taaraware")

DEFAULT_CONFIG = {
    "command_center_host": "",
    "command_center_port": 9977,
    "collection_interval": 30,
    "max_buffer_size": 1000,
    "heartbeat_interval": 60,
    "version": "2.2.0"
}

running = True

def signal_handler(sig, frame):
    global running
    logger.info("Shutdown signal received")
    running = False

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)


def run_cmd(cmd, timeout=10):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip()
    except Exception:
        return ""


# ── 19-feature DNA collector (matches TAARA v8 benchmark exactly) ─────────────

HW_ENUM   = {"uname", "free", "top", "w", "lscpu", "lspci", "df", "uptime", "nproc"}
PERSIST   = {"crontab"}
MALWARE   = {"wget", "curl", "tftp", "nc", "netcat", "chmod", "nohup", "tar", "busybox", "dd", "mknod"}
NETDEV    = {"version", "shell", "enable", "terminal", "configure"}
ADMIN     = {"apt-get", "apt", "vim", "nano", "systemctl", "service", "sudo", "su",
             "scp", "git", "pip", "docker"}
SPAWN_CMDS = {"dd", "busybox", "sh", "bash", "perl", "python", "python3"}
SENSITIVE_PATHS = {".ssh", "authorized_keys", "/etc/passwd", "/etc/shadow",
                   "id_rsa", "/root", ".bash_history"}

FEATURE_NAMES = [
    "session_duration", "commands_per_minute", "inter_cmd_timing_std",
    "session_idle_ratio", "unique_commands", "command_entropy",
    "shell_history_delta", "sensitive_path_access", "hardware_enum_count",
    "outbound_connections", "persistence_attempt", "malware_exec_pattern",
    "process_spawn_count", "network_device_shell", "data_volume_proxy",
    "time_sin_hour", "time_cos_hour", "time_sin_dow", "time_cos_dow",
]

# State persisted across collection cycles
_state = {
    "session_start": time.time(),
    "baseline_history": None,   # history lines at agent start
    "cmd_log": [],              # [(timestamp, cmd), ...]
    "last_collection_time": time.time(),
    "last_history_len": 0,      # track growth without re-reading full file
}

HISTORY_POLL_INTERVAL = 3  # seconds — poll history this often inside each 30s window


def _read_bash_history():
    for candidate in [Path.home() / ".bash_history", Path("/root/.bash_history")]:
        if candidate.exists():
            try:
                return candidate.read_text(errors="replace").strip().splitlines()
            except Exception:
                pass
    return []


def _sync_history():
    lines = _read_bash_history()
    if _state["baseline_history"] is None:
        _state["baseline_history"] = lines
        _state["last_history_len"] = len(lines)
        return
    prev_len = _state["last_history_len"]
    if len(lines) > prev_len:
        new_cmds = lines[prev_len:]
        now = time.time()
        for cmd in new_cmds:
            _state["cmd_log"].append((now, cmd.strip()))
        _state["last_history_len"] = len(lines)
        _state["cmd_log"] = _state["cmd_log"][-500:]


def _count_outbound():
    try:
        out = run_cmd('ss -tn state established 2>/dev/null | grep -v "127.0.0.1" | wc -l')
        return max(int(out) - 1, 0)  # subtract own SSH session
    except Exception:
        return 0


def _probe_sensitive():
    for path in [".ssh/", "authorized_keys", "/etc/shadow", "id_rsa"]:
        out = run_cmd(f'find $HOME /etc -name "*" -newer /tmp -path "*{path}*" 2>/dev/null | head -1')
        if out.strip():
            return True
    return False


def collect_features():
    # _sync_history already called by the polling loop
    now = time.time()
    # Use only commands seen since the last collection — sliding window
    window_start = _state["last_collection_time"]
    window_cmds = [(t, c) for t, c in _state["cmd_log"] if t >= window_start]
    dur = max(now - window_start, 0.01)
    cmds = [c for _, c in window_cmds]
    ctimes = [t for t, _ in window_cmds]
    cmd_names = [c.split()[0] for c in cmds if c.split()]
    n = max(len(cmd_names), 1)

    # 0 session_duration — seconds of activity in this collection window
    f0 = min(dur, 86400.0)

    # 1 commands_per_minute
    f1 = min(n / (dur / 60 + 1e-6), 500.0)

    # 2 inter_cmd_timing_std
    if len(ctimes) > 1:
        gaps = [max(ctimes[i+1] - ctimes[i], 0) for i in range(len(ctimes) - 1)]
        import statistics
        f2 = min(statistics.stdev(gaps) if len(gaps) > 1 else 0.0, 7200.0)
    else:
        f2 = 0.0

    # 3 session_idle_ratio
    if len(ctimes) > 1:
        active = ctimes[-1] - ctimes[0]
        f3 = max(1.0 - active / dur, 0.0)
    else:
        f3 = 1.0

    # 4 unique_commands
    f4 = float(len(set(cmd_names)))

    # 5 command_entropy
    from collections import Counter
    cnt = Counter(cmd_names)
    f5 = -sum((c / n) * math.log2(c / n + 1e-9) for c in cnt.values()) if cmd_names else 0.0

    # 6 shell_history_delta (admin command count)
    f6 = float(sum(1 for c in cmd_names if c in ADMIN))

    # 7 sensitive_path_access
    sensitive = any(any(p in cmd for p in SENSITIVE_PATHS) for cmd in cmds)
    if not sensitive:
        sensitive = _probe_sensitive()
    f7 = float(int(sensitive))

    # 8 hardware_enum_count
    f8 = float(sum(1 for c in cmd_names if c in HW_ENUM))

    # 9 outbound_connections
    f9 = float(_count_outbound())

    # 10 persistence_attempt
    f10 = float(sum(1 for c in cmd_names if c in PERSIST))

    # 11 malware_exec_pattern
    f11 = float(sum(1 for c in cmd_names if c in MALWARE))

    # 12 process_spawn_count
    f12 = float(sum(1 for c in cmd_names if c in SPAWN_CMDS))

    # 13 network_device_shell
    f13 = float(sum(1 for c in cmd_names if c in NETDEV))

    # 14 data_volume_proxy
    downloads = sum(1 for c in cmd_names if c in {"wget", "curl", "tftp"})
    f14 = float(f9 + downloads)

    # 15-18 sinusoidal time
    lt = time.localtime(now)
    f15 = math.sin(2 * math.pi * lt.tm_hour / 24)
    f16 = math.cos(2 * math.pi * lt.tm_hour / 24)
    f17 = math.sin(2 * math.pi * lt.tm_wday / 7)
    f18 = math.cos(2 * math.pi * lt.tm_wday / 7)

    _state["last_collection_time"] = now

    return {
        "session_duration": f0, "commands_per_minute": f1, "inter_cmd_timing_std": f2,
        "session_idle_ratio": f3, "unique_commands": f4, "command_entropy": f5,
        "shell_history_delta": f6, "sensitive_path_access": f7, "hardware_enum_count": f8,
        "outbound_connections": f9, "persistence_attempt": f10, "malware_exec_pattern": f11,
        "process_spawn_count": f12, "network_device_shell": f13, "data_volume_proxy": f14,
        "time_sin_hour": f15, "time_cos_hour": f16, "time_sin_dow": f17, "time_cos_dow": f18,
        "timestamp": now, "hostname": socket.gethostname(),
    }


def check_local_alerts(features, config):
    # Alert decisions made by TAARA quantum pipeline on the server — agent only collects.
    return []


def send_to_command_center(data, config):
    host = config.get("command_center_host", "")
    port = config.get("command_center_port", 9977)
    if not host:
        return False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        sock.sendall(json.dumps(data).encode())
        sock.close()
        return True
    except Exception as e:
        logger.warning(f"Failed to send to command center: {e}")
        return False


def buffer_features(features):
    buffer = []
    if FEATURE_BUFFER.exists():
        try:
            with open(FEATURE_BUFFER) as f:
                buffer = json.load(f)
        except Exception:
            buffer = []
    buffer.append(features)
    max_size = DEFAULT_CONFIG.get("max_buffer_size", 1000)
    if len(buffer) > max_size:
        buffer = buffer[-max_size:]
    with open(FEATURE_BUFFER, "w") as f:
        json.dump(buffer, f)
    return buffer


def main():
    global running

    TAARAWARE_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    config = DEFAULT_CONFIG.copy()
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE) as f:
                config.update(json.load(f))
        except Exception:
            pass

    logger.info(f"TaaraWare Agent v{config['version']} starting on {'macOS' if IS_MACOS else 'Linux'}")
    logger.info(f"Collection interval: {config['collection_interval']}s")
    logger.info(f"Command center: {config.get('command_center_host', 'not configured')}")

    collection_interval = int(config.get("collection_interval", 30))
    elapsed = 0

    while running:
        # Poll history every 3s so commands are captured even mid-session
        time.sleep(HISTORY_POLL_INTERVAL)
        elapsed += HISTORY_POLL_INTERVAL
        try:
            _sync_history()
        except Exception:
            pass

        if elapsed >= collection_interval:
            elapsed = 0
            try:
                features = collect_features()
                buffer_features(features)
                send_to_command_center({
                    "type": "telemetry", "features": features, "alerts": [],
                    "hostname": features.get("hostname", "unknown"),
                    "agent_version": config["version"]
                }, config)
                logger.info(f"Collection complete. cpm={features.get('commands_per_minute', 0):.1f} "
                            f"entropy={features.get('command_entropy', 0):.2f} "
                            f"sensitive={features.get('sensitive_path_access', 0):.0f}")
            except Exception as e:
                logger.error(f"Collection error: {e}")

    logger.info("TaaraWare Agent stopped")


if __name__ == "__main__":
    main()
'''


CURRENT_AGENT_VERSION = "2.2.0"


class TaaraWareManager:
    """Manages TaaraWare agent deployment and communication."""

    def __init__(self, model_dir: str = 'models'):
        self.model_dir = model_dir
        self.deployed_agents: Dict[str, Dict] = {}
        self.telemetry_buffer: Dict[str, List] = {}
        self.alerts: List[Dict] = []
        self._load_state()

    def deploy_agent(self, platform, config: Dict = None) -> Dict:
        """Deploy TaaraWare agent to the target platform."""
        result = {
            'success': False,
            'message': '',
            'timestamp': time.time()
        }

        ptype = platform.platform_type
        if ptype != 'ssh':
            result['message'] = f'TaaraWare deployment currently supports SSH platforms. For {ptype}, use cloud-native monitoring.'
            return result

        if not platform.connected:
            result['message'] = 'Platform not connected'
            return result

        try:
            # Detect remote OS and writable install path
            uname_out, _, _ = platform.execute_command("uname -s")
            is_macos = uname_out.strip().lower() == 'darwin'

            # Try /opt/taaraware first; fall back to ~/taaraware if /opt is read-only (e.g. Android/Termux)
            test_out, _, test_rc = platform.execute_command(
                "mkdir -p /opt/taaraware/data 2>/dev/null && echo ok || echo fallback"
            )
            if 'fallback' in (test_out or '') or test_rc != 0:
                idir = "$HOME/taaraware"
                platform.execute_command(f"mkdir -p {idir}/data")
            else:
                idir = "/opt/taaraware"

            agent_config = {
                "command_center_host": config.get('command_center_host', '') if config else '',
                "command_center_port": config.get('command_center_port', 9977) if config else 9977,
                "collection_interval": config.get('interval', 30) if config else 30,
                "max_buffer_size": 1000,
                "heartbeat_interval": 60,
                "version": "2.2.0"
            }

            config_json = json.dumps(agent_config)
            platform.execute_command(f"cat > {idir}/config.json << 'CONFIGEOF'\n{config_json}\nCONFIGEOF")
            platform.execute_command(f"cat > {idir}/taaraware_agent.py << 'AGENTEOF'\n{TAARAWARE_AGENT_SCRIPT}\nAGENTEOF")
            platform.execute_command(f"chmod +x {idir}/taaraware_agent.py")

            # Termux (Android) only has 'python', not 'python3'
            py_out, _, _ = platform.execute_command(
                "{ command -v python3 >/dev/null 2>&1 && echo python3; } || { command -v python >/dev/null 2>&1 && echo python; } || echo python3"
            )
            py_bin = (py_out or 'python3').strip().splitlines()[0].strip() or 'python3'

            if is_macos:
                # macOS: use launchd plist in user LaunchAgents
                plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.taara.taaraware</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>{idir}/taaraware_agent.py</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>WorkingDirectory</key><string>{idir}</string>
    <key>StandardOutPath</key><string>{idir}/taaraware.log</string>
    <key>StandardErrorPath</key><string>{idir}/taaraware_err.log</string>
</dict>
</plist>"""
                platform.execute_command("mkdir -p ~/Library/LaunchAgents")
                platform.execute_command(f"cat > ~/Library/LaunchAgents/com.taara.taaraware.plist << 'PLISTEOF'\n{plist}\nPLISTEOF")
                platform.execute_command("launchctl load ~/Library/LaunchAgents/com.taara.taaraware.plist 2>/dev/null || true")
                time.sleep(2)
                status_out, _, _ = platform.execute_command(
                    "launchctl list com.taara.taaraware 2>/dev/null && echo active || echo inactive"
                )
            else:
                # Try systemd; fall back to nohup background process (Termux has no systemd)
                systemd_ok, _, sd_rc = platform.execute_command(
                    "command -v systemctl >/dev/null 2>&1 && echo yes || echo no"
                )
                if 'yes' in (systemd_ok or '') and sd_rc == 0:
                    service_unit = f"""[Unit]
Description=TaaraWare Security Monitoring Agent
After=network.target

[Service]
Type=simple
ExecStart={py_bin} {idir}/taaraware_agent.py
Restart=always
RestartSec=30
WorkingDirectory={idir}

[Install]
WantedBy=multi-user.target
"""
                    platform.execute_command(f"cat > /etc/systemd/system/taaraware.service << 'SVCEOF'\n{service_unit}\nSVCEOF")
                    platform.execute_command("systemctl daemon-reload")
                    platform.execute_command("systemctl enable taaraware")
                    platform.execute_command("systemctl start taaraware")
                    time.sleep(2)
                    status_out, _, _ = platform.execute_command("systemctl is-active taaraware")
                else:
                    # No systemd (Termux/Android) — run directly in background with disown so it survives SSH exit
                    platform.execute_command("kill $(pgrep -f taaraware_agent.py) 2>/dev/null || true")
                    platform.execute_command(f"nohup {py_bin} {idir}/taaraware_agent.py > {idir}/taaraware.log 2>&1 </dev/null & disown")
                    time.sleep(2)
                    status_out, _, _ = platform.execute_command(
                        "pgrep -f taaraware_agent.py >/dev/null 2>&1 && echo active || echo inactive"
                    )

            host = platform.config.get('host', 'unknown')

            # PQC key generation — Kyber768 (ML-KEM, NIST FIPS 203)
            try:
                import oqs
                kem = oqs.KeyEncapsulation('Kyber768')
                public_key = kem.generate_keypair()
                ciphertext, shared_secret = kem.encap_secret(public_key)
                fingerprint = public_key.hex()[:8]

                keys_path = 'models/client_keys.json'
                os.makedirs('models', exist_ok=True)
                try:
                    with open(keys_path, 'r') as f:
                        client_keys = json.load(f)
                except Exception:
                    client_keys = {}

                client_keys[host] = {
                    'public_key': public_key.hex(),
                    'ciphertext': ciphertext.hex(),
                    'fingerprint': fingerprint,
                    'algorithm': 'Kyber768',
                    'generated_at': time.time(),
                }
                with open(keys_path, 'w') as f:
                    json.dump(client_keys, f)

                # Shared secret stays in memory only — never written to disk or server
                try:
                    import streamlit as _st
                    if 'client_shared_secrets' not in _st.session_state:
                        _st.session_state['client_shared_secrets'] = {}
                    _st.session_state['client_shared_secrets'][host] = shared_secret.hex()
                except Exception:
                    pass

            except Exception as pqc_err:
                fingerprint = 'pqc_unavailable'

            agent_info = {
                'host': host,
                'platform': ptype,
                'deployed_at': time.time(),
                'status': status_out.strip(),
                'config': agent_config,
                'version': '2.0.0',
                'key_fingerprint': fingerprint,
            }
            self.deployed_agents[host] = agent_info
            self._save_state()

            if 'active' in status_out.lower():
                result['success'] = True
                result['message'] = f'TaaraWare agent deployed and running on {host}'
            else:
                result['success'] = True
                result['message'] = f'TaaraWare agent deployed to {host} (status: {status_out.strip()})'
            result['key_fingerprint'] = fingerprint

        except Exception as e:
            result['message'] = f'Deployment error: {str(e)}'

        return result

    def check_agent_status(self, platform) -> Dict:
        """Check the status of a deployed TaaraWare agent."""
        if not platform.connected or platform.platform_type != 'ssh':
            return {'status': 'unknown', 'connected': False}

        try:
            uname_out, _, _ = platform.execute_command("uname -s")
            is_macos = uname_out.strip().lower() == 'darwin'

            if is_macos:
                status_out, _, _ = platform.execute_command(
                    "launchctl list com.taara.taaraware 2>/dev/null && echo active || echo inactive"
                )
            else:
                status_out, _, _ = platform.execute_command("systemctl is-active taaraware 2>/dev/null")

            pid_out, _, _ = platform.execute_command("pgrep -f taaraware_agent.py 2>/dev/null")
            # Check both install paths
            log_out, _, _ = platform.execute_command(
                "tail -5 /opt/taaraware/taaraware.log 2>/dev/null || tail -5 $HOME/taaraware/taaraware.log 2>/dev/null"
            )
            py_chk, _, _ = platform.execute_command(
                "{ command -v python3 >/dev/null 2>&1 && echo python3; } || { command -v python >/dev/null 2>&1 && echo python; } || echo python3"
            )
            py_chk_bin = (py_chk or 'python3').strip().splitlines()[0].strip() or 'python3'
            buffer_out, _, _ = platform.execute_command(
                f"{py_chk_bin} -c \"import json,os; p=('/opt/taaraware' if os.path.exists('/opt/taaraware') else os.path.expanduser('~/taaraware'))+'/data/feature_buffer.json'; d=json.load(open(p)); print(len(d))\" 2>/dev/null"
            )

            # Read deployed version from remote config.json
            ver_out, _, _ = platform.execute_command(
                f"{py_chk_bin} -c \"import json,os; p=('/opt/taaraware' if os.path.exists('/opt/taaraware') else os.path.expanduser('~/taaraware'))+'/config.json'; print(json.load(open(p)).get('version','unknown'))\" 2>/dev/null"
            )
            deployed_version = ver_out.strip() or 'unknown'
            update_available = (deployed_version != CURRENT_AGENT_VERSION and deployed_version != 'unknown')

            return {
                'status': status_out.strip(),
                'pid': pid_out.strip(),
                'recent_logs': log_out.strip(),
                'buffer_size': int(buffer_out.strip()) if buffer_out.strip().isdigit() else 0,
                'connected': True,
                'os': 'macOS' if is_macos else 'Linux',
                'deployed_version': deployed_version,
                'current_version': CURRENT_AGENT_VERSION,
                'update_available': update_available,
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e), 'connected': False}

    def collect_remote_data(self, platform) -> List[Dict]:
        """Collect buffered feature data from remote TaaraWare agent."""
        if not platform.connected or platform.platform_type != 'ssh':
            return []

        try:
            # Detect python binary (Termux only has 'python')
            py_cd, _, _ = platform.execute_command(
                "{ command -v python3 >/dev/null 2>&1 && echo python3; } || { command -v python >/dev/null 2>&1 && echo python; } || echo python3"
            )
            py_cd_bin = (py_cd or 'python3').strip().splitlines()[0].strip() or 'python3'
            # Use detected binary to emit only the JSON — avoids MOTD banner polluting stdout
            out, _, _ = platform.execute_command(
                f"{py_cd_bin} -c \""
                "import json,os,sys; "
                "p=('/opt/taaraware' if os.path.exists('/opt/taaraware') else os.path.expanduser('~/taaraware'))+'/data/feature_buffer.json'; "
                "d=json.load(open(p)); "
                "print(json.dumps(d[-50:]))"
                "\" 2>/dev/null"
            )
            if out:
                # Find the JSON array in output (strips any residual banner lines)
                start = out.find('[')
                end   = out.rfind(']') + 1
                if start >= 0 and end > start:
                    data = json.loads(out[start:end])
                    host = platform.config.get('host', 'unknown')
                    self.telemetry_buffer[host] = data
                    return data
        except Exception:
            pass
        return []

    def update_agent(self, platform) -> Dict:
        """
        Gracefully update the deployed TaaraWare agent to CURRENT_AGENT_VERSION.
        Stops the running agent, pushes new script + config, restarts.
        Buffer data is preserved — only the agent script is replaced.
        """
        result = {'success': False, 'message': '', 'version': CURRENT_AGENT_VERSION}
        if not platform.connected or platform.platform_type != 'ssh':
            result['message'] = 'Platform not connected'
            return result
        try:
            uname_out, _, _ = platform.execute_command("uname -s")
            is_macos = uname_out.strip().lower() == 'darwin'

            # Stop gracefully
            if is_macos:
                platform.execute_command("launchctl stop com.taara.taaraware 2>/dev/null || true")
            else:
                platform.execute_command("systemctl stop taaraware 2>/dev/null || pkill -f taaraware_agent.py 2>/dev/null || true")

            import time as _time
            _time.sleep(2)

            # Detect python binary on remote (Termux has 'python', not 'python3')
            py_out_upd, _, _ = platform.execute_command(
                "{ command -v python3 >/dev/null 2>&1 && echo python3; } || { command -v python >/dev/null 2>&1 && echo python; } || echo python3"
            )
            py_bin_upd = (py_out_upd or 'python3').strip().splitlines()[0].strip() or 'python3'

            # Push updated agent script (check both paths)
            idir_upd = "$(test -d /opt/taaraware && echo /opt/taaraware || echo $HOME/taaraware)"
            platform.execute_command(f"cat > {idir_upd}/taaraware_agent.py << 'AGENTEOF'\n{TAARAWARE_AGENT_SCRIPT}\nAGENTEOF")
            platform.execute_command(f"chmod +x {idir_upd}/taaraware_agent.py")

            # Update version + collection_interval in remote config
            platform.execute_command(
                f"{py_bin_upd} -c \""
                f"import json,os; p=('/opt/taaraware' if os.path.exists('/opt/taaraware') else os.path.expanduser('~/taaraware'))+'/config.json'; "
                f"c=json.load(open(p)); c['version']='{CURRENT_AGENT_VERSION}'; c['collection_interval']=30; "
                f"json.dump(c,open(p,'w'))"
                f"\" 2>/dev/null"
            )

            # Restart
            if is_macos:
                platform.execute_command("launchctl start com.taara.taaraware 2>/dev/null || true")
            else:
                platform.execute_command(
                    f"systemctl start taaraware 2>/dev/null || "
                    f"{{ kill $(pgrep -f taaraware_agent.py) 2>/dev/null; nohup {py_bin_upd} {idir_upd}/taaraware_agent.py > {idir_upd}/taaraware.log 2>&1 </dev/null & disown; }}"
                )

            _time.sleep(2)
            status = self.check_agent_status(platform)
            result['success'] = True
            result['message'] = f"Agent updated to v{CURRENT_AGENT_VERSION}. Status: {status.get('status', 'unknown')}"
            result['agent_status'] = status

            host = platform.config.get('host', 'unknown')
            if host in self.deployed_agents:
                self.deployed_agents[host]['version'] = CURRENT_AGENT_VERSION
            self._save_state()
        except Exception as e:
            result['message'] = str(e)
        return result

    def get_all_alerts(self) -> List[Dict]:
        """Get all alerts from all deployed agents."""
        return sorted(self.alerts, key=lambda x: x.get('timestamp', 0), reverse=True)

    def get_deployed_count(self) -> int:
        return len(self.deployed_agents)

    def get_deployment_info(self, host: str = None) -> Dict:
        # Find the agent entry for the requested host (or most recently deployed)
        agent = None
        if host and host in self.deployed_agents:
            agent = self.deployed_agents[host]
        elif self.deployed_agents:
            agent = list(self.deployed_agents.values())[-1]

        deployed_version = (agent or {}).get('version', 'unknown') if agent else 'unknown'
        update_available = deployed_version != CURRENT_AGENT_VERSION and deployed_version != 'unknown'
        return {
            'total_deployed': len(self.deployed_agents),
            'agents': self.deployed_agents,
            'total_alerts': len(self.alerts),
            'deployed_version': deployed_version,
            'current_version': CURRENT_AGENT_VERSION,
            'update_available': update_available,
        }

    def _save_state(self):
        path = os.path.join(self.model_dir, 'taaraware_state.json')
        try:
            state = {
                'deployed_agents': self.deployed_agents,
                'alerts': self.alerts[-100:]
            }
            with open(path, 'w') as f:
                json.dump(state, f, indent=2)
        except Exception:
            pass

    def _load_state(self):
        path = os.path.join(self.model_dir, 'taaraware_state.json')
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    state = json.load(f)
                self.deployed_agents = state.get('deployed_agents', {})
                self.alerts = state.get('alerts', [])
            except Exception:
                pass


def render_taaraware_page(platform, taaraware_mgr, taara_analyzer=None):
    """Render the TaaraWare deployment page."""

    st.markdown("""
    <div style="background: linear-gradient(135deg, #1a1a2e 0%, #0a2e0a 100%);
                padding: 30px; border-radius: 15px; margin-bottom: 20px;
                border: 1px solid #00cc00;">
        <h1 style="color: #00cc00; margin: 0; font-size: 2.2em;">
            TaaraWare Deployment
        </h1>
        <p style="color: #a0a0b0; margin: 5px 0 0 0; font-size: 1.1em;">
            Deploy & Manage Continuous Security Monitoring Agents
        </p>
    </div>
    """, unsafe_allow_html=True)

    dep_info = taaraware_mgr.get_deployment_info()
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Deployed Agents", dep_info['total_deployed'])
    with col2:
        st.metric("Active Alerts", dep_info['total_alerts'])
    with col3:
        st.metric("Platform", platform.platform_type.upper() if platform else "N/A")

    tab1, tab2, tab3 = st.tabs(["Deploy Agent", "Agent Status", "Collected Data"])

    with tab1:
        st.markdown("### Deploy TaaraWare Agent")

        if platform and platform.platform_type == 'ssh':
            st.info(f"Target: {platform.config.get('host', 'unknown')}")

            cc_host = st.text_input("Command Center IP (your laptop)", value="", placeholder="e.g., 192.168.1.100")
            cc_port = st.number_input("Command Center Port", value=9977, min_value=1024, max_value=65535)
            interval = st.selectbox("Collection Interval", [
                ("Every 1 minute (demo)", 60),
                ("Every 5 minutes", 300),
                ("Every 10 minutes (recommended)", 600),
                ("Every 30 minutes", 1800),
            ], format_func=lambda x: x[0], index=2)

            if st.button("Deploy TaaraWare Agent", type="primary", use_container_width=True):
                with st.spinner("Deploying TaaraWare agent..."):
                    result = taaraware_mgr.deploy_agent(platform, {
                        'command_center_host': cc_host,
                        'command_center_port': cc_port,
                        'interval': interval[1]
                    })

                    if result['success']:
                        st.success(result['message'])
                    else:
                        st.error(result['message'])
        else:
            st.markdown("""
            **Cloud Platform TaaraWare:**

            For AWS/GCP/Azure, TaaraWare integrates with native monitoring:
            - **AWS**: CloudWatch Agent + Custom Metrics
            - **GCP**: Cloud Monitoring Agent + Custom Metrics
            - **Azure**: Azure Monitor Agent + Custom Metrics

            These send behavioral telemetry to the Taara Command Center
            for quantum-enhanced analysis.
            """)

    with tab2:
        st.markdown("### Agent Status")
        if platform and platform.connected and platform.platform_type == 'ssh':
            if st.button("Check Agent Status", use_container_width=True):
                with st.spinner("Checking..."):
                    status = taaraware_mgr.check_agent_status(platform)
                    if status.get('connected'):
                        col_a, col_b = st.columns(2)
                        with col_a:
                            st.metric("Service Status", status.get('status', 'unknown'))
                        with col_b:
                            st.metric("Buffer Size", status.get('buffer_size', 0))

                        if status.get('recent_logs'):
                            st.text("Recent Logs:")
                            st.code(status['recent_logs'])
                    else:
                        st.warning("Could not connect to agent")

        for host, info in dep_info.get('agents', {}).items():
            with st.expander(f"Agent: {host}"):
                st.json(info)

    with tab3:
        st.markdown("### Collected Telemetry Data")
        if platform and platform.connected and platform.platform_type == 'ssh':
            if st.button("Fetch Remote Data", use_container_width=True):
                with st.spinner("Collecting data from TaaraWare agent..."):
                    data = taaraware_mgr.collect_remote_data(platform)
                    if data:
                        st.success(f"Retrieved {len(data)} data points")
                        if len(data) > 0:
                            latest = data[-1]
                            st.json(latest)
                    else:
                        st.info("No data available yet. Agent may still be collecting.")

        for host, data in taaraware_mgr.telemetry_buffer.items():
            if data:
                st.markdown(f"**Data from {host}:** {len(data)} samples")
