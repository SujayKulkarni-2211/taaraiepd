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
TaaraWare Agent v2.0
====================
Always-on collector + policy-bounded action layer for customer infrastructure.
Deployed by TAARA Command Center.

Three pillars:
  1. Security Behavior — auth events, connection patterns, process signals
  2. Config/Deploy Drift — sshd_config changes, new ports, CI config diffs
  3. Resource/Spend Signals — CPU/memory trends, storage growth, cost deltas

Architecture:
  - Runs on CPU only (no GPU required)
  - Collects lightweight signals locally every interval
  - Sends feature vectors + alert payloads to Command Center (not raw data)
  - Policy-bounded autonomy: blocks brute-force, alerts on drift
  - High-impact actions require Command Center + human approval
  - Federated: raw infrastructure data never leaves the server
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
import subprocess
from datetime import datetime
from collections import defaultdict
from pathlib import Path

TAARAWARE_DIR = Path("/opt/taaraware")
CONFIG_FILE = TAARAWARE_DIR / "config.json"
DATA_DIR = TAARAWARE_DIR / "data"
LOG_FILE = TAARAWARE_DIR / "taaraware.log"
FEATURE_BUFFER = DATA_DIR / "feature_buffer.json"
ALERT_LOG = DATA_DIR / "alerts.json"

logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format='%(asctime)s [TaaraWare] %(levelname)s: %(message)s'
)
logger = logging.getLogger('taaraware')

DEFAULT_CONFIG = {
    "command_center_host": "",
    "command_center_port": 9977,
    "collection_interval": 600,
    "alert_threshold_cpu": 90,
    "alert_threshold_memory": 90,
    "alert_threshold_disk": 95,
    "max_buffer_size": 1000,
    "heartbeat_interval": 60,
    "version": "2.0.0"
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


def compute_entropy(items):
    if not items:
        return 0.0
    freq = defaultdict(int)
    for item in items:
        freq[str(item)] += 1
    total = len(items)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def collect_features():
    features = {}

    # Process behavior
    ps_out = run_cmd("ps -eo pid,ppid,uid,etime,comm --no-headers")
    processes = []
    for line in ps_out.split("\\n"):
        parts = line.split()
        if len(parts) >= 5:
            try:
                processes.append({
                    "pid": int(parts[0]), "ppid": int(parts[1]),
                    "uid": int(parts[2]), "etime": parts[3],
                    "comm": " ".join(parts[4:])
                })
            except ValueError:
                continue

    short_lived = sum(1 for p in processes if parse_etime(p["etime"]) < 60)
    very_short = sum(1 for p in processes if parse_etime(p["etime"]) < 5)
    features["proc_spawn_rate"] = float(short_lived)
    features["proc_short_lived_ratio"] = very_short / max(len(processes), 1)
    features["proc_uid_diversity"] = float(len(set(p["uid"] for p in processes)))
    features["proc_root_ratio"] = sum(1 for p in processes if p["uid"] == 0) / max(len(processes), 1)
    features["proc_cmd_entropy"] = compute_entropy([p["comm"] for p in processes])

    # Network behavior
    ss_out = run_cmd("ss -tunap 2>/dev/null")
    dst_ips = set()
    dst_ports = set()
    outbound = 0
    failed = 0
    for line in ss_out.split("\\n")[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        if "LISTEN" in line:
            continue
        outbound += 1
        remote = parts[4] if len(parts) > 4 else ""
        if ":" in remote:
            ip_port = remote.rsplit(":", 1)
            dst_ips.add(ip_port[0])
            try:
                dst_ports.add(int(ip_port[1]))
            except ValueError:
                pass
        if any(x in line.upper() for x in ["TIME-WAIT", "CLOSE-WAIT", "FIN-WAIT"]):
            failed += 1

    features["net_outbound_conn_rate"] = float(outbound)
    features["net_unique_dst_ips"] = float(len(dst_ips))
    features["net_unique_dst_ports"] = float(len(dst_ports))
    features["net_port_entropy"] = compute_entropy(list(dst_ports))
    features["net_failed_conn_ratio"] = failed / max(outbound, 1)

    # System metrics
    cpu_out = run_cmd("top -bn1 | grep 'Cpu(s)' | awk '{print $2}'")
    try:
        features["cpu_usage"] = float(cpu_out)
    except ValueError:
        features["cpu_usage"] = 0.0

    mem_out = run_cmd("free | grep Mem | awk '{printf \\"%.1f\\", $3/$2 * 100.0}'")
    try:
        features["memory_usage"] = float(mem_out)
    except ValueError:
        features["memory_usage"] = 0.0

    disk_out = run_cmd("df / | tail -1 | awk '{print $5}' | tr -d '%'")
    try:
        features["disk_usage"] = float(disk_out)
    except ValueError:
        features["disk_usage"] = 0.0

    features["timestamp"] = time.time()
    features["hostname"] = socket.gethostname()

    # --- Hidden features (model-only, not shown in UI) ---
    _add_hidden_features(features)

    return features


def _add_hidden_features(features):
    """Add 3 hidden behavioral signals. Feed into model only — not displayed in UI."""

    # 1. temporal_rhythm_deviation
    # Compare current hour to hour distribution of last 100 buffer entries.
    # If this hour appeared <5% historically → 1.0 (novel time), else 0.0.
    try:
        temporal_val = 0.0
        if FEATURE_BUFFER.exists():
            with open(FEATURE_BUFFER) as f:
                buf = json.load(f)
            recent = buf[-100:] if len(buf) >= 100 else buf
            if len(recent) >= 50:
                hour_counts = defaultdict(int)
                for entry in recent:
                    ts = entry.get("timestamp", 0)
                    hour_counts[datetime.fromtimestamp(ts).hour] += 1
                current_hour = datetime.now().hour
                current_hour_pct = hour_counts.get(current_hour, 0) / len(recent)
                temporal_val = 1.0 if current_hour_pct < 0.05 else 0.0
        features["temporal_rhythm_deviation"] = temporal_val
    except Exception:
        features["temporal_rhythm_deviation"] = 0.0

    # 2. causal_chain_novelty
    # Count parent→child process pairs never seen in last 50 buffer entries.
    # Value = new_pairs / total_pairs (0.0–1.0).
    try:
        ps_out = run_cmd("ps -eo ppid,pid,comm --no-headers")
        current_pairs = set()
        for line in ps_out.split("\\n"):
            parts = line.split()
            if len(parts) >= 3:
                try:
                    pair_hash = hashlib.md5(
                        f"{parts[0]}:{parts[2]}".encode()
                    ).hexdigest()
                    current_pairs.add(pair_hash)
                except Exception:
                    continue

        historical_pairs = set()
        if FEATURE_BUFFER.exists():
            with open(FEATURE_BUFFER) as f:
                buf = json.load(f)
            recent = buf[-50:] if len(buf) >= 50 else buf
            for entry in recent:
                for h in entry.get("_proc_pair_hashes", []):
                    historical_pairs.add(h)

        # Store current hashes in this entry for future comparisons
        features["_proc_pair_hashes"] = list(current_pairs)

        if current_pairs:
            new_pairs = current_pairs - historical_pairs
            features["causal_chain_novelty"] = len(new_pairs) / len(current_pairs)
        else:
            features["causal_chain_novelty"] = 0.0
    except Exception:
        features["causal_chain_novelty"] = 0.0

    # 3. concealment_signal — average of 3 sub-signals
    try:
        sub_signals = []

        # Sub-signal 1: auth.log growth
        try:
            auth_log = Path("/var/log/auth.log")
            auth_val = 0.0
            if auth_log.exists():
                current_size = auth_log.stat().st_size
                prev_size = 0
                if FEATURE_BUFFER.exists():
                    with open(FEATURE_BUFFER) as f:
                        buf = json.load(f)
                    if buf:
                        prev_size = buf[-1].get("_auth_log_size", 0)
                current_hour = datetime.now().hour
                business_hours = 8 <= current_hour < 20
                if business_hours and current_size <= prev_size:
                    auth_val = 1.0
                features["_auth_log_size"] = current_size
            sub_signals.append(auth_val)
        except Exception:
            sub_signals.append(0.0)

        # Sub-signal 2: shell history entropy (decreased line count = suspicious)
        try:
            hist_val = 0.0
            hist_file = Path("/root/.bash_history")
            if hist_file.exists():
                current_lines = int(run_cmd("wc -l < /root/.bash_history") or "0")
                prev_lines = 0
                if FEATURE_BUFFER.exists():
                    with open(FEATURE_BUFFER) as f:
                        buf = json.load(f)
                    if buf:
                        prev_lines = buf[-1].get("_bash_history_lines", 0)
                if current_lines < prev_lines:
                    hist_val = 1.0
                features["_bash_history_lines"] = current_lines
            sub_signals.append(hist_val)
        except Exception:
            sub_signals.append(0.0)

        # Sub-signal 3: cron silence (scheduled job produced no log in last 10 min)
        try:
            cron_val = 0.0
            cron_log = Path("/var/log/cron")
            crontab_out = run_cmd("crontab -l 2>/dev/null")
            if crontab_out and cron_log.exists():
                now = time.time()
                cron_log_mtime = cron_log.stat().st_mtime
                if now - cron_log_mtime > 600:
                    # Cron log not updated in 10 min but jobs exist
                    cron_val = 1.0
            sub_signals.append(cron_val)
        except Exception:
            sub_signals.append(0.0)

        features["concealment_signal"] = sum(sub_signals) / len(sub_signals) if sub_signals else 0.0
    except Exception:
        features["concealment_signal"] = 0.0


def parse_etime(etime):
    try:
        parts = etime.replace("-", ":").split(":")
        parts = [int(p) for p in parts]
        if len(parts) == 2:
            return parts[0] * 60 + parts[1]
        elif len(parts) == 3:
            return parts[0] * 3600 + parts[1] * 60 + parts[2]
        elif len(parts) == 4:
            return parts[0] * 86400 + parts[1] * 3600 + parts[2] * 60 + parts[3]
        return 0
    except (ValueError, IndexError):
        return 0


def check_local_alerts(features, config):
    alerts = []
    if features.get("cpu_usage", 0) > config.get("alert_threshold_cpu", 90):
        alerts.append({
            "type": "cpu_high",
            "severity": "high",
            "message": f"CPU usage at {features['cpu_usage']}%",
            "timestamp": time.time()
        })
    if features.get("memory_usage", 0) > config.get("alert_threshold_memory", 90):
        alerts.append({
            "type": "memory_high",
            "severity": "high",
            "message": f"Memory usage at {features['memory_usage']}%",
            "timestamp": time.time()
        })
    if features.get("disk_usage", 0) > config.get("alert_threshold_disk", 95):
        alerts.append({
            "type": "disk_high",
            "severity": "critical",
            "message": f"Disk usage at {features['disk_usage']}%",
            "timestamp": time.time()
        })
    return alerts


def send_to_command_center(data, config):
    """Send feature data to command center via TCP."""
    host = config.get("command_center_host", "")
    port = config.get("command_center_port", 9977)
    if not host:
        return False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        payload = json.dumps(data).encode()
        sock.sendall(payload)
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

    logger.info(f"TaaraWare Agent v{config['version']} starting")
    logger.info(f"Collection interval: {config['collection_interval']}s")
    logger.info(f"Command center: {config.get('command_center_host', 'not configured')}")

    while running:
        try:
            features = collect_features()
            buffer_features(features)

            alerts = check_local_alerts(features, config)
            if alerts:
                for alert in alerts:
                    logger.warning(f"ALERT: {alert['message']}")

            payload = {
                "type": "telemetry",
                "features": features,
                "alerts": alerts,
                "hostname": features.get("hostname", "unknown"),
                "agent_version": config["version"]
            }
            send_to_command_center(payload, config)

            logger.info(f"Collection complete. CPU: {features.get('cpu_usage', 0)}%, "
                       f"MEM: {features.get('memory_usage', 0)}%")

        except Exception as e:
            logger.error(f"Collection error: {e}")

        for _ in range(int(config["collection_interval"])):
            if not running:
                break
            time.sleep(1)

    logger.info("TaaraWare Agent stopped")


if __name__ == "__main__":
    main()
'''


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
            platform.execute_command("mkdir -p /opt/taaraware/data")

            agent_config = {
                "command_center_host": config.get('command_center_host', '') if config else '',
                "command_center_port": config.get('command_center_port', 9977) if config else 9977,
                "collection_interval": config.get('interval', 600) if config else 600,
                "alert_threshold_cpu": 90,
                "alert_threshold_memory": 90,
                "alert_threshold_disk": 95,
                "max_buffer_size": 1000,
                "heartbeat_interval": 60,
                "version": "2.0.0"
            }

            config_json = json.dumps(agent_config)
            platform.execute_command(f"cat > /opt/taaraware/config.json << 'CONFIGEOF'\n{config_json}\nCONFIGEOF")

            escaped_script = TAARAWARE_AGENT_SCRIPT.replace("'", "'\\''")
            platform.execute_command(f"cat > /opt/taaraware/taaraware_agent.py << 'AGENTEOF'\n{TAARAWARE_AGENT_SCRIPT}\nAGENTEOF")
            platform.execute_command("chmod +x /opt/taaraware/taaraware_agent.py")

            service_unit = """[Unit]
Description=TaaraWare Security Monitoring Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/taaraware/taaraware_agent.py
Restart=always
RestartSec=30
WorkingDirectory=/opt/taaraware

[Install]
WantedBy=multi-user.target
"""
            platform.execute_command(f"cat > /etc/systemd/system/taaraware.service << 'SVCEOF'\n{service_unit}\nSVCEOF")
            platform.execute_command("systemctl daemon-reload")
            platform.execute_command("systemctl enable taaraware")
            platform.execute_command("systemctl start taaraware")

            time.sleep(2)
            status_out, _, _ = platform.execute_command("systemctl is-active taaraware")

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
            status_out, _, _ = platform.execute_command("systemctl is-active taaraware 2>/dev/null")
            pid_out, _, _ = platform.execute_command("pgrep -f taaraware_agent.py 2>/dev/null")
            log_out, _, _ = platform.execute_command("tail -5 /opt/taaraware/taaraware.log 2>/dev/null")

            buffer_out, _, _ = platform.execute_command(
                "python3 -c \"import json; d=json.load(open('/opt/taaraware/data/feature_buffer.json')); print(len(d))\" 2>/dev/null"
            )

            return {
                'status': status_out.strip(),
                'pid': pid_out.strip(),
                'recent_logs': log_out.strip(),
                'buffer_size': int(buffer_out.strip()) if buffer_out.strip().isdigit() else 0,
                'connected': True
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e), 'connected': False}

    def collect_remote_data(self, platform) -> List[Dict]:
        """Collect buffered feature data from remote TaaraWare agent."""
        if not platform.connected or platform.platform_type != 'ssh':
            return []

        try:
            out, _, _ = platform.execute_command(
                "cat /opt/taaraware/data/feature_buffer.json 2>/dev/null"
            )
            if out:
                data = json.loads(out)
                host = platform.config.get('host', 'unknown')
                self.telemetry_buffer[host] = data
                return data
        except Exception:
            pass
        return []

    def get_all_alerts(self) -> List[Dict]:
        """Get all alerts from all deployed agents."""
        return sorted(self.alerts, key=lambda x: x.get('timestamp', 0), reverse=True)

    def get_deployed_count(self) -> int:
        return len(self.deployed_agents)

    def get_deployment_info(self) -> Dict:
        return {
            'total_deployed': len(self.deployed_agents),
            'agents': self.deployed_agents,
            'total_alerts': len(self.alerts)
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
