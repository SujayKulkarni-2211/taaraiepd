# TAARA Q.0 — Quantum-Enhanced Continuous Authentication

**GoodWinSun | Prevent Crash, Preserve Cash**

> *"79% of breaches use valid credentials. Authentication proves identity at login. TAARA proves it every second."*

---

## What Is TAARA?

TAARA is a **Continuous Authentication and Infrastructure Intelligence** platform. The fundamental problem it solves: every security tool on the market asks *"does this login look suspicious?"* — but attackers with stolen credentials log in correctly. No failed attempts. No suspicious IP. Nothing to flag. TAARA asks a different question: *"is this actually the person who owns this account?"* — evaluated continuously, inside every session, using quantum geometric behavioral modeling.

**How it catches what others miss:** TAARA builds a per-identity quantum behavioral baseline unique to each user on each server. When someone logs in with valid credentials but behaves differently — different commands, different timing, accessing files the real user never touches — the quantum circuit detects that the behavioral direction is geometrically new in Hilbert space. Not just statistically unusual. Genuinely new.

**Live demo numbers:** Normal Q Confidence = 0.20 → Under attack = 0.48 → Threshold = 0.4382. Valid credentials. No failed logins. Detected in the same session.

---

## How to Run the App

### Electron Desktop App

The full TAARA experience: Electron frontend + FastAPI backend.

**Prerequisites:**
- Python 3.11+
- Node.js 18+ (for Electron)
- `.env` file with `GEMINI_API_KEY`

**First-time setup:**
```bash
# Clone and enter the repo
git clone <repo-url>
cd taaraiepd

# Python environment
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Desktop dependencies (first time only)
cd desktop && npm install && npm run build && cd ..
```

**Launch:**
```bash
./launch_taara.sh
```

This kills any stale process on port 8765, then starts Electron which automatically spawns the Python backend (`server.py` on port 8765). The app opens as a native desktop window.

> **If Electron does not open:** Check `DISPLAY` is set (`echo $DISPLAY`). On a headless server, set `export DISPLAY=:0` first.

---

### Backend Only (API / Headless)

Run just the FastAPI server to use API endpoints directly or integrate with other tools.

```bash
source venv/bin/activate
python server.py
```

API available at `http://localhost:8765`. Swagger docs at `http://localhost:8765/docs`.

---

## Environment Setup

Create a `.env` file in the project root:

```bash
GEMINI_API_KEY=your_gemini_api_key_here
```

Get a free Gemini API key from [Google AI Studio](https://aistudio.google.com/).

The app runs without the API key — AI summary features will be disabled but everything else (scanning, detection, TaaraWare, PDF reports) works fully.

---

## Project Structure

```
taaraiepd/
├── launch_taara.sh              # Single launch script → Electron + Python backend
├── server.py                    # FastAPI backend (port 8765) — all API endpoints
├── requirements.txt             # Python dependencies
├── .env                         # API keys (never commit this)
│
├── desktop/                     # Electron + React frontend
│   ├── electron/main.js         # Electron main process, spawns Python server
│   ├── src/
│   │   ├── App.jsx              # Root React component
│   │   ├── views/
│   │   │   ├── DashboardView.jsx    # Main dashboard, health score, alerts
│   │   │   ├── TaaraWareView.jsx    # Live TaaraWare monitoring (Q Confidence, SWAP Fidelity)
│   │   │   ├── AnalysisView.jsx     # TaaraAnalysis security scan results
│   │   │   ├── AgentView.jsx        # ContrastiveBandit agent panel
│   │   │   └── ReportView.jsx       # TaaraWords PDF generation
│   │   └── services/api.js          # API client for all backend calls
│   └── build/                   # Built React app (generated, not in git)
│
├── components/
│   ├── taaraware_manager.py     # TaaraWare agent: deploy, monitor, collect (v2.2.0)
│   ├── quantum_engine.py        # PennyLane 3-qubit circuits, V3 fusion, fidelity
│   ├── taara_core.py            # Memory basis, reconstruction novelty, threshold-free detection
│   ├── dna_autoencoder.py       # PyTorch autoencoder (19→64→8→64→19, Tanh bottleneck)
│   ├── atomic_dna_collector.py  # 19-feature behavioral collector (SSH, reads bash history)
│   ├── action_bandit.py         # ContrastiveBandit: UCB action selection + reward learning
│   ├── platform_manager.py      # SSH / AWS / GCP / Azure connectors
│   ├── taara_analysis.py        # Security scan pipeline (SSH hardening, CVEs, permissions)
│   ├── taara_words.py           # ReportLab PDF report generator
│   ├── security_agent.py        # Autonomous agent with bandit + pre-approval logic
│   └── llm_service.py           # Gemini / Groq API wrapper
│
├── models/                      # Trained model state (auto-created, some gitignored)
│   ├── dna_autoencoder.pt       # PyTorch autoencoder weights
│   ├── isolation_forest.pkl     # IsolationForest trained on normal behavioral data
│   ├── taara_state.json         # Per-identity quantum bases, thresholds, V3 weights
│   ├── action_bandit.json       # ContrastiveBandit per-action statistics
│   ├── nodes/                   # Per-identity quantum basis vectors (gitignored — private)
│   └── client_keys.json         # Kyber768 shared secrets (gitignored — private)
│
├── demo/
│   ├── zerotier_run_attack.sh   # ZeroTier attack simulation (8 phases, ~120s)
│   ├── zerotier_setup_target.sh # Configure target machine for demo
│   └── DEMO_GUIDE.md            # Step-by-step demo instructions
│
├── experiments/
│   ├── taara_benchmark_v8.py    # Final benchmark script (use this)
│   ├── results/                 # benchmark_v8_results.json, benchmark_v6_results.json
│   └── transformer_feature_discovery.py  # Attention head analysis that validated 19 features
│
├── benchmark/
│   ├── datasets/                # Cowrie + elastic_auth data (download separately)
│   └── scripts/                 # Benchmark runner scripts
│
├── taara_internals.tex          # Deep technical document (researcher-to-researcher)
├── taara_founder_guide.tex      # Founder pitch guide: hooks, 30s/90s explains, Elevate demo
└── taara.pdf                    # TAARA research paper
```

---

## TaaraWare — Deploying the Monitoring Agent

TaaraWare is the lightweight behavioral collector that runs on client servers. It collects 19 features every 30 seconds and sends feature vectors (not raw logs) to the Command Center.

**Deploy from the Electron app:**
1. Open the TaaraWare tab
2. Enter the target server's SSH credentials
3. Click "Deploy Agent" — pushes `taaraware_agent.py` to `/opt/taaraware/` and starts it

**Deploy manually (VPS / ZeroTier):**
```bash
# The manager handles deployment via the /api/taaraware/deploy endpoint
# Or SSH directly to the server and run:
python3 /opt/taaraware/taaraware_agent.py &
```

**Check agent status:**
```bash
# Via API
curl http://localhost:8765/api/taaraware/status

# Returns: Q Confidence, SWAP Fidelity, Directionality, Phase Coherence,
#          buffer size, last collection time, agent version
```

**Current production deployment:**
- VPS: `103.160.106.48` — identity `taaraware_103.160.106.48`
- ZeroTier network: `88c5b1f33907fd78`
- Agent version: `2.2.0`

---

## The 19 Behavioral Features

TaaraWare collects these features from every 30-second session window. Features 8, 10, and 13 were discovered via transformer attention analysis — not hand-engineered.

| # | Feature | What it detects |
|---|---------|----------------|
| 0 | `session_duration` | Attackers leave in <2min; admins stay 5+ min |
| 1 | `commands_per_minute` | Burst CPM exclusive to automated attack sessions |
| 2 | `inter_cmd_timing_std` | Humans pause; scripts run instantly |
| 3 | `session_idle_ratio` | Human thinking gaps vs continuous scripted execution |
| 4 | `unique_commands` | Attackers probe with 20–40 commands; admins repeat 5–15 |
| 5 | `command_entropy` | Shannon entropy — attackers diverse, admins repetitive |
| 6 | `shell_history_delta` | Real admin work writes to bash history |
| 7 | `sensitive_path_access` | `/etc/passwd`, `/etc/shadow`, `~/.ssh/authorized_keys` |
| 8 | `hardware_enum_count` | **Attention-discovered.** `uname+free+top+lscpu+w` cluster — in 99% of attack sessions |
| 9 | `outbound_connections` | `wget`/`curl`/`tftp` to C2 — present in 84% of attacks |
| 10 | `persistence_attempt` | **Attention-discovered.** `crontab` — in 99% of attack sessions |
| 11 | `malware_exec_pattern` | Execute from `/var/`, `/tmp/` + `chmod +x` |
| 12 | `process_spawn_count` | `dd`, `busybox`, `sh`/`bash` launches |
| 13 | `network_device_shell` | **Attention-discovered.** `version`/`shell`/`enable` — router/IoT exploitation |
| 14 | `data_volume_proxy` | Outbound + downloads combined — exfiltration proxy |
| 15 | `hour_sin` | `sin(2π·hour/24)` — cyclic time encoding |
| 16 | `hour_cos` | `cos(2π·hour/24)` |
| 17 | `dow_sin` | `sin(2π·day/7)` — day-of-week encoding |
| 18 | `dow_cos` | `cos(2π·day/7)` |

---

## Running the ZeroTier Demo

The live attack demo uses ZeroTier to create a private network between the Command Center laptop and an "attacker" machine (phone, second laptop, or VPS).

**Setup:**
```bash
# Join the ZeroTier network on all devices
zerotier-cli join 88c5b1f33907fd78

# Verify connectivity (phone should appear at 10.248.248.67)
zerotier-cli listpeers
```

**Run the attack (from attacker machine):**
```bash
bash demo/zerotier_run_attack.sh
```

The script runs 8 phases of attack behavior over ~120 seconds:
hardware enumeration → network recon → persistence attempt → sensitive file access → outbound C2 → malware pattern → log clearing → sustained activity

Watch the Electron app: Q Confidence rises from ~0.20 to ~0.48 as the attack progresses. Alert fires when it crosses 0.4382.

---

## Running Benchmarks

The definitive benchmark is v8. Uses 1,151 normal sessions + 1,163 command-active Cowrie attack sessions.

```bash
source venv/bin/activate
python experiments/taara_benchmark_v8.py
```

Results written to `experiments/results/benchmark_v8_results.json`.

**v8 Results (final — cite these):**

| Method | TPR | FPR | F1 | AUC |
|--------|-----|-----|----|-----|
| **TAARA v8** | **0.969** | **0.093** | **0.970** | 0.933 |
| IF\_global | 1.000 | 0.141 | 0.979 | 0.991 |
| IF\_per\_identity | 1.000 | 0.621 | 0.914 | 0.993 |
| PerUser\_ZScore | 0.000 | 0.040 | 0.000 | 0.000 |
| LSTM\_AE | 0.997 | 0.198 | 0.969 | 0.993 |

TAARA achieves the **lowest FPR (9.3%) of any working detection method**. Every competitor that catches more attacks produces 2–7× more false alarms.

---

## API Endpoints

The FastAPI backend exposes these key endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | Overall system status, quantum confidence, anomaly count |
| `/api/taaraware/status` | GET | Live TaaraWare metrics: Q Confidence, SWAP Fidelity, buffer size |
| `/api/taaraware/deploy` | POST | Deploy TaaraWare agent to a target server |
| `/api/analyze` | POST | Run a one-shot behavioral analysis on a feature vector |
| `/api/execute` | POST | Execute a shell command on a connected server |
| `/api/scan` | POST | Run TaaraAnalysis security scan |
| `/api/report` | POST | Generate TaaraWords PDF report |
| `/api/agent/action` | POST | Submit agent action (ContrastiveBandit) |

Full Swagger docs at `http://localhost:8765/docs` when server is running.

---

## Dependencies

### Core (required for everything)
```
paramiko>=3.4.0
cryptography>=42.0.0
numpy>=1.26.0
torch>=2.0.0
scikit-learn>=1.3.0
scipy>=1.11.0
pennylane>=0.38.0
liboqs-python>=0.12.0      # Kyber768 post-quantum cryptography
google-generativeai>=0.7.0
groq>=1.0.0
reportlab>=4.0.0
sentence-transformers>=3.0.0
fastapi
uvicorn
python-dotenv>=1.0.0
```

### Cloud SDKs (optional, install as needed)
```bash
pip install boto3                                          # AWS
pip install google-cloud-compute google-cloud-storage     # GCP
pip install azure-identity azure-mgmt-compute             # Azure
pip install docker                                        # Docker
pip install kubernetes                                    # Kubernetes
```

Install all at once:
```bash
pip install -r requirements.txt
```

---

## The Detection Pipeline

```
TaaraWare agent (on client server)
       ↓ 19-feature vector every 30s
DNA Autoencoder (19→64→8, Tanh bottleneck)
       ↓ 8-dim behavioral DNA z_t
Quantum Circuit A: Amplitude Encoding
Quantum Circuit B: Angle Encoding
       ↓ fidelity against per-identity memory basis
V3 Fusion: conf = α·s_swap + β·q_dir + γ·c_coh·√(s_swap·q_dir)
       ↓ compare to per-identity threshold (p95 of normal)
ALERT (conf > threshold) or NORMAL
       ↓ if alert
ContrastiveBandit → recommended action
```

**Why quantum:** The SWAP fidelity test measures whether the current behavioral state is in the same Hilbert space subspace as prior normal states. `F_min < 0.5` means the state is more orthogonal than parallel to everything this identity has done before — a geometric fact, not a tuned threshold. An attacker who keeps all individual feature values in their normal ranges can still produce a quantum state that is orthogonal to the entire memory basis, because the specific combination of features creates a new direction in Hilbert space.

**Post-quantum security:** The Kyber768 (NIST FIPS 203) shared secret between TaaraWare and the Command Center is used to perturb the latent vector before quantum encoding, making every client's detection geometry private. An attacker cannot compute "normal" for a specific deployment without breaking Module LWE.

---

## Honest Disclosure

| Component | Status |
|-----------|--------|
| SSH/cloud security scanning | Real — actual SSH commands and API calls |
| TAARA reconstruction algorithm | Real — exact math from the research paper |
| Per-identity memory basis | Real — per-server behavioral subspace |
| DNA Autoencoder | Real — PyTorch, trained on elastic\_auth.log + SSH.log |
| 19-feature behavioral collection | Real — reads bash history, process list, network state |
| Quantum circuits | **Simulated** — PennyLane `default.qubit`, not real hardware |
| Quantum fidelity math | Mathematically real — same result as real hardware |
| Kyber768 (PQC) | Real — liboqs NIST FIPS 203 implementation |
| PDF report generation | Real — ReportLab, downloadable PDFs |
| ContrastiveBandit | Real — UCB action selection, persisted reward learning |
| Benchmark v8 | Real — 1,151 normal + 1,163 attack sessions, reproducible |

The quantum circuit runs on PennyLane simulation. No quantum speedup is claimed. The value is the geometry: the Hilbert space fidelity criterion is parameter-free, per-identity, and mathematically principled. The same code runs on real quantum hardware when moved — no modification required.

---

## Business Model

| Tier | What | Price |
|------|------|-------|
| **TaaraAnalysis** | One-time security assessment — scan, findings, breach cost estimate | ₹5,000–25,000 |
| **TaaraWords** | Professional PDF report (the deliverable clients pay for) | Included in assessment |
| **TaaraWare** | Deploy continuous monitoring agent on client server | Project-based setup |
| **Subscription** | Ongoing monitoring, alerts, agent actions, monthly reports | ₹8,000–15,000/month |

**Current traction (May 2026):** 3 paid assessments, 5 LOIs, 1 production deployment.

---

## Security Notes

- **Never commit `.env`** — contains API keys
- **Never commit `models/nodes/`** — per-identity quantum states, private host data
- **Never commit `models/client_keys.json`** — Kyber768 shared secrets
- SSH credentials are held in session state only (not persisted to disk)
- All executed commands are logged with rollback capability
- Raw behavioral data never leaves the client server — only feature vectors transit

---

## Company

**GoodWinSun**, Bengaluru  
Sujay V Kulkarni (CEO) · Aditya S Maller (CFO)  
Elevate NXT Stage 3 — May 22, 2026 — Panel 1: Quantum Tech Cybersecurity

*TAARA Q.0 — Prevent Crash, Preserve Cash*
