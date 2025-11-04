# ⚡ Taara - Threat-Aware Autonomous Response Agent

**A unified DevSecOps control cockpit for managing and securing remote servers with AI-powered threat detection and adaptive defense.**

---

## 🎯 What is Taara?

Taara is an intelligent DevSecOps automation platform that combines:

- **Digital System DNA** - Behavioral fingerprinting with quantum-inspired anomaly detection
- **NIAD (Non-Invasive Adaptive Deception)** - Automatic honeypot deployment on threat detection
- **Causal Reasoning Engine** - AI-powered threat correlation and explainable recommendations
- **Unified Security Stack** - CrowdSec, ClamAV, and custom LLM heuristics in one interface
- **Human-in-the-Loop** - Command approval workflow with automatic rollback capability

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- A VPS/server with SSH access
- Gemini API key (from Google AI Studio)

### Installation

1. **Clone the repository**
   ```bash
   cd taaradevsecops
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   ```

3. **Activate virtual environment**

   Windows:
   ```bash
   venv\Scripts\activate
   ```

   Linux/Mac:
   ```bash
   source venv/bin/activate
   ```

4. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

5. **Configure API key**

   Edit `.env` file (or create it):
   ```
   GEMINI_API_KEY=your_api_key_here
   ```

6. **Run the application**
   ```bash
   streamlit run main.py
   ```

7. **Access the web interface**

   Open your browser to: `http://localhost:8501`

---

## 🎮 Using Taara

### Initial Setup

1. **Enter API Keys**
   - Reasoning Engine API Key (Gemini API key)
   - Security Stack API Key (optional)

2. **Connect to Your Server**
   - VPS IP Address
   - SSH Username
   - SSH Password (or SSH key in future versions)

3. **Initialize Baseline**
   - Taara will automatically collect system metrics
   - Creates a "DNA fingerprint" of normal behavior

### Main Interface

**Left Panel - Command Line Interface**
- View server status and system health
- See proposed commands before execution
- Approve or reject operations
- View command output in real-time

**Right Panel - Control Dashboard**
- **Dashboard**: System metrics, threat alerts, DNA similarity score
- **DevOps Actions**: Deploy services, restart containers, manage infrastructure
- **Security Actions**: Malware scans, NIAD isolation, firewall management
- **Actions Log**: Full audit trail with rollback capability

---

## 🔐 Core Features

### 1. Digital System DNA
```
CPU usage + Memory + Processes + Open Ports
        ↓
Normalized vector [0.23, 0.45, 0.67, 0.12]
        ↓
Quantum-inspired similarity: S = |<ψ|φ>|²
        ↓
Drift detection: if S < 0.80 → ANOMALY
```

### 2. NIAD (Non-Invasive Adaptive Deception)

When an anomaly is detected:
1. Suspicious container is isolated from network
2. Honeypot clone is created
3. Attacker is redirected to honeypot
4. All activity is logged for analysis
5. Production service remains protected

### 3. AI-Powered Reasoning

- Correlates DNA drift, security alerts, and system metrics
- Uses Gemini LLM for causal analysis
- Provides explainable recommendations
- Generates safe, reviewable commands

### 4. Command Approval Workflow

```
User Request → LLM Analysis → Proposed Commands → Human Approval → Execute → Log with Rollback
```

Every action can be rolled back with one click.

---

## 📊 Example Workflows

### Deploy a Service
1. Go to **DevOps Actions** → Select "Deploy"
2. Enter service name and version
3. Click "Propose Deploy with AI"
4. Review proposed Docker commands
5. Approve execution
6. Monitor deployment in CLI panel

### Respond to Threat
1. Dashboard shows anomaly alert
2. Click **Security Actions** → "NIAD Isolation"
3. Enter suspicious container name
4. System proposes honeypot commands
5. Approve to isolate and monitor
6. View attacker activity logs

### Rollback an Action
1. Go to **Actions Log**
2. Find the action to revert
3. Click "↩️ Rollback"
4. System executes rollback command
5. Service restored to previous state

---

## 🛡️ Security Features

- **ClamAV Integration** - Antivirus scanning on remote servers
- **CrowdSec Integration** - IP reputation and intrusion detection
- **DNA Drift Detection** - Behavioral anomaly identification
- **Adaptive Honeypots** - Automatic deception layer deployment
- **Audit Trail** - Complete command history with rollback
- **Secure Storage** - API keys never leave local session

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────┐
│           Streamlit Frontend                │
│  ┌─────────────┐      ┌──────────────┐    │
│  │  CLI View   │      │  Chat/GUI    │    │
│  └─────────────┘      └──────────────┘    │
└─────────────────────────────────────────────┘
              ↓                ↓
┌─────────────────────────────────────────────┐
│           Backend Components                 │
│  ┌──────────────────────────────────────┐  │
│  │  SSH Manager    │  LLM Service       │  │
│  │  DNA Engine     │  NIAD Engine       │  │
│  │  Security Stack │  Reasoning Engine  │  │
│  │  Rollback Mgr   │                    │  │
│  └──────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────┐
│         Remote VPS (SSH)                    │
│  - Docker containers                        │
│  - System metrics                           │
│  - ClamAV / CrowdSec                       │
└─────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
taaradevsecops/
├── main.py                    # Main application entry
├── requirements.txt           # Python dependencies
├── .env                       # API keys (DO NOT COMMIT)
├── .gitignore                # Git ignore rules
├── README.md                 # This file
└── components/
    ├── __init__.py
    ├── frontend.py           # Streamlit UI components
    ├── ssh_manager.py        # SSH connection handler
    ├── dna_engine.py         # System DNA & drift detection
    ├── llm_service.py        # Gemini AI integration
    ├── security_integrator.py # ClamAV & CrowdSec
    ├── reasoning_engine.py    # Causal analysis
    ├── niad_engine.py        # Honeypot deployment
    └── rollback_manager.py    # Action logging & rollback
```

---

## 🔧 Configuration

### Environment Variables (.env)
```bash
GEMINI_API_KEY=your_gemini_api_key_here
```

### DNA Engine Settings
Edit `components/dna_engine.py`:
```python
self.anomaly_threshold = 0.80  # Lower = more sensitive
```

### LLM Model
Edit `components/llm_service.py`:
```python
self.model = genai.GenerativeModel('gemini-1.5-flash')  # or 'gemini-1.5-pro'
```

---

## ⚠️ Important Notes

### Security
- **NEVER commit `.env` file** - Contains sensitive API keys
- Rotate API keys if accidentally exposed
- Use SSH keys instead of passwords in production
- Review all commands before approving execution

### Server Requirements
- SSH access with sudo privileges (for some operations)
- Docker installed (for container operations)
- ClamAV installed (for malware scanning)
- CrowdSec installed (for threat detection)

### Limitations (MVP)
- Single server support (multi-server coming soon)
- Password authentication only (SSH keys coming soon)
- Basic CrowdSec integration (full API integration planned)
- No TLS/encryption for local web interface

---

## 🚧 Roadmap

- [ ] Multi-server management
- [ ] SSH key authentication
- [ ] Full CrowdSec API integration
- [ ] Falco & Wazuh integration
- [ ] Prometheus/Grafana metrics
- [ ] TLS encryption for web interface
- [ ] User authentication & RBAC
- [ ] Cloud provider integrations (AWS, GCP, Azure)
- [ ] Advanced NIAD behaviors
- [ ] Real quantum computing integration

---

## 🤝 Contributing

This is a research/patent project. For collaboration inquiries, please reach out.

---

## 📄 License

Proprietary - All Rights Reserved

---

## 💡 Concepts & Innovation

**Patent-worthy Elements:**
1. Digital System DNA - Unified behavioral fingerprinting
2. NIAD - Non-invasive adaptive deception layer
3. Quantum-inspired anomaly scoring
4. Causal reasoning for threat correlation
5. Human-in-the-loop autonomous defense

---

## 🎓 Citation

```
Taara: Threat-Aware Autonomous Response Agent
A unified DevSecOps control plane with adaptive defense
```

---

## 📞 Support

For issues or questions:
1. Check this README
2. Review code comments in `components/` directory
3. Verify `.env` configuration
4. Ensure server connectivity

---

**Built with ❤️ for DevSecOps automation**
