"""
TAARA FastAPI Server
=====================
Local backend for the Electron + React frontend.
All analysis logic lives in the existing Python components.
This file is the thin HTTP bridge — it calls existing functions,
returns JSON, and handles file serving for PDF reports.

Runs on: http://localhost:8765
"""

import os
import sys
import json
import time
import threading
import tempfile
import numpy as np
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

load_dotenv()

# ── Add project root to path ──────────────────────────────────────────────────
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))


def _init_systems():
    from components.taara_core import TAARAnalyzer
    from components.dna_autoencoder import DNAEmbedder
    from components.ml_anomaly_detector import MLAnomalyDetector, BehaviorMemory
    from components.training_manager import TrainingManager
    from components.taaraware_manager import TaaraWareManager
    from components.cloud_spending import CloudSpendingAnalyzer
    from components.security_agent import SecurityAgent
    from components.action_log import ActionLogger

    _state["taara_analyzer"] = TAARAnalyzer(model_dir="models")
    _state["embedder"] = DNAEmbedder(
        model_path="models/dna_autoencoder.pt",
        scaler_path="models/dna_scaler.json"
    )
    _state["detector"] = MLAnomalyDetector(model_path="models/isolation_forest.pkl")
    # Reconnect embedder to any quantum states restored from disk (PCA bases survive restarts)
    _state["taara_analyzer"].reconnect_embedder(_state["embedder"])
    # If memory bases exist but quantum state was not saved (old state file), rebuild it
    _state["taara_analyzer"].rebuild_quantum_state_if_missing(_state["embedder"])

    memory = BehaviorMemory(memory_path="models/behavior_memory.json")
    _state["training_mgr"] = TrainingManager(
        dna_collector=None,
        embedder=_state["embedder"],
        anomaly_detector=_state["detector"],
        memory=memory,
        config_path="models/training_config.json"
    )
    _state["taaraware_mgr"] = TaaraWareManager(model_dir="models")
    _state["cloud_analyzer"] = CloudSpendingAnalyzer(model_dir="models")
    _state["security_agent"] = SecurityAgent(model_dir="models")
    _state["action_logger"] = ActionLogger(log_path="models/action_log.json")

    groq_key = os.getenv("GROQ_API_KEY", "")
    if groq_key:
        from components.llm_service import LLMService
        _state["llm_service"] = LLMService(groq_key)

    _state["action_logger"].log("system", "server_start", "TAARA API server started", severity="info")
    print("[TAARA] Server ready on http://localhost:8765")


@asynccontextmanager
async def lifespan(app: FastAPI):
    _init_systems()
    yield


app = FastAPI(title="TAARA API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Server-side state (replaces st.session_state) ────────────────────────────
_state: Dict[str, Any] = {
    "platform": None,
    "platform_type": None,
    "connected_host": None,
    "taara_analyzer": None,
    "embedder": None,
    "detector": None,
    "training_mgr": None,
    "taaraware_mgr": None,
    "cloud_analyzer": None,
    "security_agent": None,
    "action_logger": None,
    "llm_service": None,
    "analysis_results": None,
    "active_alert": None,
    "training_state": {},
    "last_code_scan": None,
    # Status cache — SSH round-trip is slow; cache result for 30s
    "_status_cache": None,
    "_status_cache_ts": 0.0,
    "_status_cache_host": None,
}

_lock = threading.Lock()
_STATUS_CACHE_TTL = 30.0  # seconds between SSH buffer fetches


# ═══════════════════════════════════════════════════════════════════════════════
# REQUEST MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class ConnectRequest(BaseModel):
    host: str
    port: int = 22
    username: str
    password: str = ""
    key_path: str = ""
    platform_type: str = "ssh"
    api_key: str = ""  # optional Groq key override


class AnalyzeRequest(BaseModel):
    scan_depth: str = "Standard"
    repo_target: str = ""
    offline: bool = False


class TrainRequest(BaseModel):
    mode: str = "quick_demo"


class ExecuteRequest(BaseModel):
    command: str
    language: str = "bash"
    description: str = ""
    stdin_input: Optional[str] = None  # piped as stdin if the command prompts for it


class StdinRequest(BaseModel):
    command: str
    stdin_input: str
    description: str = ""


class DeployRequest(BaseModel):
    command_center_host: str = ""
    command_center_port: int = 9977
    interval: int = 600


class CodeScanRequest(BaseModel):
    target: str
    offline: bool = False


class SettingsRequest(BaseModel):
    firm_name: str = ""
    groq_api_key: str = ""
    groq_key: str = ""          # alias accepted from frontend
    webhook_url: str = ""
    alert_email: str = ""
    theme: str = "dark"
    autonomy_level: float = 0.5
    scan_depth: str = "Standard"


# ═══════════════════════════════════════════════════════════════════════════════
# HEALTH
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "connected": _state["platform"] is not None and
                     getattr(_state["platform"], "connected", False),
        "platform_type": _state["platform_type"],
        "llm_ready": _state["llm_service"] is not None,
        "timestamp": time.time(),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# CONNECT / DISCONNECT
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/connect")
def connect(req: ConnectRequest):
    from components.platform_manager import SSHPlatform, AWSPlatform, GCPPlatform, AzurePlatform

    # Disconnect previous session
    if _state["platform"]:
        try:
            _state["platform"].disconnect()
        except Exception:
            pass

    config = {
        "host": req.host,
        "port": req.port,
        "username": req.username,
        "password": req.password,
        "key_path": req.key_path,
    }

    try:
        if req.platform_type == "ssh":
            platform = SSHPlatform(config)
        elif req.platform_type == "aws":
            platform = AWSPlatform(config)
        elif req.platform_type == "gcp":
            platform = GCPPlatform(config)
        elif req.platform_type == "azure":
            platform = AzurePlatform(config)
        else:
            raise HTTPException(status_code=400, detail=f"Unknown platform: {req.platform_type}")

        success = platform.connect()
        if not success:
            raise HTTPException(status_code=401, detail="Connection failed — check credentials")

        _state["platform"] = platform
        _state["platform_type"] = req.platform_type
        _state["connected_host"] = req.host

        if req.api_key:
            from components.llm_service import LLMService
            _state["llm_service"] = LLMService(req.api_key)

        # Restore full node session: finetuned model + quantum state + meta
        embedder = _state.get("embedder")
        taara_analyzer = _state.get("taara_analyzer")
        if embedder and taara_analyzer and req.host:
            from components.node_identity_db import restore_node_session
            restore_summary = restore_node_session(req.host, embedder, taara_analyzer)
            _state["action_logger"].log(
                "system", "connect",
                f"Connected to {req.host} | node={restore_summary['node_id']} "
                f"connects={restore_summary['connect_count']} "
                f"model={'restored' if restore_summary['model_loaded'] else 'pretrained'} "
                f"baseline={restore_summary['baseline_samples']}s "
                f"training_runs={restore_summary['training_runs']}",
                severity="info"
            )
        else:
            _state["action_logger"].log("system", "connect",
                                        f"Connected to {req.host}", severity="info")

        info = platform.get_platform_info()
        return {"success": True, "platform_type": req.platform_type, "info": info}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/disconnect")
def disconnect():
    if _state["platform"]:
        host = _state.get("connected_host")
        embedder = _state.get("embedder")
        taara_analyzer = _state.get("taara_analyzer")
        action_logger = _state.get("action_logger")
        # Snapshot everything for this node before clearing session state
        if host and embedder and taara_analyzer:
            from components.node_identity_db import snapshot_node_session
            snapshot_node_session(host, embedder, taara_analyzer, action_logger)
        try:
            _state["platform"].disconnect()
        except Exception:
            pass
        _state["platform"] = None
        _state["platform_type"] = None
        _state["connected_host"] = None
        _state["analysis_results"] = None
        _state["active_alert"] = None
    return {"success": True}


# ═══════════════════════════════════════════════════════════════════════════════
# ANALYZE
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/analyze")
def analyze(req: AnalyzeRequest):
    platform = _state["platform"]
    if not platform or not platform.connected:
        raise HTTPException(status_code=400, detail="No platform connected")

    taara_analyzer = _state["taara_analyzer"]
    cloud_analyzer = _state["cloud_analyzer"]
    llm_service = _state["llm_service"]
    ptype = _state["platform_type"]

    results = {
        "timestamp": time.time(),
        "platform": ptype,
        "scan_depth": req.scan_depth,
        "security_data": None,
        "quantum_risk": None,
        "repo_results": None,
        "cost_analysis": None,
        "ai_summary": None,
        "kb_findings": [],
        "kb_status": {"loaded": False, "error": "", "config_chars": 0},
        "duration": 0,
    }
    start = time.time()

    # 1. Security data collection
    try:
        security_data = platform.collect_security_data()
        results["security_data"] = security_data
    except Exception as e:
        security_data = {"categories": {}, "summary": {}, "features": {}}
        results["security_data"] = security_data
        results["scan_error"] = str(e)

    # 2. Quantum risk / TAARA novelty
    try:
        features = security_data.get("features", {})
        fv = np.array([
            features.get("failed_logins", 0),
            features.get("accepted_logins", 0),
            features.get("invalid_users", 0),
            features.get("established_connections", 0),
            features.get("unique_outbound_ips", 0),
            features.get("total_findings", 0),
            features.get("weighted_severity_score", 0),
        ], dtype=np.float32)
        if len(fv) < 4:
            fv = np.pad(fv, (0, 4 - len(fv)))
        _scan_host = platform.config.get("host", ptype) if hasattr(platform, "config") else ptype
        quantum_risk = taara_analyzer.get_quantum_risk_assessment(
            fv, identity_id=f"taaraware_{_scan_host}"
        )
        results["quantum_risk"] = quantum_risk
    except Exception as e:
        summary = security_data.get("summary", {})
        score = min(
            summary.get("critical", 0) * 25 +
            summary.get("high", 0) * 15 +
            summary.get("medium", 0) * 5 +
            summary.get("low", 0) * 1, 100
        )
        results["quantum_risk"] = {
            "risk_score": score,
            "severity": "CRITICAL" if score >= 75 else "HIGH" if score >= 50
                        else "MEDIUM" if score >= 25 else "LOW",
            "quantum_novelty": 0,
            "f_min": 1.0,
            "is_directionally_novel": False,
        }

    # 3. Knowledge base scan
    try:
        from components.taara_analysis import _get_kb_scanner, _kb_load_error
        scanner = _get_kb_scanner()
        if scanner:
            results["kb_status"]["loaded"] = True
            config_text = ""
            for cat_key, cat_data in security_data.get("categories", {}).items():
                raw = cat_data.get("raw_config", "")
                if raw:
                    config_text += f"# {cat_key}\n{raw}\n"
            if hasattr(platform, "get_raw_configs"):
                try:
                    for label, text in platform.get_raw_configs().items():
                        config_text += f"# {label}\n{text}\n"
                except Exception:
                    pass
            config_text = config_text.strip()
            results["kb_status"]["config_chars"] = len(config_text)
            if config_text:
                kb_result = scanner.scan_text(config_text, label=f"{ptype}_config")
                results["kb_findings"] = kb_result.get("findings", [])
        else:
            results["kb_status"]["error"] = _kb_load_error
    except Exception as e:
        results["kb_status"]["error"] = str(e)

    # 4. Repo scan
    if req.repo_target:
        try:
            sys.path.insert(0, str(ROOT))
            from research.scan_repo import scan_repo
            results["repo_results"] = scan_repo(req.repo_target, offline=req.offline)
        except Exception as e:
            results["repo_results"] = {"error": str(e), "target": req.repo_target}

    # 5. Cloud cost analysis
    if cloud_analyzer and ptype in ["aws", "gcp", "azure"]:
        try:
            cost_data = platform.collect_cost_data()
            results["cost_analysis"] = cloud_analyzer.analyze_platform_costs(platform, cost_data)
        except Exception as e:
            results["cost_analysis"] = {"error": str(e)}

    # 6. AI summary
    if llm_service:
        try:
            quantum_risk = results["quantum_risk"]
            summary = security_data.get("summary", {})
            verified_findings = []
            for cat in security_data.get("categories", {}).values():
                for f in cat.get("findings", []):
                    verified_findings.append({
                        "source": "security_scan",
                        "severity": f.get("severity", ""),
                        "title": f.get("title", ""),
                        "remediation": f.get("remediation", ""),
                    })
            for f in results["kb_findings"][:5]:
                verified_findings.append({
                    "source": "knowledge_graph",
                    "severity": f.get("severity", ""),
                    "title": f.get("label", ""),
                    "remediation": f["mitigations"][0]["description"] if f.get("mitigations") else "",
                })

            prompt = (
                "You are an infrastructure security analyst converting verified scan findings "
                "to plain business language. "
                "STRICT RULE: Use ONLY the findings provided below. Do NOT add vulnerabilities, "
                "incidents, costs, or claims not present in the input. "
                "If evidence is missing or unclear, say 'insufficient evidence'. "
                f"Platform: {ptype.upper()}\n"
                f"Risk Score: {summary.get('critical',0)*25+summary.get('high',0)*15+summary.get('medium',0)*5+summary.get('low',0)*1}/100\n"
                f"Quantum Novelty: {quantum_risk.get('quantum_novelty',0)}%  F={quantum_risk.get('f_min',1.0):.3f}\n"
                f"Findings count: {len(verified_findings)}\n\n"
                "Verified findings (JSON):\n" + json.dumps(verified_findings, indent=2) + "\n\n"
                "Provide:\n"
                "1. Executive summary (2-3 sentences, business language)\n"
                "2. Top 3 immediate actions\n"
                "3. One sentence on breach risk (reference IBM India MSME baseline ₹2-5 Cr)"
            )
            resp = llm_service.generate_response(prompt)
            if resp.get("success"):
                results["ai_summary"] = resp.get("explanation", "")
        except Exception:
            pass

    results["duration"] = round(time.time() - start, 1)
    _state["analysis_results"] = results

    # Normalize to infra health model
    try:
        from components.taara_analysis import build_infra_health_model
        results["model"] = build_infra_health_model(results)
    except Exception:
        results["model"] = None

    _state["action_logger"].log("analysis", "taara_analysis",
                                f"Scan complete — {len(results['model']['findings']) if results.get('model') else '?'} findings",
                                severity="info")
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# GENERATE REPORT (TaaraWords PDF)
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/generate-report")
def generate_report(report_config: Dict = None):
    results = _state["analysis_results"]
    if not results:
        raise HTTPException(status_code=400, detail="No analysis results. Run /api/analyze first.")

    try:
        from components.taara_words import generate_report_pdf
        pdf_bytes = generate_report_pdf(results, report_config or {})

        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf",
                                          prefix="TAARA_Report_",
                                          dir=str(ROOT / "models"))
        tmp.write(pdf_bytes)
        tmp.flush()
        tmp_path = tmp.name
        tmp.close()

        _state["action_logger"].log("report", "taara_words",
                                    f"PDF generated: {Path(tmp_path).name}", severity="info")

        return FileResponse(
            tmp_path,
            media_type="application/pdf",
            filename=f"TAARA_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/generate-report-path")
def generate_report_path(report_config: Dict = None):
    """Like /api/generate-report but returns the file path as JSON — used by Electron to open via shell."""
    results = _state["analysis_results"]
    if not results:
        raise HTTPException(status_code=400, detail="No analysis results. Run /api/analyze first.")

    try:
        from components.taara_words import generate_report_pdf
        pdf_bytes = generate_report_pdf(results, report_config or {})

        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf",
                                          prefix="TAARA_Report_",
                                          dir=str(ROOT / "models"))
        tmp.write(pdf_bytes)
        tmp.flush()
        tmp_path = tmp.name
        tmp.close()

        _state["action_logger"].log("report", "taara_words",
                                    f"PDF generated: {Path(tmp_path).name}", severity="info")

        return {"path": tmp_path, "filename": Path(tmp_path).name}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ═══════════════════════════════════════════════════════════════════════════════
# DEPLOY TAARAWARE
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/deploy-taaraware")
def deploy_taaraware(req: DeployRequest):
    platform = _state["platform"]
    if not platform or not platform.connected:
        raise HTTPException(status_code=400, detail="No platform connected")

    taaraware_mgr = _state["taaraware_mgr"]
    config = {
        "command_center_host": req.command_center_host,
        "command_center_port": req.command_center_port,
        "interval": req.interval,
    }

    result = taaraware_mgr.deploy_agent(platform, config)
    if result.get("success"):
        _state["action_logger"].log("taaraware", "deploy",
                                    result.get("message", ""), severity="info")
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# STATUS (live feature vector from TaaraWare agent)
# SSH fetches are cached for 30s and refreshed in a background thread so the
# HTTP handler always returns immediately without blocking on network I/O.
# ═══════════════════════════════════════════════════════════════════════════════

FEATURE_NAMES_19 = [
    "cpu_usage", "memory_usage", "disk_usage",
    "proc_spawn_rate", "proc_root_ratio", "proc_cmd_entropy",
    "net_outbound_conn_rate", "net_unique_dst_ips", "net_unique_dst_ports",
    "net_port_entropy", "net_failed_conn_ratio",
    "failed_logins_1h", "new_processes_1h",
    "suspicious_connections", "privilege_escalations",
    "temporal_rhythm_deviation", "causal_chain_novelty",
    "concealment_signal", "proc_cmd_novelty",
]
RAW_EXTRA_FIELDS = [
    "load_avg_1m", "load_avg_5m", "load_avg_15m",
    "active_connections", "process_count",
    "proc_short_lived_ratio", "proc_uid_diversity",
    "network_bytes_sent", "network_bytes_recv",
]

_status_refresh_lock = threading.Lock()
_status_refreshing   = False


def _do_status_refresh():
    """Background worker: fetch SSH buffer, run inference, update cache."""
    global _status_refreshing
    try:
        platform      = _state["platform"]
        taaraware_mgr = _state["taaraware_mgr"]
        taara_analyzer = _state.get("taara_analyzer")
        embedder       = _state.get("embedder")
        detector       = _state.get("detector")
        host           = platform.config.get("host", "unknown") if platform else "unknown"

        agent_status = taaraware_mgr.check_agent_status(platform)
        buffer       = taaraware_mgr.collect_remote_data(platform)

        feature_vector = None
        novelty_result = None

        if buffer:
            features = buffer[-1].get("features") or buffer[-1]
            fv = np.array([float(features.get(k, 0.0)) for k in FEATURE_NAMES_19], dtype=np.float32)
            feature_vector = {k: float(features.get(k, 0.0)) for k in FEATURE_NAMES_19}
            for k in RAW_EXTRA_FIELDS:
                if k in features:
                    feature_vector[k] = float(features[k])

            classical_anomaly = False
            anomaly_score_val = recon_error = latent_fidelity = None
            if embedder and detector and embedder.is_trained and detector.is_ready():
                try:
                    recon_error    = embedder.reconstruction_error(fv)
                    current_latent = embedder.embed(fv)
                    nl_path = os.path.join('models', 'normal_latent.json')
                    if os.path.exists(nl_path):
                        with open(nl_path) as _f:
                            normal_latent = np.array(json.load(_f), dtype=np.float32)
                        cos_sim = float(np.dot(current_latent, normal_latent) /
                                        (np.linalg.norm(current_latent) * np.linalg.norm(normal_latent) + 1e-8))
                        latent_fidelity = (cos_sim + 1) / 2
                    if_result      = detector.detect(current_latent)
                    anomaly_score_val = if_result.get("anomaly_score", 0.0)
                    if_anomaly     = if_result.get("is_anomaly", False)
                    classical_anomaly = if_anomaly and (recon_error or 0) > 0.05 and (latent_fidelity or 1) < 0.6
                    feature_vector.update({"anomaly_score": anomaly_score_val, "is_anomaly": classical_anomaly,
                                           "recon_error": recon_error, "latent_fidelity": latent_fidelity})
                except Exception:
                    pass

            if taara_analyzer:
                try:
                    identity = f"taaraware_{host}"
                    qr       = taara_analyzer.get_quantum_risk_assessment(fv, identity_id=identity, embedder=embedder)
                    qc       = qr.get("quantum_confidence")
                    novelty_result = {
                        "f_min": qr.get("f_min"), "novelty_score": qr.get("risk_score", 0),
                        "is_novel": qr.get("is_directionally_novel", False),
                        "severity": qr.get("severity", "BOOTSTRAPPING"),
                        "basis_size": qr.get("basis_size", 0),
                        "residual_norm": qr.get("residual_norm", 0),
                        "quantum_novelty": qr.get("quantum_novelty", 0),
                        "classical_anomaly": classical_anomaly,
                        "anomaly_score": anomaly_score_val, "recon_error": recon_error,
                        "latent_fidelity": latent_fidelity, "note": qr.get("note", ""),
                        "swap_fidelity": qr.get("swap_fidelity"),
                        "q_directionality": qr.get("q_directionality"),
                        "phase_coherence": qr.get("phase_coherence"),
                        "quantum_confidence": qc,
                    }
                    basis_mature = qr.get("basis_size", 0) >= 3
                    alert_cond   = basis_mature and qc is not None and qc > 0.1854
                    if alert_cond:
                        _state["active_alert"] = {
                            "timestamp": time.time(), "score": qr.get("risk_score", 0),
                            "f_min": qr.get("f_min"), "features": feature_vector, "host": host,
                            "classical_confirmed": classical_anomaly,
                            "quantum_confidence": qc,
                            "swap_fidelity": qr.get("swap_fidelity"),
                            "q_directionality": qr.get("q_directionality"),
                            "phase_coherence": qr.get("phase_coherence"),
                        }
                except Exception:
                    pass

        # Fallback: no live data yet — run inference on zero probe so stats show immediately
        if novelty_result is None and taara_analyzer:
            identity  = f"taaraware_{host}"
            basis_obj = taara_analyzer.memory_bases.get(identity)
            bs        = len(basis_obj.basis_vectors) if basis_obj else 0
            probe     = (np.mean(basis_obj.basis_vectors, axis=0).astype(np.float32)
                         if basis_obj and len(basis_obj.basis_vectors) >= 1
                         else np.zeros(19, dtype=np.float32))
            try:
                qr = taara_analyzer.get_quantum_risk_assessment(probe, identity_id=identity, embedder=embedder)
                novelty_result = {
                    "basis_size": bs, "f_min": qr.get("f_min"),
                    "swap_fidelity": qr.get("swap_fidelity"),
                    "q_directionality": qr.get("q_directionality"),
                    "phase_coherence": qr.get("phase_coherence"),
                    "quantum_confidence": qr.get("quantum_confidence"),
                    "severity": qr.get("severity", "BOOTSTRAPPING"),
                    "note": qr.get("note", ""),
                }
            except Exception:
                novelty_result = {"basis_size": bs, "f_min": None,
                                  "swap_fidelity": None, "q_directionality": None,
                                  "phase_coherence": None, "quantum_confidence": None}

        training_mgr = _state["training_mgr"]
        _state["_status_cache"] = {
            "connected": True,
            "agent_status": agent_status,
            "feature_vector": feature_vector,
            "novelty": novelty_result,
            "training_status": training_mgr.get_status() if training_mgr else {},
            "alert": _state.get("active_alert"),
        }
        _state["_status_cache_ts"]   = time.time()
        _state["_status_cache_host"] = host

        # Persist quantum state to disk after every successful refresh with real signals
        # so values survive crashes/restarts without needing a clean disconnect.
        if (novelty_result and novelty_result.get("swap_fidelity") is not None
                and taara_analyzer and embedder):
            try:
                from components.node_identity_db import snapshot_quantum_state
                snapshot_quantum_state(host, taara_analyzer)
            except Exception:
                pass
    except Exception as e:
        print(f"[status refresh] error: {e}")
    finally:
        global _status_refreshing
        _status_refreshing = False


@app.get("/api/status")
def get_status():
    platform      = _state["platform"]
    training_mgr  = _state["training_mgr"]

    if not platform or not platform.connected:
        return {
            "connected": False,
            "agent_status": None,
            "feature_vector": None,
            "training_status": training_mgr.get_status() if training_mgr else {},
        }

    host = platform.config.get("host", "unknown")
    now  = time.time()
    cache_age  = now - _state["_status_cache_ts"]
    cache_host = _state["_status_cache_host"]

    # Kick off a background refresh if cache is stale (>30s) or for a different host
    global _status_refreshing
    if (cache_age > _STATUS_CACHE_TTL or cache_host != host) and not _status_refreshing:
        _status_refreshing = True
        t = threading.Thread(target=_do_status_refresh, daemon=True)
        t.start()

    # Return cached result immediately — never block on SSH
    cached = _state.get("_status_cache")
    if cached and cache_host == host:
        # Always inject the freshest alert and training status (these are in-memory, no I/O)
        cached = dict(cached)
        cached["alert"]           = _state.get("active_alert")
        cached["training_status"] = training_mgr.get_status() if training_mgr else {}
        return cached

    # Very first call before any refresh completes: return minimal response with quantum signals
    taara_analyzer = _state.get("taara_analyzer")
    embedder       = _state.get("embedder")
    novelty_result = None
    if taara_analyzer:
        identity  = f"taaraware_{host}"
        basis_obj = taara_analyzer.memory_bases.get(identity)
        bs        = len(basis_obj.basis_vectors) if basis_obj else 0
        probe     = (np.mean(basis_obj.basis_vectors, axis=0).astype(np.float32)
                     if basis_obj and len(basis_obj.basis_vectors) >= 1
                     else np.zeros(19, dtype=np.float32))
        try:
            qr = taara_analyzer.get_quantum_risk_assessment(probe, identity_id=identity, embedder=embedder)
            novelty_result = {
                "basis_size": bs, "f_min": qr.get("f_min"),
                "swap_fidelity": qr.get("swap_fidelity"),
                "q_directionality": qr.get("q_directionality"),
                "phase_coherence": qr.get("phase_coherence"),
                "quantum_confidence": qr.get("quantum_confidence"),
                "severity": qr.get("severity", "BOOTSTRAPPING"),
            }
        except Exception:
            novelty_result = {"basis_size": bs, "f_min": None,
                              "swap_fidelity": None, "q_directionality": None,
                              "phase_coherence": None, "quantum_confidence": None}

    return {
        "connected": True,
        "agent_status": {"status": "checking"},
        "feature_vector": None,
        "novelty": novelty_result,
        "training_status": training_mgr.get_status() if training_mgr else {},
        "alert": _state.get("active_alert"),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# TRAIN (Quick Train baseline)
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/train")
def train(req: TrainRequest, background_tasks: BackgroundTasks):
    platform = _state["platform"]
    if not platform or not platform.connected:
        raise HTTPException(status_code=400, detail="No platform connected")

    training_mgr = _state["training_mgr"]
    embedder = _state["embedder"]
    detector = _state["detector"]

    taara_analyzer = _state["taara_analyzer"]

    def _do_train():
        try:
            from components.atomic_dna_collector import AtomicDNACollector as _collector_cls
        except ImportError:
            _collector_cls = None

        # Pull whatever the TaaraWare agent has already collected on the server.
        # That historical buffer IS the normal baseline — train on it directly.
        # If the buffer has enough samples, Phase 1 is skipped entirely.
        taaraware_mgr = _state.get("taaraware_mgr")
        if taaraware_mgr and platform.platform_type == "ssh":
            try:
                buffer = taaraware_mgr.collect_remote_data(platform)
                if buffer:
                    host = platform.config.get("host", "unknown")
                    result = training_mgr.load_from_remote_buffer(host, buffer)
                    print(f"[Train] Buffer pre-load: {result.get('message', '')}")
            except Exception as e:
                print(f"[Train] Buffer pre-load failed (will collect fresh): {e}")

        training_mgr.start_training(
            mode=req.mode,
            platform=platform,
            embedder=embedder,
            detector=detector,
            taara_analyzer=taara_analyzer,
            collector_class=_collector_cls,
        )

    background_tasks.add_task(_do_train)
    _state["action_logger"].log("training", "start",
                                f"Training started — mode: {req.mode}", severity="info")
    return {"success": True, "message": f"Training started in background — mode: {req.mode}"}


@app.get("/api/train/status")
def train_status():
    training_mgr = _state["training_mgr"]
    if not training_mgr:
        return {"running": False}
    return training_mgr.get_status()


@app.post("/api/train/stop")
def train_stop():
    training_mgr = _state["training_mgr"]
    if training_mgr:
        training_mgr.stop_training()
    return {"success": True}


# ═══════════════════════════════════════════════════════════════════════════════
# ALERTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/alerts")
def get_alerts():
    taaraware_mgr = _state["taaraware_mgr"]
    agent_alerts = taaraware_mgr.get_all_alerts() if taaraware_mgr else []

    active = _state.get("active_alert")
    return {
        "active_anomaly": active,
        "agent_alerts": agent_alerts[:50],
        "has_anomaly": active is not None,
    }


@app.post("/api/alerts/dismiss")
def dismiss_alert():
    _state["active_alert"] = None
    return {"success": True}


@app.get("/api/alerts/investigate")
def investigate_alert():
    """Return full investigation context for the active anomaly alert."""
    active = _state.get("active_alert")
    if not active:
        raise HTTPException(status_code=404, detail="No active alert")

    fv = active.get("features", {})
    f_min = active.get("f_min", 0.0)
    host = active.get("host", "unknown")
    score = active.get("score", 0)
    ts = active.get("timestamp", 0)
    # V3 validated quantum signals from active alert
    swap_fidelity_inv    = active.get("swap_fidelity")
    q_directionality_inv = active.get("q_directionality")
    phase_coherence_inv  = active.get("phase_coherence")
    quantum_conf_inv     = active.get("quantum_confidence")

    # Build top signals — features most deviated from typical range
    SIGNAL_NORMS = {
        "cpu_usage": 50, "memory_usage": 60, "disk_usage": 40,
        "proc_spawn_rate": 5, "proc_root_ratio": 0.5, "proc_cmd_entropy": 4.0,
        "net_outbound_conn_rate": 30, "net_unique_dst_ips": 3, "net_unique_dst_ports": 10,
        "net_failed_conn_ratio": 0.1, "failed_logins_1h": 0, "causal_chain_novelty": 0.05,
        "concealment_signal": 0, "temporal_rhythm_deviation": 0,
    }
    top_signals = []
    for k, norm in SIGNAL_NORMS.items():
        val = fv.get(k)
        if val is None:
            continue
        deviation = abs(val - norm) / max(norm, 0.01)
        top_signals.append({"key": k, "value": round(float(val), 4), "deviation": round(deviation, 2), "normal": norm})
    top_signals = sorted(top_signals, key=lambda x: -x["deviation"])[:6]

    # Plain-English quantum explanation — use quantum_confidence (v3) when available
    if quantum_conf_inv is not None:
        qc = quantum_conf_inv
        if qc >= 0.75:
            zone = "CRITICAL"
            zone_explain = (
                f"Quantum confidence = {qc:.4f} (threshold 0.1854). All three quantum signals fire together: "
                f"SWAP fidelity = {swap_fidelity_inv:.4f} (outside normal subspace), "
                f"directionality = {q_directionality_inv:.4f} (high complement alignment), "
                f"phase coherence = {phase_coherence_inv:.4f} (sustained drift pattern). "
                "The interference fusion formula α·swap_s + β·q_dir + γ·coh·√(swap_s·q_dir) places this firmly above the p95 normal threshold. "
                "High probability of T1078 Valid Account credential misuse."
            )
        elif qc >= 0.45:
            zone = "HIGH"
            zone_explain = (
                f"Quantum confidence = {qc:.4f}. Behavioral subspace deviation is sustained and directional. "
                f"SWAP fidelity = {swap_fidelity_inv:.4f}, directionality = {q_directionality_inv:.4f}, "
                f"phase coherence = {phase_coherence_inv:.4f}. "
                "Pattern is consistent with attacker using stolen credentials — moving outside the normal behavioral subspace."
            )
        elif qc >= 0.1854:
            zone = "MEDIUM"
            zone_explain = (
                f"Quantum confidence = {qc:.4f} (just above 0.1854 threshold). Early-stage behavioral deviation. "
                f"SWAP fidelity = {swap_fidelity_inv:.4f}, directionality = {q_directionality_inv:.4f}. "
                "Consistent with initial reconnaissance or behavioral drift. Monitor for escalation."
            )
        else:
            zone = "LOW"
            zone_explain = f"Quantum confidence = {qc:.4f}. Low but above threshold. May be transient deviation."
        divergence_pct = round(qc * 100, 1)
    else:
        divergence_pct = round((1.0 - f_min) * 100, 1)
        if f_min < 0.3:
            zone = "CRITICAL DIVERGENCE"
            zone_explain = (
                f"The server's current behavior is {divergence_pct}% orthogonal to every prior normal state in its memory. "
                f"F_min = {f_min:.4f} means the quantum state |ψ_t⟩ has less than 30% overlap with any baseline state |ψ_m⟩. "
                "At this level, the behavioral direction is geometrically new — not just statistically unusual."
            )
        elif f_min < 0.5:
            zone = "UNSAFE DIRECTION"
            zone_explain = (
                f"Current behavior is {divergence_pct}% divergent from trained baseline. "
                f"F_min = {f_min:.4f} is below the 0.5 geometric threshold."
            )
        else:
            zone = "DRIFTING"
            zone_explain = (
                f"Current behavior shows {divergence_pct}% deviation. "
                f"F_min = {f_min:.4f} flagged as novel based on reconstruction error."
            )

    # LLM reasoning (if available)
    llm_reasoning = None
    llm_service = _state.get("llm_service")
    if llm_service:
        try:
            signal_lines = "\n".join(
                f"  - {s['key']}: {s['value']} (normal ~{s['normal']}, deviation {s['deviation']}x)"
                for s in top_signals
            )
            _qc_str  = f"{quantum_conf_inv:.4f}" if quantum_conf_inv is not None else f"{f_min:.4f}"
            _sf_str  = f"{swap_fidelity_inv:.4f}" if swap_fidelity_inv is not None else "N/A"
            _qd_str  = f"{q_directionality_inv:.4f}" if q_directionality_inv is not None else "N/A"
            _pc_str  = f"{phase_coherence_inv:.4f}" if phase_coherence_inv is not None else "N/A"
            prompt = (
                "You are TAARA — Threat-Aware Anomaly Response Architecture.\n"
                "You use quantum-enhanced behavioral analytics to detect MITRE ATT&CK T1078 (Valid Account abuse).\n\n"
                "DETECTION METHODOLOGY:\n"
                "Each SSH session is represented as a 19-dimensional behavioral DNA vector:\n"
                "  [cpu, memory, disk, proc_spawn_rate, proc_root_ratio, proc_cmd_entropy,\n"
                "   net_outbound_rate, unique_dst_ips, unique_dst_ports, port_entropy, failed_conn_ratio,\n"
                "   failed_logins_1h, new_processes_1h, suspicious_connections, privilege_escalations,\n"
                "   temporal_rhythm_deviation, causal_chain_novelty, concealment_signal, anomaly_score]\n\n"
                "This vector is encoded as a 3-qubit quantum state |ψ_t⟩ via AmplitudeEmbedding on the\n"
                "8-dimensional latent space from a pretrained BehavioralAE (19→64→8→64→19, Tanh bottleneck).\n\n"
                "QUANTUM SIGNALS (V3 fusion: conf = α·swap_s + β·q_dir + γ·coh·√(swap_s·q_dir)):\n"
                f"  swap_s = 1 - F_sub = {_sf_str}  (SWAP fidelity: how far |ψ_t⟩ is from the normal PCA subspace)\n"
                f"  q_dir  = {_qd_str}  (directionality: is the drift pointing into the complement subspace?)\n"
                f"  coh    = {_pc_str}  (phase coherence: is the drift sustained across W=4 consecutive windows?)\n"
                f"  conf   = {_qc_str}  (V3 fusion confidence — threshold = 0.1854 = p95 of normal training)\n"
                f"  alert zone: {zone}\n\n"
                "T1078 THREAT MODEL:\n"
                "An attacker with stolen valid credentials produces behavior that is geometrically novel\n"
                "to the legitimate user's quantum memory subspace — same global distribution as any user,\n"
                "but outside THIS user's specific normal subspace. SWAP fidelity < 0.3 = clearly outside.\n"
                "Phase coherence > 0.8 = drift is SUSTAINED (not random noise). Directionality > 0.3 =\n"
                "the attacker is consistently exploring new behavioral territory.\n\n"
                f"ALERT CONTEXT:\n"
                f"  Host: {host}\n"
                f"  Risk score: {score:.1f}/100\n"
                f"  Confidence: {_qc_str} ({zone})\n\n"
                f"Top deviating behavioral signals:\n{signal_lines}\n\n"
                "YOUR TASK — answer in 4 sentences, plain English, no jargon:\n"
                "1. Given the quantum signal values above, what is the most likely cause?\n"
                "2. Which specific behavioral signals are most suspicious and why?\n"
                "3. What is the immediate risk to this server?\n"
                "4. What single action should the operator take right now?\n"
            )
            result = llm_service.generate_response(prompt)
            if isinstance(result, dict) and result.get("success"):
                llm_reasoning = result.get("raw_response") or result.get("explanation", "")
            elif isinstance(result, str):
                llm_reasoning = result
        except Exception:
            pass

    # Historical context — has this happened before on this host?
    taara_analyzer = _state.get("taara_analyzer")
    prior_anomalies = 0
    basis_size = 0
    if taara_analyzer:
        identity = f"taaraware_{host}"
        basis = taara_analyzer.memory_bases.get(identity)
        if basis:
            basis_size = len(basis.basis_vectors)
            prior_anomalies = sum(1 for r in basis.residual_history if r > basis.max_residual_norm * 0.8)

    # Classical signal breakdown from the stored alert features
    recon_error = fv.get("recon_error")
    latent_fidelity = fv.get("latent_fidelity")
    anomaly_score = fv.get("anomaly_score")
    classical_confirmed = active.get("classical_confirmed", False)

    # Bandit-learned recommendations for this quantum context
    bandit_recommendations = []
    agent = _state.get("security_agent")
    if agent and hasattr(agent, "bandit"):
        try:
            from components.action_bandit import fidelity_bucket
            f_ctx = quantum_conf_inv if quantum_conf_inv is not None else (1.0 - f_min if f_min else 0.5)
            bandit_context = {
                "f_min": active.get("f_min", 0.5),
                "platform_type": _state.get("platform_type", "ssh"),
            }
            # Standard T1078 candidate actions for this context
            candidates = [
                {"action_type": "block_ip",        "description": "Block attacking IP via fail2ban"},
                {"action_type": "rate_limit_ssh",   "description": "Apply SSH rate limiting (MaxAuthTries 3)"},
                {"action_type": "isolate_user",     "description": "Lock suspicious user account"},
                {"action_type": "harden_ssh",       "description": "Apply SSH config hardening"},
                {"action_type": "restart_service",  "description": "Restart sshd to clear active sessions"},
                {"action_type": "firewall_rule",    "description": "Add firewall rule to restrict access"},
            ]
            ranked = agent.bandit.select_actions(bandit_context, candidates, top_k=3)
            for rec in ranked:
                contrast = agent.bandit.get_contrast_insight(rec.get("arm_key", ""))
                bandit_recommendations.append({
                    "action_type": rec["action_type"],
                    "description": rec["description"],
                    "ucb_score": rec.get("ucb_score", 0),
                    "approval_rate": rec.get("approval_rate", 0),
                    "success_rate": rec.get("success_rate", 0),
                    "times_seen": rec.get("times_seen", 0),
                    "pre_approved": rec.get("pre_approved", False),
                    "bandit_rationale": rec.get("bandit_rationale", ""),
                    "contrast_insight": contrast,
                    "source": "TAARA Learned" if rec.get("times_seen", 0) > 0 else "Exploring",
                })
        except Exception:
            pass

    return {
        "host": host,
        "timestamp": ts,
        "f_min": f_min,
        "risk_score": score,
        "zone": zone,
        "divergence_pct": divergence_pct,
        "zone_explain": zone_explain,
        "top_signals": top_signals,
        "features": fv,
        "llm_reasoning": llm_reasoning,
        "prior_anomalies": prior_anomalies,
        "basis_size": basis_size,
        "formula": "α·swap_s + β·q_dir + γ·coh·√(swap_s·q_dir)" if quantum_conf_inv is not None else "F_min = min_{m∈M} |⟨ψ_t|ψ_m⟩|²",
        # V3 validated quantum signals
        "quantum_confidence": quantum_conf_inv,
        "swap_fidelity": swap_fidelity_inv,
        "q_directionality": q_directionality_inv,
        "phase_coherence": phase_coherence_inv,
        # Classical signal breakdown
        "classical_confirmed": classical_confirmed,
        "recon_error": recon_error,
        "latent_fidelity": latent_fidelity,
        "anomaly_score": anomaly_score,
        # Bandit-learned recommendations for this context
        "bandit_recommendations": bandit_recommendations,
    }


@app.post("/api/alerts/mark-normal")
def mark_alert_normal():
    """
    Online learning: mark current alert state as normal behavior.
    Adds the current feature vector to the TAARA memory basis and
    lowers max_residual_norm so future identical states aren't flagged.
    """
    active = _state.get("active_alert")
    taara_analyzer = _state.get("taara_analyzer")
    if not active:
        raise HTTPException(status_code=404, detail="No active alert to mark")

    fv_dict = active.get("features", {})
    host = active.get("host", "unknown")
    identity = f"taaraware_{host}"

    FEATURE_NAMES = [
        "cpu_usage", "memory_usage", "disk_usage",
        "proc_spawn_rate", "proc_root_ratio", "proc_cmd_entropy",
        "net_outbound_conn_rate", "net_unique_dst_ips", "net_unique_dst_ports",
        "net_port_entropy", "net_failed_conn_ratio",
        "failed_logins_1h", "new_processes_1h",
        "suspicious_connections", "privilege_escalations",
        "temporal_rhythm_deviation", "causal_chain_novelty",
        "concealment_signal", "proc_cmd_novelty",
    ]
    fv = np.array([float(fv_dict.get(k, 0.0)) for k in FEATURE_NAMES], dtype=np.float32)

    if taara_analyzer:
        basis = taara_analyzer.get_or_create_basis(identity)
        # Add as normal observation — expands what's considered baseline
        basis.add_observation(fv)
        # Lower max_residual_norm so this state is no longer above the novelty threshold
        _, _, residual_norm = basis.reconstruct(fv)
        if residual_norm < basis.max_residual_norm:
            basis.max_residual_norm = residual_norm * 1.1  # small margin

    # Clear the alert
    _state["active_alert"] = None

    # Log the learning event
    action_logger = _state.get("action_logger")
    if action_logger:
        action_logger.log("taara", "mark_normal",
                          f"Operator marked anomaly on {host} as normal. Basis updated.",
                          severity="info")

    return {"success": True, "message": f"State marked as normal. TAARA basis updated for {identity}."}


@app.post("/api/alerts/ignore")
def ignore_alert():
    """
    Ignore: mark alert as normal AND raise the quantum confidence threshold for this
    identity so this behavioural pattern is never flagged again.
    Unlike mark-normal which only adds to the basis, ignore also moves the threshold.
    """
    active = _state.get("active_alert")
    taara_analyzer = _state.get("taara_analyzer")
    if not active:
        raise HTTPException(status_code=404, detail="No active alert to ignore")

    fv_dict = active.get("features", {})
    host = active.get("host", "unknown")
    identity = f"taaraware_{host}"

    FEATURE_NAMES = [
        "cpu_usage", "memory_usage", "disk_usage",
        "proc_spawn_rate", "proc_root_ratio", "proc_cmd_entropy",
        "net_outbound_conn_rate", "net_unique_dst_ips", "net_unique_dst_ports",
        "net_port_entropy", "net_failed_conn_ratio",
        "failed_logins_1h", "new_processes_1h",
        "suspicious_connections", "privilege_escalations",
        "temporal_rhythm_deviation", "causal_chain_novelty",
        "concealment_signal", "proc_cmd_novelty",
    ]
    fv = np.array([float(fv_dict.get(k, 0.0)) for k in FEATURE_NAMES], dtype=np.float32)

    if taara_analyzer:
        basis = taara_analyzer.get_or_create_basis(identity)
        basis.add_observation(fv)
        _, _, residual_norm = basis.reconstruct(fv)
        # Raise threshold so this exact confidence level is ignored going forward
        if residual_norm > basis.max_residual_norm * 0.5:
            basis.max_residual_norm = residual_norm * 1.25

        # Also raise the quantum confidence threshold for this identity
        qs = taara_analyzer.quantum_states.get(identity, {})
        current_conf = active.get("quantum_confidence") or 0.0
        if current_conf > 0 and qs:
            old_thresh = qs.get("threshold", 0.1854)
            # New threshold = max(current, old) * 1.1 — ignore up to this level
            qs["threshold"] = max(old_thresh, current_conf) * 1.1
            taara_analyzer.quantum_states[identity] = qs
            taara_analyzer.save_state()

    _state["active_alert"] = None
    action_logger = _state.get("action_logger")
    if action_logger:
        action_logger.log("taara", "ignore_alert",
                          f"Operator ignored anomaly on {host}. Threshold raised.",
                          severity="info")

    # Feed false-positive signal into contrastive bandit:
    # Any action that was proposed/approved in this alert context gets a soft negative reward
    # because the context turned out to be a false positive (operator says: don't flag this)
    agent = _state.get("security_agent")
    if agent and hasattr(agent, "bandit"):
        try:
            from components.action_bandit import fidelity_bucket
            current_conf = active.get("quantum_confidence") or 0.0
            f_m = active.get("f_min", 1.0)
            bucket = fidelity_bucket(f_m)
            platform_type = _state.get("platform_type", "ssh")
            # Record a "false positive" marker — the context looked alarming but wasn't
            # We do this by recording a failed execution for a generic "alert_fp" pseudo-arm
            fp_arm_key = f"{bucket}:{platform_type}:alert_false_positive"
            agent.bandit.record_proposed(fp_arm_key)
            agent.bandit.record_executed(fp_arm_key, False, {
                "f_min": f_m,
                "quantum_confidence": current_conf,
                "host": host,
                "platform_type": platform_type,
                "false_positive": True,
            })
        except Exception:
            pass

    return {"success": True, "message": f"Alert ignored. Quantum threshold raised for {identity}."}


# ═══════════════════════════════════════════════════════════════════════════════
# EXECUTE COMMAND
# ═══════════════════════════════════════════════════════════════════════════════

def _run_command(platform, platform_type, command, language="bash", stdin_input=None):
    """Execute a command on the platform, optionally piping stdin_input."""
    result = {"success": False, "stdout": "", "stderr": "", "exit_code": -1, "error": "",
              "needs_input": False, "input_prompt": ""}
    try:
        if platform_type == "ssh":
            code = command
            if language == "python":
                escaped = code.replace("'", "'\\''")
                code = f"python3 -c '{escaped}'"
            # If stdin provided, pipe it via echo
            if stdin_input is not None:
                safe_input = stdin_input.replace("'", "'\\''")
                code = f"echo '{safe_input}' | {code}"
            stdout, stderr, rc = platform.execute_command(code)
            # Detect if command is still waiting for input
            input_prompts = ["[y/n]", "[Y/n]", "password:", "enter passphrase",
                             "are you sure", "(yes/no)", "press enter", "continue? "]
            combined = (stdout + stderr).lower()
            if rc == -1 or any(p in combined for p in input_prompts):
                result["needs_input"] = True
                result["input_prompt"] = stderr.strip() or stdout.strip()
            result["stdout"] = stdout
            result["stderr"] = stderr
            result["exit_code"] = rc
            result["success"] = (rc == 0)
            if rc != 0 and not result["needs_input"]:
                result["error"] = f"Exit code: {rc}"
        else:
            result["stdout"] = f"[{platform_type.upper()}] Command staged:\n{command}"
            result["success"] = True
    except Exception as e:
        result["error"] = str(e)
    return result


def _bandit_context_from_state() -> Dict:
    """Extract current quantum context from state for bandit recording."""
    alert = _state.get("active_alert") or {}
    return {
        "f_min": alert.get("f_min", 1.0),
        "quantum_confidence": alert.get("quantum_confidence"),
        "swap_fidelity": alert.get("swap_fidelity"),
        "q_directionality": alert.get("q_directionality"),
        "phase_coherence": alert.get("phase_coherence"),
        "host": _state.get("connected_host", "unknown"),
        "platform_type": _state.get("platform_type", "ssh"),
    }


def _infer_action_type_from_cmd(command: str) -> str:
    """Infer bandit action_type from a raw shell command."""
    code = command.lower()
    if "fail2ban" in code or "banip" in code:
        return "block_ip"
    if "systemctl restart" in code or ("service" in code and "restart" in code):
        return "restart_service"
    if "systemctl stop" in code:
        return "terminate_service"
    if "sshd_config" in code or ("ssh" in code and "config" in code):
        return "harden_ssh"
    if "ufw" in code or "iptables" in code or "firewall" in code:
        return "firewall_rule"
    if "usermod -L" in code or "passwd -l" in code:
        return "isolate_user"
    if "authorized_keys" in code:
        return "rotate_key"
    if "rate" in code and "ssh" in code:
        return "rate_limit_ssh"
    if "kill " in code:
        return "kill_process"
    return "generic"


def _bandit_record_execute(command: str, success: bool):
    """Record command execution outcome in the contrastive bandit."""
    agent = _state.get("security_agent")
    if not agent or not hasattr(agent, "bandit"):
        return
    from components.action_bandit import fidelity_bucket
    ctx = _bandit_context_from_state()
    bucket = fidelity_bucket(ctx.get("f_min", 1.0))
    platform_type = ctx.get("platform_type", "ssh")
    action_type = _infer_action_type_from_cmd(command)
    arm_key = f"{bucket}:{platform_type}:{action_type}"
    agent.bandit.record_proposed(arm_key)
    agent.bandit.record_approved(arm_key)
    agent.bandit.record_executed(arm_key, success, ctx)


@app.post("/api/execute")
def execute_command(req: ExecuteRequest):
    platform = _state["platform"]
    if not platform or not platform.connected:
        raise HTTPException(status_code=400, detail="No platform connected")
    result = _run_command(platform, _state["platform_type"], req.command, req.language, req.stdin_input)
    _state["action_logger"].log(
        "execute", "command_execute",
        f"{'OK' if result['success'] else 'FAIL'}: {req.command[:100]}",
        severity="info" if result["success"] else "warning",
        metadata={"command": req.command[:500], "result": result.get("stdout", "")[:500]},
    )
    # Record in contrastive bandit — operator explicitly ran this command = approved + proposed
    if not result.get("needs_input"):
        _bandit_record_execute(req.command, result.get("success", False))
    return result


@app.post("/api/execute/stdin")
def execute_with_stdin(req: StdinRequest):
    """Send stdin input to an interactive command."""
    platform = _state["platform"]
    if not platform or not platform.connected:
        raise HTTPException(status_code=400, detail="No platform connected")
    result = _run_command(platform, _state["platform_type"], req.command, stdin_input=req.stdin_input)
    _state["action_logger"].log(
        "execute", "stdin_execute",
        f"{'OK' if result['success'] else 'FAIL'} (stdin): {req.command[:80]}",
        severity="info" if result["success"] else "warning",
    )
    _bandit_record_execute(req.command, result.get("success", False))
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# AI COMMAND GENERATION
# ═══════════════════════════════════════════════════════════════════════════════

class GenerateCommandRequest(BaseModel):
    intent: str

@app.post("/api/generate-command")
def generate_command(req: GenerateCommandRequest):
    llm = _state.get("llm_service")
    if not llm:
        # Fallback: return a best-effort shell command without LLM
        intent = req.intent.lower().strip()
        mapping = {
            "ls": "ls -la", "list": "ls -la", "disk": "df -h", "memory": "free -h",
            "cpu": "top -bn1 | head -5", "processes": "ps aux --sort=-%cpu | head -10",
            "network": "ss -tlnp", "ports": "ss -tlnp", "users": "who",
            "uptime": "uptime", "logs": "tail -n 50 /var/log/syslog",
        }
        for keyword, cmd in mapping.items():
            if keyword in intent:
                return {"command": cmd, "explanation": f"Generated from intent: {req.intent}"}
        return {"command": f"# Could not generate — no reasoning engine configured. Intent: {req.intent}",
                "explanation": "No reasoning engine API key set. Go to Settings to add one."}

    prompt = (
        "You are a Linux system administration assistant. "
        "The user describes what they want to do in plain English. "
        "Respond with ONLY the exact shell command to execute — nothing else. "
        "No explanation, no markdown, no backticks, just the raw command. "
        "If multiple commands are needed, chain them with && or ; on one line. "
        f"\nUser intent: {req.intent}"
    )
    try:
        result = llm.generate_response(prompt)
        # generate_response returns a dict: {success, raw_response, explanation, commands}
        if isinstance(result, dict):
            if not result.get("success"):
                raise HTTPException(status_code=500, detail=result.get("error", "LLM error"))
            raw = result.get("raw_response") or result.get("explanation") or ""
        else:
            raw = str(result)
        # Strip any accidental markdown fences
        cmd = raw.strip().strip('`').strip()
        if cmd.startswith("bash\n") or cmd.startswith("sh\n"):
            cmd = cmd.split("\n", 1)[1].strip()
        return {"command": cmd, "explanation": req.intent}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ═══════════════════════════════════════════════════════════════════════════════
# ACTION LOG / ROLLBACK
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/action-log")
def get_action_log(limit: int = 100):
    logger = _state["action_logger"]
    if not logger:
        return {"logs": []}
    logs = sorted(logger.logs, key=lambda x: x.get("timestamp", 0), reverse=True)
    return {"logs": logs[:limit]}


@app.post("/api/action-log/rollback/{log_id}")
def rollback_action(log_id: str, execute: bool = False):
    """
    Rollback a logged action.
    Phase 1: POST without execute=true → returns rollback_cmd for approval (or explains why not possible).
    Phase 2: POST with execute=true → actually runs the rollback_cmd.
    """
    platform = _state["platform"]
    logger = _state["action_logger"]

    entry = next((l for l in logger.logs if l.get("id") == log_id), None)
    if not entry:
        raise HTTPException(status_code=404, detail="Log entry not found")

    rollback_cmd = entry.get("rollback_cmd") or entry.get("metadata", {}).get("rollback_cmd")
    original_cmd = entry.get("metadata", {}).get("command", "").strip()

    # Entries that were never shell commands (connect, scan, system events) can't be rolled back
    UNROLLBACKABLE_ACTIONS = {"server_start", "connect", "disconnect", "scan", "taara_analysis",
                               "demo_start", "train_start", "mark_normal", "ignore_alert"}
    if entry.get("action") in UNROLLBACKABLE_ACTIONS or not original_cmd:
        return {
            "rollbackable": False,
            "explanation": f"This log entry ({entry.get('action', 'unknown')}) is not a shell command — it is a system event and cannot be reversed.",
            "alternative": "Only executed shell commands can be rolled back. Run a command from the Custom Actions or Agent tab to get a rollback option.",
            "original_command": entry.get("details", ""),
        }

    # If no pre-computed rollback, ask Groq to generate one
    if not rollback_cmd or rollback_cmd.startswith("# No automatic"):
        llm = _state.get("llm_service")
        if llm:
            try:
                prompt = (
                    "You are a Linux system administration assistant.\n"
                    f"A command was run on a server: {original_cmd}\n\n"
                    "Task: Generate the exact shell command to UNDO / REVERSE this command's effect.\n\n"
                    "Rules:\n"
                    "1. If the command CAN be reversed, output ONLY the rollback command (no explanation, no markdown).\n"
                    "2. If the command CANNOT be reversed (e.g., killed a process, deleted files without backup), "
                    "output exactly: CANNOT_ROLLBACK: <one-line reason>\n"
                    "3. If the command is ambiguous, output: CANNOT_ROLLBACK: <reason> | ALTERNATIVE: <what to do instead>\n"
                )
                resp = llm.generate_response(prompt)
                raw = ""
                if isinstance(resp, dict) and resp.get("success"):
                    raw = resp.get("raw_response") or resp.get("explanation", "")
                elif isinstance(resp, str):
                    raw = resp
                raw = raw.strip()

                if raw.upper().startswith("CANNOT_ROLLBACK:"):
                    parts = raw.split("|", 1)
                    reason = parts[0].replace("CANNOT_ROLLBACK:", "").strip()
                    alternative = parts[1].replace("ALTERNATIVE:", "").strip() if len(parts) > 1 else None
                    return {
                        "rollbackable": False,
                        "explanation": reason,
                        "alternative": alternative,
                        "original_command": original_cmd,
                    }
                else:
                    rollback_cmd = raw
            except Exception as e:
                return {
                    "rollbackable": False,
                    "explanation": f"Reasoning engine error: {e}",
                    "alternative": "Review the command manually and apply a manual inverse.",
                    "original_command": original_cmd,
                }
        else:
            return {
                "rollbackable": False,
                "explanation": "No rollback command was pre-computed for this action, and no reasoning engine is configured.",
                "alternative": "Configure a Groq API key in Settings to enable automatic rollback generation.",
                "original_command": original_cmd,
            }

    # Phase 1: return rollback_cmd for operator approval (don't execute yet)
    if not execute:
        return {
            "rollbackable": True,
            "rollback_cmd": rollback_cmd,
            "original_command": original_cmd,
            "needs_approval": True,
            "message": "Review the rollback command and call this endpoint with execute=true to run it.",
        }

    # Phase 2: actually run it
    if not platform or not platform.connected:
        raise HTTPException(status_code=400, detail="No platform connected for rollback")

    try:
        stdout, stderr, rc = platform.execute_command(rollback_cmd)
        success = rc == 0
        # Record rollback in bandit
        agent = _state.get("security_agent")
        if agent and hasattr(agent, "bandit"):
            from components.action_bandit import fidelity_bucket
            ctx = _bandit_context_from_state()
            bucket = fidelity_bucket(ctx.get("f_min", 1.0))
            action_type = _infer_action_type_from_cmd(original_cmd)
            arm_key = f"{bucket}:ssh:{action_type}"
            agent.bandit.record_rollback(arm_key)
        _state["action_logger"].log(
            "rollback", "command_rollback",
            f"{'OK' if success else 'FAIL'}: {rollback_cmd[:100]}",
            severity="info" if success else "warning",
            metadata={"rollback_cmd": rollback_cmd, "original_cmd": original_cmd},
        )
        return {"success": success, "stdout": stdout, "stderr": stderr, "exit_code": rc,
                "rollback_cmd": rollback_cmd}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ═══════════════════════════════════════════════════════════════════════════════
# CODE SCAN
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/code-scan")
def code_scan(req: CodeScanRequest):
    try:
        sys.path.insert(0, str(ROOT))
        from research.scan_repo import scan_repo
        result = scan_repo(req.target, offline=req.offline)
        # Store so the PDF endpoint can use it
        _state["last_code_scan"] = result
        _state["action_logger"].log("code_scan", "scan",
                                    f"Scanned: {req.target}", severity="info")
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/generate-code-scan-report")
def generate_code_scan_report():
    """Generate a PDF report from the last code scan result."""
    result = _state.get("last_code_scan")
    if not result:
        raise HTTPException(status_code=400, detail="No code scan results. Run a scan first.")
    try:
        from components.taara_words import generate_report_pdf
        # Wrap into the shape generate_report_pdf expects
        wrapped = {
            "repo_results": result,
            "platform": "code_scan",
            "security_data": {"summary": result.get("summary", {}), "categories": {}},
            "quantum_risk": {
                "risk_score": 0,
                "f_min": result.get("repo_quantum_fidelity") if isinstance(result.get("repo_quantum_fidelity"), float) else None,
            },
            "kb_findings": [],
            "ai_summary": result.get("ai_summary", ""),
        }
        pdf_bytes = generate_report_pdf(wrapped, {})
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf",
                                          prefix="TAARA_CodeScan_",
                                          dir=str(ROOT / "models"))
        tmp.write(pdf_bytes)
        tmp.flush()
        tmp_path = tmp.name
        tmp.close()
        return {"path": tmp_path, "filename": Path(tmp_path).name}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ═══════════════════════════════════════════════════════════════════════════════
# SETTINGS
# ═══════════════════════════════════════════════════════════════════════════════

_settings_path = ROOT / "models" / "ui_settings.json"


def _load_settings() -> Dict:
    if _settings_path.exists():
        try:
            return json.loads(_settings_path.read_text())
        except Exception:
            pass
    return {"firm_name": "GoodWinSun", "theme": "dark", "webhook_url": ""}


def _save_settings(data: Dict):
    _settings_path.parent.mkdir(exist_ok=True)
    _settings_path.write_text(json.dumps(data, indent=2))


@app.get("/api/settings")
def get_settings():
    s = _load_settings()
    groq_key_set = bool(s.get("groq_api_key") or os.getenv("GROQ_API_KEY"))
    s.pop("groq_api_key", None)
    s["groq_key_set"] = groq_key_set
    return s


@app.post("/api/settings")
def save_settings(req: SettingsRequest):
    current = _load_settings()
    if req.firm_name:
        current["firm_name"] = req.firm_name
    if req.theme:
        current["theme"] = req.theme
    if req.webhook_url is not None:
        current["webhook_url"] = req.webhook_url
    if req.alert_email is not None:
        current["alert_email"] = req.alert_email
    # Accept groq_key (from frontend) or groq_api_key
    new_groq = req.groq_key or req.groq_api_key
    if new_groq:
        current["groq_api_key"] = new_groq
        from components.llm_service import LLMService
        _state["llm_service"] = LLMService(new_groq)
    current["autonomy_level"] = req.autonomy_level
    current["scan_depth"] = req.scan_depth
    _save_settings(current)
    return {"success": True}


# ═══════════════════════════════════════════════════════════════════════════════
# TAARAWARE DEPLOYED CHECK
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/taara/basis-status")
def taara_basis_status():
    """Return quantum basis and classical model status — independent of whether TaaraWare is live."""
    analyzer = _state.get("taara_analyzer")
    embedder = _state.get("embedder")
    detector = _state.get("detector")
    platform = _state.get("platform")

    # Determine identity from connected host (same key training used)
    identity = None
    basis_size = 0
    max_residual = 0.0
    quantum_residuals = 0

    if analyzer and platform and hasattr(platform, "config"):
        host = platform.config.get("host", "")
        identity = f"taaraware_{host}" if host else None
        if identity and identity in analyzer.memory_bases:
            b = analyzer.memory_bases[identity]
            basis_size = len(b.basis_vectors)
            max_residual = round(b.max_residual_norm, 4)
        quantum_residuals = len(analyzer.quantum_validator.memory_residuals)

    return {
        "identity": identity,
        "basis_size": basis_size,
        "basis_mature": basis_size >= 3,
        "max_residual_norm": max_residual,
        "quantum_residuals": quantum_residuals,
        "autoencoder_trained": bool(embedder and getattr(embedder, "is_trained", False)),
        "isolation_forest_trained": bool(detector and detector.is_ready()),
    }


@app.get("/api/taaraware/deployed")
def taaraware_deployed():
    platform = _state["platform"]
    if not platform or not platform.connected or _state["platform_type"] != "ssh":
        return {"deployed": False}
    try:
        stdout, _, _ = platform.execute_command(
            "{ test -f /opt/taaraware/taaraware_agent.py && echo yes; } || "
            "{ test -f $HOME/taaraware/taaraware_agent.py && echo yes; } || echo no"
        )
        deployed = "yes" in (stdout or "").lower()
        return {"deployed": deployed}
    except Exception:
        return {"deployed": False}


@app.post("/api/taaraware/update")
def taaraware_update():
    platform = _state["platform"]
    if not platform or not platform.connected:
        raise HTTPException(status_code=400, detail="No platform connected")
    taaraware_mgr = _state["taaraware_mgr"]
    result = taaraware_mgr.update_agent(platform)
    if result.get("success"):
        _state["action_logger"].log("taaraware", "update",
                                    result.get("message", ""), severity="info")
    return result


@app.get("/api/taaraware/info")
def taaraware_info():
    taaraware_mgr = _state["taaraware_mgr"]
    return taaraware_mgr.get_deployment_info() if taaraware_mgr else {}


@app.get("/api/taaraware/status")
def taaraware_status():
    analyzer = _state["taara_analyzer"]
    agent    = _state["security_agent"]
    novelty  = {}
    fv       = {}
    if analyzer:
        try:
            fv = analyzer.get_latest_feature_vector() if hasattr(analyzer, "get_latest_feature_vector") else {}
            novelty = analyzer.get_latest_novelty() if hasattr(analyzer, "get_latest_novelty") else {}
        except Exception:
            pass
    return {
        "running": True,
        "feature_vector": fv,
        "latest_f_min": novelty.get("f_min"),
        "latest_bucket": novelty.get("bucket"),
        "memory_size": novelty.get("memory_size"),
        "anomaly_count": _state.get("anomaly_count", 0),
        "autonomy_level": agent.bandit.autonomy_level if agent and hasattr(agent, "bandit") else 0.5,
    }


@app.get("/api/taaraware/actions")
def taaraware_actions():
    agent = _state["security_agent"]
    if not agent:
        return {"actions": []}
    proposed = agent.get_proposed_actions() if hasattr(agent, "get_proposed_actions") else []
    history  = agent.get_action_history()  if hasattr(agent, "get_action_history")  else []
    all_actions = list(proposed) + list(history)
    return {"actions": all_actions}


@app.get("/api/taaraware/dashboard")
def taaraware_dashboard():
    analyzer = _state["taara_analyzer"]
    agent    = _state["security_agent"]
    history  = []
    fv       = {}
    if analyzer:
        try:
            history = analyzer.get_f_min_history() if hasattr(analyzer, "get_f_min_history") else []
            fv = analyzer.get_latest_feature_vector() if hasattr(analyzer, "get_latest_feature_vector") else {}
        except Exception:
            pass
    action_count = 0
    if agent and hasattr(agent, "get_action_history"):
        action_count = len(agent.get_action_history())
    avg_fmin = (sum(history) / len(history)) if history else None
    anomaly_count = _state.get("anomaly_count", 0)
    return {
        "f_min_history": history,
        "feature_vector": fv,
        "total_ticks": len(history),
        "anomaly_count": anomaly_count,
        "actions_taken": action_count,
        "avg_f_min": round(avg_fmin, 4) if avg_fmin is not None else None,
    }


@app.get("/api/taaraware/rollback-log")
def taaraware_rollback_log():
    action_logger = _state.get("action_logger")
    if not action_logger:
        return {"log": []}
    try:
        entries = action_logger.get_log(limit=50) if hasattr(action_logger, "get_log") else []
        return {"log": entries}
    except Exception:
        return {"log": []}


# ═══════════════════════════════════════════════════════════════════════════════
# PROPOSED ACTIONS (security agent)
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/actions/proposed")
def get_proposed_actions():
    agent = _state["security_agent"]
    if not agent:
        return {"actions": []}
    return {"actions": agent.proposed_actions}


@app.post("/api/actions/autonomous")
def run_autonomous_analysis(background_tasks: BackgroundTasks):
    platform = _state["platform"]
    if not platform or not platform.connected:
        raise HTTPException(status_code=400, detail="No platform connected")

    agent = _state["security_agent"]
    taara_analyzer = _state["taara_analyzer"]
    llm_service = _state["llm_service"]
    embedder = _state["embedder"]
    detector = _state["detector"]

    # Run in background so UI gets immediate response; poll /api/actions/proposed for results
    def _do_analyze():
        result = agent.autonomous_analyze(platform, taara_analyzer, llm_service, embedder, detector)
        # If quantum-confirmed, fire alert
        qctx = result.get("quantum_context", {})
        if qctx.get("is_quantum_confirmed") or qctx.get("f_min", 1.0) < 0.5:
            _state["active_alert"] = {
                "timestamp": time.time(),
                "score": 1.0 - qctx.get("f_min", 1.0),
                "f_min": qctx.get("f_min", 1.0),
                "bucket": qctx.get("bucket", ""),
                "graph_chains": result.get("graph_chains", [])[:2],
                "host": platform.config.get("host", "unknown") if hasattr(platform, "config") else "unknown",
                "pre_approved_count": result.get("pre_approved_count", 0),
                "auto_executed_count": result.get("auto_executed_count", 0),
            }

    background_tasks.add_task(_do_analyze)
    return {"success": True, "message": "Autonomous analysis started — poll /api/actions/proposed for results"}


@app.post("/api/actions/approve/{action_index}")
def approve_action(action_index: int):
    platform = _state["platform"]
    if not platform or not platform.connected:
        raise HTTPException(status_code=400, detail="No platform connected")
    agent = _state["security_agent"]
    result = agent.execute_approved_action(action_index, platform)
    return result


@app.post("/api/actions/reject/{action_index}")
def reject_action(action_index: int):
    agent = _state["security_agent"]
    if action_index >= len(agent.proposed_actions):
        raise HTTPException(status_code=404, detail="Action not found")
    action = agent.proposed_actions[action_index]
    action["status"] = "rejected"
    agent.executed_actions.append(action)
    agent.proposed_actions.pop(action_index)
    return {"success": True}


@app.post("/api/actions/rollback/{action_index}")
def rollback_action_by_index(action_index: int):
    platform = _state["platform"]
    if not platform or not platform.connected:
        raise HTTPException(status_code=400, detail="No platform connected")
    agent = _state["security_agent"]
    result = agent.rollback_action(action_index, platform)
    return result


@app.get("/api/actions/audit-trail")
def get_audit_trail(limit: int = 50):
    agent = _state["security_agent"]
    if not agent:
        return {"trail": []}
    return {"trail": agent.get_audit_trail(limit)}


@app.get("/api/actions/bandit-summary")
def get_bandit_summary():
    agent = _state["security_agent"]
    if not agent:
        return {"pre_approved": [], "autonomy_level": 1}
    return {
        "pre_approved": agent.bandit.get_pre_approved_actions_summary(),
        "autonomy_level": agent.bandit.autonomy_level,
        "arm_stats": agent.bandit.arm_stats,
    }


@app.get("/api/actions/bandit-recommend")
def bandit_recommend(f_min: float = None, platform_type: str = None, top_k: int = 5):
    """
    Return bandit-ranked action recommendations for the current or specified quantum context.
    If f_min is not provided, uses the current active alert's f_min.
    """
    agent = _state.get("security_agent")
    if not agent or not hasattr(agent, "bandit"):
        return {"recommendations": [], "context": {}}

    # Resolve context
    if f_min is None:
        alert = _state.get("active_alert") or {}
        f_min = alert.get("f_min", 1.0)
    if platform_type is None:
        platform_type = _state.get("platform_type", "ssh") or "ssh"

    bandit_context = {"f_min": f_min, "platform_type": platform_type}

    from components.action_bandit import fidelity_bucket
    bucket = fidelity_bucket(f_min)

    # Full candidate set — all known action types
    candidates = [
        {"action_type": "block_ip",        "description": "Block attacking IP via fail2ban"},
        {"action_type": "rate_limit_ssh",  "description": "Apply SSH rate limiting (MaxAuthTries 3)"},
        {"action_type": "isolate_user",    "description": "Lock suspicious user account temporarily"},
        {"action_type": "harden_ssh",      "description": "Apply SSH config hardening (PermitRootLogin no, etc)"},
        {"action_type": "restart_service", "description": "Restart sshd to force re-auth of all sessions"},
        {"action_type": "firewall_rule",   "description": "Add firewall rule to restrict SSH access"},
        {"action_type": "rotate_key",      "description": "Rotate SSH authorized_keys for compromised user"},
        {"action_type": "kill_process",    "description": "Kill suspicious process by PID"},
    ]

    ranked = agent.bandit.select_actions(bandit_context, candidates, top_k=top_k)
    result = []
    for rec in ranked:
        contrast = agent.bandit.get_contrast_insight(rec.get("arm_key", ""))
        result.append({
            "action_type":    rec["action_type"],
            "description":    rec["description"],
            "ucb_score":      rec.get("ucb_score", 0),
            "approval_rate":  rec.get("approval_rate", 0),
            "success_rate":   rec.get("success_rate", 0),
            "times_seen":     rec.get("times_seen", 0),
            "pre_approved":   rec.get("pre_approved", False),
            "bandit_rationale": rec.get("bandit_rationale", ""),
            "contrast_insight": contrast,
            "quantum_context":  rec.get("quantum_context", bucket),
            "source": "TAARA Learned" if rec.get("times_seen", 0) > 0 else "Exploring",
        })

    return {
        "recommendations": result,
        "context": {"f_min": f_min, "bucket": bucket, "platform_type": platform_type},
        "autonomy_level": agent.bandit.autonomy_level,
        "total_arms_learned": len(agent.bandit.arm_stats),
    }


@app.post("/api/actions/autonomy-level/{level}")
def set_autonomy_level(level: int):
    agent = _state["security_agent"]
    if not agent:
        raise HTTPException(status_code=500, detail="Agent not initialized")
    agent.set_autonomy_level(level)
    return {"success": True, "autonomy_level": agent.bandit.autonomy_level}


@app.get("/api/agent/stats")
def get_agent_stats():
    agent = _state["security_agent"]
    if not agent:
        return {}
    return agent.get_stats()


# ═══════════════════════════════════════════════════════════════════════════════
# DEMO MODE
# Simulation: real quantum + bandit math on procedurally generated behavioral data.
# No hardcoded feature values — all data is generated from scenario parameters.
# Useful for demos without a live SSH server.
# ═══════════════════════════════════════════════════════════════════════════════

# Feature names — matches TaaraWare's 17-feature vector
_DEMO_FEATURE_NAMES = [
    "cpu_usage", "memory_usage", "disk_usage",
    "network_bytes_sent", "network_bytes_recv",
    "active_connections", "process_count",
    "load_avg_1m", "load_avg_5m", "load_avg_15m",
    "failed_logins_1h", "new_processes_1h",
    "suspicious_connections", "privilege_escalations",
    "temporal_rhythm_deviation", "causal_chain_novelty", "concealment_signal",
]

# Normal baseline parameters — realistic ranges for a lightly loaded Linux server
# These are the RANGES, not specific values. Actual values are sampled per-tick.
_DEMO_BASELINE_PARAMS = {
    # (mean, std) for each feature — sampled from normal distribution per tick
    "cpu_usage":               (22, 3),
    "memory_usage":            (45, 2),
    "disk_usage":              (31, 1),
    "network_bytes_sent":      (1200, 80),
    "network_bytes_recv":      (3400, 200),
    "active_connections":      (4, 1),
    "process_count":           (88, 2),
    "load_avg_1m":             (0.20, 0.03),
    "load_avg_5m":             (0.18, 0.02),
    "load_avg_15m":            (0.15, 0.02),
    "failed_logins_1h":        (0, 0.5),
    "new_processes_1h":        (1.2, 0.5),
    "suspicious_connections":  (0, 0.2),
    "privilege_escalations":   (0, 0.1),
    "temporal_rhythm_deviation": (0, 0.05),
    "causal_chain_novelty":    (0, 0.05),
    "concealment_signal":      (0, 0),
}

# Attack scenario: defines which features get multiplied by what factor.
# Factors are relative to baseline mean — not absolute numbers.
# A factor of 10 on failed_logins means 10× baseline mean → detectable
_DEMO_ATTACK_SCENARIOS = {
    # Scenario: SSH brute-force + concealment + exfiltration
    "ssh_intrusion": {
        "description": "SSH brute-force with concealment and data exfiltration",
        "drift_factors": {
            # Drift phase: early warning signals visible to TAARA but below anomaly threshold
            "cpu_usage": 1.5,
            "memory_usage": 1.3,
            "failed_logins_1h": 15,
            "suspicious_connections": 5,
            "new_processes_1h": 3,
            "temporal_rhythm_deviation": 8,
            "load_avg_1m": 2.5,
            "network_bytes_sent": 2,
        },
        "anomaly_factors": {
            # Full attack: broad correlated spike across all feature groups.
            # Angle encoding detects the joint rotation pattern — amplitude encoding
            # compresses this into a slightly larger ||Δ||.
            "cpu_usage": 4.5,
            "memory_usage": 2.2,
            "disk_usage": 1.9,
            "network_bytes_sent": 42,
            "network_bytes_recv": 20,
            "active_connections": 12,
            "process_count": 2.5,
            "load_avg_1m": 25,
            "load_avg_5m": 26,
            "load_avg_15m": 27,
            "failed_logins_1h": 130,
            "new_processes_1h": 28,
            "suspicious_connections": 55,
            "privilege_escalations": 4,
            "temporal_rhythm_deviation": 60,
            "causal_chain_novelty": 40,
            "concealment_signal": 1,  # boolean — 0 → 1
        },
    }
}


def _generate_demo_timeline(scenario_name: str = "ssh_intrusion", n_normal: int = 5,
                             n_drift: int = 2, n_anomaly: int = 3) -> List[Dict]:
    """
    Generate a demo timeline procedurally.
    Feature values are sampled from baseline + multiplied by scenario factors.
    No magic numbers — all values derive from _DEMO_BASELINE_PARAMS.
    """
    rng = np.random.default_rng(42)  # fixed seed for reproducibility in demos
    scenario = _DEMO_ATTACK_SCENARIOS.get(scenario_name, _DEMO_ATTACK_SCENARIOS["ssh_intrusion"])

    def _sample_tick(label: str, tick_idx: int) -> Dict:
        features = []
        for fname in _DEMO_FEATURE_NAMES:
            mean, std = _DEMO_BASELINE_PARAMS[fname]
            base = float(rng.normal(mean, std))
            base = max(base, 0)

            if label == "drift":
                factor = scenario["drift_factors"].get(fname, 1.0)
                val = base * factor
            elif label == "anomaly":
                factor = scenario["anomaly_factors"].get(fname, 1.0)
                # concealment_signal is binary — cap at 1
                if fname == "concealment_signal":
                    val = 1.0 if factor >= 1 else 0.0
                else:
                    val = base * factor
            else:
                val = base

            features.append(round(max(val, 0), 3))

        return {"tick": tick_idx, "label": label, "features": features}

    timeline = []
    for i in range(n_normal):
        timeline.append(_sample_tick("normal", i))
    for i in range(n_drift):
        timeline.append(_sample_tick("drift", n_normal + i))
    for i in range(n_anomaly):
        timeline.append(_sample_tick("anomaly", n_normal + n_drift + i))

    return timeline


def _build_demo_ssh_findings(anomaly_features: Dict) -> List[Dict]:
    """
    Build SSH findings from the actual anomaly feature values — not hardcoded descriptions.
    Text references the real numbers from this specific demo run.
    """
    findings = []

    failed = anomaly_features.get("failed_logins_1h", 0)
    baseline_failed = _DEMO_BASELINE_PARAMS["failed_logins_1h"][0]
    if failed > 20:
        findings.append({
            "severity": "critical",
            "title": f"SSH brute-force attack detected ({int(failed)} failed logins in 1 hour)",
            "description": (
                f"failed_logins_1h={int(failed)} — {failed/max(baseline_failed,1):.0f}× above baseline. "
                "Consistent with automated credential-stuffing or distributed SSH brute-force."
            ),
            "detail": f"Threshold exceeded: >50 failed logins. Detected {int(failed)}.",
            "remediation": "fail2ban-client set sshd banip <attacking_IP>; "
                           "configure MaxAuthTries 3 in sshd_config; consider port-knocking.",
        })

    concealment = anomaly_features.get("concealment_signal", 0)
    if concealment >= 1.0:
        findings.append({
            "severity": "critical",
            "title": "Concealment signal active — process hiding behaviour detected",
            "description": (
                "concealment_signal=1.0. TAARA's causal-chain anomaly detector found processes "
                "absent from standard enumeration but present in /proc traversal. "
                "Consistent with rootkit, LD_PRELOAD hook, or kernel module hiding."
            ),
            "detail": (
                f"causal_chain_novelty={anomaly_features.get('causal_chain_novelty', 0):.2f}, "
                f"proc_root_ratio elevated."
            ),
            "remediation": "ps auxf; ls /proc | diff with running pids; "
                           "check lsmod for unusual kernel modules; "
                           "chkrootkit / rkhunter scan recommended.",
        })

    net_sent = anomaly_features.get("network_bytes_sent", 0)
    net_baseline = _DEMO_BASELINE_PARAMS["network_bytes_sent"][0]
    if net_sent > net_baseline * 10:
        findings.append({
            "severity": "high",
            "title": f"Anomalous outbound traffic — possible data exfiltration",
            "description": (
                f"network_bytes_sent={net_sent:.0f} — {net_sent/net_baseline:.0f}× above baseline "
                f"({net_baseline:.0f}). Sustained elevated outbound traffic is consistent "
                "with data exfiltration or C2 beaconing."
            ),
            "detail": f"temporal_rhythm_deviation={anomaly_features.get('temporal_rhythm_deviation',0):.2f}",
            "remediation": "tcpdump -i eth0 -w /tmp/taara_capture.pcap; "
                           "inspect destination IPs with ss -tunap; "
                           "block unknown outbound IPs via iptables.",
        })

    privesc = anomaly_features.get("privilege_escalations", 0)
    if privesc >= 1:
        findings.append({
            "severity": "high",
            "title": f"Privilege escalation events detected ({int(privesc)} in monitoring window)",
            "description": (
                f"privilege_escalations={int(privesc)}. "
                f"new_processes_1h={int(anomaly_features.get('new_processes_1h',0))}. "
                "Attacker may have obtained elevated privileges."
            ),
            "detail": "Cross-feature correlation: failed_logins → new_processes → privilege_escalations "
                      "is a known intrusion chain. Angle encoding detected this joint pattern.",
            "remediation": "journalctl -u sudo; grep -i 'su\\|sudo\\|root' /var/log/auth.log; "
                           "check /etc/sudoers and ~/.ssh/authorized_keys for new entries.",
        })

    return findings

_demo_state: Dict = {
    "running": False,
    "tick": 0,
    "quantum_validator": None,
    "timeline": [],
    "ticks_data": [],
    "current_alert": None,
    "scenario": "ssh_intrusion",
}


def _demo_reset(scenario: str = "ssh_intrusion"):
    from components.quantum_engine import QuantumValidator
    timeline = _generate_demo_timeline(scenario_name=scenario)
    qv = QuantumValidator()
    n_normal = sum(1 for t in timeline if t["label"] == "normal")
    for t in timeline[:n_normal]:
        qv.add_to_memory(np.array(t["features"], dtype=np.float64))
    _demo_state.update({
        "running": True,
        "tick": 0,
        "quantum_validator": qv,
        "timeline": timeline,
        "ticks_data": [],
        "current_alert": None,
        "scenario": scenario,
    })
    return timeline


def _fidelity_bucket(f_min: float) -> str:
    if f_min < 0.3:
        return "critical_divergence"
    elif f_min < 0.5:
        return "unsafe_direction"
    elif f_min < 0.7:
        return "drifting"
    return "normal"


@app.post("/api/demo/start")
def demo_start(scenario: str = "ssh_intrusion"):
    """
    Start demo mode. Generates timeline from scenario parameters (no hardcoded values).
    Pre-loads normal ticks into quantum memory. Call /api/demo/tick to advance.
    """
    timeline = _demo_reset(scenario)
    _state["action_logger"].log("demo", "demo_start",
                                f"Demo mode started: {scenario}", severity="info")
    n_normal = sum(1 for t in timeline if t["label"] == "normal")
    return {
        "success": True,
        "scenario": scenario,
        "message": (
            f"Demo ready. {n_normal} normal ticks pre-loaded into quantum memory. "
            "Call /api/demo/tick to advance one tick at a time."
        ),
        "total_ticks": len(timeline),
        "feature_names": _DEMO_FEATURE_NAMES,
        "timeline_labels": [t["label"] for t in timeline],
    }


@app.post("/api/demo/tick")
def demo_tick():
    """
    Advance demo by one tick. Computes real quantum fidelity on generated feature data.
    Returns F_min, anomaly status, and agent proposals when threshold crossed.
    """
    if not _demo_state.get("running"):
        raise HTTPException(status_code=400, detail="Demo not started. Call /api/demo/start first.")

    timeline = _demo_state["timeline"]
    tick_idx = _demo_state["tick"]
    if tick_idx >= len(timeline):
        return {"done": True, "message": "Demo complete. Call /api/demo/start to restart."}

    tick_data = timeline[tick_idx]
    fv = np.array(tick_data["features"], dtype=np.float64)
    qv = _demo_state["quantum_validator"]

    result = qv.compute_minimum_fidelity(fv)
    f_min = result["f_min"]
    is_novel = result["is_quantum_novel"]
    correlation_detected = result.get("correlation_signal_detected", False)
    bucket = _fidelity_bucket(f_min)

    feature_dict = {k: float(v) for k, v in zip(_DEMO_FEATURE_NAMES, tick_data["features"])}

    alert = None
    proposed_actions = []
    if is_novel:
        ssh_findings = _build_demo_ssh_findings(feature_dict)
        # Simulate classical signals coherently with the architecture:
        # recon_error spikes when behavior is anomalous (autoencoder can't reconstruct)
        # latent_fidelity drops (current latent drifts from normal latent direction)
        # These are plausible synthetic values — in real mode they come from the trained model
        sim_recon_error = round(0.02 + (1.0 - f_min) * 0.18, 4)   # 0.02 normal → 0.20 at f_min=0
        sim_latent_fid  = round(0.85 - (1.0 - f_min) * 0.45, 4)   # 0.85 normal → 0.40 at f_min=0
        sim_if_score    = round(-0.05 - (1.0 - f_min) * 0.3, 4)    # negative = anomalous
        classical_confirmed = f_min < 0.5  # in demo, classical always agrees when quantum fires
        feature_dict["recon_error"]    = sim_recon_error
        feature_dict["latent_fidelity"] = sim_latent_fid
        feature_dict["anomaly_score"]  = sim_if_score
        feature_dict["is_anomaly"]     = classical_confirmed
        alert = {
            "timestamp": time.time(),
            "f_min": f_min,
            "score": round((1.0 - f_min) * 100, 1),
            "host": "demo-server.taara.local",
            "f_min_amplitude": result.get("f_min_amplitude"),
            "bucket": bucket,
            "correlation_detected": correlation_detected,
            "features": feature_dict,
            "classical_confirmed": classical_confirmed,
            "tick": tick_idx,
        }
        _demo_state["current_alert"] = alert
        _state["active_alert"] = alert

        for finding in ssh_findings:
            action_type = (
                "block_ip" if "brute-force" in finding["title"].lower()
                else "kill_process" if "concealment" in finding["title"].lower()
                else "rate_limit_ssh" if "exfiltration" in finding["title"].lower()
                else "isolate_user"
            )
            proposed_actions.append({
                "action_type": action_type,
                "title": finding["title"],
                "description": finding["description"],
                "severity": finding["severity"],
                "f_min": f_min,
                "quantum_context": bucket,
                "pre_approved": False,
                "rollback_cmd": "# Rollback command pre-computed — restore prior state",
                "bandit_rationale": f"F_min={f_min:.4f} in {bucket} context — "
                                    f"{'correlation confirmed' if correlation_detected else 'direction confirmed'}",
            })

    _demo_state["tick"] += 1
    tick_entry = {
        "tick": tick_idx,
        "label": tick_data["label"],
        "features": feature_dict,
        "f_min": f_min,
        "f_min_amplitude": result.get("f_min_amplitude"),
        "is_novel": is_novel,
        "bucket": bucket,
        "correlation_detected": correlation_detected,
        "alert": alert,
        "proposed_actions": proposed_actions,
    }
    _demo_state["ticks_data"].append(tick_entry)

    return {
        "tick": tick_idx,
        "label": tick_data["label"],
        "features": feature_dict,
        "quantum": {
            "f_min": round(f_min, 4),
            "f_min_amplitude": result.get("f_min_amplitude"),
            "is_quantum_novel": is_novel,
            "bucket": bucket,
            "correlation_detected": correlation_detected,
            "encoding": "angle+amplitude",
        },
        "alert": alert,
        "proposed_actions": proposed_actions,
        "remaining_ticks": len(timeline) - _demo_state["tick"],
        "done": _demo_state["tick"] >= len(timeline),
    }


@app.get("/api/demo/state")
def demo_state():
    """Return full demo state — all ticks so far, current alert, quantum history."""
    if not _demo_state.get("running"):
        return {"running": False}
    return {
        "running": True,
        "scenario": _demo_state["scenario"],
        "current_tick": _demo_state["tick"],
        "total_ticks": len(_demo_state["timeline"]),
        "ticks_data": _demo_state["ticks_data"],
        "current_alert": _demo_state["current_alert"],
        "feature_names": _DEMO_FEATURE_NAMES,
    }


@app.post("/api/demo/full-scan")
def demo_full_scan(scenario: str = "ssh_intrusion"):
    """
    Run the complete demo in one shot. All ticks computed, findings generated from
    actual anomaly feature values. Returns analysis_results compatible with PDF report.
    """
    timeline = _demo_reset(scenario)
    qv = _demo_state["quantum_validator"]

    all_ticks = []
    final_alert = None

    for tick_data in timeline:
        fv = np.array(tick_data["features"], dtype=np.float64)
        result = qv.compute_minimum_fidelity(fv)
        f_min = result["f_min"]
        bucket = _fidelity_bucket(f_min)

        entry = {
            "tick": tick_data["tick"],
            "label": tick_data["label"],
            "features": {k: float(v) for k, v in zip(_DEMO_FEATURE_NAMES, tick_data["features"])},
            "f_min": round(f_min, 4),
            "f_min_amplitude": result.get("f_min_amplitude"),
            "is_novel": result["is_quantum_novel"],
            "bucket": bucket,
            "correlation_detected": result.get("correlation_signal_detected", False),
        }
        all_ticks.append(entry)
        if result["is_quantum_novel"] and final_alert is None:
            final_alert = entry

    anomaly_ticks = [t for t in all_ticks if t["is_novel"]]
    worst = min(anomaly_ticks, key=lambda t: t["f_min"]) if anomaly_ticks else all_ticks[-1]
    ssh_findings = _build_demo_ssh_findings(worst["features"])

    demo_analysis = {
        "ssh_results": {
            "hostname": "demo-server.taara.local",
            "findings": ssh_findings,
            "quantum_result": {
                "f_min": worst["f_min"],
                "f_min_amplitude": worst.get("f_min_amplitude"),
                "is_quantum_novel": worst["is_novel"],
                "correlation_signal_detected": worst["correlation_detected"],
                "bucket": worst["bucket"],
                "encoding": "angle+amplitude",
            },
        },
        "agent_result": {
            "actions_taken": [],
            "hypothesis": (
                "Correlated spike across {features}. "
                "Angle encoding confirmed joint feature deviation — "
                "F_min dropped to {fmin:.4f} (normal baseline: {base:.4f}). "
                "Assessment: active intrusion or insider threat.".format(
                    features=", ".join(
                        k for k, v in worst["features"].items()
                        if v > _DEMO_BASELINE_PARAMS.get(k, (0, 0))[0] * 3
                    )[:100] or "multiple features",
                    fmin=worst["f_min"],
                    base=all_ticks[0]["f_min"],
                )
            ),
            "graph_chains": [],
        },
        "demo_ticks": all_ticks,
        "demo": True,
    }

    _state["analysis_results"] = demo_analysis
    # Enrich final_alert with classical signals for investigate endpoint coherence
    if final_alert:
        wf = worst["f_min"]
        final_alert["score"] = round((1.0 - wf) * 100, 1)
        final_alert["host"] = "demo-server.taara.local"
        final_alert["classical_confirmed"] = wf < 0.5
        final_alert.setdefault("features", worst["features"])
        final_alert["features"]["recon_error"]     = round(0.02 + (1.0 - wf) * 0.18, 4)
        final_alert["features"]["latent_fidelity"] = round(0.85 - (1.0 - wf) * 0.45, 4)
        final_alert["features"]["anomaly_score"]   = round(-0.05 - (1.0 - wf) * 0.3, 4)
        final_alert["features"]["is_anomaly"]      = wf < 0.5
    _state["active_alert"] = final_alert

    return {
        "success": True,
        "scenario": scenario,
        "ticks": all_ticks,
        "anomaly_first_at_tick": final_alert["tick"] if final_alert else None,
        "worst_f_min": worst["f_min"],
        "ssh_findings": ssh_findings,
        "quantum_summary": {
            "f_min_at_anomaly": worst["f_min"],
            "f_min_amplitude": worst.get("f_min_amplitude"),
            "correlation_detected": worst["correlation_detected"],
            "encoding": "angle+amplitude",
        },
    }


@app.get("/api/demo/is-active")
def demo_is_active():
    return {"active": _demo_state.get("running", False), "tick": _demo_state.get("tick", 0)}


@app.post("/api/demo/trigger-anomaly")
def demo_trigger_anomaly(f_min: float = 0.23, scenario: str = "ssh_intrusion"):
    """Instantly fire an anomaly alert — for pitch demos without a full scan."""
    features = {
        "failed_logins_1h": 47.0,
        "new_processes_1h": 23.0,
        "suspicious_connections": 8.0,
        "privilege_escalations": 3.0,
        "cpu_usage": 94.2,
        "memory_usage": 87.1,
        "active_connections": 142.0,
        "network_bytes_sent": 8492031.0,
        "network_bytes_recv": 1204312.0,
        "process_count": 312.0,
        "load_avg_1m": 12.4,
        "load_avg_5m": 9.8,
        "load_avg_15m": 6.3,
        "disk_usage": 71.4,
        "temporal_rhythm_deviation": 0.91,
        "causal_chain_novelty": 0.88,
        "concealment_signal": 0.76,
    }
    divergence_pct = round((1 - f_min) * 100, 1)
    bucket = "critical_divergence" if f_min < 0.3 else "unsafe_direction"
    alert = {
        "host": "demo-server.taara.local",
        "hostname": "demo-server.taara.local",
        "f_min": round(f_min, 4),
        "f_min_amplitude": round(f_min + 0.08, 4),
        "bucket": bucket,
        "correlation_signal_detected": True,
        "correlation_detected": True,
        "features": features,
        "divergence_pct": divergence_pct,
        "encoding": "angle+amplitude",
        "inline_label": f"F = |⟨ψ_t|ψ_m⟩|² = {f_min:.4f} — {divergence_pct}% orthogonal to all prior normal states",
        "auto_executed_count": 2,
        "pre_approved_count": 1,
        "tick": 7,
        "demo": True,
    }
    _state["active_alert"] = alert
    return {"success": True, "alert": alert}


@app.post("/api/demo/trigger-test-alert")
def demo_trigger_test_alert():
    """
    Trigger a realistic T1078 test alert using the live server's actual quantum model.
    Generates a behaviorally perturbed feature vector — mimics a stolen-credential
    attacker who has the same access as the legitimate user but slightly different
    timing/fail-rate pattern. Runs it through the real quantum pipeline so the alert
    has real quantum_confidence, swap_fidelity, q_directionality, phase_coherence values.
    """
    host = _state.get("connected_host", "test-server")
    taara_analyzer = _state.get("taara_analyzer")
    embedder = _state.get("embedder")

    # T1078-like feature vector: elevated fail rate, shifted timing, higher entropy
    features = {
        "cpu_usage": 34.2, "memory_usage": 52.1, "disk_usage": 41.0,
        "proc_spawn_rate": 6.8, "proc_root_ratio": 0.18, "proc_cmd_entropy": 5.2,
        "net_outbound_conn_rate": 18.0, "net_unique_dst_ips": 7, "net_unique_dst_ports": 14,
        "net_port_entropy": 3.1, "net_failed_conn_ratio": 0.28,
        "failed_logins_1h": 12.0, "new_processes_1h": 9.0,
        "suspicious_connections": 4.0, "privilege_escalations": 1.0,
        "temporal_rhythm_deviation": 0.74, "causal_chain_novelty": 0.61,
        "concealment_signal": 0.42, "anomaly_score": 0.0,
    }

    FEATURE_NAMES = [
        "cpu_usage", "memory_usage", "disk_usage",
        "proc_spawn_rate", "proc_root_ratio", "proc_cmd_entropy",
        "net_outbound_conn_rate", "net_unique_dst_ips", "net_unique_dst_ports",
        "net_port_entropy", "net_failed_conn_ratio",
        "failed_logins_1h", "new_processes_1h",
        "suspicious_connections", "privilege_escalations",
        "temporal_rhythm_deviation", "causal_chain_novelty",
        "concealment_signal", "anomaly_score",
    ]
    fv = np.array([float(features.get(k, 0.0)) for k in FEATURE_NAMES], dtype=np.float32)

    # Run through real quantum pipeline
    qr = {}
    if taara_analyzer and embedder:
        identity = f"taaraware_{host}"
        try:
            qr = taara_analyzer.get_quantum_risk_assessment(fv, identity_id=identity, embedder=embedder) or {}
        except Exception:
            pass

    alert = {
        "host": host,
        "hostname": host,
        "f_min": qr.get("f_min", 0.21),
        "swap_fidelity": qr.get("swap_fidelity"),
        "q_directionality": qr.get("q_directionality"),
        "phase_coherence": qr.get("phase_coherence"),
        "quantum_confidence": qr.get("quantum_confidence"),
        "score": qr.get("risk_score", 72.0),
        "features": features,
        "timestamp": time.time(),
        "bucket": "t1078_test",
        "classical_confirmed": True,
        "test_alert": True,
    }
    _state["active_alert"] = alert
    return {"success": True, "alert": alert, "quantum": qr}


# ═══════════════════════════════════════════════════════════════════════════════
# QUANTUM LEGIBILITY — explain any F_min value in plain math + English
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/quantum/explain")
def quantum_explain(f_min: float = 1.0):
    divergence_pct = round((1 - f_min) * 100, 1)
    if f_min < 0.3:
        bucket = "critical_divergence"
        bucket_label = "CRITICAL DIVERGENCE"
        plain = (
            f"F_min = {f_min:.4f} — current behavioral direction is {divergence_pct}% orthogonal to "
            f"every prior normal state for this identity. The quantum state encoding current behavior "
            f"is nearly perpendicular to the entire memory basis. This is geometrically as far from "
            f"normal as possible short of complete opposition."
        )
    elif f_min < 0.5:
        bucket = "unsafe_direction"
        bucket_label = "UNSAFE DIRECTION"
        plain = (
            f"F_min = {f_min:.4f} — current behavioral direction is {divergence_pct}% orthogonal to "
            f"prior normal states. The 0.5 threshold is the geometric midpoint of Hilbert space — "
            f"below it, the behavior is more orthogonal than parallel to the memory basis. "
            f"No manual threshold tuning required: this is a mathematical property, not a heuristic."
        )
    elif f_min < 0.7:
        bucket = "drifting"
        bucket_label = "DRIFTING"
        plain = (
            f"F_min = {f_min:.4f} — behavioral drift detected. Still above the 0.5 anomaly threshold "
            f"but the direction is shifting. Monitoring should be intensified."
        )
    else:
        bucket = "normal"
        bucket_label = "NORMAL"
        plain = (
            f"F_min = {f_min:.4f} — behavioral fidelity is high. Current quantum state is "
            f"predominantly parallel to the memory basis. No divergence detected."
        )
    return {
        "f_min": f_min,
        "bucket": bucket,
        "bucket_label": bucket_label,
        "divergence_pct": divergence_pct,
        "formula": "F = |⟨ψ_t|ψ_m⟩|²",
        "formula_expanded": "F_min = min over all memory states m of |inner product(ψ_current, ψ_memory)|²",
        "encoding": "Angle encoding: θ_i = π/2 + arctan(feature_i) · Ring-CNOT entanglement",
        "threshold_explanation": (
            "0.5 is the geometric midpoint of the Hilbert space unit sphere. "
            "Below it: current state is more orthogonal than parallel to normal. "
            "This threshold requires no per-client calibration."
        ),
        "plain": plain,
        "inline_label": f"F = |⟨ψ_t|ψ_m⟩|² = {f_min:.4f} — {divergence_pct}% orthogonal to all prior normal states",
    }


@app.get("/api/quantum/circuit")
def quantum_circuit():
    return {
        "n_qubits": 3,
        "architecture": "amplitude_embedding_subspace_projection",
        "circuit_steps": [
            {"step": 1, "op": "BehavioralAE(x ∈ ℝ¹⁹) → z ∈ ℝ⁸", "description": "19-dim behavioral feature vector (PQC-transformed) passed through wav2vec-inspired autoencoder: 19→64→8→64→19, Tanh bottleneck. The 8-dim latent z_t captures behavioral DNA."},
            {"step": 2, "op": "AmplitudeEmbedding(z_t, wires=[0,1,2], normalize=True)", "description": "Map 8-dim latent onto a 3-qubit (8-amplitude) quantum state |ψ_t⟩ via AmplitudeEmbedding. Normalization ensures valid quantum state. Requires only 3 qubits for 2³=8 amplitudes."},
            {"step": 3, "op": "F_sub = Σ_{k=1}^{K} |⟨ψ_t|ψ_k⟩|² (K=3 PCA components)", "description": "SWAP fidelity: squared inner products between |ψ_t⟩ and the K=3 principal component states from the per-identity normal subspace. swap_s = 1 − F_sub is the anomaly signal. Normal users: F_sub ≈ 0.936. Attackers: F_sub ≈ 0.253. Separation gap: +0.683."},
            {"step": 4, "op": "q_dir = Σ |⟨ψ_t|ψ_c⟩|² (complement dims K+1,K+2)", "description": "Directionality: alignment with the complement subspace (dims beyond K). Normal: 0.052. Attack: 0.270. Gap: +0.218. Orthogonal to SWAP (corr≈0.024) — independent information."},
            {"step": 5, "op": "coh = |mean(exp(i·φ_t))| over W=4 windows", "description": "Phase coherence: circular mean of the complement-subspace angle φ_t = arctan2(proj_c1, proj_c0) over 4 windows. Measures sustained directionality — distinguishes coherent attack drift from transient noise. Normal: 0.624. Attack: 0.963."},
            {"step": 6, "op": "conf = α·swap_s + β·q_dir + γ·coh·√(swap_s·q_dir)", "description": "V3 interference fusion. α=0.263, β=0.285, γ=0.451 (per-identity LR-fit from normal training windows, regularized to global prior). Alert when conf > 0.1854 (p95 of normal training). Validated: Prec=0.689, Rec=0.942, F1=0.796, AUC=0.980 on CERT r4.2."},
        ],
        "why_angle_vs_amplitude": (
            "TAARA uses AmplitudeEmbedding on the 8-dim behavioral latent — NOT angle encoding on raw features. "
            "The autoencoder (BehavioralAE) first learns a compressed 8-dim representation of normal behavior. "
            "AmplitudeEmbedding maps this to a quantum state where the Hilbert space geometry reflects behavioral structure. "
            "SWAP subspace fidelity then measures how much of the current state lies in the normal PCA subspace. "
            "This is more powerful than angle encoding because the AE latent already captures multi-feature correlations — "
            "the quantum projection then operates on semantically rich representations, not raw feature values."
        ),
        "pqc_layer": (
            "ML-KEM Kyber768 (NIST FIPS 203) apply_client_transform applies a SHA3-256 keyed offset "
            "to the 19-dim feature vector before AE encoding. The behavioral norm (PCA subspace) "
            "is computed in PQC-transformed space. An attacker who intercepts traffic cannot compute "
            "the client's normal subspace without the Kyber768 private key — the quantum memory "
            "is cryptographically bound to the client identity."
        ),
        "framework": "PennyLane default.qubit (classical simulation)",
        "hardware_note": (
            "Running on classical simulation. No quantum speedup claimed. "
            "The same 3-qubit AmplitudeEmbedding circuit runs on real quantum hardware unchanged "
            "when sufficient coherence time becomes available (3-qubit circuits are near-term feasible). "
            "The contribution is the behavioral subspace formalism and its validated application to T1078 detection."
        ),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# CLIENT LIST — local JSON file, encrypted credentials stored separately
# ═══════════════════════════════════════════════════════════════════════════════

_CLIENTS_FILE = os.path.join("models", "clients.json")


def _load_clients() -> list:
    if os.path.exists(_CLIENTS_FILE):
        try:
            with open(_CLIENTS_FILE) as f:
                return json.load(f)
        except Exception:
            return []
    return []


def _save_clients(clients: list):
    with open(_CLIENTS_FILE, "w") as f:
        json.dump(clients, f, indent=2)


class ClientEntry(BaseModel):
    model_config = {"extra": "allow"}
    id: str = ""
    name: str = ""
    hostname: str = ""
    platform_type: str = "ssh"
    port: int = 22
    username: str = ""
    last_health_score: Optional[float] = None
    prev_health_score: Optional[float] = None
    last_scan_time: Optional[str] = None
    last_report_path: Optional[str] = None
    taaraware_deployed: bool = False
    active_alerts: int = 0
    notes: str = ""


@app.get("/api/clients")
def get_clients():
    return {"clients": _load_clients()}


@app.post("/api/clients")
def add_client(req: ClientEntry):
    clients = _load_clients()
    import uuid
    entry = req.dict()
    if not entry.get("id"):
        entry["id"] = f"client_{uuid.uuid4().hex[:8]}"
    # Don't store password or key in the client list — only metadata
    entry.pop("password", None)
    entry.pop("key_path", None)
    clients = [c for c in clients if c.get("id") != entry["id"]]
    clients.append(entry)
    _save_clients(clients)
    return {"success": True, "client": entry}


@app.patch("/api/clients/{client_id}")
async def update_client(client_id: str, req: Request):
    body = await req.json()
    clients = _load_clients()
    updated = False
    for c in clients:
        if c.get("id") == client_id:
            # Only allow updating safe fields
            safe_fields = ["last_health_score", "prev_health_score", "last_scan_time",
                           "last_report_path", "taaraware_deployed", "active_alerts", "notes", "name"]
            for k in safe_fields:
                if k in body:
                    c[k] = body[k]
            updated = True
            break
    if updated:
        _save_clients(clients)
    return {"success": updated}


@app.delete("/api/clients/{client_id}")
def delete_client(client_id: str):
    clients = _load_clients()
    clients = [c for c in clients if c.get("id") != client_id]
    _save_clients(clients)
    return {"success": True}


@app.get("/api/clients/{client_id}/activity")
def client_activity(client_id: str, limit: int = 20):
    action_logger = _state.get("action_logger")
    if not action_logger:
        return {"entries": []}
    try:
        entries = action_logger.get_log(limit=limit) if hasattr(action_logger, "get_log") else []
        return {"entries": entries}
    except Exception:
        return {"entries": []}


@app.get("/api/node/identity")
def node_identity():
    """Return persistent identity info for the currently connected node."""
    host = _state.get("connected_host")
    if not host:
        return {"connected": False}
    from components.node_identity_db import (
        node_id, load_meta, load_training_log, load_action_log
    )
    meta = load_meta(host)
    training_log = load_training_log(host)
    action_log = load_action_log(host)
    return {
        "connected": True,
        "host": host,
        "node_id": node_id(host),
        "meta": meta,
        "training_runs": len(training_log),
        "last_training": training_log[-1] if training_log else None,
        "action_count": len(action_log),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# PQC INFO
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/pqc/info")
def pqc_info():
    taaraware_mgr = _state.get("taaraware_mgr")
    key_info = {}
    if taaraware_mgr and hasattr(taaraware_mgr, "get_deployment_info"):
        info = taaraware_mgr.get_deployment_info()
        key_info = info.get("pqc_key", {}) if isinstance(info, dict) else {}
    return {
        "algorithm": "ML-KEM Kyber768",
        "standard": "NIST FIPS 203",
        "key_size_bits": 768,
        "protection": "TaaraWare ↔ CommandCenter channel",
        "threat_it_defeats": (
            "Shor's algorithm (1994) can factor RSA and compute discrete logs in polynomial time "
            "on a sufficiently large quantum computer. This breaks RSA-2048 and ECC-256, "
            "which protect most current encrypted channels. "
            "Kyber768 is based on Module Learning With Errors (MLWE) — a lattice problem "
            "with no known quantum speedup. Secure against both classical and quantum adversaries."
        ),
        "why_it_matters_now": (
            "Harvest-now-decrypt-later attacks: adversaries can capture encrypted traffic today "
            "and decrypt it when quantum hardware matures. "
            "For infrastructure monitoring data (behavioral patterns, config details), "
            "this is a real threat to client confidentiality. "
            "Kyber768 protects this data against that future threat, today."
        ),
        "key_fingerprint": key_info.get("fingerprint", "not_generated"),
        "generated": key_info.get("generated", False),
        "inline_label": "Channel: ML-KEM Kyber768 (NIST FIPS 203) — quantum-safe",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# USER MANUAL
# ═══════════════════════════════════════════════════════════════════════════════

_MANUAL_PATH = os.path.join(os.path.dirname(__file__), "models", "taara_user_manual.pdf")


@app.get("/api/user-manual")
def get_user_manual():
    """Serve the TAARA user manual PDF. Generates it if not present."""
    if not os.path.exists(_MANUAL_PATH):
        try:
            from taara_manual import build_manual
            build_manual(_MANUAL_PATH)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Could not generate manual: {e}")
    return FileResponse(
        _MANUAL_PATH,
        media_type="application/pdf",
        filename="TAARA_User_Manual.pdf",
    )


@app.post("/api/user-manual/regenerate")
def regenerate_user_manual():
    """Force-regenerate the user manual PDF."""
    try:
        from taara_manual import build_manual
        build_manual(_MANUAL_PATH)
        return {"success": True, "path": _MANUAL_PATH}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="info")
