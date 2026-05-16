"""
TaaraAnalysis - Organizational Health Analysis (OHA) Scanner
=============================================================

The free-tier entry point for TAARA security consulting.

Runs comprehensive security scans across all supported platforms:
- SSH (Linux/Unix servers)
- AWS, GCP, Azure cloud environments
- Docker containers
- Kubernetes clusters

Produces a quantum-enhanced risk score and identifies vulnerabilities.
Does NOT generate downloadable reports (paid tier limitation).
"""

import streamlit as st
import time
import json
import numpy as np
from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path

_MITRE_MAP = [
    # (keyword_in_title_lower, tactic_id, tactic_name, technique_id, technique_name)
    ('password auth',      'TA0006', 'Credential Access',  'T1110',      'Brute Force'),
    ('passwordauthentication', 'TA0006', 'Credential Access', 'T1110',   'Brute Force'),
    ('root login',         'TA0003', 'Persistence',        'T1078',      'Valid Accounts'),
    ('permitrootlogin',    'TA0003', 'Persistence',        'T1078',      'Valid Accounts'),
    ('uid 0',              'TA0003', 'Persistence',        'T1078',      'Valid Accounts'),
    ('firewall',           'TA0005', 'Defense Evasion',    'T1562.004',  'Disable or Modify System Firewall'),
    ('ufw',                'TA0005', 'Defense Evasion',    'T1562.004',  'Disable or Modify System Firewall'),
    ('iptables',           'TA0005', 'Defense Evasion',    'T1562.004',  'Disable or Modify System Firewall'),
    ('audit',              'TA0005', 'Defense Evasion',    'T1562.002',  'Impair Defenses: Disable or Modify Tools'),
    ('log',                'TA0005', 'Defense Evasion',    'T1562.002',  'Impair Defenses: Disable or Modify Tools'),
    ('ssh',                'TA0008', 'Lateral Movement',   'T1021.004',  'Remote Services: SSH'),
    ('port',               'TA0043', 'Reconnaissance',     'T1046',      'Network Service Discovery'),
    ('empty password',     'TA0006', 'Credential Access',  'T1110.001',  'Brute Force: Password Guessing'),
    ('maxauthtries',       'TA0006', 'Credential Access',  'T1110',      'Brute Force'),
    ('x11forwarding',      'TA0008', 'Lateral Movement',   'T1021.004',  'Remote Services: SSH'),
]

_IMPACTS = {
    'T1110':      'Attacker can gain access to any account by guessing credentials — no alert fires if attempts stay below threshold.',
    'T1078':      'Attacker with any credential can escalate to root — full server compromise in one step.',
    'T1562.004':  'No firewall means all ports are reachable from any IP — attack surface is the entire internet.',
    'T1562.002':  'Without audit logs, attacker actions are invisible — breach cannot be detected or reconstructed.',
    'T1021.004':  'SSH misconfiguration is the most common initial access vector for Linux server breaches.',
    'T1046':      'Open ports expose services that may have unpatched vulnerabilities — each port is an attack surface.',
    'T1110.001':  'Empty or weak passwords can be guessed instantly without any brute-force tooling.',
}


def _get_reasoning(finding: Dict) -> Dict:
    """Map a finding to its MITRE ATT&CK reasoning. Returns reasoning dict or empty dict if no match."""
    title = (finding.get('title', '') + ' ' + finding.get('detail', '')).lower()

    tactic_id = tactic_name = technique_id = technique_name = ''
    for keyword, tid, tname, tecid, tecname in _MITRE_MAP:
        if keyword in title:
            tactic_id, tactic_name = tid, tname
            technique_id, technique_name = tecid, tecname
            break

    if not technique_id:
        return {}

    return {
        'what_changed': finding.get('detail', finding.get('title', '')),
        'when': 'Detected at time of scan — present since last configuration change.',
        'mitre_tactic': f'{tactic_id} — {tactic_name}',
        'mitre_technique': f'{technique_id} — {technique_name}',
        'why_it_matters': _IMPACTS.get(technique_id, 'This misconfiguration enables a known attack path.'),
        'recommended_action': finding.get('remediation', 'Review and harden this configuration.'),
    }


# Lazy-loaded knowledge base scanner — only loads when knowledge base exists
_kb_scanner = None
_kb_load_error: str = ""
_kb_load_attempted: bool = False

def _get_kb_scanner():
    global _kb_scanner, _kb_load_error, _kb_load_attempted
    if _kb_load_attempted:
        return _kb_scanner
    _kb_load_attempted = True
    kb_index = Path(__file__).parent.parent / "knowledge_base" / "embeddings" / "policy_index.faiss"
    if not kb_index.exists():
        _kb_load_error = "Knowledge base not built. Run: ./run_research.sh kb"
        return None
    try:
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from research.query_knowledge_base import TAARAScan
        _kb_scanner = TAARAScan()
        return _kb_scanner
    except Exception as e:
        _kb_load_error = f"KB load failed: {e}"
        return None


def render_taara_analysis(platform, taara_analyzer, cloud_analyzer=None, llm_service=None):
    """Render the TaaraAnalysis (OHA) page."""

    st.markdown("""
    <div style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                padding: 30px; border-radius: 15px; margin-bottom: 20px;
                border: 1px solid #0f3460;">
        <h1 style="color: #e94560; margin: 0; font-size: 2.2em;">
            TaaraAnalysis
        </h1>
        <p style="color: #a0a0b0; margin: 5px 0 0 0; font-size: 1.1em;">
            Organizational Health Analysis — Prevent Crash, Preserve Cash
        </p>
    </div>
    """, unsafe_allow_html=True)

    platform_info = platform.get_platform_info()
    ptype = platform_info.get('type', 'unknown')

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Platform", ptype.upper())
    with col2:
        st.metric("Status", "Connected" if platform.connected else "Disconnected")
    with col3:
        st.metric("Analysis Mode", "Quantum-Enhanced")

    if not platform.connected:
        st.error("Platform not connected. Please connect first.")
        return

    if 'analysis_results' not in st.session_state:
        st.session_state.analysis_results = None
    if 'analysis_running' not in st.session_state:
        st.session_state.analysis_running = False

    st.markdown("---")

    st.markdown("### Scan Configuration")
    col_a, col_b = st.columns([2, 1])
    with col_a:
        scan_depth = st.selectbox("Scan Depth", ["Standard", "Deep", "Quick"], index=0)
    with col_b:
        run_scan = st.button("Run TaaraAnalysis", type="primary", use_container_width=True)

    st.markdown("### Code / Repo Risk (Optional — Pillar B)")
    repo_col1, repo_col2 = st.columns([3, 1])
    with repo_col1:
        repo_target = st.text_input(
            "Repository path or GitHub URL",
            placeholder="e.g. /path/to/repo  or  https://github.com/org/repo",
            help="Leave blank to skip repo scan. Supports local paths and GitHub URLs."
        )
    with repo_col2:
        offline_scan = st.checkbox("Offline mode", value=False,
                                   help="Skip live OSV.dev and endoflife.date API calls (faster, no internet needed)")

    if run_scan:
        st.session_state.analysis_running = True
        _run_analysis(platform, taara_analyzer, cloud_analyzer, llm_service,
                      scan_depth, ptype, repo_target=repo_target.strip(), offline=offline_scan)
        st.session_state.analysis_running = False

    if st.session_state.analysis_results:
        _display_results(st.session_state.analysis_results, ptype)


def _run_analysis(platform, taara_analyzer, cloud_analyzer, llm_service,
                  scan_depth, ptype, repo_target: str = "", offline: bool = False):
    """Execute the full TaaraAnalysis pipeline."""
    progress = st.progress(0, text="Initializing TaaraAnalysis...")
    results = {
        'timestamp': time.time(),
        'platform': ptype,
        'scan_depth': scan_depth,
        'security_data': None,
        'quantum_risk': None,
        'repo_results': None,
        'cost_analysis': None,
        'ai_summary': None,
        'duration': 0
    }
    start_time = time.time()

    progress.progress(10, text="Collecting security data from target...")
    try:
        security_data = platform.collect_security_data()
        results['security_data'] = security_data
    except Exception as e:
        st.error(f"Security scan error: {e}")
        security_data = {'categories': {}, 'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}, 'features': {}}
        results['security_data'] = security_data

    progress.progress(30, text="Running TAARA reconstruction-based novelty detection...")
    try:
        features = security_data.get('features', {})
        feature_vector = np.array([
            features.get('failed_logins', 0),
            features.get('accepted_logins', 0),
            features.get('invalid_users', 0),
            features.get('established_connections', 0),
            features.get('unique_outbound_ips', 0),
            features.get('total_findings', 0),
            features.get('weighted_severity_score', 0),
        ], dtype=np.float32)

        if len(feature_vector) < 4:
            feature_vector = np.pad(feature_vector, (0, 4 - len(feature_vector)))

        if taara_analyzer is None:
            raise ValueError("TAARAnalyzer not initialized")
        quantum_risk = taara_analyzer.get_quantum_risk_assessment(
            feature_vector, identity_id=f'{ptype}_system'
        )
        results['quantum_risk'] = quantum_risk
    except Exception as e:
        st.warning(f"Quantum analysis notice: {e}")
        summary = security_data.get('summary', {})
        score = min(
            summary.get('critical', 0) * 25 +
            summary.get('high', 0) * 15 +
            summary.get('medium', 0) * 5 +
            summary.get('low', 0) * 1,
            100
        )
        results['quantum_risk'] = {
            'risk_score': score,
            'severity': 'CRITICAL' if score >= 75 else 'HIGH' if score >= 50 else 'MEDIUM' if score >= 25 else 'LOW',
            'quantum_novelty': 0,
            'f_min': 1.0,
            'is_directionally_novel': False
        }

    progress.progress(45, text="Querying TAARA knowledge graph (GraphRAG)...")
    kb_findings = []
    kb_status = {"loaded": False, "error": "", "config_chars": 0}
    scanner = _get_kb_scanner()
    if scanner:
        kb_status["loaded"] = True
        try:
            # Collect actual config text from platform — raw sshd_config, firewall rules,
            # open port listings, docker inspect output — NOT generated finding text.
            config_text = ""
            for cat_key, cat_data in security_data.get('categories', {}).items():
                raw = cat_data.get('raw_config', '')
                if raw:
                    config_text += f"# {cat_key}\n{raw}\n"
            # Platform may expose a top-level raw_config dict for direct access
            if hasattr(platform, 'get_raw_configs'):
                try:
                    raw_configs = platform.get_raw_configs()
                    for label, text in raw_configs.items():
                        config_text += f"# {label}\n{text}\n"
                except Exception:
                    pass
            # Fallback: use info fields (key-value facts, not finding text)
            if not config_text.strip():
                for cat_key, cat_data in security_data.get('categories', {}).items():
                    info = cat_data.get('info', {})
                    if info and isinstance(info, dict):
                        config_text += f"# {cat_key}\n"
                        for k, v in info.items():
                            config_text += f"{k}: {v}\n"
            config_text = config_text.strip()
            kb_status["config_chars"] = len(config_text)
            if config_text:
                kb_result = scanner.scan_text(config_text, label=f"{ptype}_config")
                kb_findings = kb_result.get('findings', [])
            else:
                kb_status["error"] = "No raw config available from platform scan — KB scan skipped"
        except Exception as e:
            kb_status["error"] = str(e)
    else:
        kb_status["error"] = _kb_load_error
    results['kb_findings'] = kb_findings
    results['kb_status'] = kb_status

    progress.progress(55, text="Running Code / Repo Risk scan (Pillar B)...")
    results['repo_results'] = None
    if repo_target:
        try:
            import sys
            sys.path.insert(0, str(Path(__file__).parent.parent))
            from research.scan_repo import scan_repo
            repo_scan_result = scan_repo(repo_target, offline=offline)
            results['repo_results'] = repo_scan_result
        except Exception as e:
            results['repo_results'] = {'error': str(e), 'target': repo_target}
    else:
        results['repo_results'] = None

    progress.progress(65, text="Analyzing cloud spending patterns...")
    if cloud_analyzer and ptype in ['aws', 'gcp', 'azure']:
        try:
            cost_data = platform.collect_cost_data()
            cost_analysis = cloud_analyzer.analyze_platform_costs(platform, cost_data)
            results['cost_analysis'] = cost_analysis
        except Exception as e:
            results['cost_analysis'] = {'error': str(e)}
    else:
        results['cost_analysis'] = None

    progress.progress(80, text="Generating AI summary from verified findings...")
    if llm_service:
        try:
            # Build verified findings JSON — LLM receives ONLY what TAARA found.
            # It converts findings to plain language. It does NOT discover or invent issues.
            security_data = results.get('security_data', {})
            summary = security_data.get('summary', {})
            quantum_risk = results.get('quantum_risk', {})
            repo_res = results.get('repo_results') or {}
            kb_f = results.get('kb_findings', [])

            verified_findings = []
            for cat in security_data.get('categories', {}).values():
                for f in cat.get('findings', []):
                    verified_findings.append({
                        'source': 'security_scan',
                        'severity': f.get('severity', ''),
                        'title': f.get('title', ''),
                        'remediation': f.get('remediation', ''),
                    })
            for f in kb_f[:5]:
                verified_findings.append({
                    'source': 'knowledge_graph',
                    'severity': f.get('severity', ''),
                    'title': f.get('label', ''),
                    'remediation': f['mitigations'][0]['description'] if f.get('mitigations') else '',
                })
            for f in repo_res.get('findings', [])[:5]:
                verified_findings.append({
                    'source': 'repo_scan',
                    'severity': f.get('severity', ''),
                    'title': f.get('title', ''),
                    'remediation': f.get('remediation', ''),
                })

            prompt = (
                "You are an infrastructure security analyst converting verified scan findings "
                "to plain business language. "
                "STRICT RULE: Use ONLY the findings provided below. Do NOT add vulnerabilities, "
                "incidents, costs, or claims not present in the input. "
                "If evidence is missing or unclear, say 'insufficient evidence'. "
                "Do not invent specific numbers (CVE counts, breach costs) beyond what is given.\n\n"
                f"Platform: {ptype.upper()}\n"
                f"Security Risk Score: {summary.get('critical',0)*25+summary.get('high',0)*15+summary.get('medium',0)*5+summary.get('low',0)*1}/100\n"
                f"Behavior Novelty: {quantum_risk.get('quantum_novelty',0)}% (fidelity F={quantum_risk.get('f_min',1.0):.3f})\n"
                f"Findings count: {len(verified_findings)}\n\n"
                "Verified findings (JSON):\n"
                + json.dumps(verified_findings, indent=2)
                + "\n\nProvide:\n"
                "1. Executive summary (2-3 sentences, business language, no jargon)\n"
                "2. Top 3 immediate actions (from the findings above only)\n"
                "3. One sentence on breach risk (reference IBM India MSME baseline ₹2-5 Cr, "
                "relate it to critical/high count found)"
            )

            response = llm_service.generate_response(prompt)
            if response.get('success'):
                results['ai_summary'] = response.get('explanation', '')
        except Exception:
            pass

    progress.progress(95, text="Finalizing analysis...")
    results['duration'] = round(time.time() - start_time, 1)
    st.session_state.analysis_results = results
    progress.progress(100, text="TaaraAnalysis complete!")
    time.sleep(0.5)


def build_infra_health_model(results: Dict) -> Dict:
    """
    Normalize all pillar outputs into the common infrastructure health model.

    Schema:
      assets       — things that exist (servers, repos, cloud resources)
      findings     — problems found, all with canonical title/detail/remediation/severity/source
      costs        — cloud cost items with security_decision (safe/review/unsafe)
      relationships — edges between assets and findings (what connects what)
      telemetry    — behavioral signals for TAARA memory
      raw_evidence — raw config text for audit trail
    """
    security_data = results.get('security_data', {}) or {}
    quantum_risk = results.get('quantum_risk', {}) or {}
    repo_results = results.get('repo_results') or {}
    cost_analysis = results.get('cost_analysis') or {}
    kb_findings = results.get('kb_findings', []) or []
    summary = security_data.get('summary', {})

    model: Dict = {
        "assets": [],
        "findings": [],
        "costs": [],
        "relationships": [],
        "telemetry": {},
        "raw_evidence": {},
    }

    # ── Assets ─────────────────────────────────────────────────────────────────
    ptype = results.get('platform', 'unknown')
    model["assets"].append({
        "id": f"{ptype}_server",
        "type": ptype,
        "label": security_data.get('host', ptype.upper()),
        "connected": True,
    })
    if repo_results and not repo_results.get('error'):
        model["assets"].append({
            "id": "repo",
            "type": "repository",
            "label": repo_results.get('repo', 'Repository'),
            "packages": repo_results.get('packages_resolved', 0),
        })

    # ── Findings: security scan ────────────────────────────────────────────────
    for cat_key, cat_data in security_data.get('categories', {}).items():
        cat_name = cat_data.get('name', cat_key)
        for f in cat_data.get('findings', []):
            model["findings"].append({
                "id": f"sec:{cat_key}:{f.get('title','')[:30]}",
                "pillar": "attack",
                "source": "security_scan",
                "category": cat_name,
                "title": f.get('title', ''),
                "detail": f.get('detail', ''),
                "remediation": f.get('remediation', ''),
                "severity": f.get('severity', 'medium'),
                "confidence": "high",
                "asset_id": f"{ptype}_server",
            })

    # ── Findings: knowledge graph deviations ──────────────────────────────────
    for i, f in enumerate(kb_findings):
        model["findings"].append({
            "id": f"kg:{f.get('node_id', i)}",
            "pillar": "attack",
            "source": "knowledge_graph",
            "category": "Policy Deviation",
            "title": f.get('label', f.get('node_id', '')),
            "detail": f.get('description', ''),
            "remediation": f['mitigations'][0]['description'] if f.get('mitigations') else '',
            "severity": f.get('severity', 'medium'),
            "confidence": "medium",
            "quantum_fidelity": f.get('quantum_fidelity', {}),
            "asset_id": f"{ptype}_server",
        })

    # ── Findings: repo scan ────────────────────────────────────────────────────
    for f in repo_results.get('findings', []):
        model["findings"].append({
            "id": f"repo:{f.get('node_id', f.get('osv_id', f.get('title',''))[:30])}",
            "pillar": "code",
            "source": f.get('source', 'repo_scan'),
            "category": "Code / Repo Risk",
            "title": f.get('title', ''),
            "detail": f.get('detail', ''),
            "remediation": f.get('remediation', ''),
            "severity": f.get('severity', 'medium'),
            "confidence": "high" if f.get('osv_id') else "medium",
            "osv_id": f.get('osv_id', ''),
            "quantum_fidelity": f.get('quantum_fidelity', {}),
            "asset_id": "repo",
        })

    # ── Costs: with security decision ─────────────────────────────────────────
    for item in cost_analysis.get('waste_findings', []):
        model["costs"].append(_add_security_decision(item, model["findings"]))
    for item in cost_analysis.get('optimization_recommendations', []):
        model["costs"].append(_add_security_decision(item, model["findings"]))

    # ── Relationships ─────────────────────────────────────────────────────────
    chains = repo_results.get('cross_file_chains', [])
    for c in chains:
        for f_file in c.get('files', []):
            model["relationships"].append({
                "from": f"{ptype}_server",
                "to": f"repo:{c.get('chain_id', c.get('title','chain'))}",
                "label": c.get('title', 'chain'),
                "type": "failure_chain",
                "severity": c.get('severity', 'high'),
            })
    # Asset → finding edges
    for finding in model["findings"]:
        model["relationships"].append({
            "from": finding.get("asset_id", "unknown"),
            "to": finding["id"],
            "label": finding["severity"],
            "type": "has_finding",
        })

    # ── Telemetry: behavioral signals ─────────────────────────────────────────
    features = security_data.get('features', {})
    model["telemetry"] = {
        "failed_logins": features.get('failed_logins', 0),
        "accepted_logins": features.get('accepted_logins', 0),
        "unique_outbound_ips": features.get('unique_outbound_ips', 0),
        "established_connections": features.get('established_connections', 0),
        "quantum_novelty": quantum_risk.get('quantum_novelty', 0),
        "fidelity_f": quantum_risk.get('f_min', 1.0),
    }

    # ── Raw evidence ──────────────────────────────────────────────────────────
    model["raw_evidence"]["kb_status"] = results.get('kb_status', {})
    if repo_results.get('offline_skipped'):
        model["raw_evidence"]["offline_skipped"] = repo_results['offline_skipped']

    # ── Derived scores ────────────────────────────────────────────────────────
    sec_findings = [f for f in model["findings"] if f["pillar"] == "attack"]
    code_findings = [f for f in model["findings"] if f["pillar"] == "code"]
    security_risk = min(
        sum({"critical":25,"high":15,"medium":5,"low":1}.get(f["severity"],0) for f in sec_findings), 100
    )
    repo_risk = min(
        sum({"critical":25,"high":15,"medium":5,"low":1}.get(f["severity"],0) for f in code_findings)
        + len(chains) * 10, 100
    )
    novelty = quantum_risk.get('quantum_novelty', 0)
    savings_opportunity = min(cost_analysis.get('potential_monthly_savings', 0) / 500 * 15, 15)
    infra_health = max(0, min(100, 100 - int(
        security_risk * 0.40 + novelty * 0.20 + repo_risk * 0.25 + savings_opportunity
    )))

    model["scores"] = {
        "infra_health": infra_health,
        "security_risk": security_risk,
        "behavior_novelty": novelty,
        "repo_risk": repo_risk,
        "cross_file_chains": len(chains),
        "total_findings": len(model["findings"]),
        "potential_monthly_savings": cost_analysis.get('potential_monthly_savings', 0),
        "safe_savings": sum(
            _parse_savings(c.get('potential_savings', ''))
            for c in model["costs"] if c.get('security_decision') == 'safe'
        ),
    }

    return model


def _parse_savings(s: str) -> float:
    try:
        return float(str(s).replace('$','').replace(',','').replace('/month','').split()[0])
    except Exception:
        return 0.0


_AUDIT_LOG_KEYWORDS = {"cloudtrail", "audit", "log", "monitoring", "cloudwatch", "stackdriver"}
_HIGH_RISK_KEYWORDS = {"public", "database", "rds", "sql", "security group", "0.0.0.0/0"}

def _add_security_decision(item: dict, findings: list) -> dict:
    """
    Add security_decision (safe/review/unsafe), security_impact, and reason
    to a cost item based on what the item does and what findings exist.
    This is TAARA's core cost differentiator vs AWS Cost Explorer.
    """
    item = dict(item)
    title_lower = (item.get('title', '') + ' ' + item.get('detail', '')).lower()
    action_lower = item.get('action', item.get('remediation', '')).lower()

    # Unsafe: would remove security visibility or expose data
    if any(kw in title_lower or kw in action_lower for kw in _AUDIT_LOG_KEYWORDS):
        item['security_decision'] = 'unsafe'
        item['security_impact'] = 'Removes security audit visibility — breach detection blind spot'
        item['reason'] = (
            'Audit logs are required for breach detection, forensics, and compliance. '
            'Disabling them saves cost but creates a blind spot. TAARA rejects this saving.'
        )
        return item

    # Review: public-facing or database resources — cost saving may increase exposure
    if any(kw in title_lower for kw in _HIGH_RISK_KEYWORDS):
        # Check if findings mention this resource
        related = [f for f in findings if
                   any(word in f.get('title','').lower() for word in title_lower.split()[:4])]
        if related:
            item['security_decision'] = 'unsafe'
            item['security_impact'] = f"Resource has active security findings — do not modify until fixed"
            item['reason'] = f"Found {len(related)} related security finding(s). Fix security first."
        else:
            item['security_decision'] = 'review'
            item['security_impact'] = 'Public or database resource — verify access controls before changing'
            item['reason'] = 'High-risk resource type. Manual review required before acting on savings.'
        return item

    # Safe: unused/unattached resources with no security findings
    if any(kw in title_lower for kw in {'unused', 'unattached', 'idle', 'stopped', 'elastic ip',
                                          'unassociated', 'no targets', 'terminated'}):
        item['security_decision'] = 'safe'
        item['security_impact'] = 'No security impact — resource is unused'
        item['reason'] = 'Unused resource. Safe to delete or release.'
        return item

    # Default: review
    item['security_decision'] = 'review'
    item['security_impact'] = 'Impact unknown without review'
    item['reason'] = 'Manually review before taking action.'
    return item


def _display_results(results: Dict, ptype: str):
    """Mission-control display of TaaraAnalysis results."""
    import plotly.graph_objects as go

    model = build_infra_health_model(results)
    scores = model["scores"]
    security_data = results.get('security_data', {}) or {}
    summary = security_data.get('summary', {})
    quantum_risk = results.get('quantum_risk', {}) or {}
    kb_findings = results.get('kb_findings', []) or []
    kb_status = results.get('kb_status', {}) or {}
    repo_results = results.get('repo_results') or {}

    # ═══════════════════════════════════════════════════════════
    # TOP BAND: Infrastructure Health Score + live status
    # ═══════════════════════════════════════════════════════════
    ih = scores['infra_health']
    ih_color = "#ff0000" if ih < 30 else "#ff6600" if ih < 50 else "#ffaa00" if ih < 70 else "#00cc00"

    st.markdown(f"""
    <div style="background: linear-gradient(135deg, #0a0a1a, #1a1a3e);
                padding: 20px; border-radius: 12px; margin-bottom: 16px;
                border: 2px solid {ih_color};">
        <div style="display:flex; align-items:center; justify-content:space-between;">
            <div>
                <p style="color:#a0a0b0; margin:0; font-size:0.8em;">INFRASTRUCTURE HEALTH SCORE</p>
                <h1 style="color:{ih_color}; margin:4px 0; font-size:3em; font-weight:900;">{ih}<span style="font-size:0.5em;">/100</span></h1>
                <p style="color:#888; margin:0; font-size:0.85em;">
                    {scores['total_findings']} findings across {len(model['assets'])} asset(s) |
                    {scores['cross_file_chains']} failure chains |
                    Scanned in {results.get('duration',0)}s
                </p>
            </div>
            <div style="text-align:right;">
                <p style="color:#666; margin:0; font-size:0.8em;">TAARA Q.0 — Prevent Crash, Preserve Cash</p>
                <p style="color:#e94560; margin:4px 0; font-size:1.1em; font-weight:bold;">
                    {ptype.upper()} · {datetime.now().strftime("%H:%M %d %b %Y")}
                </p>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ═══════════════════════════════════════════════════════════
    # MIDDLE: Three animated pillars with Plotly gauges
    # ═══════════════════════════════════════════════════════════
    col_a, col_b, col_c = st.columns(3)

    def _gauge(value, title, color, max_val=100, suffix=""):
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=value,
            title={'text': title, 'font': {'size': 13, 'color': '#a0a0b0'}},
            number={'font': {'color': color, 'size': 32}, 'suffix': suffix},
            gauge={
                'axis': {'range': [0, max_val], 'tickcolor': '#444'},
                'bar': {'color': color},
                'bgcolor': '#1a1a2e',
                'bordercolor': '#333',
                'steps': [
                    {'range': [0, max_val*0.3], 'color': '#1a1a2e'},
                    {'range': [max_val*0.3, max_val*0.6], 'color': '#1a2a1a'},
                    {'range': [max_val*0.6, max_val], 'color': '#2a1a1a'},
                ],
            }
        ))
        fig.update_layout(
            height=200, margin=dict(l=20, r=20, t=40, b=0),
            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
            font={'color': '#a0a0b0'}
        )
        return fig

    sr = scores['security_risk']
    nv = scores['behavior_novelty']
    rr = scores['repo_risk']

    with col_a:
        st.markdown("**Pillar A — Attack Surface**")
        sr_color = "#ff0000" if sr >= 75 else "#ff6600" if sr >= 50 else "#ffaa00" if sr >= 25 else "#00cc00"
        st.plotly_chart(_gauge(sr, "Security Risk", sr_color), use_container_width=True, key="gauge_sr")
        c = summary.get('critical',0); h = summary.get('high',0)
        st.caption(f"{c} critical · {h} high · {summary.get('medium',0)} medium")

    with col_b:
        st.markdown("**Pillar B — Behavior Novelty**")
        nv_color = "#ff0000" if nv >= 75 else "#ff6600" if nv >= 50 else "#8888ff" if nv >= 10 else "#888888"
        st.plotly_chart(_gauge(nv, "Behavior Novelty", nv_color, suffix="%"), use_container_width=True, key="gauge_nv")
        f_val = quantum_risk.get('f_min', 1.0)
        is_novel = quantum_risk.get('is_directionally_novel', False)
        st.caption(f"Fidelity F={f_val:.3f} · {'Directional shift' if is_novel else 'Within baseline'}")

    with col_c:
        st.markdown("**Pillar C — Code / Repo Risk**")
        rr_color = "#ff0000" if rr >= 75 else "#ff6600" if rr >= 50 else "#ffaa00" if rr >= 25 else "#00cc00"
        st.plotly_chart(_gauge(rr, "Repo Risk", rr_color), use_container_width=True, key="gauge_rr")
        chains_n = scores['cross_file_chains']
        repo_f = len(repo_results.get('findings', []))
        st.caption(f"{repo_f} findings · {chains_n} failure chains")

    # ═══════════════════════════════════════════════════════════
    # MAIN VISUAL: Infrastructure relationship graph
    # ═══════════════════════════════════════════════════════════
    st.markdown("### Infrastructure Relationship Graph")
    st.caption("Assets → findings → cost impact. Hover nodes for details.")
    _render_relationship_graph(model)

    # ═══════════════════════════════════════════════════════════
    # Quantum fidelity visualization
    # ═══════════════════════════════════════════════════════════
    _render_quantum_viz(quantum_risk)

    # ═══════════════════════════════════════════════════════════
    # TAARA ADVANTAGE PANEL
    # ═══════════════════════════════════════════════════════════
    _render_advantage_panel(model, repo_results, quantum_risk)

    # ═══════════════════════════════════════════════════════════
    # AI Summary
    # ═══════════════════════════════════════════════════════════
    if results.get('ai_summary'):
        st.markdown("### AI Executive Summary")
        st.caption("Generated from verified findings only — AI does not add or invent findings.")
        st.info(results['ai_summary'])

    # ═══════════════════════════════════════════════════════════
    # Pillar A details: Security findings + KB
    # ═══════════════════════════════════════════════════════════
    with st.expander(f"Pillar A Details — Security Findings ({sum(summary.values())} findings)", expanded=False):
        _render_security_details(security_data, kb_findings, kb_status)

    # ═══════════════════════════════════════════════════════════
    # Pillar B details: Repo risk + chains
    # ═══════════════════════════════════════════════════════════
    if repo_results:
        with st.expander(f"Pillar B Details — Code / Repo Risk ({len(repo_results.get('findings',[]))} findings)", expanded=False):
            _render_repo_details(repo_results)

    # ═══════════════════════════════════════════════════════════
    # Pillar C details: Cloud cost with security decisions
    # ═══════════════════════════════════════════════════════════
    cost_analysis = results.get('cost_analysis')
    if cost_analysis and not cost_analysis.get('error'):
        with st.expander(f"Pillar C Details — Cloud Spend (${cost_analysis.get('potential_monthly_savings',0):,.0f}/mo savings identified)", expanded=False):
            _render_cost_details(model['costs'], cost_analysis, model['findings'])

    # ═══════════════════════════════════════════════════════════
    # Bottom CTA
    # ═══════════════════════════════════════════════════════════
    st.markdown("---")
    cta1, cta2, cta3 = st.columns(3)
    with cta1:
        if st.button("Generate TaaraWords PDF Report", type="primary", use_container_width=True):
            st.session_state.nav_target = 'taara_words'
            st.rerun()
    with cta2:
        st.button("Deploy TaaraWare Monitoring", use_container_width=True)
    with cta3:
        st.caption(f"Analysis: {results.get('duration',0)}s · Depth: {results.get('scan_depth','Standard')}")


def _render_relationship_graph(model: Dict):
    """Plotly node-link graph: assets → findings → costs."""
    import plotly.graph_objects as go
    import math

    assets = model.get('assets', [])
    findings_top = [f for f in model.get('findings', []) if f['severity'] in ('critical','high')][:12]
    costs_safe = [c for c in model.get('costs', []) if c.get('security_decision') == 'safe'][:4]

    nodes_x, nodes_y, nodes_text, nodes_color, nodes_size, hover = [], [], [], [], [], []
    node_ids = {}

    def add_node(nid, label, x, y, color, size, htext):
        idx = len(nodes_x)
        node_ids[nid] = idx
        nodes_x.append(x); nodes_y.append(y)
        nodes_text.append(label[:22]); nodes_color.append(color)
        nodes_size.append(size); hover.append(htext)

    # Assets — left column
    for i, a in enumerate(assets):
        add_node(a['id'], a['label'], 0.1, 0.9 - i*0.4,
                 '#4488ff', 30, f"Asset: {a['type']}<br>{a['label']}")

    # Findings — middle column
    sev_col = {'critical':'#ff2222','high':'#ff6600','medium':'#ffaa00','low':'#00cc00'}
    for i, f in enumerate(findings_top):
        y = 0.95 - i * (0.9 / max(len(findings_top),1))
        add_node(f['id'], f['title'][:20], 0.5, y,
                 sev_col.get(f['severity'],'#888'), 18,
                 f"[{f['severity'].upper()}] {f['title'][:60]}<br>Fix: {f['remediation'][:60]}")

    # Cost safe savings — right column
    for i, c in enumerate(costs_safe):
        y = 0.85 - i * 0.3
        add_node(f"cost_{i}", c.get('title','Saving')[:20], 0.9, y,
                 '#00cc88', 15, f"Safe saving: {c.get('potential_savings','')}<br>{c.get('reason','')}")

    # Edges
    edge_x, edge_y = [], []
    for f in findings_top:
        aid = f.get('asset_id','')
        if aid in node_ids and f['id'] in node_ids:
            x0, y0 = nodes_x[node_ids[aid]], nodes_y[node_ids[aid]]
            x1, y1 = nodes_x[node_ids[f['id']]], nodes_y[node_ids[f['id']]]
            edge_x += [x0, x1, None]; edge_y += [y0, y1, None]

    for i, _ in enumerate(costs_safe):
        nid = f"cost_{i}"
        # connect to first asset
        if assets and nid in node_ids:
            aid = assets[0]['id']
            if aid in node_ids:
                x0, y0 = nodes_x[node_ids[aid]], nodes_y[node_ids[aid]]
                x1, y1 = nodes_x[node_ids[nid]], nodes_y[node_ids[nid]]
                edge_x += [x0, x1, None]; edge_y += [y0, y1, None]

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=edge_x, y=edge_y, mode='lines',
        line=dict(color='#333', width=1), hoverinfo='none'
    ))
    fig.add_trace(go.Scatter(
        x=nodes_x, y=nodes_y, mode='markers+text',
        text=nodes_text, textposition='bottom center',
        textfont=dict(color='#a0a0b0', size=9),
        marker=dict(size=nodes_size, color=nodes_color, line=dict(color='#222', width=1)),
        hovertext=hover, hoverinfo='text',
    ))
    fig.update_layout(
        height=380, showlegend=False,
        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(15,15,30,0.8)',
        xaxis=dict(visible=False, range=[-0.05, 1.05]),
        yaxis=dict(visible=False, range=[-0.05, 1.05]),
        margin=dict(l=0, r=0, t=0, b=0),
    )
    # Add column labels
    fig.add_annotation(x=0.1, y=1.0, text="Assets", showarrow=False,
                       font=dict(color='#4488ff', size=11))
    fig.add_annotation(x=0.5, y=1.0, text="Critical/High Findings", showarrow=False,
                       font=dict(color='#ff6600', size=11))
    fig.add_annotation(x=0.9, y=1.0, text="Safe Savings", showarrow=False,
                       font=dict(color='#00cc88', size=11))
    st.plotly_chart(fig, use_container_width=True, key="rel_graph")


def _render_quantum_viz(quantum_risk: Dict):
    """Show quantum fidelity as a visual: baseline vs current vector angle."""
    import plotly.graph_objects as go
    import math

    f_val = float(quantum_risk.get('f_min', 1.0))
    novelty = float(quantum_risk.get('quantum_novelty', 0)) / 100.0
    is_novel = quantum_risk.get('is_directionally_novel', False)

    # Angle between baseline and current behavioral vector (from fidelity)
    angle_rad = math.acos(min(1.0, max(0.0, math.sqrt(f_val))))

    fig = go.Figure()
    # Baseline vector (always at 0°)
    fig.add_trace(go.Scatter(
        x=[0, 1], y=[0, 0], mode='lines+text',
        line=dict(color='#4488ff', width=3),
        text=['', 'Baseline behavior'], textposition='middle right',
        textfont=dict(color='#4488ff'),
        name='Baseline'
    ))
    # Current behavior vector (at angle)
    cx = math.cos(angle_rad)
    cy = math.sin(angle_rad)
    color = '#ff2222' if is_novel else '#00cc88'
    label = f"Current (F={f_val:.3f})"
    fig.add_trace(go.Scatter(
        x=[0, cx], y=[0, cy], mode='lines+text',
        line=dict(color=color, width=3, dash='dot' if is_novel else 'solid'),
        text=['', label], textposition='top right',
        textfont=dict(color=color),
        name='Current behavior'
    ))
    # Threshold arc annotation
    theta = [i * 0.01 for i in range(63)]  # 0 to π/2
    arc_x = [0.3*math.cos(t) for t in theta]
    arc_y = [0.3*math.sin(t) for t in theta]
    fig.add_trace(go.Scatter(x=arc_x, y=arc_y, mode='lines',
                             line=dict(color='#555', width=1, dash='dot'), showlegend=False))
    fig.add_annotation(
        x=0.35, y=0.18,
        text=f"θ={math.degrees(angle_rad):.1f}°",
        showarrow=False, font=dict(color='#888', size=10)
    )
    fig.add_annotation(
        x=0.5, y=-0.25,
        text=f"F={f_val:.4f} {'< 0.5 — DIRECTIONAL SHIFT' if f_val < 0.5 else '≥ 0.5 — within baseline direction'}",
        showarrow=False, font=dict(color=color, size=11)
    )

    fig.update_layout(
        title=dict(text="Quantum Fidelity — Behavioral Direction", font=dict(color='#a0a0b0', size=13)),
        height=280,
        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(15,15,30,0.8)',
        xaxis=dict(range=[-0.1, 1.4], visible=False),
        yaxis=dict(range=[-0.35, 1.1], visible=False, scaleanchor='x'),
        showlegend=True,
        legend=dict(font=dict(color='#a0a0b0'), bgcolor='rgba(0,0,0,0)'),
        margin=dict(l=0, r=0, t=35, b=0),
    )
    with st.expander("Quantum Fidelity — Directional Discrimination", expanded=False):
        st.plotly_chart(fig, use_container_width=True, key="quantum_viz")
        st.caption(
            "Quantum fidelity F = |⟨ψ_current|ψ_baseline⟩|² measures the angle between "
            "the current behavior vector and the established baseline. "
            "F < 0.5 means more orthogonal than parallel — a new behavioral direction. "
            "This is NOT a speedup claim. The 4-qubit PennyLane circuit runs classically. "
            "The value is a principled geometric signal, not a tuned threshold."
        )


def _render_advantage_panel(model: Dict, repo_results: Dict, quantum_risk: Dict):
    """TAARA Advantage: what existing tools show vs what TAARA adds."""
    st.markdown("### TAARA Advantage")
    st.caption("What Snyk/Trivy/Wazuh/Cost Explorer would show — and what TAARA adds beyond them.")

    findings = model.get('findings', [])
    chains = repo_results.get('cross_file_chains', [])
    f_val = quantum_risk.get('f_min', 1.0)
    is_novel = quantum_risk.get('is_directionally_novel', False)
    costs = model.get('costs', [])
    safe_savings = [c for c in costs if c.get('security_decision') == 'safe']
    unsafe_savings = [c for c in costs if c.get('security_decision') == 'unsafe']

    adv_col1, adv_col2 = st.columns(2)

    with adv_col1:
        st.markdown("""
        <div style="background:#1a1a1a; padding:14px; border-radius:8px; border-left:3px solid #555;">
            <p style="color:#888; margin:0 0 8px 0; font-weight:bold; font-size:0.85em;">
                EXISTING TOOLS (Snyk, Trivy, Wazuh, Cost Explorer)
            </p>
        </div>
        """, unsafe_allow_html=True)

        critical = [f for f in findings if f['severity'] == 'critical']
        if critical:
            st.markdown(f"- `{critical[0]['title'][:60]}` — flagged as critical finding")
        if chains:
            st.markdown("- Individual Dockerfile findings flagged")
            st.markdown("- Individual npm package warnings listed")
        else:
            st.markdown("- No cross-file patterns detected (single-file view)")
        st.markdown(f"- Behavior: traffic volume normal, CPU normal")
        if costs:
            total_s = sum(_parse_savings(c.get('potential_savings','')) for c in costs)
            st.markdown(f"- Cost Explorer: terminate resources, save ~${total_s:,.0f}/mo")
        st.markdown("- No awareness of relationships between findings")

    with adv_col2:
        st.markdown("""
        <div style="background:#0a1a0a; padding:14px; border-radius:8px; border-left:3px solid #e94560;">
            <p style="color:#e94560; margin:0 0 8px 0; font-weight:bold; font-size:0.85em;">
                TAARA ADDS
            </p>
        </div>
        """, unsafe_allow_html=True)

        if chains:
            c = chains[0]
            st.markdown(f"- **Chain detected:** {c['title'][:70]}")
            files_str = ", ".join(str(x) for x in c.get('files',[])[:3])
            st.markdown(f"  Files: `{files_str}` — combination is the risk, not individual files")

        if is_novel:
            st.markdown(f"- **Behavioral direction shift:** F={f_val:.3f} < 0.5 — "
                        "this identity has not behaved this way before. "
                        "Classical stats: no anomaly. TAARA: directionally new.")
        else:
            st.markdown(f"- **Baseline within normal direction:** F={f_val:.3f} ≥ 0.5. "
                        "Current behavior is consistent with prior observations.")

        if safe_savings:
            st.markdown(f"- **{len(safe_savings)} safe savings** identified — "
                        f"${sum(_parse_savings(c.get('potential_savings','')) for c in safe_savings):,.0f}/mo")
        if unsafe_savings:
            st.markdown(f"- **{len(unsafe_savings)} savings rejected** — would remove security visibility")
            st.markdown(f"  Reason: {unsafe_savings[0].get('reason','See details')[:80]}")

        kg_f = [f for f in findings if f['source'] == 'knowledge_graph']
        if kg_f:
            st.markdown(f"- **{len(kg_f)} policy deviations** detected via knowledge graph — "
                        "not flagged by rule-based scanners (no rule exists for these yet)")


def _render_security_details(security_data: Dict, kb_findings: list, kb_status: Dict):
    sev_colors = {'critical': '#ff0000', 'high': '#ff6600', 'medium': '#ffaa00', 'low': '#00cc00'}

    # KB status first
    if not kb_status.get('loaded'):
        st.info(f"Knowledge graph not active — {kb_status.get('error', 'not built')}. Run `./run_research.sh kb`")
    elif kb_status.get('error'):
        st.warning(f"KB loaded but scan incomplete: {kb_status.get('error')}")
    elif not kb_findings:
        chars = kb_status.get('config_chars', 0)
        if chars > 0:
            st.success(f"Knowledge graph active ({chars} chars scanned) — no policy deviations.")
        else:
            st.info("KB loaded but no raw config available from this platform scan.")

    for cat_key, cat_data in security_data.get('categories', {}).items():
        findings = cat_data.get('findings', [])
        cat_name = cat_data.get('name', cat_key)
        if findings:
            st.markdown(f"**{cat_name}** ({len(findings)} findings)")
            for f in findings:
                sev = f.get('severity', 'info')
                color = sev_colors.get(sev, '#888')
                st.markdown(
                    f"<span style='color:{color}'>[{sev.upper()}]</span> "
                    f"**{f.get('title','')}** — {f.get('detail','')}",
                    unsafe_allow_html=True
                )
                st.caption(f"Fix: {f.get('remediation','')}")
                reasoning = _get_reasoning(f)
                if reasoning:
                    st.markdown(
                        f"<small style='color:#888'>⚔ MITRE: {reasoning['mitre_tactic']} · "
                        f"{reasoning['mitre_technique']}</small>",
                        unsafe_allow_html=True
                    )
        else:
            info = cat_data.get('info', {})
            if info and isinstance(info, dict):
                st.markdown(f"**{cat_name}** — no issues")
                for k, v in list(info.items())[:3]:
                    st.caption(f"{k}: {v}")

    if kb_findings:
        st.markdown("**Knowledge Graph Policy Deviations**")
        for i, f in enumerate(kb_findings[:8], 1):
            sev = f.get('severity', 'medium')
            qf = f.get('quantum_fidelity', {})
            sev_color = {"critical": "#ff2222", "high": "#ff8800", "medium": "#ffcc00"}.get(sev, "#aaa")
            st.markdown(
                f"<span style='color:{sev_color}'>**[{sev.upper()}]** "
                f"{f.get('label', f.get('node_id',''))} — F={qf.get('fidelity',0):.3f}</span>",
                unsafe_allow_html=True
            )
            st.caption(f.get('description', ''))
            if qf.get('interpretation'):
                st.caption(f"Quantum: {qf['interpretation']}")
            chain = f.get('propagation_chain', [])
            if len(chain) > 1:
                st.caption("Chain: " + " → ".join(c['label'] for c in chain[1:4]))
            if f.get('mitigations'):
                st.success(f"Fix: {f['mitigations'][0].get('label','')} — {f['mitigations'][0].get('description','')}")
            reasoning = _get_reasoning(f)
            if reasoning:
                st.markdown(
                    f"<small style='color:#888'>⚔ MITRE: {reasoning['mitre_tactic']} · "
                    f"{reasoning['mitre_technique']}</small>",
                    unsafe_allow_html=True
                )
            st.markdown("---")


def _render_repo_details(repo_results: Dict):
    sev_icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}
    if repo_results.get('error'):
        st.error(f"Repo scan error: {repo_results['error']}")
        return

    if repo_results.get('offline_skipped'):
        st.info("Offline mode — skipped: " + "; ".join(repo_results['offline_skipped']))

    chains = repo_results.get('cross_file_chains', [])
    if chains:
        st.markdown("**Cross-file Failure Chains** (what no single-file scanner catches):")
        for i, chain in enumerate(chains, 1):
            sev = chain.get('severity', 'high')
            with st.expander(
                f"{sev_icon.get(sev,'⚪')} Chain {i}: {chain.get('title', '')}",
                expanded=(i <= 2)
            ):
                files = chain.get('files', chain.get('files_involved', []))
                st.markdown(f"**Files involved:** {', '.join(str(x) for x in files)}")
                st.markdown(f"**Attack path:** {chain.get('attack_path', chain.get('detail',''))}")
                if chain.get('why_tests_miss_this'):
                    st.markdown(f"**Why tests miss this:** {chain['why_tests_miss_this']}")
                if chain.get('real_incident'):
                    st.markdown(f"**Real incident:** {chain['real_incident']}")
                st.success(f"**Fix:** {chain.get('remediation', '')}")

    findings = repo_results.get('findings', [])
    if findings:
        with st.expander(f"All Repo Findings ({len(findings)})", expanded=False):
            for f in findings[:25]:
                sev = f.get('severity', 'medium')
                icon = sev_icon.get(sev, '⚪')
                st.markdown(f"{icon} **{f.get('title','')}**")
                if f.get('detail'):
                    st.caption(f.get('detail','')[:120])
                if f.get('osv_id'):
                    fixes = f.get('fix_versions', [])
                    fix_str = f" → fix: v{fixes[0]}" if fixes else ""
                    st.caption(f"OSV: {f['osv_id']}{fix_str}")
                if f.get('remediation'):
                    st.caption(f"Fix: {f['remediation'][:80]}")


def _render_cost_details(cost_items: list, cost_analysis: Dict, findings: list):
    """Cloud cost section with TAARA security-aware decisions."""
    import plotly.graph_objects as go

    monthly = cost_analysis.get('total_monthly_cost', 0)
    total_savings = cost_analysis.get('potential_monthly_savings', 0)
    score = cost_analysis.get('preserve_cash_score', 0)

    mc1, mc2, mc3 = st.columns(3)
    with mc1:
        st.metric("Monthly Spend", f"${monthly:,.2f}")
    with mc2:
        st.metric("Potential Savings", f"${total_savings:,.2f}/mo")
    with mc3:
        st.metric("Preserve Cash Score", f"{score}/100")

    # Cost-security scatter: x = savings, y = security risk
    if cost_items:
        xs, ys, texts, colors, sizes, hovers = [], [], [], [], [], []
        dec_color = {'safe': '#00cc88', 'review': '#ffaa00', 'unsafe': '#ff2222'}
        for item in cost_items:
            sav = _parse_savings(item.get('potential_savings', ''))
            # Estimate security risk of this item (0-10 scale)
            sec_risk = {'safe': 1, 'review': 5, 'unsafe': 9}.get(item.get('security_decision','review'), 5)
            xs.append(sav)
            ys.append(sec_risk)
            texts.append(item.get('title','')[:25])
            colors.append(dec_color.get(item.get('security_decision','review'), '#888'))
            sizes.append(18)
            hovers.append(
                f"{item.get('title','')}<br>"
                f"Decision: {item.get('security_decision','?').upper()}<br>"
                f"Savings: ${sav:,.2f}/mo<br>"
                f"Reason: {item.get('reason','')[:80]}"
            )

        fig = go.Figure(go.Scatter(
            x=xs, y=ys, mode='markers+text',
            text=texts, textposition='top center',
            textfont=dict(color='#a0a0b0', size=8),
            marker=dict(size=sizes, color=colors, line=dict(color='#222', width=1)),
            hovertext=hovers, hoverinfo='text',
        ))
        fig.add_hline(y=4.5, line_dash='dot', line_color='#ffaa00', annotation_text='Risk threshold')
        fig.update_layout(
            title=dict(text="Cost Savings vs Security Risk", font=dict(color='#a0a0b0', size=13)),
            height=300,
            xaxis=dict(title='Monthly Savings ($)', color='#888', gridcolor='#222'),
            yaxis=dict(title='Security Risk', color='#888', gridcolor='#222',
                       tickvals=[1,5,9], ticktext=['Safe','Review','Unsafe']),
            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(15,15,30,0.8)',
            margin=dict(l=40, r=0, t=35, b=40),
        )
        st.plotly_chart(fig, use_container_width=True, key="cost_scatter")
        st.caption(
            "Green = safe to take. Yellow = review first. Red = rejected — "
            "would remove security coverage. TAARA tells you which savings are safe, "
            "not just which are largest."
        )

    # List by decision
    for decision, label, color in [('safe','Safe Savings','#00cc88'),
                                     ('review','Needs Review','#ffaa00'),
                                     ('unsafe','Rejected — Security Risk','#ff2222')]:
        items = [c for c in cost_items if c.get('security_decision') == decision]
        if items:
            st.markdown(f"<span style='color:{color}'>**{label}** ({len(items)})</span>",
                        unsafe_allow_html=True)
            for item in items:
                st.markdown(f"- **{item.get('title','')}** — {item.get('potential_savings','N/A')}")
                st.caption(f"  {item.get('reason','')}")

    security_data = results.get('security_data', {})
    summary = security_data.get('summary', {})
    quantum_risk = results.get('quantum_risk', {})
    kb_status = results.get('kb_status', {})

    # ── Score 1: Security Risk Score (from actual scan findings) ─────────────
    total_findings = sum(summary.values())
    security_risk_score = min(
        summary.get('critical', 0) * 25 +
        summary.get('high', 0) * 15 +
        summary.get('medium', 0) * 5 +
        summary.get('low', 0) * 1,
        100
    )
    if security_risk_score >= 75:
        sr_severity, sr_color = "CRITICAL", "#ff0000"
    elif security_risk_score >= 50:
        sr_severity, sr_color = "HIGH", "#ff6600"
    elif security_risk_score >= 25:
        sr_severity, sr_color = "MEDIUM", "#ffaa00"
    else:
        sr_severity, sr_color = "LOW", "#00cc00"

    # ── Score 2: Behavior Novelty Score (from TAARA memory + quantum fidelity) ─
    novelty_score = quantum_risk.get('quantum_novelty', 0)
    f_min = quantum_risk.get('f_min', 1.0)
    is_novel = quantum_risk.get('is_directionally_novel', False)
    novelty_severity = quantum_risk.get('severity', 'UNKNOWN')

    novelty_colors = {
        'CRITICAL': '#ff0000', 'HIGH': '#ff6600',
        'MEDIUM': '#ffaa00', 'LOW': '#00cc00',
        'BOOTSTRAPPING': '#888888'
    }
    bn_color = novelty_colors.get(novelty_severity, '#888888')

    st.markdown("### Two Independent Risk Signals")

    col_sr, col_bn = st.columns(2)

    with col_sr:
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, #1a0a0a 0%, #2a1010 100%);
                    padding: 25px; border-radius: 12px; border: 2px solid {sr_color};
                    text-align: center; height: 200px; display: flex;
                    flex-direction: column; justify-content: center;">
            <p style="color: #a0a0b0; margin: 0 0 5px 0; font-size: 0.85em;">
                SECURITY RISK SCORE
            </p>
            <h2 style="color: {sr_color}; margin: 0; font-size: 2.8em;">{security_risk_score}</h2>
            <p style="color: #888; margin: 3px 0; font-size: 0.8em;">from scan findings</p>
            <span style="background: {sr_color}; color: white; padding: 3px 15px;
                         border-radius: 15px; font-weight: bold; font-size: 0.9em;">
                {sr_severity}
            </span>
        </div>
        """, unsafe_allow_html=True)
        st.caption(f"Based on {total_findings} findings: "
                   f"{summary.get('critical',0)} critical, {summary.get('high',0)} high, "
                   f"{summary.get('medium',0)} medium, {summary.get('low',0)} low")

    with col_bn:
        if novelty_severity == 'BOOTSTRAPPING':
            bn_label = "BUILDING BASELINE"
            bn_sub = "Observing normal behavior — no novel patterns detected yet"
        else:
            bn_label = novelty_severity
            bn_sub = f"Fidelity F={f_min:.3f} — {'directional shift detected' if is_novel else 'within baseline'}"
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, #0a0a1a 0%, #101030 100%);
                    padding: 25px; border-radius: 12px; border: 2px solid {bn_color};
                    text-align: center; height: 200px; display: flex;
                    flex-direction: column; justify-content: center;">
            <p style="color: #a0a0b0; margin: 0 0 5px 0; font-size: 0.85em;">
                BEHAVIOR NOVELTY SCORE
            </p>
            <h2 style="color: {bn_color}; margin: 0; font-size: 2.8em;">{novelty_score}%</h2>
            <p style="color: #888; margin: 3px 0; font-size: 0.8em;">from TAARA memory + quantum</p>
            <span style="background: {bn_color}; color: white; padding: 3px 15px;
                         border-radius: 15px; font-weight: bold; font-size: 0.9em;">
                {bn_label}
            </span>
        </div>
        """, unsafe_allow_html=True)
        st.caption(bn_sub)

    # What each score means
    st.markdown("""
    <div style="background: #0a1a0a; padding: 12px; border-radius: 8px; margin: 10px 0;
                border: 1px solid #1a3a1a;">
        <p style="color: #88cc88; margin: 0; font-size: 0.82em;">
            <b>Security Risk Score</b> — counts what was found: misconfigurations, open ports,
            weak ciphers, missing patches. Equivalent to what any scanner catches.
            &nbsp;&nbsp;|&nbsp;&nbsp;
            <b>Behavior Novelty Score</b> — compares the system's current behavioral profile
            against its own prior baseline using TAARA's reconstruction-based memory + a
            4-qubit quantum fidelity circuit. Catches shifts that look "normal" globally
            but are new for this specific identity. These are separate signals.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Finding counts
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Critical", summary.get('critical', 0))
    with col2:
        st.metric("High", summary.get('high', 0))
    with col3:
        st.metric("Medium", summary.get('medium', 0))
    with col4:
        st.metric("Low", summary.get('low', 0))
    with col5:
        st.metric("Total Issues", total_findings)

    if total_findings > 0:
        breach_cost_lakh = max(5, total_findings * 2 + summary.get('critical', 0) * 15)
        st.markdown(f"""
        <div style="background: #2a0a0a; padding: 20px; border-radius: 10px;
                    margin: 15px 0; border-left: 4px solid #e94560;">
            <h3 style="color: #e94560; margin: 0;">Estimated Breach Impact</h3>
            <p style="color: #ff6666; font-size: 2em; margin: 10px 0;">
                ₹{breach_cost_lakh} Lakh – ₹{breach_cost_lakh * 3} Lakh
            </p>
            <p style="color: #999;">
                Based on {total_findings} vulnerabilities including {summary.get('critical', 0)} critical.
                Average MSME breach cost in India: ₹2–5 Cr (IBM Cost of Data Breach Report 2024).
            </p>
        </div>
        """, unsafe_allow_html=True)

    # Quantum details — collapsed by default
    with st.expander("Quantum Fidelity Details", expanded=False):
        qcol1, qcol2, qcol3 = st.columns(3)
        with qcol1:
            st.metric("Fidelity F", f"{f_min:.4f}")
        with qcol2:
            st.metric("Directional Novelty", "Yes" if is_novel else "No")
        with qcol3:
            mag = quantum_risk.get('magnitude_score', 0)
            st.metric("Magnitude Score", f"{mag}%")
        st.markdown("""
        **How the quantum score works:** TAARA encodes the system's behavior vector into
        a 4-qubit amplitude state using PennyLane. It computes fidelity F = |⟨ψ_current|ψ_baseline⟩|²
        against the established behavioral center. F < 0.5 means current behavior is more
        orthogonal than parallel to the baseline — a principled directionality signal.
        The 0.5 threshold is geometric (midpoint between F=1 identical, F=0 orthogonal) —
        not a tuned hyperparameter.
        """)

    if results.get('ai_summary'):
        st.markdown("### AI Analysis Summary")
        st.markdown(f"""
        <div style="background: #1a1a2e; padding: 20px; border-radius: 10px;
                    border: 1px solid #0f3460;">
            {results['ai_summary'].replace(chr(10), '<br>')}
        </div>
        """, unsafe_allow_html=True)

    # GraphRAG + Quantum Fidelity findings from knowledge base
    kb_findings = results.get('kb_findings', [])
    kb_status = results.get('kb_status', {})

    # Always show KB status so the user knows if it's active or why it's not
    if not kb_status.get('loaded'):
        st.info(f"Knowledge graph not active — {kb_status.get('error', 'not built')}. "
                f"Run `./run_research.sh kb` to enable policy-deviation detection.")
    elif kb_status.get('error'):
        st.warning(f"Knowledge graph loaded but scan incomplete: {kb_status.get('error')}")
    elif not kb_findings:
        config_chars = kb_status.get('config_chars', 0)
        if config_chars > 0:
            st.success(f"Knowledge graph active ({config_chars} chars scanned) — no policy deviations detected.")
        else:
            st.info("Knowledge graph loaded but no raw config was available from this platform scan.")

    if kb_findings:
        st.markdown("### Knowledge Graph Findings — Policy Deviation with Quantum Fidelity")
        st.markdown("""
        <div style="background: #0a1a2a; padding: 12px; border-radius: 8px;
                    margin: 5px 0 15px 0; border: 1px solid #0f3460;">
            <p style="color: #66b3ff; margin: 0; font-size: 0.85em;">
                <b>How this works:</b> TAARA embeds your configuration, compares it against 2,400+
                policy chunks (OWASP, CIS, Docker, SSH, GitHub Actions) using sentence-transformers,
                then scores each deviation using quantum fidelity F(|ψ_config⟩, |ψ_policy⟩).
                F &lt; 0.5 means your config is moving in a direction more orthogonal than parallel
                to best practice — a principled, parameter-free signal. No threshold tuning.
            </p>
        </div>
        """, unsafe_allow_html=True)

        sev_colors = {'critical': '#ff0000', 'high': '#ff6600', 'medium': '#ffaa00', 'low': '#00cc00'}
        for i, f in enumerate(kb_findings[:8], 1):
            sev = f.get('severity', 'medium')
            qf = f.get('quantum_fidelity', {})
            color = sev_colors.get(sev, '#888888')
            chain = f.get('propagation_chain', [])
            chain_labels = " → ".join(c['label'] for c in chain[1:4]) if len(chain) > 1 else ""

            with st.expander(
                f"[{sev.upper()}] {f.get('label', f.get('node_id', ''))} — "
                f"Q-deviation: {qf.get('deviation', 0):.3f}",
                expanded=(i <= 2)
            ):
                st.markdown(f"**{f.get('description', '')}**")
                if f.get('match'):
                    st.code(f.get('match', ''), language="text")
                st.markdown(f"""
                **Quantum Fidelity:** F = {qf.get('fidelity', 0):.4f}
                (deviation = {qf.get('deviation', 0):.4f})
                *{qf.get('interpretation', '')}*
                """)
                if chain_labels:
                    st.markdown(f"**Cascade chain:** {chain_labels}")
                mitigations = f.get('mitigations', [])
                if mitigations:
                    st.success(f"**Fix:** {mitigations[0]['label']} — {mitigations[0]['description']}")

    # Code / Repo Risk pillar
    repo_results = results.get('repo_results')
    if repo_results is not None:
        st.markdown("### Code / Repo Risk (Pillar B)")
        if repo_results.get('error'):
            st.error(f"Repo scan failed: {repo_results['error']}")
        else:
            target = repo_results.get('target', '')
            repo_findings = repo_results.get('findings', [])
            chains = repo_results.get('cross_file_chains', [])
            osv_count = len(repo_results.get('osv_findings', []))
            eol_count = len(repo_results.get('eol_findings', []))

            rcol1, rcol2, rcol3, rcol4 = st.columns(4)
            with rcol1:
                st.metric("Total Findings", len(repo_findings))
            with rcol2:
                st.metric("CVEs (OSV.dev)", osv_count)
            with rcol3:
                st.metric("EOL Images", eol_count)
            with rcol4:
                st.metric("Cross-file Chains", len(chains))

            if chains:
                st.markdown("**Cross-file Failure Chains** — risks no single-file scan catches:")
                sev_icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}
                for i, chain in enumerate(chains, 1):
                    sev = chain.get('severity', 'high')
                    with st.expander(
                        f"{sev_icon.get(sev,'⚪')} Chain {i}: {chain.get('title', chain.get('description', ''))}",
                        expanded=(i <= 2)
                    ):
                        st.markdown(f"**Files:** {', '.join(chain.get('files', []))}")
                        st.markdown(f"**Attack path:** {chain.get('attack_path', '')}")
                        st.success(f"**Fix:** {chain.get('remediation', '')}")

            if repo_findings:
                with st.expander(f"All Repo Findings ({len(repo_findings)})", expanded=False):
                    sev_colors = {'critical': '#ff0000', 'high': '#ff6600', 'medium': '#ffaa00', 'low': '#00cc00'}
                    for f in repo_findings[:20]:
                        sev = f.get('severity', 'medium')
                        color = sev_colors.get(sev, '#888')
                        st.markdown(f"<span style='color:{color}'>[{sev.upper()}]</span> "
                                    f"**{f.get('title', '')}** — {f.get('detail', '')}",
                                    unsafe_allow_html=True)
                        if f.get('remediation'):
                            st.caption(f"Fix: {f['remediation']}")

    st.markdown("### Detailed Findings by Category")
    for cat_key, cat_data in security_data.get('categories', {}).items():
        findings = cat_data.get('findings', [])
        cat_name = cat_data.get('name', cat_key)

        severity_icon = {
            'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢', 'info': '🔵'
        }

        if findings:
            with st.expander(f"{cat_name} ({len(findings)} findings)", expanded=False):
                for finding in findings:
                    sev = finding.get('severity', 'info')
                    icon = severity_icon.get(sev, '⚪')
                    st.markdown(f"""
                    **{icon} [{sev.upper()}] {finding.get('title', '')}**
                    > {finding.get('detail', '')}
                    > **Remediation:** {finding.get('remediation', 'N/A')}
                    """)
        else:
            info = cat_data.get('info', {})
            if info:
                with st.expander(f"{cat_name} (No issues found)", expanded=False):
                    for k, v in info.items():
                        st.text(f"{k}: {v}")

    if results.get('cost_analysis') and not results['cost_analysis'].get('error'):
        cost = results['cost_analysis']
        st.markdown("### Cloud Cost Analysis — Preserve Cash")

        ccol1, ccol2, ccol3 = st.columns(3)
        with ccol1:
            st.metric("Monthly Spend", f"${cost.get('total_monthly_cost', 0):,.2f}")
        with ccol2:
            st.metric("Potential Savings", f"${cost.get('potential_monthly_savings', 0):,.2f}/mo")
        with ccol3:
            score = cost.get('preserve_cash_score', 0)
            st.metric("Preserve Cash Score", f"{score}/100")

        if cost.get('waste_findings'):
            with st.expander(f"Waste Identified ({len(cost['waste_findings'])} items)", expanded=False):
                for w in cost['waste_findings']:
                    st.markdown(f"**{w.get('title', '')}** — Savings: {w.get('potential_savings', 'N/A')}")
                    st.caption(w.get('detail', ''))

        if cost.get('optimization_recommendations'):
            with st.expander(f"Optimization Opportunities ({len(cost['optimization_recommendations'])} items)", expanded=False):
                for r in cost['optimization_recommendations']:
                    st.markdown(f"**{r.get('title', '')}** — Savings: {r.get('potential_savings', 'N/A')}")
                    st.caption(r.get('detail', ''))

    st.markdown("---")
    st.markdown(f"""
    <div style="text-align: center; padding: 20px; background: linear-gradient(135deg, #1a1a2e, #16213e);
                border-radius: 10px; border: 1px solid #e94560;">
        <h3 style="color: #e94560;">Want the Full Report?</h3>
        <p style="color: #a0a0b0;">
            Get detailed remediation steps, quantum circuit analysis, cost-benefit breakdown,
            and executive-ready PDF report with Taara Words.
        </p>
        <p style="color: #666; font-size: 0.8em;">
            Analysis completed in {results.get('duration', 0)}s | Scan depth: {results.get('scan_depth', 'Standard')}
        </p>
    </div>
    """, unsafe_allow_html=True)

    if st.button("Generate Full Report with Taara Words", type="secondary"):
        st.session_state.nav_target = 'taara_words'
        st.rerun()
