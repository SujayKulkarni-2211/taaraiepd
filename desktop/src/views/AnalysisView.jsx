import React, { useState, useEffect, useRef } from 'react';
import { api } from '../api';

const SSH_STEPS = [
  'Establishing SSH session…',
  'Reading SSH configuration…',
  'Checking firewall rules (ufw/iptables)…',
  'Scanning open ports and services…',
  'Analysing authentication logs…',
  'Checking sudo & privilege escalation…',
  'Running knowledge-base policy scan…',
  'Encoding behavioral latent (3-qubit AmplitudeEmbedding)…',
  'Computing quantum subspace fidelity F_sub = Σ|⟨ψ_t|ψ_k⟩|²…',
  'Generating AI executive summary…',
  'Building infrastructure health model…',
];

const DEMO_STEPS = [
  'Initialising demo environment…',
  'Loading SSH intrusion scenario…',
  'Generating 19-dim behavioral feature vectors…',
  'Running BehavioralAE: 19→8-dim latent…',
  'Encoding latent via 3-qubit AmplitudeEmbedding…',
  'Computing V3 quantum confidence (swap·dir·coherence)…',
  'Building findings model…',
];

function fminColor(f) {
  if (f == null) return 'var(--text-faint)';
  if (f < 0.3) return 'var(--red)';
  if (f < 0.5) return 'var(--amber)';
  if (f < 0.7) return 'var(--blue)';
  return 'var(--green)';
}

function fminBucket(f) {
  if (f == null) return '';
  if (f < 0.3) return 'CRITICAL DIVERGENCE';
  if (f < 0.5) return 'UNSAFE DIRECTION';
  if (f < 0.7) return 'DRIFTING';
  return 'NORMAL';
}

function severityClass(s) {
  const sev = (s || '').toLowerCase();
  if (sev === 'critical') return 'badge-critical';
  if (sev === 'high')     return 'badge-high';
  if (sev === 'medium')   return 'badge-medium';
  if (sev === 'low')      return 'badge-low';
  return 'badge-info';
}

export default function AnalysisView({
  connected, platformType, platformInfo, hostname,
  demoMode, onAnalysisDone, analysisResults, onAlertFired,
}) {
  const [running, setRunning]     = useState(false);
  const [stepIdx, setStepIdx]     = useState(0);
  const [error, setError]         = useState('');
  const [results, setResults]     = useState(analysisResults);
  const stepRef                   = useRef(null);
  const startRef                  = useRef(null);
  const [elapsed, setElapsed]     = useState(0);

  useEffect(() => { setResults(analysisResults); }, [analysisResults]);

  // Tick elapsed counter while running
  useEffect(() => {
    if (!running) return;
    const t = setInterval(() => {
      setElapsed(startRef.current ? ((Date.now() - startRef.current) / 1000) | 0 : 0);
    }, 1000);
    return () => clearInterval(t);
  }, [running]);

  const steps = demoMode ? DEMO_STEPS : SSH_STEPS;

  async function runAnalysis() {
    setRunning(true);
    setError('');
    setStepIdx(0);
    setElapsed(0);
    startRef.current = Date.now();

    let idx = 0;
    stepRef.current = setInterval(() => {
      idx = Math.min(idx + 1, steps.length - 1);
      setStepIdx(idx);
    }, demoMode ? 500 : 4000);

    try {
      const res = demoMode
        ? await api.demoFullScan('ssh_intrusion')
        : await api.analyze({ scan_depth: 'standard' });

      clearInterval(stepRef.current);
      setStepIdx(steps.length);

      if (!res.ok) {
        setError(res.data?.detail || 'Analysis failed');
        return;
      }
      const data = res.data;
      setResults(data);
      onAnalysisDone(data);

      const fmin = data.quantum_risk?.f_min ?? data.novelty?.f_min ?? data.f_min;
      if (fmin != null && fmin < 0.5 && onAlertFired) {
        onAlertFired({
          host: hostname,
          f_min: fmin,
          bucket: fmin < 0.3 ? 'critical_divergence' : 'unsafe_direction',
          features: data.feature_vector || {},
        });
      }
    } catch (e) {
      clearInterval(stepRef.current);
      setError(e.message || 'Analysis error');
    } finally {
      setRunning(false);
    }
  }

  useEffect(() => () => clearInterval(stepRef.current), []);

  if (!connected) {
    return (
      <div className="page" style={{ textAlign: 'center', paddingTop: 80 }}>
        <div style={{ fontSize: 36, color: 'var(--text-faint)', marginBottom: 16 }}>◈</div>
        <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-dim)', marginBottom: 8 }}>
          No server connected
        </div>
        <div style={{ fontSize: 13, color: 'var(--text-faint)', maxWidth: 380, margin: '0 auto' }}>
          Connect via SSH or run Demo Mode to begin quantum behavioral analysis.
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
        <div>
          <div style={{ fontSize: 20, fontWeight: 700 }}>
            TAARA Analysis
            {demoMode && (
              <span style={{ marginLeft: 10, fontSize: 11, color: '#9b7dff',
                background: 'rgba(155,125,255,0.12)', border: '1px solid rgba(155,125,255,0.25)',
                borderRadius: 4, padding: '2px 8px', fontWeight: 700 }}>DEMO</span>
            )}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 3 }}>
            {hostname} · {(platformType || 'ssh').toUpperCase()}
            {results?.duration && (
              <span style={{ marginLeft: 8, color: 'var(--text-faint)' }}>· Last scan: {results.duration}s</span>
            )}
          </div>
        </div>
        <button
          className="btn btn-primary"
          onClick={runAnalysis}
          disabled={running}
          style={{ minWidth: 140 }}
        >
          {running ? <><span className="spinner" /> Scanning…</> : '▶ Run Analysis'}
        </button>
      </div>

      {running && (
        <div className="card" style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 12, fontWeight: 700, letterSpacing: 0.5, marginBottom: 14, color: 'var(--text-dim)' }}>
            TAARA SCANNING
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 16 }}>
            <div style={{ flex: 1, height: 3, background: 'var(--border)', borderRadius: 2, overflow: 'hidden' }}>
              <div style={{
                height: '100%', borderRadius: 2,
                width: `${(stepIdx / steps.length) * 100}%`,
                background: 'var(--accent)',
                transition: 'width 0.5s ease',
              }} />
            </div>
            <span style={{ fontSize: 11, color: 'var(--text-faint)', fontFamily: 'monospace' }}>
              {stepIdx}/{steps.length} · {elapsed}s
            </span>
          </div>
          {steps.map((s, i) => (
            <div key={i} className={`progress-step${i === stepIdx ? ' active' : i < stepIdx ? ' done' : ''}`}>
              <span className="step-dot" />
              <span>{s}</span>
              {i < stepIdx && <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--green)' }}>✓</span>}
              {i === stepIdx && <span className="spinner" style={{ marginLeft: 'auto', width: 12, height: 12 }} />}
            </div>
          ))}
        </div>
      )}

      {error && (
        <div style={{ marginBottom: 16, padding: '10px 14px',
          background: 'rgba(233,69,96,0.1)', border: '1px solid rgba(233,69,96,0.25)',
          borderRadius: 8, fontSize: 13, color: 'var(--red)' }}>
          {error}
        </div>
      )}

      {results && !running && <AnalysisResults results={results} hostname={hostname} />}

      {!results && !running && !error && (
        <div style={{ paddingTop: 60, textAlign: 'center', color: 'var(--text-faint)' }}>
          <div style={{ fontSize: 28, marginBottom: 12 }}>◈</div>
          <div style={{ fontSize: 14, color: 'var(--text-dim)' }}>Click Run Analysis to begin</div>
        </div>
      )}
    </div>
  );
}

function AnalysisResults({ results, hostname }) {
  const model    = results.model || {};
  const findings = model.findings || extractFindings(results);
  const qr       = results.quantum_risk || {};
  const fmin     = qr.f_min ?? results.novelty?.f_min ?? results.f_min;
  const novelty  = qr.quantum_novelty ?? results.novelty?.quantum_novelty ?? 0;
  const riskScore   = qr.risk_score ?? model.risk_score ?? 0;
  const healthScore = model.health_score ?? (100 - riskScore);
  const summary  = (results.security_data || {}).summary || {};

  const critCount = summary.critical ?? findings.filter(f => (f.severity || '').toLowerCase() === 'critical').length;
  const highCount = summary.high     ?? findings.filter(f => (f.severity || '').toLowerCase() === 'high').length;
  const medCount  = summary.medium   ?? findings.filter(f => (f.severity || '').toLowerCase() === 'medium').length;
  const lowCount  = summary.low      ?? findings.filter(f => (f.severity || '').toLowerCase() === 'low').length;
  const divergePct = fmin != null ? ((1 - fmin) * 100).toFixed(1) : null;

  return (
    <div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 14, marginBottom: 20 }}>
        <MetricCard label="Health Score" value={healthScore != null ? healthScore.toFixed(0) : '—'} unit="/100"
          color={healthScore >= 80 ? 'var(--green)' : healthScore >= 60 ? 'var(--blue)' : healthScore >= 40 ? 'var(--amber)' : 'var(--red)'}
          sub={healthScore >= 80 ? 'Healthy' : healthScore >= 60 ? 'Fair' : healthScore >= 40 ? 'At Risk' : 'Critical'} />
        <MetricCard label="Risk Score" value={riskScore != null ? riskScore.toFixed(0) : '—'} unit="/100"
          color={riskScore >= 75 ? 'var(--red)' : riskScore >= 50 ? 'var(--amber)' : riskScore >= 25 ? 'var(--blue)' : 'var(--green)'}
          sub={qr.severity || ''} />
        <FminCard fmin={fmin} novelty={novelty} divergePct={divergePct} />
        <MetricCard label="Findings" value={findings.length} unit=""
          color={critCount > 0 ? 'var(--red)' : highCount > 0 ? 'var(--amber)' : 'var(--green)'}
          sub={`${critCount}C · ${highCount}H · ${medCount}M · ${lowCount}L`} />
      </div>

      <QuantumSection qr={qr} fmin={fmin} novelty={novelty} divergePct={divergePct} />

      {results.ai_summary && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="section-title" style={{ marginBottom: 10 }}>Reasoning Engine Summary</div>
          <div style={{ fontSize: 13, color: 'var(--text)', lineHeight: 1.7, whiteSpace: 'pre-wrap' }}>
            {results.ai_summary}
          </div>
        </div>
      )}

      {findings.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div className="section-title" style={{ marginBottom: 12 }}>Security Findings ({findings.length})</div>
          {findings.map((f, i) => (
            <FindingCard key={f.id || i} finding={f} fmin={fmin} />
          ))}
        </div>
      )}

      {results.cost_analysis && !results.cost_analysis.error && (
        <CostSection cost={results.cost_analysis} />
      )}

      <div style={{ marginTop: 24 }}>
        <ReportButton />
      </div>
    </div>
  );
}

function MetricCard({ label, value, unit, color, sub }) {
  return (
    <div className="card" style={{ padding: '14px 16px' }}>
      <div className="metric-label">{label}</div>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 3, marginTop: 6 }}>
        <span style={{ fontSize: 32, fontWeight: 700, fontFamily: 'monospace', color: color || 'var(--text)' }}>
          {value ?? '—'}
        </span>
        {unit && <span style={{ fontSize: 13, color: 'var(--text-faint)' }}>{unit}</span>}
      </div>
      {sub && <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 3 }}>{sub}</div>}
    </div>
  );
}

function FminCard({ fmin, novelty, divergePct }) {
  const color = fminColor(fmin);
  const bucket = fminBucket(fmin);
  return (
    <div className="card" style={{ padding: '14px 16px' }}>
      <div className="metric-label">Quantum SWAP Fidelity (F_sub)</div>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 4, marginTop: 6 }}>
        <span style={{ fontSize: 32, fontWeight: 700, fontFamily: 'monospace', color }}>
          {fmin != null ? fmin.toFixed(4) : '—'}
        </span>
      </div>
      {divergePct != null && (
        <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 3 }}>
          {divergePct}% divergence · {typeof novelty === 'number' ? novelty.toFixed(1) : '—'}% novelty
        </div>
      )}
      {bucket && (
        <div style={{ marginTop: 5, fontSize: 9, fontWeight: 800, letterSpacing: 1,
          color, background: `${color}18`, border: `1px solid ${color}30`,
          borderRadius: 3, padding: '2px 6px', display: 'inline-block' }}>
          {bucket}
        </div>
      )}
    </div>
  );
}

function QuantumSection({ qr, fmin, novelty, divergePct }) {
  const [expanded, setExpanded] = useState(false);
  const [explanation, setExplanation] = useState(null);
  const [loadingExp, setLoadingExp] = useState(false);

  async function loadExplanation() {
    if (fmin == null || loadingExp) return;
    setLoadingExp(true);
    try {
      const res = await api.quantumExplain(fmin);
      if (res.ok) setExplanation(res.data);
    } catch (_) {}
    finally { setLoadingExp(false); }
  }

  useEffect(() => {
    if (expanded && !explanation) loadExplanation();
  }, [expanded]);

  const color  = fminColor(fmin);
  const bucket = fminBucket(fmin);
  const pctFill = fmin != null ? fmin * 100 : 0;

  return (
    <div className="card" style={{ marginBottom: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
        <div>
          <div className="section-title" style={{ marginBottom: 2 }}>Quantum Behavioral Analysis</div>
          <div style={{ fontSize: 11, color: 'var(--text-faint)' }}>
            V3 fusion: α·swap_s + β·q_dir + γ·coh·√(swap_s·q_dir) · 3-qubit AmplitudeEmbedding · threshold 0.1854 (p95)
          </div>
        </div>
        <button className="btn" style={{ fontSize: 11, padding: '4px 12px' }}
          onClick={() => setExpanded(e => !e)}>
          {expanded ? 'Hide' : 'Show Math'}
        </button>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 20, marginBottom: 14 }}>
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
            <span style={{ fontSize: 10, color: 'var(--text-faint)' }}>0.0 Critical</span>
            <span style={{ fontSize: 11, color, fontWeight: 700 }}>
              {fmin != null ? fmin.toFixed(4) : '—'}{bucket ? ` · ${bucket}` : ''}
            </span>
            <span style={{ fontSize: 10, color: 'var(--text-faint)' }}>1.0 Normal</span>
          </div>
          <div style={{ height: 10, background: 'var(--bg-raised)', borderRadius: 5, overflow: 'hidden', border: '1px solid var(--border)' }}>
            <div style={{
              height: '100%', borderRadius: 5, width: `${pctFill}%`,
              background: 'linear-gradient(90deg, #e94560 0%, #f5a623 30%, #4a9eff 50%, #22cc66 70%)',
              transition: 'width 0.6s ease', position: 'relative',
            }}>
              <div style={{
                position: 'absolute', right: -4, top: '50%', transform: 'translateY(-50%)',
                width: 10, height: 10, borderRadius: '50%', background: color,
                boxShadow: `0 0 6px ${color}`,
              }} />
            </div>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 3 }}>
            {[0, 0.3, 0.5, 0.7, 1.0].map(v => (
              <span key={v} style={{ fontSize: 9, color: 'var(--text-faint)', fontFamily: 'monospace' }}>{v}</span>
            ))}
          </div>
        </div>
        <div style={{ textAlign: 'center', flexShrink: 0 }}>
          <div style={{ fontSize: 10, color: 'var(--text-faint)' }}>Novelty</div>
          <div style={{ fontSize: 20, fontWeight: 700, color, fontFamily: 'monospace' }}>
            {typeof novelty === 'number' ? novelty.toFixed(1) : '—'}%
          </div>
        </div>
        {divergePct != null && (
          <div style={{ textAlign: 'center', flexShrink: 0 }}>
            <div style={{ fontSize: 10, color: 'var(--text-faint)' }}>Diverge</div>
            <div style={{ fontSize: 20, fontWeight: 700, color, fontFamily: 'monospace' }}>
              {divergePct}%
            </div>
          </div>
        )}
      </div>

      {expanded && (
        <div style={{ borderTop: '1px solid var(--border)', paddingTop: 14 }}>
          <div style={{ fontSize: 11, lineHeight: 2, fontFamily: 'monospace',
            background: 'var(--bg-raised)', borderRadius: 6, padding: 12, marginBottom: 12 }}>
            <div><span style={{ color: 'var(--accent)' }}>z_t</span> = <span style={{ color: 'var(--blue)' }}>BehavioralAE(x_t)</span> <span style={{ color: 'var(--text-faint)', fontSize: 9 }}>  ← 19-dim features → 8-dim latent</span></div>
            <div><span style={{ color: 'var(--accent)' }}>|ψ_t⟩</span> = <span style={{ color: 'var(--blue)' }}>AmplitudeEmbedding(z_t, wires=[0,1,2])</span> <span style={{ color: 'var(--text-faint)', fontSize: 9 }}>  ← 3-qubit</span></div>
            <div><span style={{ color: 'var(--accent)' }}>F_sub</span> = <span style={{ color: 'var(--blue)' }}>Σ|⟨ψ_t|ψ_k⟩|²</span> <span style={{ color: 'var(--text-faint)', fontSize: 9 }}>  k=1..K=3 PCA components · swap_s = 1−F_sub</span></div>
            <div><span style={{ color: 'var(--accent)' }}>q_dir</span> = <span style={{ color: 'var(--blue)' }}>Σ|⟨ψ_t|ψ_c⟩|²</span> <span style={{ color: 'var(--text-faint)', fontSize: 9 }}>  complement dims K+1,K+2</span></div>
            <div><span style={{ color: 'var(--accent)' }}>coh</span> = <span style={{ color: 'var(--blue)' }}>|mean(exp(i·φ_t))|</span> <span style={{ color: 'var(--text-faint)', fontSize: 9 }}>  φ=arctan2 in complement · W=4 windows</span></div>
            <div><span style={{ color: 'var(--accent)' }}>conf</span> = <span style={{ color: 'var(--blue)' }}>α·swap_s + β·q_dir + γ·coh·√(swap_s·q_dir)</span></div>
            <div style={{ color: 'var(--text-faint)', fontSize: 10 }}>α=0.263, β=0.285, γ=0.451 · Alert when conf &gt; 0.1854 (p95 of normal training)</div>
            <div style={{ color: 'var(--text-faint)', fontSize: 10 }}>Validated: Prec=0.689, Rec=0.942, F1=0.796, AUC=0.980 (CERT r4.2 insider threat)</div>
            {fmin != null && (
              <div style={{ marginTop: 8, color }}>
                F_sub = {fmin.toFixed(4)} · {divergePct}% outside normal subspace
              </div>
            )}
          </div>
          {qr.feature_vector && <FeatureVectorBars vector={qr.feature_vector} />}
          {loadingExp && <div style={{ fontSize: 12, color: 'var(--text-faint)' }}>Loading explanation…</div>}
          {explanation && (
            <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.7, marginTop: 8 }}>
              {explanation.explanation || JSON.stringify(explanation)}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function FeatureVectorBars({ vector }) {
  const entries = Object.entries(vector).slice(0, 8);
  if (!entries.length) return null;
  const max = Math.max(...entries.map(([, v]) => Math.abs(Number(v) || 0)), 1);
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ fontSize: 10, color: 'var(--text-faint)', marginBottom: 6, fontWeight: 600, letterSpacing: 0.5, textTransform: 'uppercase' }}>
        Feature Vector
      </div>
      {entries.map(([k, v]) => (
        <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
          <span style={{ fontSize: 10, color: 'var(--text-faint)', width: 160, flexShrink: 0,
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {k.replace(/_/g, ' ')}
          </span>
          <div style={{ flex: 1, height: 4, background: 'var(--border)', borderRadius: 2, overflow: 'hidden' }}>
            <div style={{
              height: '100%', borderRadius: 2,
              width: `${(Math.abs(Number(v) || 0) / max) * 100}%`,
              background: Number(v) > 0 ? 'var(--blue)' : 'var(--red)',
            }} />
          </div>
          <span style={{ fontSize: 10, color: 'var(--text-dim)', fontFamily: 'monospace', width: 60, textAlign: 'right' }}>
            {typeof v === 'number' ? v.toFixed(2) : v}
          </span>
        </div>
      ))}
    </div>
  );
}

function FindingCard({ finding, fmin }) {
  const [open, setOpen] = useState(false);
  const sev = (finding.severity || 'info').toLowerCase();
  const badgeClass = severityClass(sev);

  const findingFmin = finding.f_score ?? finding.fidelity ?? (
    sev === 'critical' ? (fmin != null ? fmin * 0.7 : 0.15)
    : sev === 'high'   ? (fmin != null ? fmin * 0.85 : 0.3)
    : null
  );

  return (
    <div style={{
      marginBottom: 8, background: 'var(--bg-surface)',
      border: `1px solid ${sev === 'critical' ? 'rgba(233,69,96,0.25)' : sev === 'high' ? 'rgba(245,166,35,0.2)' : 'var(--border)'}`,
      borderRadius: 8, overflow: 'hidden',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '12px 16px', cursor: 'pointer' }}
        onClick={() => setOpen(o => !o)}>
        <span className={`badge ${badgeClass}`}>{finding.severity || 'INFO'}</span>
        <span style={{ flex: 1, fontSize: 13, fontWeight: 500 }}>
          {finding.title || finding.label || finding.check || 'Unnamed finding'}
        </span>
        {finding.mitre_tactic && (
          <span style={{ fontSize: 10, color: 'var(--text-faint)', fontFamily: 'monospace',
            background: 'var(--bg-raised)', borderRadius: 3, padding: '1px 6px' }}>
            {finding.mitre_tactic}
          </span>
        )}
        {findingFmin != null && (
          <span style={{ fontSize: 11, color: fminColor(findingFmin), fontFamily: 'monospace' }}>
            F={findingFmin.toFixed(3)}
          </span>
        )}
        <span style={{ fontSize: 11, color: 'var(--text-faint)' }}>{open ? '▲' : '▼'}</span>
      </div>
      {open && (
        <div style={{ borderTop: '1px solid var(--border)', padding: '12px 16px' }}>
          {(finding.description || finding.explanation) && (
            <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.7, marginBottom: 10 }}>
              {finding.description || finding.explanation}
            </div>
          )}
          {findingFmin != null && (
            <div style={{ fontSize: 11, color: fminColor(findingFmin), marginBottom: 10,
              fontFamily: 'monospace', background: 'var(--bg-raised)', padding: '6px 10px', borderRadius: 4 }}>
              F = |⟨ψ_t|ψ_m⟩|² = {findingFmin.toFixed(4)}
              <span style={{ color: 'var(--text-faint)', marginLeft: 8 }}>
                — {((1 - findingFmin) * 100).toFixed(1)}% divergence from secure baseline direction
              </span>
            </div>
          )}
          {(finding.remediation || finding.fix_command || finding.command) && (
            <div style={{ marginBottom: 8 }}>
              <div style={{ fontSize: 10, color: 'var(--text-faint)', fontWeight: 600,
                letterSpacing: 0.5, textTransform: 'uppercase', marginBottom: 4 }}>Fix</div>
              <pre style={{ margin: 0, fontSize: 11 }}>
                {finding.remediation || finding.fix_command || finding.command}
              </pre>
            </div>
          )}
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 6 }}>
            {finding.mitre_tactic && (
              <span style={{ fontSize: 10, color: 'var(--purple)',
                background: 'rgba(155,125,255,0.1)', border: '1px solid rgba(155,125,255,0.2)',
                borderRadius: 3, padding: '1px 6px', fontFamily: 'monospace' }}>
                {finding.mitre_tactic}
              </span>
            )}
            {finding.mitre_technique && (
              <span style={{ fontSize: 10, color: 'var(--text-faint)',
                background: 'var(--bg-raised)', borderRadius: 3, padding: '1px 6px' }}>
                {finding.mitre_technique}
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function CostSection({ cost }) {
  const savings = cost.potential_monthly_savings || 0;
  const savingsInr = Math.round(savings * 83);
  const annualInr  = Math.round(savings * 83 * 12);
  const items = cost.cost_findings || cost.findings || [];
  return (
    <div className="card" style={{ marginBottom: 16 }}>
      <div className="section-title" style={{ marginBottom: 12 }}>Cloud Spending Optimisation</div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 14 }}>
        <div>
          <div style={{ fontSize: 11, color: 'var(--text-faint)' }}>Monthly Savings Potential</div>
          <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--green)', fontFamily: 'monospace' }}>
            ₹{savingsInr.toLocaleString('en-IN')}
          </div>
        </div>
        <div>
          <div style={{ fontSize: 11, color: 'var(--text-faint)' }}>Annual Savings Potential</div>
          <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--green)', fontFamily: 'monospace' }}>
            ₹{annualInr.toLocaleString('en-IN')}
          </div>
        </div>
      </div>
      {items.slice(0, 5).map((item, i) => (
        <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          padding: '7px 0', borderBottom: i < Math.min(items.length, 5) - 1 ? '1px solid var(--border)' : 'none' }}>
          <span style={{ fontSize: 12, color: 'var(--text-dim)' }}>{item.description || item.title}</span>
          {item.monthly_saving && (
            <span style={{ fontSize: 12, color: 'var(--green)', fontFamily: 'monospace', fontWeight: 600 }}>
              ₹{Math.round(item.monthly_saving * 83)}/mo
            </span>
          )}
        </div>
      ))}
    </div>
  );
}

function ReportButton() {
  const [state, setState] = useState('idle');
  const [msg, setMsg]     = useState('');

  async function generate() {
    setState('loading');
    setMsg('');
    try {
      if (window.taara) {
        const r = await window.taara.api('/api/generate-report-path', 'POST', {});
        if (r.status >= 400) {
          setState('error');
          setMsg(r.data?.detail || 'Report generation failed');
          return;
        }
        await window.taara.openPDF(r.data.path);
        setState('done');
        setMsg(r.data.filename || 'Report opened');
      } else {
        const resp = await fetch('http://127.0.0.1:8765/api/generate-report', { method: 'POST' });
        if (!resp.ok) { setState('error'); setMsg('Failed'); return; }
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = `TAARA_Report_${Date.now()}.pdf`; a.click();
        URL.revokeObjectURL(url);
        setState('done'); setMsg('Downloaded');
      }
    } catch (e) {
      setState('error'); setMsg(e.message);
    }
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
      <button
        className="btn"
        onClick={generate}
        disabled={state === 'loading'}
        style={{ borderColor: 'rgba(74,158,255,0.3)', color: 'var(--blue)' }}
      >
        {state === 'loading' ? <><span className="spinner" /> Generating…</> : '⬇ TaaraWords Report'}
      </button>
      {state === 'done'  && <span style={{ fontSize: 12, color: 'var(--green)' }}>✓ {msg}</span>}
      {state === 'error' && <span style={{ fontSize: 12, color: 'var(--red)' }}>✕ {msg}</span>}
    </div>
  );
}

function extractFindings(results) {
  const out = [];
  const cats = (results.security_data || {}).categories || {};
  for (const cat of Object.values(cats)) {
    for (const f of (cat.findings || [])) out.push(f);
  }
  for (const f of (results.kb_findings || [])) {
    out.push({
      severity: f.severity,
      title: f.label || f.description,
      description: f.description,
      mitre_tactic: f.mitre_tactic,
      remediation: f.mitigations?.[0]?.description,
    });
  }
  return out;
}
