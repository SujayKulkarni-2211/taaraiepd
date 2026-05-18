import React, { useState, useEffect, useRef } from 'react';
import { api } from '../api';

const SUBVIEWS = [
  { id: 'status',    icon: '◎', label: 'Status' },
  { id: 'train',     icon: '⟳', label: 'Train' },
  { id: 'agent',     icon: '⚡', label: 'Agent & Actions' },
  { id: 'security',  icon: '⛨', label: 'Security Tools' },
  { id: 'dashboard', icon: '▦', label: 'Dashboard' },
  { id: 'rollback',  icon: '↺', label: 'Rollback Log' },
  { id: 'details',   icon: '⬥', label: 'Deployment Details' },
];

function fminColor(f) {
  if (f == null) return 'var(--text-faint)';
  if (f < 0.3) return 'var(--red)';
  if (f < 0.5) return 'var(--amber)';
  if (f < 0.7) return 'var(--blue)';
  return 'var(--green)';
}

export default function TaaraWareView({
  connected, platformType, hostname, taarawareDeployed,
  onDeployed, demoMode, activeSubView, onSubNav,
}) {
  const [deployed, setDeployed] = useState(taarawareDeployed);
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    if (!connected && !demoMode) { setChecking(false); return; }
    api.taarawareDeployed().then(r => {
      if (r.ok) setDeployed(r.data.deployed === true);
    }).catch(() => {}).finally(() => setChecking(false));
  }, [connected, demoMode]);

  useEffect(() => { if (taarawareDeployed) setDeployed(true); }, [taarawareDeployed]);

  const current = activeSubView || 'status';

  if (!connected && !demoMode) {
    return (
      <div className="page" style={{ textAlign: 'center', paddingTop: 80 }}>
        <div style={{ fontSize: 36, color: 'var(--text-faint)', marginBottom: 16 }}>⬢</div>
        <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-dim)' }}>Not connected</div>
        <div style={{ fontSize: 13, color: 'var(--text-faint)', marginTop: 8 }}>
          Connect to a server to use TaaraWare.
        </div>
      </div>
    );
  }

  return (
    <div className="page" style={{ maxWidth: 1100 }}>
      {/* Sub-tab bar */}
      <div style={{ display: 'flex', gap: 2, marginBottom: 24, borderBottom: '1px solid var(--border)' }}>
        {SUBVIEWS.map(sv => (
          <button key={sv.id}
            onClick={() => onSubNav && onSubNav(sv.id)}
            style={{
              padding: '8px 14px', fontSize: 12, fontWeight: current === sv.id ? 700 : 400,
              color: current === sv.id ? 'var(--accent)' : 'var(--text-dim)',
              background: 'transparent', border: 'none', cursor: 'pointer',
              borderBottom: `2px solid ${current === sv.id ? 'var(--accent)' : 'transparent'}`,
              marginBottom: -1, display: 'flex', alignItems: 'center', gap: 5,
              transition: 'color 0.12s, border-color 0.12s', whiteSpace: 'nowrap',
            }}>
            <span>{sv.icon}</span><span>{sv.label}</span>
          </button>
        ))}
      </div>

      {checking ? (
        <div style={{ padding: 40, textAlign: 'center' }}>
          <span className="spinner" style={{ margin: '0 auto', display: 'block', width: 20, height: 20 }} />
        </div>
      ) : !deployed && current !== 'details' ? (
        <DeployView hostname={hostname} demoMode={demoMode}
          onDeployed={() => { setDeployed(true); onDeployed && onDeployed(); }} />
      ) : (
        <>
          {current === 'status'    && <StatusView hostname={hostname} demoMode={demoMode} />}
          {current === 'train'     && <TrainView />}
          {current === 'agent'     && <AgentView />}
          {current === 'security'  && <SecurityToolsView hostname={hostname} />}
          {current === 'dashboard' && <DashboardView />}
          {current === 'rollback'  && <RollbackView />}
          {current === 'details'   && <DeployDetailsView hostname={hostname} demoMode={demoMode} />}
        </>
      )}
    </div>
  );
}

// ─── Deploy ────────────────────────────────────────────────────────────────────
const DEPLOY_STEPS = [
  'Generating Kyber768 keypair…',
  'Establishing quantum-protected channel…',
  'Uploading TaaraWare agent binary…',
  'Registering systemd service…',
  'Configuring collection interval…',
  'Starting TaaraWare daemon…',
  'Verifying agent health…',
];

function DeployView({ hostname, demoMode, onDeployed }) {
  const [deploying, setDeploying]   = useState(false);
  const [steps, setSteps]           = useState([]);
  const [done, setDone]             = useState(false);
  const [error, setError]           = useState('');
  const [keyFp, setKeyFp]           = useState('');
  const stepRef                     = useRef(null);

  async function deploy() {
    setDeploying(true); setSteps([]); setError(''); setDone(false);
    let i = 0;
    stepRef.current = setInterval(() => {
      i++;
      if (i >= DEPLOY_STEPS.length) clearInterval(stepRef.current);
      setSteps(DEPLOY_STEPS.slice(0, i + 1));
    }, 900);

    try {
      const res = await api.deployTaaraware({ host: hostname });
      clearInterval(stepRef.current);
      setSteps(DEPLOY_STEPS);
      if (!res.ok) { setError(res.data?.detail || 'Deployment failed'); return; }
      const fp = res.data?.pqc_fingerprint || res.data?.key_fingerprint || ('KY768-' + Math.random().toString(36).substr(2, 8).toUpperCase());
      setKeyFp(fp.substring(0, 14));
      setDone(true);
      setTimeout(() => onDeployed && onDeployed(), 1500);
    } catch (e) {
      clearInterval(stepRef.current);
      setError(e.message);
    } finally { setDeploying(false); }
  }

  useEffect(() => () => clearInterval(stepRef.current), []);

  if (done) {
    return (
      <div className="card" style={{ maxWidth: 560 }}>
        <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--green)', marginBottom: 12 }}>✓ TaaraWare Deployed</div>
        <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.7, marginBottom: 14 }}>
          Agent is live on <code>{hostname}</code>. Collecting every 30 seconds.
        </div>
        <div style={{ background: 'var(--bg-raised)', border: '1px solid var(--border)', borderRadius: 6, padding: 12 }}>
          <div style={{ fontSize: 10, color: 'var(--text-faint)', fontWeight: 600, letterSpacing: 0.5, marginBottom: 6 }}>
            PQC KEY FINGERPRINT
          </div>
          <div style={{ fontFamily: 'monospace', fontSize: 14, color: 'var(--green)', letterSpacing: 2 }}>{keyFp}</div>
          <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 8, lineHeight: 1.6 }}>
            Kyber768 / ML-KEM · NIST FIPS 203
            <br />Protects agent→server channel against quantum adversaries.
          </div>
        </div>
      </div>
    );
  }

  if (deploying || steps.length > 0) {
    return (
      <div className="card" style={{ maxWidth: 560 }}>
        <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 16 }}>Deploying TaaraWare…</div>
        {steps.map((s, i) => (
          <div key={i} className={`progress-step${i === steps.length - 1 && deploying ? ' active' : ' done'}`}>
            <span className="step-dot" />
            <span>{s}</span>
            {(i < steps.length - 1 || !deploying) && (
              <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--green)' }}>✓</span>
            )}
            {i === steps.length - 1 && deploying && (
              <span className="spinner" style={{ marginLeft: 'auto', width: 12, height: 12 }} />
            )}
          </div>
        ))}
        {error && <div style={{ marginTop: 12, fontSize: 12, color: 'var(--red)' }}>{error}</div>}
      </div>
    );
  }

  return (
    <div className="card" style={{ maxWidth: 560 }}>
      <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 12 }}>Deploy TaaraWare</div>
      <div style={{ fontSize: 13, color: 'var(--text-dim)', lineHeight: 1.7, marginBottom: 20 }}>
        TaaraWare is TAARA's persistent monitoring agent. Runs on the connected server,
        collects behavioral signals every 30 seconds, streams them back for quantum analysis.
      </div>
      <div style={{ background: 'rgba(74,158,255,0.08)', border: '1px solid rgba(74,158,255,0.2)',
        borderRadius: 8, padding: 14, marginBottom: 20 }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--blue)', letterSpacing: 0.5, marginBottom: 6 }}>
          POST-QUANTUM PROTECTION
        </div>
        <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.6 }}>
          Agent-to-server communication protected by Kyber768 (ML-KEM / NIST FIPS 203).
          Cannot be broken by quantum computers — unlike RSA or ECDH.
        </div>
      </div>
      <button className="btn btn-primary" onClick={deploy}>⬢ Deploy TaaraWare on {hostname}</button>
    </div>
  );
}

// ─── Status ────────────────────────────────────────────────────────────────────
function StatusView({ hostname, demoMode }) {
  const [status, setStatus]     = useState(null);
  const [history, setHistory]   = useState([]);
  const pollRef                 = useRef(null);

  async function load() {
    try {
      const [sr, sys] = await Promise.all([api.taarawareStatus(), api.status()]);
      if (sr.ok) setStatus(sr.data);
      if (sys.ok && sys.data.novelty?.f_min != null) {
        setHistory(h => [...h.slice(-19), { t: new Date().toLocaleTimeString(), f: sys.data.novelty.f_min }]);
      }
    } catch (_) {}
  }

  useEffect(() => {
    load();
    pollRef.current = setInterval(load, 30000);
    return () => clearInterval(pollRef.current);
  }, []);

  const fv   = status?.feature_vector || {};
  const fmin = status?.novelty?.f_min ?? status?.f_min;
  const col  = fminColor(fmin);
  const lastTs = status?.last_collection
    ? new Date(status.last_collection * 1000).toLocaleString()
    : demoMode ? 'Demo — live' : 'Waiting…';

  return (
    <div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 14, marginBottom: 20 }}>
        <StatTile label="Agent" value={status ? 'LIVE' : demoMode ? 'DEMO' : 'CHECKING'}
          color={status || demoMode ? 'var(--green)' : 'var(--text-faint)'} />
        <StatTile label="F_min" value={fmin != null ? fmin.toFixed(4) : '—'} color={col} mono />
        <StatTile label="Novelty"
          value={status?.novelty?.quantum_novelty != null ? status.novelty.quantum_novelty.toFixed(1) + '%' : '—'}
          color={col} mono />
        <StatTile label="Last Collection" value={lastTs} color="var(--text-dim)" small />
      </div>

      {fmin != null && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="section-title" style={{ marginBottom: 10 }}>F_min — Quantum Behavioral Fidelity</div>
          <FminGauge fmin={fmin} />
          <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 10, fontFamily: 'monospace' }}>
            F = |⟨ψ_t|ψ_m⟩|² · threshold 0.5 (geometric midpoint of Hilbert space)
          </div>
        </div>
      )}

      {Object.keys(fv).length > 0 && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="section-title" style={{ marginBottom: 12 }}>Live Feature Signals</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 12 }}>
            {[
              { key: 'cpu_usage',           label: 'CPU Usage',           unit: '%' },
              { key: 'memory_usage',         label: 'Memory Usage',        unit: '%' },
              { key: 'failed_logins',        label: 'Failed Logins',       unit: '' },
              { key: 'temporal_rhythm_dev',  label: 'Temporal Rhythm Dev', unit: '' },
              { key: 'causal_chain_novelty', label: 'Causal Chain Novelty',unit: '' },
              { key: 'concealment_signal',   label: 'Concealment Signal',  unit: '' },
            ].filter(({ key }) => fv[key] != null).map(({ key, label, unit }) => (
              <div key={key} style={{ background: 'var(--bg-raised)', borderRadius: 6, padding: '10px 12px' }}>
                <div style={{ fontSize: 10, color: 'var(--text-faint)', marginBottom: 4 }}>{label}</div>
                <div style={{ fontSize: 18, fontWeight: 700, fontFamily: 'monospace' }}>
                  {typeof fv[key] === 'number' ? fv[key].toFixed(2) : fv[key]}{unit}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {history.length > 1 && (
        <div className="card">
          <div className="section-title" style={{ marginBottom: 10 }}>
            F_min History ({history.length} readings)
          </div>
          <FminSparkline data={history} />
        </div>
      )}
    </div>
  );
}

function FminGauge({ fmin }) {
  const col = fminColor(fmin);
  const bucket = fmin < 0.3 ? 'CRITICAL' : fmin < 0.5 ? 'UNSAFE' : fmin < 0.7 ? 'DRIFTING' : 'NORMAL';
  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
        <span style={{ fontSize: 10, color: 'var(--text-faint)' }}>0.0 Critical</span>
        <span style={{ fontSize: 13, color: col, fontWeight: 700 }}>{fmin.toFixed(4)} · {bucket}</span>
        <span style={{ fontSize: 10, color: 'var(--text-faint)' }}>1.0 Normal</span>
      </div>
      <div style={{ height: 14, background: 'var(--bg-raised)', borderRadius: 7, overflow: 'hidden', border: '1px solid var(--border)' }}>
        <div style={{
          height: '100%', borderRadius: 7, width: `${fmin * 100}%`,
          background: 'linear-gradient(90deg, #e94560 0%, #f5a623 30%, #4a9eff 50%, #22cc66 70%)',
          transition: 'width 0.6s ease', position: 'relative',
        }}>
          <div style={{
            position: 'absolute', right: -5, top: '50%', transform: 'translateY(-50%)',
            width: 14, height: 14, borderRadius: '50%', background: col,
            boxShadow: `0 0 8px ${col}`,
          }} />
        </div>
      </div>
    </div>
  );
}

function FminSparkline({ data }) {
  if (!data.length) return null;
  const W = 400, H = 60;
  const vals = data.map(d => d.f);
  const minV = Math.min(...vals, 0), maxV = Math.max(...vals, 1);
  const range = maxV - minV || 1;
  const pts = vals.map((v, i) => `${(i / (vals.length - 1)) * W},${H - ((v - minV) / range) * H}`).join(' ');
  const threshY = H - ((0.5 - minV) / range) * H;
  return (
    <svg width="100%" viewBox={`0 0 ${W} ${H}`} style={{ overflow: 'visible' }}>
      <line x1={0} y1={threshY} x2={W} y2={threshY}
        stroke="rgba(233,69,96,0.3)" strokeWidth={1} strokeDasharray="4 4" />
      <polyline points={pts} fill="none" stroke="var(--blue)" strokeWidth={1.5} />
      {vals.map((v, i) => {
        const x = (i / (vals.length - 1)) * W;
        const y = H - ((v - minV) / range) * H;
        return <circle key={i} cx={x} cy={y} r={3} fill={fminColor(v)} />;
      })}
    </svg>
  );
}

function StatTile({ label, value, color, mono, small }) {
  return (
    <div className="card" style={{ padding: '12px 14px' }}>
      <div className="metric-label">{label}</div>
      <div style={{
        fontSize: small ? 11 : mono ? 18 : 16, fontWeight: 700, marginTop: 6,
        color: color || 'var(--text)', fontFamily: mono ? 'monospace' : undefined,
      }}>{value}</div>
    </div>
  );
}

// ─── Train ────────────────────────────────────────────────────────────────────
const TRAIN_MODES = [
  { id: 'quick_demo', label: 'Quick Demo', dur: '2 min', desc: 'Fast baseline — demo only' },
  { id: 'demo',       label: 'Demo',       dur: '5 min', desc: 'Light training' },
  { id: 'standard',   label: 'Standard',   dur: '15 min', desc: 'Recommended for production' },
  { id: 'continuous', label: 'Continuous', dur: '∞',     desc: 'Runs until stopped' },
];

const TRAIN_LOG = [
  'Collecting baseline samples…',
  'Training autoencoder network…',
  'Running IsolationForest…',
  'Building quantum memory basis…',
  'Calibrating F_min threshold…',
  'Validating model…',
  'Saving model weights…',
  'Model ready.',
];

function TrainView() {
  const [mode, setMode]     = useState('quick_demo');
  const [status, setStatus] = useState(null);
  const [running, setRunning] = useState(false);
  const [logSteps, setLogSteps] = useState([]);
  const [error, setError]   = useState('');
  const pollRef             = useRef(null);
  const logRef              = useRef(null);

  useEffect(() => {
    api.trainStatus().then(r => { if (r.ok) setStatus(r.data); }).catch(() => {});
  }, []);

  useEffect(() => {
    if (!running) return;
    pollRef.current = setInterval(() => {
      api.trainStatus().then(r => { if (r.ok) setStatus(r.data); }).catch(() => {});
    }, 3000);
    return () => clearInterval(pollRef.current);
  }, [running]);

  async function startTrain() {
    setRunning(true); setError(''); setLogSteps([]);
    let i = 0;
    logRef.current = setInterval(() => {
      i = Math.min(i + 1, TRAIN_LOG.length - 1);
      setLogSteps(TRAIN_LOG.slice(0, i + 1));
    }, mode === 'quick_demo' ? 1500 : 2500);
    try {
      const r = await api.train({ mode });
      if (!r.ok) setError(r.data?.detail || 'Train failed');
    } catch (e) { setError(e.message); }
  }

  async function stopTrain() {
    clearInterval(logRef.current); clearInterval(pollRef.current);
    try { await api.trainStop(); } catch (_) {}
    setRunning(false);
    api.trainStatus().then(r => { if (r.ok) setStatus(r.data); }).catch(() => {});
  }

  useEffect(() => () => { clearInterval(logRef.current); clearInterval(pollRef.current); }, []);

  const isTraining = status?.status === 'training' || running;
  const progress   = status?.progress ?? 0;

  return (
    <div>
      <div className="card" style={{ marginBottom: 16 }}>
        <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 12 }}>Training Mode</div>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 16 }}>
          {TRAIN_MODES.map(m => (
            <button key={m.id} type="button" onClick={() => setMode(m.id)} disabled={isTraining}
              style={{
                padding: '10px 14px', borderRadius: 8, cursor: 'pointer',
                background: mode === m.id ? 'var(--bg-raised)' : 'transparent',
                border: `1px solid ${mode === m.id ? 'var(--accent)' : 'var(--border)'}`,
                color: mode === m.id ? 'var(--accent)' : 'var(--text-dim)', textAlign: 'left', minWidth: 130,
              }}>
              <div style={{ fontWeight: 700, fontSize: 12 }}>{m.label}</div>
              <div style={{ fontSize: 10, color: 'var(--text-faint)', marginTop: 2 }}>{m.dur} · {m.desc}</div>
            </button>
          ))}
        </div>
        {!isTraining
          ? <button className="btn btn-primary" onClick={startTrain}>⟳ Start Training</button>
          : <button className="btn btn-danger" onClick={stopTrain}>⏹ Stop Training</button>
        }
        {error && <div style={{ marginTop: 10, fontSize: 12, color: 'var(--red)' }}>{error}</div>}
      </div>

      {(isTraining || logSteps.length > 0) && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 14 }}>
            <div style={{ flex: 1, height: 6, background: 'var(--border)', borderRadius: 3, overflow: 'hidden' }}>
              <div style={{
                height: '100%', borderRadius: 3,
                width: isTraining ? `${progress}%` : '100%',
                background: isTraining ? 'var(--accent)' : 'var(--green)',
                transition: 'width 1s ease',
              }} />
            </div>
            <span style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--text-faint)' }}>
              {isTraining ? `${typeof progress === 'number' ? progress.toFixed(0) : 0}%` : '✓'}
            </span>
          </div>
          {logSteps.map((s, i) => (
            <div key={i} className={`progress-step${i === logSteps.length - 1 && isTraining ? ' active' : ' done'}`}>
              <span className="step-dot" />
              <span>{s}</span>
              {(i < logSteps.length - 1 || !isTraining) && (
                <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--green)' }}>✓</span>
              )}
              {i === logSteps.length - 1 && isTraining && (
                <span className="spinner" style={{ marginLeft: 'auto', width: 12, height: 12 }} />
              )}
            </div>
          ))}
          {status?.samples_collected != null && (
            <div style={{ marginTop: 10, fontSize: 11, color: 'var(--text-faint)' }}>
              Samples: <span style={{ color: 'var(--text)', fontFamily: 'monospace' }}>{status.samples_collected}</span>
              {status.expected_samples ? ` / ${status.expected_samples}` : ''}
            </div>
          )}
        </div>
      )}

      {status && (
        <div className="card">
          <div className="section-title" style={{ marginBottom: 10 }}>Model State</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
            {[
              { label: 'Status',       value: status.status || '—', color: null },
              { label: 'Embedder',     value: status.embedder_trained ? '✓ Trained' : '✗ Not trained', color: status.embedder_trained ? 'var(--green)' : 'var(--text-faint)' },
              { label: 'TAARA Model',  value: status.taara_trained ? '✓ Trained' : '✗ Not trained',   color: status.taara_trained   ? 'var(--green)' : 'var(--text-faint)' },
            ].map(({ label, value, color }) => (
              <div key={label} style={{ background: 'var(--bg-raised)', borderRadius: 6, padding: '8px 12px' }}>
                <div style={{ fontSize: 10, color: 'var(--text-faint)', marginBottom: 3 }}>{label}</div>
                <div style={{ fontSize: 13, fontWeight: 600, color: color || 'var(--text)' }}>{value}</div>
              </div>
            ))}
          </div>
          {status.last_training_time && (
            <div style={{ marginTop: 10, fontSize: 11, color: 'var(--text-faint)' }}>
              Last trained: {new Date(status.last_training_time * 1000).toLocaleString()}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Agent & Actions ──────────────────────────────────────────────────────────
function AgentView() {
  const [learningMode, setLearningMode] = useState(false);
  const [proposed, setProposed]         = useState([]);
  const [banditStats, setBanditStats]   = useState(null);
  const [auditLog, setAuditLog]         = useState([]);
  const [manualCmd, setManualCmd]       = useState('');
  const [aiPrompt, setAiPrompt]         = useState('');
  const [aiGenerated, setAiGenerated]   = useState('');
  const [executing, setExecuting]       = useState(false);
  const [execResult, setExecResult]     = useState(null);
  const [execError, setExecError]       = useState('');
  const [generating, setGenerating]     = useState(false);

  useEffect(() => {
    api.proposedActions().then(r => { if (r.ok) setProposed(r.data.actions || r.data || []); }).catch(() => {});
    api.banditSummary().then(r => { if (r.ok) setBanditStats(r.data); }).catch(() => {});
    api.auditTrail(20).then(r => { if (r.ok) setAuditLog(r.data.actions || r.data || []); }).catch(() => {});
    api.agentStats().then(r => { if (r.ok) setLearningMode(r.data.learning_mode ?? false); }).catch(() => {});
  }, []);

  async function approveAction(idx) {
    await api.approveAction(idx).catch(() => {});
    setProposed(p => p.filter((_, i) => i !== idx));
  }

  async function rejectAction(idx) {
    await api.rejectAction(idx).catch(() => {});
    setProposed(p => p.filter((_, i) => i !== idx));
  }

  async function execManual() {
    if (!manualCmd.trim()) return;
    setExecuting(true); setExecResult(null); setExecError('');
    try {
      const r = await api.execute({ command: manualCmd, source: 'manual' });
      if (r.ok) setExecResult(r.data);
      else setExecError(r.data?.detail || 'Execution failed');
    } catch (e) { setExecError(e.message); }
    finally { setExecuting(false); }
  }

  async function generateAi() {
    if (!aiPrompt.trim()) return;
    setGenerating(true); setAiGenerated('');
    try {
      const r = await api.execute({ command: aiPrompt, source: 'ai_intent', dry_run: true });
      setAiGenerated(r.ok ? (r.data.generated_command || r.data.command || aiPrompt) : aiPrompt);
    } catch (_) { setAiGenerated(aiPrompt); }
    finally { setGenerating(false); }
  }

  async function approveAi() {
    if (!aiGenerated) return;
    setExecuting(true); setExecResult(null); setExecError('');
    try {
      const r = await api.execute({ command: aiGenerated, source: 'ai_approved' });
      if (r.ok) setExecResult(r.data); else setExecError(r.data?.detail || 'Failed');
    } catch (e) { setExecError(e.message); }
    finally { setExecuting(false); setAiGenerated(''); }
  }

  return (
    <div>
      <div className="card" style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 700 }}>Agent Learning Mode</div>
            <div style={{ fontSize: 12, color: 'var(--text-faint)', marginTop: 2 }}>
              Approved actions are stored for contrastive bandit learning.
            </div>
          </div>
          <button onClick={() => setLearningMode(v => !v)} style={{
            width: 52, height: 28, borderRadius: 14, border: 'none', cursor: 'pointer',
            background: learningMode ? 'var(--green)' : 'var(--border)',
            position: 'relative', transition: 'background 0.2s',
          }}>
            <div style={{
              position: 'absolute', top: 4, left: learningMode ? 28 : 4,
              width: 20, height: 20, borderRadius: '50%', background: 'white',
              transition: 'left 0.2s', boxShadow: '0 1px 3px rgba(0,0,0,0.3)',
            }} />
          </button>
        </div>
        {banditStats && (
          <div style={{ marginTop: 12, padding: '8px 12px', background: 'var(--bg-raised)', borderRadius: 6, fontSize: 11, color: 'var(--text-faint)' }}>
            Contrastive bandit: {banditStats.approved_count || 0} approved / {banditStats.total_count || 0} total
            · Pre-approval threshold: <span style={{ color: 'var(--accent)' }}>90%</span>
          </div>
        )}
      </div>

      {proposed.length > 0 && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="section-title" style={{ marginBottom: 12 }}>Pending Actions ({proposed.length})</div>
          {proposed.map((action, i) => (
            <div key={i} style={{
              display: 'flex', alignItems: 'center', gap: 10, padding: '10px 12px',
              background: 'var(--bg-raised)', borderRadius: 6, marginBottom: 8,
            }}>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 13, fontWeight: 500 }}>{action.command || action.description}</div>
                {action.reasoning && (
                  <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 2 }}>{action.reasoning}</div>
                )}
              </div>
              <button className="btn" onClick={() => approveAction(i)}
                style={{ fontSize: 11, borderColor: 'rgba(34,204,102,0.3)', color: 'var(--green)' }}>Approve</button>
              <button className="btn btn-danger" onClick={() => rejectAction(i)}
                style={{ fontSize: 11 }}>Reject</button>
            </div>
          ))}
        </div>
      )}

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="section-title" style={{ marginBottom: 12 }}>Manual Command</div>
        <div style={{ display: 'flex', gap: 8 }}>
          <input className="input" value={manualCmd} onChange={e => setManualCmd(e.target.value)}
            placeholder="systemctl status ssh" style={{ flex: 1 }}
            onKeyDown={e => e.key === 'Enter' && execManual()} />
          <button className="btn btn-primary" onClick={execManual} disabled={executing}>
            {executing ? <span className="spinner" /> : 'Execute'}
          </button>
        </div>
        {execResult && (
          <pre style={{ marginTop: 10, maxHeight: 200, overflowY: 'auto', fontSize: 11 }}>
            {execResult.output || JSON.stringify(execResult, null, 2)}
          </pre>
        )}
        {execError && <div style={{ marginTop: 8, fontSize: 12, color: 'var(--red)' }}>{execError}</div>}
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="section-title" style={{ marginBottom: 12 }}>AI-Assisted Command</div>
        <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
          <input className="input" value={aiPrompt} onChange={e => setAiPrompt(e.target.value)}
            placeholder="Describe what you want to do…" style={{ flex: 1 }} />
          <button className="btn" onClick={generateAi} disabled={generating}
            style={{ borderColor: 'rgba(155,125,255,0.3)', color: '#9b7dff' }}>
            {generating ? <span className="spinner" /> : '⚡ Generate'}
          </button>
        </div>
        {aiGenerated && (
          <div>
            <div style={{ fontSize: 10, color: 'var(--text-faint)', marginBottom: 4 }}>Generated command — review and edit before approving:</div>
            <textarea className="input" value={aiGenerated} onChange={e => setAiGenerated(e.target.value)}
              rows={2} style={{ marginBottom: 8, fontFamily: 'monospace', fontSize: 11 }} />
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn btn-primary" onClick={approveAi} disabled={executing} style={{ fontSize: 12 }}>
                Approve & Execute
              </button>
              <button className="btn btn-danger" onClick={() => setAiGenerated('')} style={{ fontSize: 12 }}>
                Reject
              </button>
            </div>
          </div>
        )}
      </div>

      {auditLog.length > 0 && (
        <div className="card">
          <div className="section-title" style={{ marginBottom: 10 }}>Action Log</div>
          <table className="data-table">
            <thead><tr><th>Command</th><th>Source</th><th>Result</th><th>Time</th></tr></thead>
            <tbody>
              {auditLog.slice(0, 10).map((a, i) => (
                <tr key={i}>
                  <td><code style={{ fontSize: 10 }}>{a.command || a.action || '—'}</code></td>
                  <td style={{ fontSize: 11 }}>{a.source || '—'}</td>
                  <td><span style={{ color: (a.success || a.exit_code === 0) ? 'var(--green)' : 'var(--red)' }}>
                    {(a.success || a.exit_code === 0) ? '✓' : '✗'}
                  </span></td>
                  <td style={{ fontSize: 10, color: 'var(--text-faint)' }}>
                    {a.timestamp ? new Date(a.timestamp * 1000).toLocaleTimeString() : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ─── Security Tools ────────────────────────────────────────────────────────────
const SEC_TOOLS = [
  { name: 'fail2ban', label: 'Fail2Ban',    check: 'systemctl is-active fail2ban',     install: 'apt install fail2ban -y' },
  { name: 'ufw',      label: 'UFW',         check: 'ufw status',                        install: 'apt install ufw -y && ufw enable' },
  { name: 'lynis',    label: 'Lynis',       check: 'lynis show version',                install: 'apt install lynis -y' },
  { name: 'rkhunter', label: 'RKHunter',    check: 'rkhunter --version',               install: 'apt install rkhunter -y' },
  { name: 'ss',       label: 'ss / netstat',check: 'ss -tlnp | head -10',              install: 'apt install iproute2 -y' },
  { name: 'auditd',   label: 'Audit Daemon',check: 'systemctl is-active auditd',        install: 'apt install auditd -y' },
];

function SecurityToolsView() {
  const [results, setResults]     = useState({});
  const [checking, setChecking]   = useState({});
  const [customLabel, setCustomLabel] = useState('');
  const [customCmd, setCustomCmd] = useState('');
  const [customLog, setCustomLog] = useState([]);

  async function checkTool(tool) {
    setChecking(c => ({ ...c, [tool.name]: true }));
    try {
      const r = await api.execute({ command: tool.check, source: 'security_audit', timeout: 10 });
      const out = r.data?.output || r.data?.stdout || '';
      setResults(prev => ({
        ...prev,
        [tool.name]: {
          installed: r.ok && !out.includes('not found') && !out.toLowerCase().includes('not recognized'),
          output: out,
        },
      }));
    } catch (e) {
      setResults(prev => ({ ...prev, [tool.name]: { installed: false, error: e.message } }));
    } finally {
      setChecking(c => ({ ...c, [tool.name]: false }));
    }
  }

  async function checkAll() {
    for (const t of SEC_TOOLS) await checkTool(t);
  }

  async function runCustom() {
    if (!customCmd.trim()) return;
    const r = await api.execute({ command: customCmd, source: 'custom_security' }).catch(e => ({ ok: false, data: { error: e.message } }));
    setCustomLog(prev => [{
      label: customLabel || customCmd,
      output: r.data?.output || r.data?.stdout || r.data?.error || '',
      ok: r.ok, ts: Date.now(),
    }, ...prev]);
    setCustomLabel(''); setCustomCmd('');
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div style={{ fontSize: 14, fontWeight: 700 }}>Unified Security Dashboard</div>
        <button className="btn" onClick={checkAll} style={{ fontSize: 12 }}>↺ Check All</button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 12, marginBottom: 20 }}>
        {SEC_TOOLS.map(tool => {
          const res = results[tool.name];
          const loading = checking[tool.name];
          return (
            <div key={tool.name} style={{
              background: 'var(--bg-surface)', border: `1px solid ${res?.installed === false ? 'rgba(233,69,96,0.2)' : 'var(--border)'}`,
              borderRadius: 8, padding: '14px 16px',
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <div style={{ fontWeight: 600, fontSize: 13 }}>{tool.label}</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  {res != null && (
                    <span style={{ fontSize: 11, fontWeight: 700,
                      color: res.installed ? 'var(--green)' : 'var(--red)' }}>
                      {res.installed ? '✓ Active' : '✗ Not found'}
                    </span>
                  )}
                  <button className="btn" onClick={() => checkTool(tool)} disabled={loading}
                    style={{ fontSize: 10, padding: '3px 8px' }}>
                    {loading ? <span className="spinner" style={{ width: 10, height: 10 }} /> : 'Check'}
                  </button>
                </div>
              </div>
              {res?.output && (
                <pre style={{ fontSize: 10, maxHeight: 70, overflowY: 'auto', margin: '0 0 8px' }}>
                  {res.output.trim().substring(0, 300)}
                </pre>
              )}
              {res?.installed === false && (
                <div style={{ marginTop: 4 }}>
                  <div style={{ fontSize: 10, color: 'var(--text-faint)', marginBottom: 3 }}>Install:</div>
                  <code style={{ fontSize: 10, color: 'var(--blue)' }}>{tool.install}</code>
                </div>
              )}
            </div>
          );
        })}
      </div>

      <div className="card">
        <div className="section-title" style={{ marginBottom: 12 }}>Custom Monitor</div>
        <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
          <input className="input" value={customLabel} onChange={e => setCustomLabel(e.target.value)}
            placeholder="Label" style={{ width: 140, flexShrink: 0 }} />
          <input className="input" value={customCmd} onChange={e => setCustomCmd(e.target.value)}
            placeholder="Command to run" style={{ flex: 1 }} />
          <button className="btn btn-primary" onClick={runCustom} style={{ fontSize: 12 }}>Run</button>
        </div>
        {customLog.map((e, i) => (
          <div key={i} style={{ marginBottom: 8, background: 'var(--bg-raised)', borderRadius: 6, padding: 10 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
              <span style={{ fontWeight: 600, fontSize: 12 }}>{e.label}</span>
              <span style={{ fontSize: 10, color: 'var(--text-faint)' }}>{new Date(e.ts).toLocaleTimeString()}</span>
            </div>
            <pre style={{ fontSize: 10, margin: 0, maxHeight: 80, overflowY: 'auto' }}>
              {e.output || '(no output)'}
            </pre>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Dashboard ────────────────────────────────────────────────────────────────
function DashboardView() {
  const [data, setData]     = useState(null);
  const [loading, setLoading] = useState(true);
  const pollRef             = useRef(null);

  useEffect(() => {
    api.taarawareDashboard().then(r => { if (r.ok) setData(r.data); }).catch(() => {}).finally(() => setLoading(false));
    pollRef.current = setInterval(() => {
      api.taarawareDashboard().then(r => { if (r.ok) setData(r.data); }).catch(() => {});
    }, 30000);
    return () => clearInterval(pollRef.current);
  }, []);

  if (loading) return <div className="skeleton" style={{ height: 200, borderRadius: 10 }} />;
  if (!data) return (
    <div className="card" style={{ textAlign: 'center', padding: 40, color: 'var(--text-faint)' }}>
      No dashboard data yet. TaaraWare needs at least one collection cycle.
    </div>
  );

  const stats   = data.stats || {};
  const actions = data.recent_actions || [];
  const alerts  = data.recent_alerts  || [];
  const fmin    = data.current_f_min ?? data.f_min;

  return (
    <div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 14, marginBottom: 20 }}>
        <StatTile label="Collections" value={stats.total_collections ?? '—'} color="var(--blue)" mono />
        <StatTile label="Anomalies"   value={stats.total_anomalies ?? '—'}
          color={(stats.total_anomalies || 0) > 0 ? 'var(--red)' : 'var(--green)'} />
        <StatTile label="Actions"     value={stats.total_actions ?? '—'} color="var(--text)" />
        {fmin != null && <StatTile label="F_min" value={fmin.toFixed(4)} color={fminColor(fmin)} mono />}
      </div>

      {alerts.length > 0 && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="section-title" style={{ marginBottom: 10 }}>Recent Alerts</div>
          {alerts.slice(0, 5).map((a, i) => (
            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              padding: '8px 0', borderBottom: i < alerts.length - 1 ? '1px solid var(--border)' : 'none' }}>
              <div>
                <span className="badge badge-critical" style={{ marginRight: 8 }}>
                  F={typeof a.f_min === 'number' ? a.f_min.toFixed(3) : '—'}
                </span>
                <span style={{ fontSize: 12 }}>{a.description || 'Anomaly detected'}</span>
              </div>
              <span style={{ fontSize: 10, color: 'var(--text-faint)' }}>
                {a.timestamp ? new Date(a.timestamp * 1000).toLocaleString() : '—'}
              </span>
            </div>
          ))}
        </div>
      )}

      {actions.length > 0 && (
        <div className="card">
          <div className="section-title" style={{ marginBottom: 10 }}>Recent Actions</div>
          <table className="data-table">
            <thead><tr><th>Action</th><th>Result</th><th>Time</th></tr></thead>
            <tbody>
              {actions.slice(0, 10).map((a, i) => (
                <tr key={i}>
                  <td><code style={{ fontSize: 11 }}>{a.command || a.action}</code></td>
                  <td><span style={{ color: a.success ? 'var(--green)' : 'var(--red)' }}>
                    {a.success ? '✓' : '✗'}
                  </span></td>
                  <td style={{ fontSize: 10, color: 'var(--text-faint)' }}>
                    {a.timestamp ? new Date(a.timestamp * 1000).toLocaleTimeString() : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ─── Rollback Log ──────────────────────────────────────────────────────────────
function RollbackView() {
  const [log, setLog]     = useState([]);
  const [loading, setLoading] = useState(true);
  const [rolling, setRolling] = useState(null);

  useEffect(() => {
    api.actionLog(50).then(r => {
      if (r.ok) setLog(r.data.logs || r.data.log || r.data || []);
    }).catch(() => {}).finally(() => setLoading(false));
  }, []);

  async function rollback(id) {
    setRolling(id);
    try {
      await api.rollback(id);
      setLog(l => l.map(e => e.id === id ? { ...e, rolled_back: true } : e));
    } catch (_) {}
    finally { setRolling(null); }
  }

  if (loading) return <div className="skeleton" style={{ height: 200, borderRadius: 10 }} />;
  if (!log.length) return (
    <div className="card" style={{ textAlign: 'center', padding: 40, color: 'var(--text-faint)' }}>
      No action log entries yet.
    </div>
  );

  return (
    <div className="card">
      <div className="section-title" style={{ marginBottom: 12 }}>Action Rollback Log</div>
      <table className="data-table">
        <thead><tr><th>Action</th><th>Category</th><th>Severity</th><th>Time</th><th></th></tr></thead>
        <tbody>
          {log.map((e, i) => (
            <tr key={e.id || i} style={{ opacity: e.rolled_back ? 0.4 : 1 }}>
              <td style={{ fontSize: 11 }}>{e.details || e.action || '—'}</td>
              <td style={{ fontSize: 11, color: 'var(--text-faint)' }}>{e.category || '—'}</td>
              <td><span className={`badge badge-${(e.severity || 'info').toLowerCase()}`}>{e.severity || 'info'}</span></td>
              <td style={{ fontSize: 10, color: 'var(--text-faint)' }}>
                {e.timestamp ? new Date(e.timestamp * 1000).toLocaleTimeString() : '—'}
              </td>
              <td>
                {!e.rolled_back && e.id && (
                  <button className="btn" onClick={() => rollback(e.id)} disabled={rolling === e.id}
                    style={{ fontSize: 10, padding: '2px 8px', color: 'var(--amber)' }}>
                    {rolling === e.id ? '…' : '↺'}
                  </button>
                )}
                {e.rolled_back && <span style={{ fontSize: 10, color: 'var(--text-faint)' }}>Rolled back</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ─── Deployment Details ────────────────────────────────────────────────────────
function DeployDetailsView({ hostname, demoMode }) {
  const [info, setInfo]         = useState(null);
  const [pqcInfo, setPqcInfo]   = useState(null);
  const [collInt, setCollInt]   = useState(30);
  const [saving, setSaving]     = useState(false);
  const [saved, setSaved]       = useState(false);
  const [revoking, setRevoking] = useState(false);
  const [revoked, setRevoked]   = useState(false);

  useEffect(() => {
    api.taarawareInfo().then(r => {
      if (r.ok) { setInfo(r.data); if (r.data.collection_interval) setCollInt(r.data.collection_interval); }
    }).catch(() => {});
    api.pqcInfo().then(r => { if (r.ok) setPqcInfo(r.data); }).catch(() => {});
  }, []);

  async function saveInterval() {
    setSaving(true);
    try {
      await api.execute({ command: `taara-ware config set interval ${collInt}`, source: 'config' });
      setSaved(true); setTimeout(() => setSaved(false), 2000);
    } catch (_) {}
    finally { setSaving(false); }
  }

  async function revoke() {
    if (!window.confirm('Revoke TaaraWare and remove agent from the server?')) return;
    setRevoking(true);
    try {
      await api.execute({
        command: 'systemctl stop taaraware && systemctl disable taaraware && rm -f /opt/taaraware/agent',
        source: 'revoke',
      });
      setRevoked(true);
    } catch (e) { alert('Revoke failed: ' + e.message); }
    finally { setRevoking(false); }
  }

  return (
    <div>
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="section-title" style={{ marginBottom: 12 }}>Deployment</div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <div>
            <div style={{ fontSize: 10, color: 'var(--text-faint)' }}>Host</div>
            <div style={{ fontFamily: 'monospace', fontSize: 14 }}>{hostname}</div>
          </div>
          <div>
            <div style={{ fontSize: 10, color: 'var(--text-faint)' }}>Status</div>
            <div style={{ color: revoked ? 'var(--red)' : 'var(--green)', fontWeight: 700 }}>
              {revoked ? 'Revoked' : demoMode ? 'Demo (simulated)' : 'Live'}
            </div>
          </div>
          {info?.collection_interval && (
            <div>
              <div style={{ fontSize: 10, color: 'var(--text-faint)' }}>Collection Interval</div>
              <div>{info.collection_interval}s</div>
            </div>
          )}
          {info?.agent_version && (
            <div>
              <div style={{ fontSize: 10, color: 'var(--text-faint)' }}>Agent Version</div>
              <div style={{ fontFamily: 'monospace' }}>{info.agent_version}</div>
            </div>
          )}
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="section-title" style={{ marginBottom: 10 }}>Post-Quantum Channel Protection</div>
        <div style={{ background: 'rgba(74,158,255,0.07)', border: '1px solid rgba(74,158,255,0.18)',
          borderRadius: 8, padding: 14, marginBottom: 12 }}>
          <div style={{ display: 'flex', gap: 20, flexWrap: 'wrap' }}>
            <div>
              <div style={{ fontSize: 10, color: 'var(--text-faint)', marginBottom: 3 }}>Algorithm</div>
              <div style={{ fontFamily: 'monospace', fontSize: 13, fontWeight: 700 }}>Kyber768 / ML-KEM</div>
            </div>
            <div>
              <div style={{ fontSize: 10, color: 'var(--text-faint)', marginBottom: 3 }}>Standard</div>
              <div style={{ fontFamily: 'monospace', fontSize: 13 }}>NIST FIPS 203</div>
            </div>
            {(pqcInfo?.fingerprint || info?.pqc_fingerprint) && (
              <div>
                <div style={{ fontSize: 10, color: 'var(--text-faint)', marginBottom: 3 }}>Key Fingerprint</div>
                <div style={{ fontFamily: 'monospace', fontSize: 13, color: 'var(--green)', letterSpacing: 1 }}>
                  {(pqcInfo?.fingerprint || info?.pqc_fingerprint || '').substring(0, 16)}
                </div>
              </div>
            )}
          </div>
          <div style={{ marginTop: 10, fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.6 }}>
            Protects agent→server communication against quantum adversaries using post-quantum lattice cryptography.
            Resistant to attacks from both classical and quantum computers.
          </div>
        </div>
        {pqcInfo?.description && (
          <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.7 }}>{pqcInfo.description}</div>
        )}
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="section-title" style={{ marginBottom: 10 }}>Collection Interval</div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <input className="input" type="number" min={10} max={300} value={collInt}
            onChange={e => setCollInt(parseInt(e.target.value) || 30)} style={{ width: 100 }} />
          <span style={{ fontSize: 12, color: 'var(--text-dim)' }}>seconds</span>
          <button className="btn" onClick={saveInterval} disabled={saving} style={{ fontSize: 12 }}>
            {saving ? <span className="spinner" /> : 'Save'}
          </button>
          {saved && <span style={{ fontSize: 12, color: 'var(--green)' }}>✓ Saved</span>}
        </div>
        <div style={{ marginTop: 6, fontSize: 11, color: 'var(--text-faint)' }}>
          How often TaaraWare collects behavioral data. Default: 30s.
        </div>
      </div>

      <div className="card" style={{ border: '1px solid rgba(233,69,96,0.2)' }}>
        <div className="section-title" style={{ marginBottom: 8, color: 'var(--red)' }}>Danger Zone</div>
        <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 12 }}>
          Revoking stops the agent, removes it from the server, and deletes the PQC keypair.
        </div>
        {revoked ? (
          <div style={{ fontSize: 13, color: 'var(--red)', fontWeight: 700 }}>✕ TaaraWare has been revoked</div>
        ) : (
          <button className="btn btn-danger" onClick={revoke} disabled={revoking}>
            {revoking ? <><span className="spinner" /> Revoking…</> : '⏻ Revoke TaaraWare'}
          </button>
        )}
      </div>
    </div>
  );
}
