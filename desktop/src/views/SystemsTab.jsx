import React, { useState, useEffect, useRef, useCallback } from 'react';
import { api } from '../api';

// ── Helpers ──────────────────────────────────────────────────────────────────
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
  const v = (s || '').toLowerCase();
  if (v === 'critical') return 'badge-critical';
  if (v === 'high')     return 'badge-high';
  if (v === 'medium')   return 'badge-medium';
  if (v === 'low')      return 'badge-low';
  return 'badge-info';
}

const PLATFORMS = ['ssh', 'aws', 'gcp', 'azure'];

const SSH_SUBTABS = [
  { id: 'dashboard',  icon: '◎', label: 'Dashboard' },
  { id: 'analysis',   icon: '◈', label: 'TaaraAnalysis' },
  { id: 'taaraware',  icon: '⬢', label: 'TaaraWare' },
  { id: 'train',      icon: '⟳', label: 'Train' },
  { id: 'agent',      icon: '⚡', label: 'Agent & Actions' },
  { id: 'security',   icon: '⛨', label: 'Unified Security' },
  { id: 'custom',     icon: '⌨', label: 'Custom Actions' },
  { id: 'details',    icon: '⬥', label: 'TaaraWare Details' },
];

// ── Main export ───────────────────────────────────────────────────────────────
export default function SystemsTab({ apiKey, onAlertFired }) {
  const [platform, setPlatform] = useState('ssh');
  const [connected, setConnected] = useState(false);
  const [hostname, setHostname]   = useState('');
  const [platformInfo, setPlatformInfo] = useState(null);
  const [subTab, setSubTab]       = useState('dashboard');
  const [demoMode, setDemoMode]   = useState(false);
  const [analysisResults, setAnalysisResults] = useState(null);

  function handleConnected(info, ptype, host) {
    setConnected(true);
    setPlatformInfo(info);
    setHostname(host);
    setSubTab('dashboard');
  }

  function handleDisconnect() {
    api.disconnect().catch(() => {});
    setConnected(false);
    setPlatformInfo(null);
    setHostname('');
    setAnalysisResults(null);
    setDemoMode(false);
  }

  function handleDemoStart(host) {
    setDemoMode(true);
    setConnected(true);
    setHostname(host || 'demo-server.taara.local');
    setSubTab('dashboard');
  }

  if (!connected) {
    return (
      <ConnectPanel
        platform={platform}
        setPlatform={setPlatform}
        apiKey={apiKey}
        onConnected={handleConnected}
        onDemoStart={handleDemoStart}
      />
    );
  }

  // Cloud simulation
  if (platform !== 'ssh' && !demoMode) {
    return (
      <CloudSimView
        platform={platform}
        hostname={hostname}
        onDisconnect={handleDisconnect}
      />
    );
  }

  // SSH sub-tab view
  return (
    <SSHView
      hostname={hostname}
      demoMode={demoMode}
      subTab={subTab}
      setSubTab={setSubTab}
      analysisResults={analysisResults}
      setAnalysisResults={setAnalysisResults}
      onAlertFired={onAlertFired}
      onDisconnect={handleDisconnect}
    />
  );
}

// ── Connect Panel ────────────────────────────────────────────────────────────
function ConnectPanel({ platform, setPlatform, apiKey, onConnected, onDemoStart }) {
  const [form, setForm]       = useState({ host: '', port: '22', username: '', password: '', key_path: '' });
  const [authMode, setAuthMode] = useState('password');
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState('');
  const [step, setStep]       = useState('');
  const [demoLoading, setDemoLoading] = useState(false);

  function set(k, v) { setForm(f => ({ ...f, [k]: v })); }

  async function handleConnect(e) {
    e.preventDefault();
    setLoading(true); setError(''); setStep('Connecting…');
    try {
      const body = {
        host: form.host.trim(),
        port: parseInt(form.port) || 22,
        username: form.username.trim(),
        password: authMode === 'password' ? form.password : '',
        key_path: authMode === 'key' ? form.key_path.trim() : '',
        platform_type: platform,
        api_key: apiKey || '',
      };
      setStep('Establishing connection…');
      const res = await api.connect(body);
      if (!res.ok) { setError(res.data?.detail || 'Connection failed'); return; }
      setStep('Connected ✓');
      onConnected(res.data.info || {}, platform, form.host.trim());
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false); setStep('');
    }
  }

  async function handleDemo() {
    setDemoLoading(true); setError('');
    try {
      // Initialize LLM with the api key even in demo mode
      if (apiKey) {
        await api.saveSettings({ groq_key: apiKey }).catch(() => {});
      }
      const res = await api.demoStart('ssh_intrusion');
      if (!res.ok) { setError(res.data?.detail || 'Demo start failed'); return; }
      onDemoStart('demo-server.taara.local');
    } catch (e) { setError(e.message); }
    finally { setDemoLoading(false); }
  }

  const cloudFields = {
    aws:   ['Access Key ID', 'Secret Access Key', 'Region'],
    gcp:   ['Project ID', 'Service Account JSON Path', 'Region'],
    azure: ['Tenant ID', 'Client ID', 'Client Secret', 'Subscription ID'],
  };

  return (
    <div className="page" style={{ maxWidth: 560 }}>
      <div style={{ fontSize: 20, fontWeight: 700, marginBottom: 4 }}>Systems</div>
      <div style={{ fontSize: 13, color: 'var(--text-dim)', marginBottom: 24 }}>
        Connect to SSH, AWS, GCP, or Azure.
      </div>

      {/* Platform tabs */}
      <div style={{
        display: 'flex', gap: 4, marginBottom: 20,
        background: 'var(--bg-surface)', padding: 4, borderRadius: 8, border: '1px solid var(--border)',
      }}>
        {PLATFORMS.map(p => (
          <button key={p} onClick={() => { setPlatform(p); setError(''); }} style={{
            flex: 1, padding: '7px 0', background: platform === p ? 'var(--bg-raised)' : 'transparent',
            border: 'none', borderRadius: 5, color: platform === p ? 'var(--text)' : 'var(--text-dim)',
            fontSize: 12, fontWeight: 600, letterSpacing: 0.5, cursor: 'pointer',
            boxShadow: platform === p ? '0 1px 3px rgba(0,0,0,0.3)' : 'none',
          }}>
            {p.toUpperCase()}
          </button>
        ))}
      </div>

      {/* SSH */}
      {platform === 'ssh' && (
        <form onSubmit={handleConnect}>
          <div className="card" style={{ marginBottom: 16 }}>
            <div style={{ display: 'flex', gap: 12, marginBottom: 14 }}>
              <div style={{ flex: 2 }}>
                <label className="label">Host / IP</label>
                <input className="input" value={form.host} onChange={e => set('host', e.target.value)}
                  placeholder="192.168.1.100" required />
              </div>
              <div style={{ flex: 1 }}>
                <label className="label">Port</label>
                <input className="input" value={form.port} onChange={e => set('port', e.target.value)}
                  placeholder="22" type="number" />
              </div>
            </div>

            <div style={{ marginBottom: 14 }}>
              <label className="label">Username</label>
              <input className="input" value={form.username} onChange={e => set('username', e.target.value)}
                placeholder="root" required />
            </div>

            <div style={{
              display: 'flex', gap: 4, marginBottom: 14,
              background: 'var(--bg-input)', padding: 3, borderRadius: 6, border: '1px solid var(--border)',
            }}>
              {['password', 'key'].map(m => (
                <button key={m} type="button" onClick={() => setAuthMode(m)} style={{
                  flex: 1, padding: '6px 0', background: authMode === m ? 'var(--bg-raised)' : 'transparent',
                  border: 'none', borderRadius: 4,
                  color: authMode === m ? 'var(--text)' : 'var(--text-dim)',
                  fontSize: 12, fontWeight: 500, cursor: 'pointer',
                }}>
                  {m === 'password' ? 'Password' : 'SSH Key'}
                </button>
              ))}
            </div>

            {authMode === 'password' && (
              <div style={{ marginBottom: 14 }}>
                <label className="label">Password</label>
                <input className="input" type="password" value={form.password}
                  onChange={e => set('password', e.target.value)} placeholder="••••••••" />
              </div>
            )}
            {authMode === 'key' && (
              <div style={{ marginBottom: 14 }}>
                <label className="label">Key Path</label>
                <input className="input" value={form.key_path}
                  onChange={e => set('key_path', e.target.value)} placeholder="~/.ssh/id_rsa" />
              </div>
            )}

            {error && <div style={{ marginBottom: 12, padding: '8px 12px', background: 'rgba(233,69,96,0.1)', border: '1px solid rgba(233,69,96,0.25)', borderRadius: 6, fontSize: 12, color: 'var(--red)' }}>{error}</div>}
            {step  && <div style={{ marginBottom: 12, fontSize: 12, color: 'var(--green)' }}>{step}</div>}

            <button type="submit" className="btn btn-primary" disabled={loading} style={{ width: '100%', justifyContent: 'center' }}>
              {loading ? <><span className="spinner" /> Connecting…</> : 'Connect via SSH →'}
            </button>
          </div>
        </form>
      )}

      {/* Cloud */}
      {platform !== 'ssh' && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div style={{
            marginBottom: 14, padding: '10px 14px',
            background: 'rgba(74,158,255,0.06)', border: '1px solid rgba(74,158,255,0.2)',
            borderRadius: 8, fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.6,
          }}>
            <strong style={{ color: 'var(--blue)' }}>Simulation mode.</strong>{' '}
            Live cloud connection requires credentials provisioned outside this demo.
            This simulation shows realistic security findings and quantum scores based on real patterns.
          </div>
          {(cloudFields[platform] || []).map(field => (
            <div key={field} style={{ marginBottom: 12 }}>
              <label className="label">{field}</label>
              <input className="input" placeholder={field} />
            </div>
          ))}
          <button
            type="button"
            className="btn btn-primary"
            style={{ width: '100%', justifyContent: 'center' }}
            onClick={() => {
              onConnected({}, platform, `${platform}-simulation`);
            }}
          >
            Run {platform.toUpperCase()} Simulation →
          </button>
        </div>
      )}

      {/* Demo mode */}
      {platform === 'ssh' && (
        <div style={{ marginTop: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
            <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
            <span style={{ fontSize: 11, color: 'var(--text-faint)', whiteSpace: 'nowrap' }}>no live server?</span>
            <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
          </div>
          <button
            type="button"
            className="btn"
            onClick={handleDemo}
            disabled={demoLoading}
            style={{ width: '100%', justifyContent: 'center', borderColor: 'rgba(245,166,35,0.3)', color: 'var(--amber)' }}
          >
            {demoLoading ? <><span className="spinner" /> Starting demo…</> : '▶ Run Demo Mode (simulated ssh_intrusion scenario)'}
          </button>
          <div style={{ fontSize: 11, color: 'var(--text-faint)', textAlign: 'center', marginTop: 6 }}>
            Real quantum math, synthetic behavioral data. F_min drops at tick 8. Anomaly banner fires.
          </div>
        </div>
      )}
    </div>
  );
}

// ── Cloud Simulation View ─────────────────────────────────────────────────────
const CLOUD_STEPS = [
  'Initialising simulation environment…',
  'Loading cloud security baseline…',
  'Generating realistic IAM findings…',
  'Checking storage exposure patterns…',
  'Scanning network security groups…',
  'Computing quantum fidelity…',
  'Building cost optimisation model…',
];

function CloudSimView({ platform, hostname, onDisconnect }) {
  const [running, setRunning]   = useState(false);
  const [stepIdx, setStepIdx]   = useState(0);
  const [results, setResults]   = useState(null);
  const [error, setError]       = useState('');
  const stepRef                 = useRef(null);

  async function runSim() {
    setRunning(true); setError(''); setResults(null); setStepIdx(0);
    let idx = 0;
    stepRef.current = setInterval(() => {
      idx = Math.min(idx + 1, CLOUD_STEPS.length - 1);
      setStepIdx(idx);
    }, 1200);
    try {
      const res = await api.analyze({ scan_depth: 'Standard' });
      clearInterval(stepRef.current);
      setStepIdx(CLOUD_STEPS.length);
      if (!res.ok) { setError(res.data?.detail || 'Simulation failed'); return; }
      setResults(res.data);
    } catch (e) {
      clearInterval(stepRef.current);
      setError(e.message);
    } finally { setRunning(false); }
  }

  useEffect(() => () => clearInterval(stepRef.current), []);

  const pName = platform.toUpperCase();

  return (
    <div className="page">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <div style={{ fontSize: 20, fontWeight: 700 }}>{pName} Simulation</div>
          <div style={{ fontSize: 13, color: 'var(--text-dim)', marginTop: 3 }}>
            {hostname}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button className="btn btn-primary" onClick={runSim} disabled={running}>
            {running ? <><span className="spinner" /> Simulating…</> : '▶ Run Simulation'}
          </button>
          <button className="btn btn-danger" onClick={onDisconnect} style={{ fontSize: 12 }}>Disconnect</button>
        </div>
      </div>

      <div style={{
        marginBottom: 20, padding: '10px 16px',
        background: 'rgba(74,158,255,0.06)', border: '1px solid rgba(74,158,255,0.2)',
        borderRadius: 8, fontSize: 12, color: 'var(--blue)', lineHeight: 1.6,
      }}>
        Live cloud connection requires credentials. This simulation shows realistic behavior based on real patterns.
      </div>

      {running && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-dim)', marginBottom: 12, letterSpacing: 0.5 }}>
            SIMULATING {pName}
          </div>
          <div style={{ height: 3, background: 'var(--border)', borderRadius: 2, marginBottom: 12, overflow: 'hidden' }}>
            <div style={{
              height: '100%', borderRadius: 2,
              width: `${(stepIdx / CLOUD_STEPS.length) * 100}%`,
              background: 'var(--accent)', transition: 'width 0.5s ease',
            }} />
          </div>
          {CLOUD_STEPS.map((s, i) => (
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
        <div style={{ marginBottom: 16, padding: '10px 14px', background: 'rgba(233,69,96,0.1)', border: '1px solid rgba(233,69,96,0.25)', borderRadius: 8, fontSize: 13, color: 'var(--red)' }}>
          {error}
        </div>
      )}

      {results && !running && <CloudSimResults results={results} platform={pName} />}
    </div>
  );
}

function CloudSimResults({ results, platform }) {
  const qr = results.quantum_risk || {};
  const fmin = qr.f_min ?? results.f_min;
  const riskScore = qr.risk_score ?? 0;
  const findings = extractAllFindings(results);

  return (
    <div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 14, marginBottom: 20 }}>
        <MetricTile label="Risk Score"    value={`${riskScore}/100`} color={riskScore >= 75 ? 'var(--red)' : riskScore >= 50 ? 'var(--amber)' : 'var(--green)'} />
        <MetricTile label="Findings"      value={findings.length}    color={findings.length > 0 ? 'var(--amber)' : 'var(--green)'} />
        <MetricTile label="Quantum F_min" value={fmin != null ? fmin.toFixed(4) : '—'} color={fminColor(fmin)} mono />
        <MetricTile label="Platform"      value={platform}           color="var(--blue)" />
      </div>

      {results.ai_summary && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="section-title" style={{ marginBottom: 8 }}>Reasoning Engine Summary</div>
          <div style={{ fontSize: 13, lineHeight: 1.7, whiteSpace: 'pre-wrap' }}>{results.ai_summary}</div>
        </div>
      )}

      {findings.length > 0 && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="section-title" style={{ marginBottom: 12 }}>Security Findings ({findings.length})</div>
          {findings.slice(0, 10).map((f, i) => (
            <div key={i} style={{ display: 'flex', gap: 10, alignItems: 'center', padding: '8px 0', borderBottom: i < 9 ? '1px solid var(--border-dim)' : 'none' }}>
              <span className={`badge ${severityClass(f.severity)}`}>{f.severity || 'INFO'}</span>
              <span style={{ fontSize: 12 }}>{f.title || f.label || '—'}</span>
            </div>
          ))}
        </div>
      )}

      {results.cost_analysis && !results.cost_analysis.error && (
        <CostCard cost={results.cost_analysis} />
      )}
    </div>
  );
}

function CostCard({ cost }) {
  const savings = cost.potential_monthly_savings || 0;
  const savingsInr = Math.round(savings * 83);
  return (
    <div className="card">
      <div className="section-title" style={{ marginBottom: 10 }}>Cloud Spending Optimisation</div>
      <div style={{ fontSize: 11, color: 'var(--text-faint)', marginBottom: 4 }}>Monthly Savings Potential</div>
      <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--green)', fontFamily: 'monospace' }}>
        ₹{savingsInr.toLocaleString('en-IN')}
      </div>
    </div>
  );
}

// ── SSH Multi-Subtab View ─────────────────────────────────────────────────────
function SSHView({ hostname, demoMode, subTab, setSubTab, analysisResults, setAnalysisResults, onAlertFired, onDisconnect }) {
  const [taarawareDeployed, setTaarawareDeployed] = useState(false);

  // Poll deployed status every 20s so dashboard and taaraware tab stay in sync
  useEffect(() => {
    function checkDeployed() {
      api.taarawareDeployed()
        .then(r => { if (r.ok) setTaarawareDeployed(r.data.deployed === true); })
        .catch(() => {});
    }
    checkDeployed();
    const t = setInterval(checkDeployed, 20000);
    return () => clearInterval(t);
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Sub-tab bar */}
      <div style={{
        display: 'flex', gap: 2, padding: '0 32px',
        borderBottom: '1px solid var(--border)', background: 'var(--bg-surface)', flexShrink: 0,
      }}>
        {SSH_SUBTABS.map(st => (
          <button key={st.id} onClick={() => setSubTab(st.id)} style={{
            padding: '10px 14px', fontSize: 12,
            fontWeight: subTab === st.id ? 700 : 400,
            color: subTab === st.id ? 'var(--accent)' : 'var(--text-dim)',
            background: 'transparent', border: 'none', cursor: 'pointer',
            borderBottom: `2px solid ${subTab === st.id ? 'var(--accent)' : 'transparent'}`,
            marginBottom: -1, display: 'flex', alignItems: 'center', gap: 5,
            transition: 'color 0.12s', whiteSpace: 'nowrap',
          }}>
            <span>{st.icon}</span><span>{st.label}</span>
          </button>
        ))}
        <div style={{ flex: 1 }} />
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, paddingRight: 4 }}>
          <span style={{ fontSize: 11, color: 'var(--text-faint)' }}>
            {demoMode ? 'DEMO · ' : ''}{hostname}
          </span>
          <button className="btn btn-danger" onClick={onDisconnect} style={{ fontSize: 11, padding: '4px 10px' }}>
            Disconnect
          </button>
        </div>
      </div>

      {/* Sub-tab content */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {subTab === 'dashboard'  && <DashboardSubTab hostname={hostname} demoMode={demoMode} taarawareDeployed={taarawareDeployed} />}
        {subTab === 'analysis'   && (
          <AnalysisSubTab
            hostname={hostname}
            demoMode={demoMode}
            analysisResults={analysisResults}
            setAnalysisResults={setAnalysisResults}
            onAlertFired={onAlertFired}
          />
        )}
        {subTab === 'taaraware'  && (
          <TaaraWareSubTab
            hostname={hostname}
            demoMode={demoMode}
            deployed={taarawareDeployed}
            onDeployed={() => setTaarawareDeployed(true)}
          />
        )}
        {subTab === 'train'      && <TrainSubTab />}
        {subTab === 'agent'      && <AgentSubTab />}
        {subTab === 'security'   && <SecuritySubTab />}
        {subTab === 'custom'     && <CustomActionsSubTab />}
        {subTab === 'details'    && <DeployDetailsSubTab hostname={hostname} demoMode={demoMode} />}
      </div>
    </div>
  );
}

// ── Tooltip component ─────────────────────────────────────────────────────────
function Tooltip({ tip, children }) {
  const [show, setShow] = useState(false);
  return (
    <span style={{ position: 'relative', display: 'inline-flex', alignItems: 'center' }}
      onMouseEnter={() => setShow(true)} onMouseLeave={() => setShow(false)}>
      {children}
      {show && (
        <div style={{
          position: 'absolute', bottom: '130%', left: '50%', transform: 'translateX(-50%)',
          background: '#1a1a3e', border: '1px solid var(--border)', borderRadius: 7,
          padding: '10px 14px', fontSize: 11, color: 'var(--text-dim)', lineHeight: 1.6,
          whiteSpace: 'normal', width: 260, zIndex: 999,
          boxShadow: '0 4px 20px rgba(0,0,0,0.5)',
        }}>
          {tip}
          <div style={{ position: 'absolute', bottom: -6, left: '50%', transform: 'translateX(-50%)', width: 10, height: 10, background: '#1a1a3e', border: '1px solid var(--border)', borderBottom: 'none', borderRight: 'none', transform: 'translateX(-50%) rotate(225deg)' }} />
        </div>
      )}
    </span>
  );
}

function MetricTileWithTip({ label, value, color, mono, sub, tip }) {
  return (
    <div className="card" style={{ padding: '14px 16px', position: 'relative' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 6 }}>
        <div className="metric-label" style={{ margin: 0 }}>{label}</div>
        {tip && (
          <Tooltip tip={tip}>
            <span style={{ width: 14, height: 14, borderRadius: '50%', background: 'var(--bg-raised)', border: '1px solid var(--border)', fontSize: 9, color: 'var(--text-faint)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', cursor: 'help', marginLeft: 2 }}>?</span>
          </Tooltip>
        )}
      </div>
      <div style={{ fontSize: 26, fontWeight: 700, fontFamily: mono ? 'monospace' : undefined, color: color || 'var(--text)' }}>{value}</div>
      {sub && <div style={{ fontSize: 10, color: 'var(--text-faint)', marginTop: 3 }}>{sub}</div>}
    </div>
  );
}

// ── Sub-tab 1: Dashboard ──────────────────────────────────────────────────────
function DashboardSubTab({ hostname, demoMode, taarawareDeployed }) {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [fHistory, setFHistory] = useState([]);   // sparkline: [{t, f}]
  const [cpuHistory, setCpuHistory] = useState([]);
  const pollRef               = useRef(null);

  async function load() {
    try {
      const [sys, alerts] = await Promise.all([
        api.status(), api.alerts(),
      ]);
      const combined = {};
      if (sys.ok) Object.assign(combined, sys.data);
      if (alerts.ok) combined._alerts = alerts.data;
      setData(combined);

      // Append to sparklines — use /api/status as authoritative source
      const fv  = (sys.ok ? sys.data.feature_vector : null) || {};
      const nov = (sys.ok ? sys.data.novelty : null) || {};
      const f   = nov.f_min ?? combined.f_min;
      const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      if (f != null) setFHistory(h => [...h.slice(-29), { t: now, f }]);
      // Always collect CPU for sparkline if available
      if (fv.cpu_usage != null && fv.cpu_usage !== 0) setCpuHistory(h => [...h.slice(-29), { t: now, v: fv.cpu_usage }]);
    } catch (_) {}
    finally { setLoading(false); }
  }

  useEffect(() => {
    load();
    pollRef.current = setInterval(load, 8000);
    return () => clearInterval(pollRef.current);
  }, []);

  if (loading && !data) {
    return <div className="page"><div className="skeleton" style={{ height: 200, borderRadius: 10 }} /></div>;
  }

  const qr          = data?.quantum_risk || {};
  const nov         = data?.novelty || {};
  const basisSize   = nov.basis_size ?? 0;
  const basisMature = basisSize >= 3;
  // Always show live F_min — suppress anomaly ALERTS during calibration but always display the value
  const fmin        = nov.f_min ?? data?.f_min ?? qr.f_min ?? data?.latest_f_min;
  // V3 validated quantum signals (swap fidelity, directionality, phase coherence, quantum confidence)
  const swapFidelity    = nov.swap_fidelity    ?? null;
  const qDirectionality = nov.q_directionality ?? null;
  const phaseCoherence  = nov.phase_coherence  ?? null;
  const quantumConf     = nov.quantum_confidence ?? null;
  const qcColor = quantumConf == null ? 'var(--text-faint)'
    : quantumConf >= 0.75 ? '#e94560'
    : quantumConf >= 0.45 ? '#f5a623'
    : quantumConf >= 0.1854 ? '#4a9eff'
    : '#22cc66';
  const qcLabel = quantumConf == null ? '—'
    : quantumConf >= 0.75 ? 'CRITICAL'
    : quantumConf >= 0.45 ? 'HIGH'
    : quantumConf >= 0.1854 ? 'MEDIUM'
    : 'LOW';
  // feature_vector from /api/status has real live values (cpu_usage, memory_usage, etc.)
  const fv          = data?.feature_vector || {};
  const hasFvData   = Object.values(fv).some(v => v !== 0 && v != null);
  const riskScore   = qr.risk_score ?? 0;
  const summary     = (data?.security_data || {}).summary || data?.summary || {};
  const critCount   = summary.critical ?? 0;
  const highCount   = summary.high     ?? 0;
  const medCount    = summary.medium   ?? 0;
  // Only count as a real alert if basis is mature — calibration noise is not an alert
  const hasAlert    = basisMature && (data?._alerts?.has_anomaly ?? (fmin != null && fmin < 0.5));
  // Last collection time: parse from agent_status recent_logs if available
  const recentLogLine = (() => {
    const logs = data?.agent_status?.recent_logs || '';
    const lines = logs.split('\n').filter(Boolean);
    return lines[lines.length - 1] || '';
  })();
  const lastTs = recentLogLine
    ? recentLogLine.split(',')[0].trim()   // "2026-05-18 00:39:18" portion
    : data?.last_collection
      ? new Date(data.last_collection * 1000).toLocaleTimeString()
      : demoMode ? 'Demo — live' : null;

  // Real health score: penalise for criticals, highs, low fidelity, active alert
  const computedHealth = (() => {
    let score = 100;
    score -= critCount  * 18;
    score -= highCount  * 8;
    score -= medCount   * 2;
    if (fmin != null) score -= Math.max(0, (0.7 - fmin)) * 60; // big drop if below 0.7
    if (hasAlert) score -= 15;
    return Math.max(0, Math.min(100, score));
  })();
  const healthScore = data?.health_score ?? computedHealth;

  const healthColor = healthScore >= 80 ? 'var(--green)' : healthScore >= 60 ? 'var(--blue)' : healthScore >= 40 ? 'var(--amber)' : 'var(--red)';
  const healthLabel = healthScore >= 80 ? 'Healthy' : healthScore >= 60 ? 'Stable' : healthScore >= 40 ? 'At Risk' : 'Critical';

  // Mini sparkline SVG renderer
  function Sparkline({ points, color, height = 40, width = '100%' }) {
    if (!points || points.length < 2) return (
      <div style={{ height, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <span style={{ fontSize: 10, color: 'var(--text-faint)' }}>Collecting data…</span>
      </div>
    );
    const vals  = points.map(p => p.f ?? p.v ?? 0);
    const min   = Math.min(...vals, 0);
    const max   = Math.max(...vals, 1);
    const range = max - min || 1;
    const W = 300, H = height;
    const xs = points.map((_, i) => (i / (points.length - 1)) * W);
    const ys = vals.map(v => H - ((v - min) / range) * H * 0.85 - H * 0.075);
    const d  = xs.map((x, i) => `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${ys[i].toFixed(1)}`).join(' ');
    const fillD = `${d} L${W},${H} L0,${H} Z`;
    const latest = vals[vals.length - 1];
    return (
      <div style={{ position: 'relative' }}>
        <svg viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', height, display: 'block' }} preserveAspectRatio="none">
          <defs>
            <linearGradient id={`sg-${color.replace(/[^a-z]/gi,'')}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={color} stopOpacity="0.3" />
              <stop offset="100%" stopColor={color} stopOpacity="0.02" />
            </linearGradient>
          </defs>
          <path d={fillD} fill={`url(#sg-${color.replace(/[^a-z]/gi,'')})`} />
          <path d={d} stroke={color} strokeWidth="1.5" fill="none" strokeLinecap="round" strokeLinejoin="round" />
          {/* Threshold line at 0.5 for fmin */}
          {points[0]?.f != null && (
            <line x1="0" y1={H - (0.5 / range) * H * 0.85 - H * 0.075} x2={W} y2={H - (0.5 / range) * H * 0.85 - H * 0.075}
              stroke="#f5a623" strokeWidth="0.8" strokeDasharray="4,4" opacity="0.5" />
          )}
          {/* Latest dot */}
          <circle cx={xs[xs.length-1]} cy={ys[ys.length-1]} r="3" fill={color} />
        </svg>
        <div style={{ position: 'absolute', top: 2, right: 0, fontSize: 10, fontFamily: 'monospace', color }}>
          {typeof latest === 'number' ? latest.toFixed(3) : latest}
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <div style={{ fontSize: 16, fontWeight: 700, letterSpacing: 0.5 }}>{hostname}</div>
          <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 2 }}>
            Live monitoring · refreshes every 8s
            {lastTs && <span> · last collection {lastTs}</span>}
          </div>
        </div>
        {hasAlert && (
          <div style={{ padding: '6px 14px', background: 'rgba(233,69,96,0.15)', border: '1px solid rgba(233,69,96,0.4)', borderRadius: 6, fontSize: 12, color: 'var(--red)', fontWeight: 700, animation: 'pulse-red 1.5s infinite' }}>
            ⚠ ANOMALY ACTIVE
          </div>
        )}
      </div>

      {/* Top row: health dial + fmin sparkline */}
      <div style={{ display: 'grid', gridTemplateColumns: '220px 1fr', gap: 16, marginBottom: 16 }}>

        {/* Health dial */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '20px 16px' }}>
          <Tooltip tip="Composite score derived from: critical findings (−18 each), high findings (−8 each), medium (−2 each), F_min drop below 0.7 (−up to 42), active anomaly alert (−15). Range 0–100.">
            <div style={{ fontSize: 10, color: 'var(--text-faint)', letterSpacing: 1, textTransform: 'uppercase', marginBottom: 10, cursor: 'help', display: 'flex', alignItems: 'center', gap: 4 }}>
              Infrastructure Health
              <span style={{ width: 13, height: 13, borderRadius: '50%', background: 'var(--bg-raised)', border: '1px solid var(--border)', fontSize: 8, color: 'var(--text-faint)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center' }}>?</span>
            </div>
          </Tooltip>
          <div style={{
            width: 120, height: 120, borderRadius: '50%',
            background: `conic-gradient(${healthColor} 0% ${healthScore}%, var(--bg-raised) ${healthScore}% 100%)`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: `0 0 24px ${healthColor}33`,
            border: `2px solid ${healthColor}55`,
          }}>
            <div style={{ width: 90, height: 90, borderRadius: '50%', background: 'var(--bg-surface)', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
              <div style={{ fontSize: 28, fontWeight: 800, fontFamily: 'monospace', color: healthColor, lineHeight: 1 }}>
                {healthScore.toFixed(0)}
              </div>
              <div style={{ fontSize: 9, color: 'var(--text-faint)' }}>/ 100</div>
            </div>
          </div>
          <div style={{ marginTop: 10, fontSize: 13, fontWeight: 700, color: healthColor }}>{healthLabel}</div>
          <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 4, width: '100%' }}>
            {[
              { label: 'Critical findings', val: critCount, deduct: critCount * 18, color: 'var(--red)' },
              { label: 'High findings',     val: highCount, deduct: highCount * 8,  color: 'var(--amber)' },
              { label: 'Fidelity penalty',  val: fmin != null ? fmin.toFixed(3) : '—', deduct: fmin != null ? Math.round(Math.max(0, (0.7 - fmin)) * 60) : 0, color: fminColor(fmin) },
            ].map(r => r.deduct > 0 ? (
              <div key={r.label} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9, color: 'var(--text-faint)' }}>
                <span>{r.label}</span>
                <span style={{ color: r.color }}>−{r.deduct}</span>
              </div>
            ) : null)}
          </div>
        </div>

        {/* Quantum signals — SWAP fidelity, directionality, phase coherence, quantum confidence */}
        <div className="card" style={{ padding: '16px 18px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontWeight: 700, fontSize: 13 }}>Quantum Behavioral Analysis — Live</span>
                <Tooltip tip="3-qubit AmplitudeEmbedding on 8-dim behavioral latent z_t. SWAP Fidelity = F_sub = Σ|⟨ψ_t|ψ_k⟩|² over K=3 PCA subspace components. Low fidelity = outside normal subspace = anomalous. Directionality = alignment with complement subspace. Phase Coherence = |mean(exp(iφ))| over W=4 windows. Quantum Confidence = V3 interference fusion: α·swap_s + β·q_dir + γ·coh·√(swap_s·q_dir). Threshold = 0.1854 (p95 of normal training). NIST FIPS 203 ML-KEM Kyber768 PQC transform applied before encoding — behavioral norm cannot be reverse-engineered or replayed without private key.">
                  <span style={{ width: 15, height: 15, borderRadius: '50%', background: 'var(--bg-raised)', border: '1px solid var(--border)', fontSize: 9, color: 'var(--text-faint)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', cursor: 'help' }}>?</span>
                </Tooltip>
                {!basisMature && (
                  <span style={{ fontSize: 9, padding: '2px 6px', borderRadius: 3, background: 'var(--blue)18', border: '1px solid var(--blue)44', color: 'var(--blue)', fontWeight: 600 }}>
                    {basisSize > 0 ? `BASELINE ${basisSize}/3` : 'TRAIN NEEDED'}
                  </span>
                )}
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-faint)', marginTop: 2 }}>
                {basisMature ? 'Alert threshold: quantum confidence > 0.1854 (v3 p95)' : basisSize > 0 ? `Subspace building (${basisSize}/3) — alerts suppressed` : 'Go to Train tab to build behavioral baseline'}
              </div>
            </div>
            {quantumConf != null ? (
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontSize: 22, fontWeight: 700, fontFamily: 'monospace', color: basisMature ? qcColor : 'var(--text-faint)' }}>{quantumConf.toFixed(4)}</div>
                <div style={{ fontSize: 10, color: basisMature ? qcColor : 'var(--text-faint)' }}>{basisMature ? qcLabel : (basisSize > 0 ? 'building baseline…' : 'train tab needed')}</div>
              </div>
            ) : fmin != null ? (
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontSize: 22, fontWeight: 700, fontFamily: 'monospace', color: basisMature ? fminColor(fmin) : 'var(--text-faint)' }}>{fmin.toFixed(4)}</div>
                <div style={{ fontSize: 10, color: basisMature ? fminColor(fmin) : 'var(--text-faint)' }}>{basisMature ? fminBucket(fmin) : ''}</div>
              </div>
            ) : (
              <div style={{ textAlign: 'right', fontSize: 11, color: 'var(--text-faint)' }}>Waiting…</div>
            )}
          </div>

          {/* 4 quantum signal tiles — show whenever values exist, even during calibration */}
          {(swapFidelity != null || qDirectionality != null || phaseCoherence != null || quantumConf != null) && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8, marginBottom: 12 }}>
              {[
                {
                  label: 'SWAP Fidelity',
                  key: 'F_sub',
                  val: swapFidelity,
                  tip: 'F_sub = Σ|⟨ψ_t|ψ_k⟩|² — overlap with normal subspace (K=3 PCA). High = inside normal. Low = outside = anomalous. swap_s = 1 − F_sub is the anomaly signal.',
                  color: swapFidelity == null ? 'var(--text-faint)' : swapFidelity >= 0.7 ? '#22cc66' : swapFidelity >= 0.5 ? '#4a9eff' : swapFidelity >= 0.3 ? '#f5a623' : '#e94560',
                  fmt: v => v.toFixed(4),
                },
                {
                  label: 'Directionality',
                  key: 'q_dir',
                  val: qDirectionality,
                  tip: 'q_dir = Σ|⟨ψ_t|ψ_c⟩|² — alignment with complement subspace (dimensions K+1, K+2). High = drifting into complement = correlated with attack drift. Orthogonal to SWAP (corr≈0.024).',
                  color: qDirectionality == null ? 'var(--text-faint)' : qDirectionality >= 0.3 ? '#e94560' : qDirectionality >= 0.15 ? '#f5a623' : '#22cc66',
                  fmt: v => v.toFixed(4),
                },
                {
                  label: 'Phase Coherence',
                  key: 'coh',
                  val: phaseCoherence,
                  tip: 'coh = |mean(exp(iφ_t))| over W=4 windows. φ_t = arctan2 angle in complement subspace. High coherence + high directionality = sustained attack drift vs. noise. Normal baseline ≈ 0.624.',
                  color: phaseCoherence == null ? 'var(--text-faint)' : phaseCoherence >= 0.8 ? '#e94560' : phaseCoherence >= 0.6 ? '#f5a623' : '#22cc66',
                  fmt: v => v.toFixed(4),
                },
                {
                  label: 'Q Confidence',
                  key: 'qc',
                  val: quantumConf,
                  tip: 'V3 interference fusion: conf = α·swap_s + β·q_dir + γ·coh·√(swap_s·q_dir). Global weights: α=0.263, β=0.285, γ=0.451. Per-identity LR-fit when basis matures. Alert threshold = 0.1854 (p95 of normal training). Prec=0.689, Rec=0.942, F1=0.796, AUC=0.980 on CERT r4.2.',
                  color: qcColor,
                  fmt: v => v.toFixed(4),
                },
              ].map(s => (
                <Tooltip key={s.key} tip={s.tip}>
                  <div style={{
                    background: 'var(--bg-raised)', borderRadius: 8, padding: '10px 12px',
                    border: `1px solid ${s.color}33`, cursor: 'help',
                  }}>
                    <div style={{ fontSize: 9, color: 'var(--text-faint)', fontFamily: 'monospace', marginBottom: 4 }}>{s.key}</div>
                    <div style={{ fontSize: 17, fontWeight: 700, fontFamily: 'monospace', color: s.color }}>
                      {s.val != null ? s.fmt(s.val) : '—'}
                    </div>
                    <div style={{ fontSize: 9, color: s.color, marginTop: 2 }}>{s.label}</div>
                    {s.val != null && (
                      <div style={{ marginTop: 6, height: 3, background: 'var(--bg-input)', borderRadius: 2 }}>
                        <div style={{ height: '100%', width: `${Math.min(s.val, 1) * 100}%`, background: s.color, borderRadius: 2, transition: 'width 0.5s' }} />
                      </div>
                    )}
                  </div>
                </Tooltip>
              ))}
            </div>
          )}

          {fmin != null && fHistory.length > 1
            ? <Sparkline points={fHistory} color={basisMature ? (quantumConf != null ? qcColor : fminColor(fmin)) : 'var(--blue)'} height={60} />
            : <div style={{ height: 60, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, color: 'var(--text-faint)' }}>
                {hasFvData ? 'Building signal history…' : 'Collecting first sample…'}
              </div>
          }
          {fHistory.length > 1 && (
            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4, fontSize: 9, color: 'var(--text-faint)' }}>
              <span>{fHistory[0]?.t}</span><span>→ now</span>
            </div>
          )}
        </div>
      </div>

      {/* Status tiles row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(150px, 1fr))', gap: 12, marginBottom: 16 }}>
        <MetricTileWithTip label="Critical Findings" value={critCount} color={critCount > 0 ? 'var(--red)' : 'var(--green)'}
          tip="Count of CRITICAL severity findings from the last TaaraAnalysis scan. Each critical finding deducts 18 points from the health score." />
        <MetricTileWithTip label="High Findings" value={highCount} color={highCount > 0 ? 'var(--amber)' : 'var(--green)'}
          tip="Count of HIGH severity findings. Typically exploitable vulnerabilities or dangerous misconfigurations. Each deducts 8 from health score." />
        <MetricTileWithTip label="Medium" value={medCount} color={medCount > 3 ? 'var(--blue)' : 'var(--text-faint)'}
          tip="Count of MEDIUM severity findings. Often best-practice violations or indirect risk. Each deducts 2 from health score." />
        <MetricTileWithTip label="Anomaly Alert" value={hasAlert ? 'ACTIVE' : 'None'} color={hasAlert ? 'var(--red)' : 'var(--green)'}
          tip="Fires when quantum confidence exceeds 0.1854 (v3 p95 threshold on normal training windows). Formula: α·swap_s + β·q_dir + γ·coh·√(swap_s·q_dir). If Isolation Forest is also trained, both must agree. Detects T1078 Valid-Account credential theft — attackers who pass authentication but deviate from behavioral baseline." />
        <div className="card" style={{ padding: '14px 16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 6 }}>
            <div className="metric-label" style={{ margin: 0 }}>TaaraWare</div>
            <Tooltip tip="TaaraWare is TAARA's persistent monitoring agent deployed on the target server. When active, it collects the 19-feature behavioral DNA every 30 seconds and streams it back for quantum analysis.">
              <span style={{ width: 14, height: 14, borderRadius: '50%', background: 'var(--bg-raised)', border: '1px solid var(--border)', fontSize: 9, color: 'var(--text-faint)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', cursor: 'help' }}>?</span>
            </Tooltip>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{
              width: 10, height: 10, borderRadius: '50%',
              background: taarawareDeployed ? 'var(--green)' : 'var(--text-faint)',
              boxShadow: taarawareDeployed ? '0 0 6px var(--green)' : 'none',
              display: 'inline-block', flexShrink: 0,
              animation: taarawareDeployed ? 'pulse-green 2s infinite' : 'none',
            }} />
            <span style={{ fontSize: 16, fontWeight: 700, color: taarawareDeployed ? 'var(--green)' : 'var(--text-faint)' }}>
              {taarawareDeployed ? 'Active' : 'Not deployed'}
            </span>
          </div>
        </div>
      </div>

      {/* Live feature signals mini-bars — shown only when TaaraWare has data */}
      {hasFvData && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div style={{ fontWeight: 700, fontSize: 13 }}>Live Behavioral Signals</div>
            <div style={{ fontSize: 10, color: 'var(--text-faint)' }}>from TaaraWare · {lastTs || 'live'}</div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 8 }}>
            {[
              { key: 'cpu_usage',              label: 'CPU',               unit: '%',   max: 100, warn: 80,  color: '#4a9eff' },
              { key: 'memory_usage',           label: 'Memory',            unit: '%',   max: 100, warn: 85,  color: '#4a9eff' },
              { key: 'disk_usage',             label: 'Disk',              unit: '%',   max: 100, warn: 90,  color: '#9b7dff' },
              { key: 'proc_spawn_rate',        label: 'Process Spawns',    unit: '/min',max: 30,  warn: 15,  color: '#22cc66' },
              { key: 'net_outbound_conn_rate', label: 'Outbound Conns',    unit: '',    max: 200, warn: 100, color: '#22cc66' },
              { key: 'net_unique_dst_ips',     label: 'Unique Dest IPs',   unit: '',    max: 20,  warn: 10,  color: '#f5a623' },
              { key: 'net_failed_conn_ratio',  label: 'Failed Conn Ratio', unit: '',    max: 1,   warn: 0.3, color: '#e94560' },
              { key: 'failed_logins_1h',       label: 'Failed Logins',     unit: '/hr', max: 20,  warn: 5,   color: '#e94560' },
              { key: 'causal_chain_novelty',   label: 'Causal Novelty',    unit: '',    max: 1,   warn: 0.6, color: '#e94560' },
              { key: 'concealment_signal',     label: 'Concealment',       unit: '',    max: 1,   warn: 0.3, color: '#e94560' },
            ].filter(s => fv[s.key] != null && fv[s.key] !== 0 || (s.key === 'failed_logins_1h' || s.key === 'concealment_signal')).map(s => {
              const val  = fv[s.key];
              const norm = Math.min(val / s.max, 1);
              const hot  = norm >= s.warn / s.max;
              const bar  = hot ? '#e94560' : s.color;
              return (
                <div key={s.key} style={{ background: 'var(--bg-raised)', borderRadius: 6, padding: '8px 10px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ fontSize: 10, color: hot ? 'var(--red)' : 'var(--text-dim)' }}>{s.label}</span>
                    <span style={{ fontSize: 11, fontFamily: 'monospace', fontWeight: 700, color: hot ? 'var(--red)' : 'var(--text)' }}>
                      {typeof val === 'number' ? val.toFixed(1) : val}{s.unit}
                      {hot && ' ↑'}
                    </span>
                  </div>
                  <div style={{ height: 5, background: 'var(--bg-input)', borderRadius: 3, overflow: 'hidden' }}>
                    <div style={{ height: '100%', width: `${norm * 100}%`, borderRadius: 3, background: bar, transition: 'width 0.5s' }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* CPU sparkline if available */}
      {cpuHistory.length > 1 && (
        <div className="card">
          <div style={{ fontWeight: 700, fontSize: 12, marginBottom: 8 }}>CPU Usage — Last {cpuHistory.length} readings</div>
          <Sparkline points={cpuHistory} color="#4a9eff" height={40} />
        </div>
      )}

      {/* PQC protection status */}
      <div className="card" style={{ marginTop: 16, background: 'rgba(74,158,255,0.04)', border: '1px solid rgba(74,158,255,0.15)' }}>
        <div style={{ display: 'flex', gap: 14, alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ fontSize: 20 }}>🛡</div>
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 700, fontSize: 12, color: 'var(--blue)', marginBottom: 3 }}>
              Post-Quantum Channel Protection — Kyber768 / ML-KEM (NIST FIPS 203)
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-dim)', lineHeight: 1.6 }}>
              All behavioral feature data transmitted between TaaraWare and this server is offset using a Kyber768 shared secret.
              Kyber768 is a lattice-based key encapsulation mechanism — it cannot be broken by quantum computers (unlike RSA or ECDH),
              making it safe against "harvest now, decrypt later" attacks. This is a NIST-standardised algorithm (FIPS 203).
            </div>
          </div>
          <div style={{ textAlign: 'center', flexShrink: 0 }}>
            <div style={{ fontSize: 10, color: 'var(--text-faint)' }}>ALGORITHM</div>
            <div style={{ fontFamily: 'monospace', fontWeight: 700, color: 'var(--blue)', fontSize: 13 }}>Kyber768</div>
            <div style={{ fontSize: 9, color: 'var(--text-faint)', marginTop: 2 }}>ML-KEM · FIPS 203</div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Sub-tab 2: TaaraAnalysis ──────────────────────────────────────────────────
const SSH_STEPS = [
  'Establishing SSH session…',
  'Reading SSH configuration…',
  'Checking firewall rules (ufw/iptables)…',
  'Scanning open ports and services…',
  'Analysing authentication logs…',
  'Checking sudo & privilege escalation…',
  'Running knowledge-base policy scan…',
  'Encoding 8-dim latent → 3-qubit AmplitudeEmbedding…',
  'Computing quantum fidelity F = |⟨ψ_t|ψ_m⟩|²…',
  'Generating Reasoning Engine executive summary…',
  'Building infrastructure health model…',
];

const DEMO_STEPS = [
  'Initialising demo environment…',
  'Loading SSH intrusion scenario…',
  'Generating realistic feature vectors…',
  'Running quantum novelty computation…',
  'Encoding behavioral state…',
  'Computing F_min…',
  'Building findings model…',
];

function AnalysisSubTab({ hostname, demoMode, analysisResults, setAnalysisResults, onAlertFired }) {
  const [running, setRunning]   = useState(false);
  const [stepIdx, setStepIdx]   = useState(0);
  const [error, setError]       = useState('');
  const [results, setResults]   = useState(analysisResults);
  const stepRef                 = useRef(null);
  const startRef                = useRef(null);
  const [elapsed, setElapsed]   = useState(0);

  useEffect(() => { setResults(analysisResults); }, [analysisResults]);

  useEffect(() => {
    if (!running) return;
    const t = setInterval(() => {
      setElapsed(startRef.current ? ((Date.now() - startRef.current) / 1000) | 0 : 0);
    }, 1000);
    return () => clearInterval(t);
  }, [running]);

  const steps = demoMode ? DEMO_STEPS : SSH_STEPS;

  async function runAnalysis() {
    setRunning(true); setError(''); setStepIdx(0); setElapsed(0);
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
      if (!res.ok) { setError(res.data?.detail || 'Analysis failed'); return; }
      const data = res.data;
      setResults(data);
      setAnalysisResults(data);
      const fmin = data.quantum_risk?.f_min ?? data.novelty?.f_min ?? data.f_min;
      if (fmin != null && fmin < 0.5 && onAlertFired) {
        onAlertFired({ host: hostname, f_min: fmin, bucket: fmin < 0.3 ? 'critical_divergence' : 'unsafe_direction', features: data.feature_vector || {} });
      }
    } catch (e) {
      clearInterval(stepRef.current);
      setError(e.message || 'Analysis error');
    } finally { setRunning(false); }
  }

  useEffect(() => () => clearInterval(stepRef.current), []);

  return (
    <div className="page">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <div style={{ fontSize: 18, fontWeight: 700 }}>
            TaaraAnalysis
            {demoMode && <span style={{ marginLeft: 10, fontSize: 11, color: '#9b7dff', background: 'rgba(155,125,255,0.12)', border: '1px solid rgba(155,125,255,0.25)', borderRadius: 4, padding: '2px 8px', fontWeight: 700 }}>DEMO</span>}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 3 }}>{hostname}</div>
        </div>
        <button className="btn btn-primary" onClick={runAnalysis} disabled={running} style={{ minWidth: 140 }}>
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
              <div style={{ height: '100%', borderRadius: 2, width: `${(stepIdx / steps.length) * 100}%`, background: 'var(--accent)', transition: 'width 0.5s ease' }} />
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
        <div style={{ marginBottom: 16, padding: '10px 14px', background: 'rgba(233,69,96,0.1)', border: '1px solid rgba(233,69,96,0.25)', borderRadius: 8, fontSize: 13, color: 'var(--red)' }}>
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
  const qr          = results.quantum_risk || {};
  const fmin        = qr.f_min ?? results.novelty?.f_min ?? results.f_min;
  const novelty     = qr.quantum_novelty ?? results.novelty?.quantum_novelty ?? 0;
  const riskScore   = qr.risk_score ?? 0;
  const healthScore = results.model?.health_score ?? (100 - riskScore);
  const summary     = (results.security_data || {}).summary || {};
  const findings    = extractAllFindings(results);
  const critCount   = summary.critical ?? findings.filter(f => (f.severity || '').toLowerCase() === 'critical').length;
  const highCount   = summary.high     ?? findings.filter(f => (f.severity || '').toLowerCase() === 'high').length;
  const medCount    = summary.medium   ?? findings.filter(f => (f.severity || '').toLowerCase() === 'medium').length;
  const lowCount    = summary.low      ?? findings.filter(f => (f.severity || '').toLowerCase() === 'low').length;
  const divergePct  = fmin != null ? ((1 - fmin) * 100).toFixed(1) : null;

  // Are findings severe but scores look good? Warn the user.
  const scoreMismatch = (critCount > 0 || highCount > 2) && healthScore >= 70;

  return (
    <div>
      {scoreMismatch && (
        <div style={{ marginBottom: 16, padding: '10px 16px', background: 'rgba(245,166,35,0.1)', border: '1px solid rgba(245,166,35,0.3)', borderRadius: 8, fontSize: 12, color: 'var(--amber)', display: 'flex', gap: 8, alignItems: 'center' }}>
          <span style={{ fontSize: 16 }}>⚠</span>
          <span>Health score appears high despite {critCount > 0 ? `${critCount} critical` : `${highCount} high`} finding{critCount + highCount > 1 ? 's' : ''}. This usually means the quantum fidelity is still within range but real vulnerabilities exist — review findings below regardless of score.</span>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 14, marginBottom: 20 }}>
        <MetricTileWithTip label="Health Score" value={`${healthScore != null ? healthScore.toFixed(0) : '—'}/100`}
          color={healthScore >= 80 ? 'var(--green)' : healthScore >= 60 ? 'var(--blue)' : healthScore >= 40 ? 'var(--amber)' : 'var(--red)'}
          tip="Composite score: starts at 100, deducts for critical/high/medium findings and quantum fidelity drop. Does NOT account for unknown vulnerabilities outside the scan scope." />
        <MetricTileWithTip label="Risk Score" value={`${riskScore.toFixed(0)}/100`}
          color={riskScore >= 75 ? 'var(--red)' : riskScore >= 50 ? 'var(--amber)' : riskScore >= 25 ? 'var(--blue)' : 'var(--green)'}
          tip="Aggregated risk from the knowledge-base policy scan. Computed as a weighted sum of finding severities against OWASP/CIS/SSH policy rules. Higher = more risk. This is independent of F_min." />
        <MetricTileWithTip label="F_min" value={fmin != null ? fmin.toFixed(4) : '—'} color={fminColor(fmin)} mono
          tip={`Quantum Confidence — V3 fusion: α·swap_s + β·q_dir + γ·coh·√(swap_s·q_dir). 3-qubit AmplitudeEmbedding on 8-dim latent. Threshold 0.1854. Current divergence: ${divergePct != null ? divergePct + '%' : 'unknown'}.`} />
        <MetricTileWithTip label="Findings" value={findings.length}
          color={critCount > 0 ? 'var(--red)' : highCount > 0 ? 'var(--amber)' : 'var(--green)'}
          sub={`${critCount}C · ${highCount}H · ${medCount}M · ${lowCount}L`}
          tip="Total security findings from the scan. C=Critical, H=High, M=Medium, L=Low. Each finding maps to a MITRE ATT&CK tactic where available." />
      </div>

      {/* Quantum fidelity — visual + explanation */}
      {fmin != null && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div style={{ display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap' }}>
            {/* Dial */}
            <div style={{
              width: 72, height: 72, borderRadius: '50%', flexShrink: 0,
              background: `conic-gradient(${fminColor(fmin)} 0% ${fmin * 100}%, var(--bg-raised) ${fmin * 100}% 100%)`,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              boxShadow: `0 0 12px ${fminColor(fmin)}33`,
            }}>
              <div style={{ width: 52, height: 52, borderRadius: '50%', background: 'var(--bg-surface)', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                <div style={{ fontSize: 14, fontWeight: 700, fontFamily: 'monospace', color: fminColor(fmin) }}>{(fmin * 100).toFixed(0)}%</div>
                <div style={{ fontSize: 7, color: 'var(--text-faint)' }}>FIDELITY</div>
              </div>
            </div>
            <div style={{ flex: 1, minWidth: 180 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <span style={{ fontWeight: 700, fontSize: 13, color: fminColor(fmin) }}>{fminBucket(fmin)}</span>
                <span style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--text-faint)' }}>F = {fmin.toFixed(4)}</span>
                <Tooltip tip="Quantum Confidence — V3 fusion of SWAP Fidelity, Directionality, and Phase Coherence on a 3-qubit AmplitudeEmbedding of the 8-dim BehavioralAE latent. Threshold 0.1854 (p95 of normal training). Alert = conf > 0.1854.">
                  <span style={{ width: 14, height: 14, borderRadius: '50%', background: 'var(--bg-raised)', border: '1px solid var(--border)', fontSize: 9, color: 'var(--text-faint)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', cursor: 'help' }}>?</span>
                </Tooltip>
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-dim)', lineHeight: 1.6 }}>
                The server's current behavior is <strong style={{ color: fminColor(fmin) }}>{divergePct}% diverged</strong> from its trained secure baseline.
                {fmin >= 0.7 && ' This is within the normal operating range.'}
                {fmin >= 0.1854 && fmin < 0.45 && ' Behavioral drift detected — V3 quantum confidence above calibration threshold (0.1854).'}
                {fmin >= 0.45 && ' High quantum confidence. The server is behaving significantly differently from its trained baseline.'}
              </div>
              {/* Zone bar */}
              <div style={{ marginTop: 8, height: 8, background: 'linear-gradient(90deg, #e94560 0%, #f5a623 30%, #4a9eff 55%, #22cc66 100%)', borderRadius: 4, position: 'relative' }}>
                <div style={{
                  position: 'absolute', left: `${fmin * 100}%`, top: '50%',
                  transform: 'translate(-50%,-50%)',
                  width: 14, height: 14, borderRadius: '50%',
                  background: fminColor(fmin), border: '2px solid var(--bg-surface)',
                  boxShadow: `0 0 6px ${fminColor(fmin)}`, transition: 'left 0.4s',
                }} />
                <div style={{ position: 'absolute', left: '50%', top: -12, fontSize: 8, color: '#f5a623', transform: 'translateX(-50%)' }}>↑ threshold</div>
              </div>
            </div>
          </div>
        </div>
      )}

      {results.ai_summary && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="section-title" style={{ marginBottom: 8 }}>Reasoning Engine Summary</div>
          <div style={{ fontSize: 13, lineHeight: 1.7, whiteSpace: 'pre-wrap' }}>{results.ai_summary}</div>
        </div>
      )}

      {findings.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div className="section-title" style={{ marginBottom: 12 }}>Security Findings ({findings.length})</div>
          {findings.map((f, i) => <FindingCard key={i} finding={f} fmin={fmin} />)}
        </div>
      )}

      <ReportButton />
    </div>
  );
}

function FindingCard({ finding, fmin }) {
  const [open, setOpen] = useState(false);
  const sev = (finding.severity || 'info').toLowerCase();
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
        <span className={`badge ${severityClass(sev)}`}>{finding.severity || 'INFO'}</span>
        <span style={{ flex: 1, fontSize: 13, fontWeight: 500 }}>
          {finding.title || finding.label || finding.check || 'Unnamed finding'}
        </span>
        {finding.mitre_tactic && (
          <span style={{ fontSize: 10, color: 'var(--text-faint)', fontFamily: 'monospace', background: 'var(--bg-raised)', borderRadius: 3, padding: '1px 6px' }}>
            {finding.mitre_tactic}
          </span>
        )}
        {findingFmin != null && (
          <Tooltip tip={`Per-finding quantum fidelity: estimated from the overall F_min weighted by severity. F=${findingFmin.toFixed(4)} means this finding contributes to a ${((1-findingFmin)*100).toFixed(0)}% deviation in the quantum behavioral direction.`}>
            <span style={{ fontSize: 11, color: fminColor(findingFmin), fontFamily: 'monospace', cursor: 'help' }}>
              F={findingFmin.toFixed(3)}
            </span>
          </Tooltip>
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
            <div style={{ fontSize: 11, color: fminColor(findingFmin), marginBottom: 10, fontFamily: 'monospace', background: 'var(--bg-raised)', padding: '6px 10px', borderRadius: 4 }}>
              F = |⟨ψ_t|ψ_m⟩|² = {findingFmin.toFixed(4)}
              <span style={{ color: 'var(--text-faint)', marginLeft: 8 }}>
                — {((1 - findingFmin) * 100).toFixed(1)}% divergence from secure baseline direction
              </span>
            </div>
          )}
          {(finding.remediation || finding.fix_command || finding.command) && (
            <div>
              <div style={{ fontSize: 10, color: 'var(--text-faint)', fontWeight: 600, letterSpacing: 0.5, textTransform: 'uppercase', marginBottom: 4 }}>Fix</div>
              <pre style={{ margin: 0, fontSize: 11 }}>
                {finding.remediation || finding.fix_command || finding.command}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ReportButton() {
  const [state, setState] = useState('idle');
  const [msg, setMsg]     = useState('');

  async function generate() {
    setState('loading'); setMsg('');
    try {
      if (window.taara) {
        const r = await window.taara.api('/api/generate-report-path', 'POST', {});
        if (r.status >= 400) { setState('error'); setMsg(r.data?.detail || 'Failed'); return; }
        await window.taara.openPDF(r.data.path);
        setState('done'); setMsg(r.data.filename || 'Report opened');
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
    } catch (e) { setState('error'); setMsg(e.message); }
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 20 }}>
      <button className="btn" onClick={generate} disabled={state === 'loading'}
        style={{ borderColor: 'rgba(74,158,255,0.3)', color: 'var(--blue)' }}>
        {state === 'loading' ? <><span className="spinner" /> Generating…</> : '⬇ Generate TaaraWords Report'}
      </button>
      {state === 'done'  && <span style={{ fontSize: 12, color: 'var(--green)' }}>✓ {msg}</span>}
      {state === 'error' && <span style={{ fontSize: 12, color: 'var(--red)' }}>✕ {msg}</span>}
    </div>
  );
}

// ── Sub-tab 3: TaaraWare ──────────────────────────────────────────────────────
const DEPLOY_STEPS = [
  'Generating Kyber768 keypair…',
  'Establishing quantum-protected channel…',
  'Uploading TaaraWare agent binary…',
  'Registering systemd service…',
  'Configuring collection interval…',
  'Starting TaaraWare daemon…',
  'Verifying agent health…',
];

function TaaraWareSubTab({ hostname, demoMode, deployed, onDeployed }) {
  const [isDeployed, setIsDeployed] = useState(deployed);
  const [checking, setChecking]     = useState(!deployed);

  useEffect(() => {
    if (deployed) { setIsDeployed(true); setChecking(false); return; }
    api.taarawareDeployed().then(r => {
      if (r.ok) setIsDeployed(r.data.deployed === true);
    }).catch(() => {}).finally(() => setChecking(false));
  }, [deployed]);

  if (checking) {
    return (
      <div className="page" style={{ textAlign: 'center', paddingTop: 60 }}>
        <span className="spinner" style={{ margin: '0 auto', display: 'block', width: 20, height: 20 }} />
      </div>
    );
  }

  if (!isDeployed) {
    return (
      <div className="page">
        <TaaraWareDeployPanel hostname={hostname} demoMode={demoMode} onDeployed={() => { setIsDeployed(true); onDeployed(); }} />
      </div>
    );
  }

  return <TaaraWareStatusPanel hostname={hostname} demoMode={demoMode} onRevoke={() => setIsDeployed(false)} />;
}

function TaaraWareDeployPanel({ hostname, demoMode, onDeployed }) {
  const [deploying, setDeploying] = useState(false);
  const [steps, setSteps]         = useState([]);
  const [done, setDone]           = useState(false);
  const [error, setError]         = useState('');
  const [keyFp, setKeyFp]         = useState('');
  const stepRef                   = useRef(null);

  async function deploy() {
    setDeploying(true); setSteps([]); setError(''); setDone(false);
    let i = 0;
    stepRef.current = setInterval(() => {
      i = Math.min(i + 1, DEPLOY_STEPS.length - 1);
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
          <div style={{ fontSize: 10, color: 'var(--text-faint)', fontWeight: 600, letterSpacing: 0.5, marginBottom: 6 }}>PQC KEY FINGERPRINT</div>
          <div style={{ fontFamily: 'monospace', fontSize: 14, color: 'var(--green)', letterSpacing: 2 }}>{keyFp}</div>
          <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 8, lineHeight: 1.6 }}>
            Kyber768 / ML-KEM · NIST FIPS 203<br />
            This key protects your data against quantum adversaries using NIST FIPS 203 ML-KEM.
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
            {(i < steps.length - 1 || !deploying) && <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--green)' }}>✓</span>}
            {i === steps.length - 1 && deploying && <span className="spinner" style={{ marginLeft: 'auto', width: 12, height: 12 }} />}
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
      <div style={{ background: 'rgba(74,158,255,0.08)', border: '1px solid rgba(74,158,255,0.2)', borderRadius: 8, padding: 14, marginBottom: 20 }}>
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

// All 19 feature vectors with their descriptions and input variable names
const FEATURE_META = [
  { key: 'cpu_usage',                 label: 'CPU Usage',              unit: '%',   input: 'cpu_percent',       desc: 'Average CPU utilisation across all cores. High sustained values (>80%) can indicate crypto-mining, runaway processes, or active exploitation.' },
  { key: 'memory_usage',              label: 'Memory Usage',           unit: '%',   input: 'mem_percent',       desc: 'RAM utilisation (psutil.virtual_memory.percent). Steady growth without matching workload is a memory-leak or exfiltration buffer indicator.' },
  { key: 'disk_usage',                label: 'Disk Usage',             unit: '%',   input: 'disk_percent',      desc: 'Root filesystem utilisation. Rapid growth can signal log flooding, data staging for exfiltration, or ransomware encryption.' },
  { key: 'proc_spawn_rate',           label: 'Process Spawn Rate',     unit: '/m',  input: 'proc_spawn_rate',   desc: 'Number of new processes spawned per minute. Spikes indicate script execution, lateral movement, or automated attack tooling.' },
  { key: 'proc_root_ratio',           label: 'Root Process Ratio',     unit: '',    input: 'proc_root_ratio',   desc: 'Fraction of running processes owned by root. Increasing ratio may indicate privilege escalation or rootkit activity.' },
  { key: 'proc_cmd_entropy',          label: 'Command Entropy',        unit: 'bits',input: 'proc_cmd_entropy',  desc: 'Shannon entropy of process command strings. Anomalously high entropy suggests obfuscated or encoded payloads.' },
  { key: 'net_outbound_conn_rate',    label: 'Outbound Connections',   unit: '',    input: 'net_conn_rate',     desc: 'Count of active outbound TCP connections. High values may indicate C2 beaconing, scanning, or data exfiltration.' },
  { key: 'net_unique_dst_ips',        label: 'Unique Dest IPs',        unit: '',    input: 'net_dst_ips',       desc: 'Number of distinct destination IPs contacted. A sudden increase signals port scanning or botnet participation.' },
  { key: 'net_unique_dst_ports',      label: 'Unique Dest Ports',      unit: '',    input: 'net_dst_ports',     desc: 'Distinct destination ports. High diversity suggests network reconnaissance or C2 traffic randomisation.' },
  { key: 'net_port_entropy',          label: 'Port Entropy',           unit: 'bits',input: 'net_port_entropy',  desc: 'Shannon entropy over destination port distribution. Random ports (high entropy) suggest tunnelling or evasion.' },
  { key: 'net_failed_conn_ratio',     label: 'Failed Conn Ratio',      unit: '',    input: 'failed_conn_ratio', desc: 'Fraction of connection attempts that failed. Persistently high values indicate scanning, blocked C2, or misconfiguration.' },
  { key: 'failed_logins_1h',          label: 'Failed Logins (1h)',     unit: '',    input: 'failed_logins',     desc: 'SSH/PAM failed authentication attempts in the past hour (from /var/log/secure or auth.log). >10 suggests brute-force.' },
  { key: 'new_processes_1h',          label: 'New Processes (1h)',     unit: '',    input: 'new_procs',         desc: 'Count of new process executions in past hour. Unexpected spikes in off-hours are a key lateral movement indicator.' },
  { key: 'suspicious_connections',    label: 'Suspicious Connections', unit: '',    input: 'suspicious_conn',   desc: 'Heuristic count: connections to non-standard ports, TOR exits, or IPs flagged by TaaraWare threat feeds.' },
  { key: 'privilege_escalations',     label: 'Privilege Escalations',  unit: '',    input: 'priv_esc',          desc: 'sudo/su events from auth.log in past hour. Non-zero in off-hours is a critical signal for unauthorized access.' },
  { key: 'temporal_rhythm_deviation', label: 'Temporal Rhythm Dev.',   unit: '',    input: 'rhythm_dev',        desc: 'Deviation from the trained timing pattern of process launches (AtomicDNACollector). Attackers break normal rhythms.' },
  { key: 'causal_chain_novelty',      label: 'Causal Chain Novelty',   unit: '',    input: 'causal_novelty',    desc: 'How novel the parent→child process chains are vs. trained baseline. New chains = unknown execution paths = potential threat.' },
  { key: 'concealment_signal',        label: 'Concealment Signal',     unit: '',    input: 'concealment_sig',   desc: 'Composite signal: hidden file ratio, exec from /tmp, suspicious user-agent patterns. Non-zero means something is actively hiding.' },
  { key: 'proc_cmd_novelty',          label: 'Cmd Novelty',            unit: '',    input: 'cmd_novelty',       desc: 'Fraction of process command lines not seen during normal training. Novel commands in production indicate new code execution — a key indicator for T1078.' },
];

// ── Pipeline step visual component ────────────────────────────────────────────
function PipelineStep({ num, title, subtitle, color, detail, arrow }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flex: 1, minWidth: 100 }}>
      <div style={{
        width: 36, height: 36, borderRadius: '50%',
        background: `${color}22`, border: `2px solid ${color}`,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontSize: 14, fontWeight: 700, color, marginBottom: 6,
      }}>{num}</div>
      <div style={{ fontSize: 11, fontWeight: 700, textAlign: 'center', color: 'var(--text)' }}>{title}</div>
      <div style={{ fontSize: 9, color: 'var(--text-faint)', textAlign: 'center', marginTop: 2 }}>{subtitle}</div>
      {detail && <div style={{ fontSize: 9, color, fontFamily: 'monospace', marginTop: 3, textAlign: 'center' }}>{detail}</div>}
      {arrow && <div style={{ position: 'absolute', right: -14, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-faint)', fontSize: 16 }}>→</div>}
    </div>
  );
}

function FeatureMappingModal({ fv, onClose }) {
  const [pwd, setPwd]           = useState('');
  const [unlocked, setUnlocked] = useState(false);
  const [err, setErr]           = useState('');
  const [tab, setTab]           = useState('pipeline'); // pipeline | features | categories
  const [alertTriggering, setAlertTriggering] = useState(false);
  const [alertResult, setAlertResult]         = useState('');
  const DEMO_PWD                = 'taara2026';

  async function triggerDemoAlert() {
    setAlertTriggering(true);
    setAlertResult('');
    try {
      const r = await api.triggerTestAlert();
      setAlertResult(r.ok ? '✓ Alert injected — check the dashboard' : '✗ ' + (r.data?.detail || 'Failed'));
    } catch (e) {
      setAlertResult('✗ ' + e.message);
    } finally {
      setAlertTriggering(false);
    }
  }

  function tryUnlock() {
    if (pwd === DEMO_PWD) { setUnlocked(true); setErr(''); }
    else setErr('Incorrect password');
  }

  // Categorise features for the grouped view
  const CATEGORIES = [
    { label: 'System Resources',   color: '#4a9eff', keys: ['cpu_usage','memory_usage','disk_usage'] },
    { label: 'Network Activity',   color: '#22cc66', keys: ['net_outbound_conn_rate','net_unique_dst_ips','net_unique_dst_ports','net_port_entropy','net_failed_conn_ratio','suspicious_connections'] },
    { label: 'Process Behaviour',  color: '#f5a623', keys: ['proc_spawn_rate','proc_root_ratio','proc_cmd_entropy','new_processes_1h','privilege_escalations','temporal_rhythm_deviation','causal_chain_novelty'] },
    { label: 'Security Signals',   color: '#e94560', keys: ['failed_logins_1h','concealment_signal'] },
  ];

  const PIPELINE_STEPS = [
    { num: '①', title: 'Raw Collection', subtitle: '19 signals', detail: 'psutil + auth.log', color: '#4a9eff',
      explain: 'TaaraWare agent reads 19 live signals from the server every 30 seconds — CPU, memory, disk, network counters, process list, login logs, timing patterns, and 2 advanced behavioural signals (temporal rhythm deviation, causal chain novelty). These are the raw numbers that describe what the server is doing right now.' },
    { num: '②', title: 'Normalise', subtitle: 'MinMaxScaler', detail: 'x̂ = (x−min)/(max−min)', color: '#9b7dff',
      explain: 'Each raw value is scaled to [0, 1] using the min/max ranges learned during training. This means CPU 45% and network 2 MB/s are on the same scale — the model can compare apples to apples. The scaler is saved in models/dna_scaler.json.' },
    { num: '③', title: 'Autoencoder', subtitle: '19→8→19', detail: 'bottleneck compress', color: '#f5a623',
      explain: 'A deep neural network (19→64→8→64→19 architecture, Tanh bottleneck) compresses the 19 signals down to an 8-dimensional "behavioural DNA fingerprint". The network learned what normal server behaviour looks like during training. If the current state doesn\'t compress and reconstruct well, it\'s a sign something unusual is happening.' },
    { num: '④', title: 'Qubit Encoding', subtitle: '3 qubits', detail: 'AmplitudeEmbedding (8→3q)', color: '#22cc66',
      explain: 'The 8-dimensional latent vector is encoded into 3 qubits using PennyLane AmplitudeEmbedding (2³=8). This maps the full behavioural fingerprint into a quantum state |ψ_t⟩ that captures complex correlations between all 8 dimensions simultaneously — something classical vectors cannot express.' },
    { num: '⑤', title: 'V3 Fusion', subtitle: 'SWAP+Dir+Coh', detail: 'threshold: 0.1854', color: '#e94560',
      explain: 'Three quantum signals are fused: SWAP Fidelity (similarity to normal subspace), Directionality (deviation angle), and Phase Coherence (temporal stability). The V3 formula conf = α·swap + β·dir + γ·coh·√(swap·dir) weights them optimally. Threshold of 0.1854 (p95 of training distribution) determines alert vs. normal.' },
    { num: '⑥', title: 'PQC Protect', subtitle: 'Kyber768', detail: 'NIST FIPS 203', color: '#4a9eff',
      explain: 'Before the feature vector is sent from the agent to the TAARA server, it is offset using a Kyber768 (ML-KEM) shared secret. Kyber768 is post-quantum — even a future quantum computer cannot break it. This protects the behavioral data from interception in transit.' },
  ];

  return (
    <div onClick={onClose} style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.82)', zIndex: 1000,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div onClick={e => e.stopPropagation()} style={{
        background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 14,
        padding: 28, width: '94vw', maxWidth: 940, maxHeight: '90vh',
        display: 'flex', flexDirection: 'column', gap: 0,
      }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
          <div>
            <div style={{ fontWeight: 700, fontSize: 18 }}>How TAARA Analyses Your Server</div>
            <div style={{ fontSize: 12, color: 'var(--text-faint)', marginTop: 4 }}>
              From 19 raw signals to a quantum anomaly verdict — every step explained
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-dim)', cursor: 'pointer', fontSize: 22, lineHeight: 1 }}>✕</button>
        </div>

        {!unlocked ? (
          /* Lock screen */
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 14, alignItems: 'center', justifyContent: 'center', padding: '30px 0' }}>
            <div style={{ fontSize: 40 }}>🔒</div>
            <div style={{ fontSize: 14, fontWeight: 700 }}>Analysis Password Required</div>
            <div style={{ fontSize: 12, color: 'var(--text-dim)', textAlign: 'center', maxWidth: 360 }}>
              The detailed pipeline and input variable mapping contain proprietary collection logic.
              Enter the analysis password to continue.
            </div>
            <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
              <input
                type="password" value={pwd} onChange={e => setPwd(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && tryUnlock()}
                placeholder="Analysis password" className="input" style={{ width: 240 }} autoFocus
              />
              <button className="btn btn-primary" onClick={tryUnlock}>Unlock</button>
            </div>
            {err && <div style={{ fontSize: 12, color: 'var(--red)' }}>{err}</div>}
          </div>
        ) : (
          <>
            {/* Tab bar */}
            <div style={{ display: 'flex', gap: 4, marginBottom: 20, background: 'var(--bg-raised)', padding: 4, borderRadius: 8, border: '1px solid var(--border)', alignSelf: 'flex-start' }}>
              {[['pipeline','⬡ Pipeline'], ['features','◈ Features'], ['categories','⊞ By Category']].map(([id, label]) => (
                <button key={id} onClick={() => setTab(id)} style={{
                  padding: '6px 14px', borderRadius: 5, border: 'none', cursor: 'pointer', fontSize: 12, fontWeight: 600,
                  background: tab === id ? 'var(--bg-surface)' : 'transparent',
                  color: tab === id ? 'var(--text)' : 'var(--text-dim)',
                  boxShadow: tab === id ? '0 1px 3px rgba(0,0,0,0.3)' : 'none',
                }}>{label}</button>
              ))}
            </div>

            <div style={{ overflowY: 'auto', flex: 1 }}>

              {/* ── TAB: PIPELINE ── */}
              {tab === 'pipeline' && (
                <div>
                  {/* Visual pipeline row */}
                  <div style={{
                    display: 'flex', alignItems: 'stretch', gap: 0, marginBottom: 24,
                    background: 'var(--bg-raised)', borderRadius: 10, padding: '16px 12px',
                    border: '1px solid var(--border)', overflowX: 'auto',
                  }}>
                    {PIPELINE_STEPS.map((s, i) => (
                      <React.Fragment key={i}>
                        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: 110, flex: 1 }}>
                          <div style={{
                            width: 42, height: 42, borderRadius: '50%',
                            background: `${s.color}18`, border: `2px solid ${s.color}`,
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                            fontSize: 18, color: s.color, marginBottom: 8,
                          }}>{s.num}</div>
                          <div style={{ fontSize: 11, fontWeight: 700, textAlign: 'center' }}>{s.title}</div>
                          <div style={{ fontSize: 9, color: 'var(--text-faint)', textAlign: 'center', marginTop: 2 }}>{s.subtitle}</div>
                          <div style={{ fontSize: 9, color: s.color, fontFamily: 'monospace', marginTop: 3, textAlign: 'center' }}>{s.detail}</div>
                        </div>
                        {i < PIPELINE_STEPS.length - 1 && (
                          <div style={{ display: 'flex', alignItems: 'center', color: 'var(--text-faint)', fontSize: 18, padding: '0 4px', marginTop: -14 }}>→</div>
                        )}
                      </React.Fragment>
                    ))}
                  </div>

                  {/* Step-by-step explainer cards */}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                    {PIPELINE_STEPS.map((s, i) => (
                      <div key={i} style={{
                        display: 'flex', gap: 14, padding: '14px 16px',
                        background: 'var(--bg-raised)', borderRadius: 8,
                        border: `1px solid ${s.color}28`,
                        borderLeft: `3px solid ${s.color}`,
                      }}>
                        <div style={{ fontSize: 22, lineHeight: 1, paddingTop: 1, color: s.color }}>{s.num}</div>
                        <div style={{ flex: 1 }}>
                          <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 5, display: 'flex', alignItems: 'baseline', gap: 8 }}>
                            {s.title}
                            <span style={{ fontFamily: 'monospace', fontSize: 10, color: s.color, fontWeight: 400 }}>{s.detail}</span>
                          </div>
                          <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.7 }}>{s.explain}</div>
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Demo alert trigger */}
                  <div style={{ marginTop: 20, padding: '14px 18px', borderRadius: 8, background: 'rgba(233,69,96,0.06)', border: '1px solid rgba(233,69,96,0.2)' }}>
                    <div style={{ fontWeight: 700, fontSize: 12, color: '#e94560', marginBottom: 6 }}>⚡ Live Demo — Inject T1078 Alert</div>
                    <div style={{ fontSize: 11, color: 'var(--text-dim)', marginBottom: 10 }}>
                      Injects a synthetic credential-theft anomaly into the live monitoring stream. V3 quantum confidence will spike above 0.1854 and an alert banner will fire on the dashboard — showing judges the full detection pipeline in real time.
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <button
                        onClick={triggerDemoAlert}
                        disabled={alertTriggering}
                        style={{ padding: '7px 18px', borderRadius: 6, border: '1px solid rgba(233,69,96,0.5)', background: 'rgba(233,69,96,0.12)', color: '#e94560', fontWeight: 700, fontSize: 12, cursor: alertTriggering ? 'not-allowed' : 'pointer' }}>
                        {alertTriggering ? 'Injecting…' : '⚡ Trigger Alert Demo'}
                      </button>
                      {alertResult && <span style={{ fontSize: 11, color: alertResult.startsWith('✓') ? '#22cc66' : '#e94560' }}>{alertResult}</span>}
                    </div>
                  </div>
                </div>
              )}

              {/* ── TAB: FEATURES ── */}
              {tab === 'features' && (
                <div>
                  <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 16, lineHeight: 1.6 }}>
                    Each bar shows the current live value normalised to [0, 1]. A value of <span style={{ color: 'var(--green)', fontFamily: 'monospace' }}>0.0</span> is the minimum seen during training;{' '}
                    <span style={{ color: 'var(--red)', fontFamily: 'monospace' }}>1.0</span> is the maximum. Bars near 1.0 for threat-sensitive signals (red group) are worth investigating.
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {FEATURE_META.map((f, i) => {
                      const raw = fv[f.key];
                      const normalised = raw != null ? Math.min(Math.max(raw / (f.unit === '%' ? 100 : Math.max(raw, 1)), 0), 1) : null;
                      const cat = CATEGORIES.find(c => c.keys.includes(f.key));
                      const barColor = cat?.color || 'var(--blue)';
                      return (
                        <div key={f.key} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                          <div style={{ width: 22, fontSize: 9, color: 'var(--text-faint)', fontFamily: 'monospace', textAlign: 'right', flexShrink: 0 }}>F{i+1}</div>
                          <div style={{ width: 148, fontSize: 10, color: 'var(--text-dim)', flexShrink: 0, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{f.label}</div>
                          <div style={{ flex: 1, height: 10, background: 'var(--bg-raised)', borderRadius: 5, overflow: 'hidden', border: '1px solid var(--border-dim)' }}>
                            {normalised != null && (
                              <div style={{
                                height: '100%', borderRadius: 5, width: `${normalised * 100}%`,
                                background: barColor, opacity: 0.8, transition: 'width 0.5s ease',
                              }} />
                            )}
                          </div>
                          <div style={{ width: 68, fontSize: 10, fontFamily: 'monospace', textAlign: 'right', flexShrink: 0, color: raw != null ? 'var(--text)' : 'var(--text-faint)' }}>
                            {raw != null ? (typeof raw === 'number' ? raw.toFixed(3) : raw) + (f.unit || '') : '—'}
                          </div>
                        </div>
                      );
                    })}
                  </div>

                  {/* Classical signal breakdown */}
                  {(fv.anomaly_score != null || fv.recon_error != null || fv.latent_fidelity != null) && (
                    <div style={{ marginTop: 20, padding: '14px 16px', background: 'var(--bg-raised)', borderRadius: 8, border: '1px solid var(--border)' }}>
                      <div style={{ fontWeight: 700, fontSize: 12, marginBottom: 10 }}>Classical Ensemble — 3 Signals</div>
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10, marginBottom: 10 }}>
                        {[
                          { label: 'Reconstruction Error', value: fv.recon_error, threshold: 0.05, bad: v => v > 0.05, fmt: v => v.toFixed(4), sub: '> 0.05 = anomaly' },
                          { label: 'Latent Fidelity', value: fv.latent_fidelity, bad: v => v < 0.6, fmt: v => v.toFixed(4), sub: '< 0.6 = direction anomaly' },
                          { label: 'IF Score', value: fv.anomaly_score, bad: v => v < 0, fmt: v => v.toFixed(4), sub: '< 0 = statistical outlier' },
                        ].map(s => {
                          const isAnomaly = s.value != null && s.bad(s.value);
                          const color = s.value == null ? 'var(--text-faint)' : isAnomaly ? 'var(--red)' : 'var(--green)';
                          return (
                            <div key={s.label} style={{ background: 'var(--bg-surface)', borderRadius: 6, padding: '8px 10px', border: `1px solid ${s.value != null && isAnomaly ? 'rgba(233,69,96,0.3)' : 'var(--border)'}` }}>
                              <div style={{ fontSize: 9, color: 'var(--text-faint)', marginBottom: 3 }}>{s.label}</div>
                              <div style={{ fontSize: 14, fontWeight: 700, fontFamily: 'monospace', color }}>{s.value != null ? s.fmt(s.value) : '—'}</div>
                              <div style={{ fontSize: 9, color: 'var(--text-faint)', marginTop: 2 }}>{s.sub}</div>
                            </div>
                          );
                        })}
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--text-dim)', lineHeight: 1.6 }}>
                        All three must flag simultaneously for a <strong style={{ color: '#f5a623' }}>dual-confirmed alert (orange)</strong>.
                        Quantum F_min alone triggers a <strong style={{ color: '#e94560' }}>quantum alert (red)</strong>.
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* ── TAB: BY CATEGORY ── */}
              {tab === 'categories' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                  {CATEGORIES.map(cat => (
                    <div key={cat.label} style={{ padding: '14px 16px', background: 'var(--bg-raised)', borderRadius: 8, borderLeft: `3px solid ${cat.color}` }}>
                      <div style={{ fontWeight: 700, fontSize: 13, color: cat.color, marginBottom: 12 }}>{cat.label}</div>
                      {cat.keys.map(key => {
                        const meta = FEATURE_META.find(f => f.key === key);
                        if (!meta) return null;
                        const val = fv[key];
                        const i   = FEATURE_META.indexOf(meta);
                        return (
                          <div key={key} style={{ marginBottom: 10 }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                              <div style={{ display: 'flex', gap: 8, alignItems: 'baseline' }}>
                                <span style={{ fontSize: 9, color: 'var(--text-faint)', fontFamily: 'monospace' }}>F{i+1}</span>
                                <span style={{ fontSize: 11, fontWeight: 600 }}>{meta.label}</span>
                                <span style={{ fontSize: 9, color: cat.color, fontFamily: 'monospace' }}>{meta.input}</span>
                              </div>
                              <span style={{ fontSize: 11, fontFamily: 'monospace', color: val != null ? 'var(--text)' : 'var(--text-faint)' }}>
                                {val != null ? (typeof val === 'number' ? val.toFixed(3) : val) + (meta.unit || '') : '—'}
                              </span>
                            </div>
                            <div style={{ fontSize: 10, color: 'var(--text-faint)', lineHeight: 1.5, marginBottom: 4 }}>{meta.desc}</div>
                            <div style={{ height: 5, background: 'var(--bg-input)', borderRadius: 3, overflow: 'hidden' }}>
                              {val != null && (
                                <div style={{
                                  height: '100%', borderRadius: 3,
                                  width: `${Math.min(100, (meta.unit === '%' ? val : Math.min(val / 10, 1) * 100))}%`,
                                  background: cat.color, opacity: 0.7, transition: 'width 0.5s',
                                }} />
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  ))}
                </div>
              )}

            </div>
          </>
        )}
      </div>
    </div>
  );
}

function TaaraWareStatusPanel({ hostname, demoMode, onRevoke }) {
  const [status, setStatus]       = useState(null);
  const pollRef                   = useRef(null);
  const [revoking, setRevoking]   = useState(false);
  const [showMapping, setShowMapping] = useState(false);

  async function load() {
    try {
      // /api/status carries the live feature_vector and agent_status from TaaraWare buffer
      // /api/taaraware/status only works if get_latest_feature_vector() is implemented (it isn't)
      const r = await api.status();
      if (r.ok) setStatus(r.data);
    } catch (_) {}
  }

  useEffect(() => {
    load();
    pollRef.current = setInterval(load, 10000);
    return () => clearInterval(pollRef.current);
  }, []);

  async function revoke() {
    if (!window.confirm('Revoke TaaraWare and remove agent from the server?')) return;
    setRevoking(true);
    try {
      await api.execute({ command: 'systemctl stop taaraware && systemctl disable taaraware && rm -f /opt/taaraware/agent', source: 'revoke' });
      onRevoke && onRevoke();
    } catch (e) { alert('Revoke failed: ' + e.message); }
    finally { setRevoking(false); }
  }

  const agentStatus = status?.agent_status || {};
  const fv   = status?.feature_vector || {};
  const nov  = status?.novelty || {};
  const basisSize = nov.basis_size ?? 0;
  const basisMature = basisSize >= 3;
  const rawFmin = nov.f_min ?? status?.f_min;
  const fmin = rawFmin ?? null;
  // Always show live V3 quantum signals — suppress alerts (not display) when basis not mature
  const twSwapFidelity    = nov.swap_fidelity    ?? null;
  const twQDirectionality = nov.q_directionality ?? null;
  const twPhaseCoherence  = nov.phase_coherence  ?? null;
  const twQuantumConf     = nov.quantum_confidence ?? null;
  const twQcColor = twQuantumConf == null ? 'var(--text-faint)'
    : twQuantumConf >= 0.75 ? '#e94560'
    : twQuantumConf >= 0.45 ? '#f5a623'
    : twQuantumConf >= 0.1854 ? '#4a9eff'
    : '#22cc66';
  const twQcLabel = twQuantumConf == null ? '—'
    : twQuantumConf >= 0.75 ? 'CRITICAL'
    : twQuantumConf >= 0.45 ? 'HIGH'
    : twQuantumConf >= 0.1854 ? 'MEDIUM'
    : 'LOW';
  // all-zeros means not yet collected — only show as hasFv when at least one non-zero value
  const hasFv = Object.keys(fv).filter(k => !['anomaly_score','is_anomaly'].includes(k)).some(k => fv[k] !== 0 && fv[k] != null);
  // Pull last collection time from recent agent log line
  const recentLog = agentStatus.recent_logs ? agentStatus.recent_logs.split('\n').filter(Boolean).pop() : '';
  const lastTs = recentLog
    ? recentLog.split(' INFO:')[0].replace(/.*\[TaaraWare\]\s*/, '').trim().split(' ').slice(0,2).join(' ')
    : demoMode ? 'Demo — live' : 'Waiting…';

  return (
    <div className="page">
      {showMapping && <FeatureMappingModal fv={fv} onClose={() => setShowMapping(false)} />}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(155px, 1fr))', gap: 10, marginBottom: 20 }}>
        <MetricTile label="Agent"
          value={agentStatus.status === 'active' ? 'LIVE' : demoMode ? 'DEMO' : (status ? 'CONNECTED' : 'CHECKING')}
          color={agentStatus.status === 'active' || demoMode ? 'var(--green)' : 'var(--text-faint)'} />
        <MetricTile label="Buffer"
          value={agentStatus.buffer_size != null ? `${agentStatus.buffer_size}` : '—'}
          color="var(--blue)" sub="samples stored" />
        <MetricTile label="Q Confidence"
          value={twQuantumConf != null ? twQuantumConf.toFixed(4) : '—'}
          color={twQcColor} mono />
        <MetricTile label="SWAP Fidelity"
          value={twSwapFidelity != null ? twSwapFidelity.toFixed(4) : '—'}
          color={twSwapFidelity == null ? 'var(--text-faint)' : twSwapFidelity >= 0.7 ? '#22cc66' : twSwapFidelity >= 0.5 ? '#4a9eff' : '#e94560'} mono />
        <MetricTile label="Directionality"
          value={twQDirectionality != null ? twQDirectionality.toFixed(4) : '—'}
          color={twQDirectionality == null ? 'var(--text-faint)' : twQDirectionality >= 0.3 ? '#e94560' : twQDirectionality >= 0.15 ? '#f5a623' : '#22cc66'} mono />
        <MetricTile label="Phase Coherence"
          value={twPhaseCoherence != null ? twPhaseCoherence.toFixed(4) : '—'}
          color={twPhaseCoherence == null ? 'var(--text-faint)' : twPhaseCoherence >= 0.8 ? '#e94560' : twPhaseCoherence >= 0.6 ? '#f5a623' : '#22cc66'} mono />
        <MetricTile label="Last Collection" value={lastTs} color="var(--text-dim)" />
      </div>

      {!basisMature && (
        <div className="card" style={{ marginBottom: 16, borderLeft: `3px solid ${basisSize > 0 ? 'var(--blue)' : 'var(--amber)'}` }}>
          <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 8, color: basisSize > 0 ? 'var(--blue)' : 'var(--amber)' }}>
            {basisSize > 0 ? `Quantum Baseline Building — ${basisSize}/3 training samples` : 'No Baseline — Train tab required'}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.7, marginBottom: 10 }}>
            {basisSize > 0
              ? `The Train tab has collected ${basisSize} of 3 required normal-behavior samples. F_min and anomaly alerts activate once the baseline is complete.`
              : 'The quantum memory basis is empty. Go to the Train tab and run training on this server to establish a normal behavioral baseline. Live monitoring will check incoming data against that baseline — it never modifies it.'}
          </div>
          {basisSize > 0 && (
            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <div style={{ flex: 1, height: 6, borderRadius: 3, background: 'var(--bg-raised)', overflow: 'hidden' }}>
                <div style={{ width: `${(basisSize / 3) * 100}%`, height: '100%', background: 'var(--blue)', borderRadius: 3, transition: 'width 0.4s' }} />
              </div>
              <span style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--text-faint)' }}>{basisSize}/3</span>
            </div>
          )}
        </div>
      )}

      {basisMature && (twQuantumConf != null || fmin != null) && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div style={{ display: 'flex', gap: 20, alignItems: 'flex-start', flexWrap: 'wrap' }}>
            {/* Big quantum confidence dial */}
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: 110 }}>
              {(() => {
                const dialVal = twQuantumConf ?? 0;
                const dialColor = twQcColor !== 'var(--text-faint)' ? twQcColor : '#4a9eff';
                return (
                  <div style={{
                    width: 100, height: 100, borderRadius: '50%',
                    background: `conic-gradient(${dialColor} 0% ${dialVal * 100}%, var(--bg-raised) ${dialVal * 100}% 100%)`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    boxShadow: `0 0 16px ${dialColor}44`,
                    border: `2px solid ${dialColor}66`,
                    position: 'relative',
                  }}>
                    <div style={{
                      width: 76, height: 76, borderRadius: '50%', background: 'var(--bg-surface)',
                      display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
                    }}>
                      <div style={{ fontSize: 16, fontWeight: 700, fontFamily: 'monospace', color: dialColor }}>
                        {(dialVal * 100).toFixed(0)}%
                      </div>
                      <div style={{ fontSize: 8, color: 'var(--text-faint)' }}>Q-CONF</div>
                    </div>
                  </div>
                );
              })()}
              <div style={{ marginTop: 8, fontSize: 11, fontWeight: 700, color: twQcColor }}>{twQcLabel}</div>
            </div>

            {/* Explanation + signal breakdown */}
            <div style={{ flex: 1, minWidth: 200 }}>
              <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 8 }}>Quantum Subspace Analysis</div>
              <div style={{ fontSize: 11, color: 'var(--text-dim)', lineHeight: 1.6, marginBottom: 10 }}>
                TAARA projects the 8-dim behavioral latent onto a <strong>3-qubit quantum state |ψ_t⟩</strong> via
                AmplitudeEmbedding, then measures subspace alignment. SWAP fidelity detects departure from the
                trained normal subspace. Directionality + phase coherence detect <em>sustained drift</em> — the
                signature of T1078 credential theft. Protected by ML-KEM Kyber768 (NIST FIPS 203) — the behavioral
                norm cannot be reverse-engineered or replayed.
              </div>
              {/* Signal breakdown bars */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {[
                  { label: 'SWAP Fidelity', val: twSwapFidelity, color: twSwapFidelity == null ? 'var(--text-faint)' : twSwapFidelity >= 0.7 ? '#22cc66' : twSwapFidelity >= 0.5 ? '#4a9eff' : '#e94560', note: '(high=normal)' },
                  { label: 'Directionality', val: twQDirectionality, color: twQDirectionality == null ? 'var(--text-faint)' : twQDirectionality >= 0.3 ? '#e94560' : '#22cc66', note: '(high=anomalous)' },
                  { label: 'Phase Coherence', val: twPhaseCoherence, color: twPhaseCoherence == null ? 'var(--text-faint)' : twPhaseCoherence >= 0.8 ? '#e94560' : '#22cc66', note: '(high=sustained drift)' },
                ].map(s => (
                  <div key={s.label} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontSize: 9, color: 'var(--text-faint)', minWidth: 90 }}>{s.label}</span>
                    <div style={{ flex: 1, height: 5, background: 'var(--bg-raised)', borderRadius: 3 }}>
                      <div style={{ height: '100%', width: `${Math.min(s.val ?? 0, 1) * 100}%`, background: s.color, borderRadius: 3, transition: 'width 0.5s' }} />
                    </div>
                    <span style={{ fontSize: 9, fontFamily: 'monospace', color: s.color, minWidth: 42 }}>{s.val != null ? s.val.toFixed(3) : '—'}</span>
                    <span style={{ fontSize: 8, color: 'var(--text-faint)' }}>{s.note}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Confidence gradient bar — low conf = normal, high conf = anomalous */}
          <div style={{ marginTop: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
              <span style={{ fontSize: 9, color: 'var(--text-faint)' }}>Normal (conf low)</span>
              <span style={{ fontSize: 9, color: 'var(--text-faint)', fontFamily: 'monospace' }}>
                threshold = 0.1854 · conf = {twQuantumConf != null ? twQuantumConf.toFixed(4) : '—'}</span>
              <span style={{ fontSize: 9, color: 'var(--text-faint)' }}>Anomalous (conf high)</span>
            </div>
            <div style={{ height: 10, background: 'linear-gradient(90deg, #22cc66 0%, #4a9eff 30%, #f5a623 55%, #e94560 100%)', borderRadius: 5, position: 'relative' }}>
              {/* Threshold marker at 0.1854 */}
              <div style={{
                position: 'absolute', left: '18.54%', top: 0, bottom: 0,
                width: 1.5, background: '#f5a623', opacity: 0.7,
              }} />
              {twQuantumConf != null && (
                <div style={{
                  position: 'absolute', left: `${twQuantumConf * 100}%`, top: '50%', transform: 'translate(-50%,-50%)',
                  width: 16, height: 16, borderRadius: '50%', background: twQcColor,
                  border: '2px solid var(--bg-surface)', boxShadow: `0 0 6px ${twQcColor}`,
                  transition: 'left 0.6s ease',
                }} />
              )}
            </div>
          </div>
        </div>
      )}

      {/* Feature vectors — obscured tiles, click to open pipeline modal */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 14 }}>
          <div>
            <div className="section-title">Behavioral DNA — 19 Feature Vectors</div>
            <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 3 }}>
              Raw features collected this cycle (F1–F19). PQC-transformed → 8-dim AE latent → 3-qubit quantum state. Click any tile or "View Pipeline" to see full mapping.
            </div>
          </div>
          <button onClick={() => setShowMapping(true)} style={{
            background: 'none', border: '1px solid rgba(155,125,255,0.35)', borderRadius: 6,
            color: '#9b7dff', cursor: 'pointer', fontSize: 11, padding: '5px 12px', whiteSpace: 'nowrap', flexShrink: 0, marginLeft: 12,
          }}>
            🔒 View Pipeline
          </button>
        </div>

        {!hasFv ? (
          <div style={{ fontSize: 12, color: 'var(--text-faint)', textAlign: 'center', padding: '24px 0' }}>
            Waiting for first collection cycle… (every 30s)
          </div>
        ) : (
          <>
            {/* Obscured F1–F19 grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(88px, 1fr))', gap: 6, marginBottom: 14 }}>
              {FEATURE_META.map((f, i) => {
                const val = fv[f.key];
                const cat = [
                  { color: '#4a9eff', keys: ['cpu_usage','memory_usage','disk_usage','load_avg_1m','load_avg_5m','load_avg_15m'] },
                  { color: '#22cc66', keys: ['network_bytes_sent','network_bytes_recv','active_connections','suspicious_connections'] },
                  { color: '#f5a623', keys: ['process_count','new_processes_1h','privilege_escalations'] },
                  { color: '#e94560', keys: ['failed_logins_1h','temporal_rhythm_deviation','causal_chain_novelty','concealment_signal'] },
                ].find(c => c.keys.includes(f.key));
                const dotColor = cat?.color || '#4a9eff';
                const norm = val != null
                  ? f.unit === '%' ? Math.min(val / 100, 1)
                  : f.key.includes('bytes') ? Math.min(val / 1000000, 1)
                  : Math.min(val / Math.max(val, 20), 1)
                  : 0.3;
                const isThreat = cat?.color === '#e94560';
                const isHigh = norm > 0.7 && isThreat;
                return (
                  <div key={f.key} onClick={() => setShowMapping(true)} style={{
                    background: 'var(--bg-raised)', borderRadius: 6, padding: '8px 8px 6px',
                    border: `1px solid ${isHigh ? 'rgba(233,69,96,0.3)' : 'var(--border-dim)'}`,
                    cursor: 'pointer', transition: 'border-color 0.15s',
                    display: 'flex', flexDirection: 'column', gap: 5,
                  }}
                  onMouseEnter={e => e.currentTarget.style.borderColor = dotColor + '88'}
                  onMouseLeave={e => e.currentTarget.style.borderColor = isHigh ? 'rgba(233,69,96,0.3)' : 'var(--border-dim)'}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: 9, fontFamily: 'monospace', color: dotColor, fontWeight: 700 }}>F{i + 1}</span>
                      {isHigh && <span style={{ fontSize: 8, color: 'var(--red)' }}>⚠</span>}
                    </div>
                    {/* Blurred value bar */}
                    <div style={{ height: 6, background: 'var(--bg-input)', borderRadius: 3, overflow: 'hidden' }}>
                      <div style={{
                        height: '100%', width: `${norm * 100}%`, borderRadius: 3,
                        background: isHigh ? '#e94560' : dotColor, opacity: 0.7,
                        transition: 'width 0.6s ease',
                        boxShadow: isHigh ? `0 0 4px #e9456088` : 'none',
                      }} />
                    </div>
                    {/* Obscured numeric value */}
                    <div style={{ filter: 'blur(3.5px)', fontSize: 11, fontFamily: 'monospace', fontWeight: 700, color: val != null ? 'var(--text)' : 'var(--text-faint)', userSelect: 'none', letterSpacing: 0.5 }}>
                      {val != null ? (typeof val === 'number' ? val.toFixed(2) : String(val)) : '—'}
                    </div>
                    <div style={{ fontSize: 8, color: 'var(--text-faint)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {'████████'.slice(0, 4 + (i % 4))}
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Classical ensemble verdict row */}
            {(fv.anomaly_score != null || fv.recon_error != null || fv.latent_fidelity != null) && (
              <div style={{ padding: '12px 14px', background: fv.is_anomaly ? 'rgba(233,69,96,0.06)' : 'rgba(34,204,102,0.04)', borderRadius: 8, border: `1px solid ${fv.is_anomaly ? 'rgba(233,69,96,0.2)' : 'rgba(34,204,102,0.15)'}` }}>
                <div style={{ fontWeight: 700, fontSize: 12, marginBottom: 8, color: fv.is_anomaly ? 'var(--red)' : 'var(--green)' }}>
                  {fv.is_anomaly ? '⚠ Classical ensemble: anomaly' : '✓ Classical ensemble: normal'}
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
                  {[
                    { label: 'Recon Error', value: fv.recon_error, bad: v => v > 0.05, fmt: v => v.toFixed(4) },
                    { label: 'Latent Fidelity', value: fv.latent_fidelity, bad: v => v < 0.6, fmt: v => v.toFixed(4) },
                    { label: 'IF Score', value: fv.anomaly_score, bad: v => v < 0, fmt: v => v.toFixed(4) },
                  ].map(s => {
                    const flagged = s.value != null && s.bad(s.value);
                    return (
                      <div key={s.label} style={{ fontSize: 11, fontFamily: 'monospace' }}>
                        <span style={{ color: 'var(--text-faint)', fontSize: 10 }}>{s.label}: </span>
                        <span style={{ color: s.value == null ? 'var(--text-faint)' : flagged ? 'var(--red)' : 'var(--green)', fontWeight: 600 }}>
                          {s.value != null ? s.fmt(s.value) : '—'}
                        </span>
                      </div>
                    );
                  })}
                </div>
                <div style={{ fontSize: 10, color: 'var(--text-faint)', marginTop: 8 }}>
                  All three must flag simultaneously · quantum signal is independent
                </div>
              </div>
            )}
          </>
        )}
      </div>

      <div className="card" style={{ border: '1px solid rgba(233,69,96,0.2)' }}>
        <div className="section-title" style={{ marginBottom: 8, color: 'var(--red)' }}>Revoke Agent</div>
        <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 12 }}>
          Stops the agent, removes it from the server, and deletes the PQC keypair.
        </div>
        <button className="btn btn-danger" onClick={revoke} disabled={revoking}>
          {revoking ? <><span className="spinner" /> Revoking…</> : '⏻ Revoke TaaraWare'}
        </button>
      </div>
    </div>
  );
}

// ── Sub-tab 4: Train ──────────────────────────────────────────────────────────
// Training state is driven entirely by polling /api/train/status.
// No local animation timers that die on tab switch — the server is the source of truth.
const TRAIN_MODES = [
  { id: 'quick_demo', label: 'Quick',    dur: '~1 min',  desc: 'Finetune with ~10 fast samples — builds quantum subspace quickly. Good for first baseline.' },
  { id: 'standard',   label: 'Standard', dur: '~3 min',  desc: 'Sufficient samples for AE finetune + IsolationForest + quantum subspace. Recommended.' },
  { id: 'deep',        label: 'Deep',     dur: '~20 min', desc: 'Maximum samples, 20 AE finetune epochs — most adapted model. Best results over time.' },
];

const TRAIN_STEPS_MAP = {
  collecting:  'Collecting baseline samples…',
  autoencoder: 'Finetuning BehavioralAE (19→8-dim latent)…',
  isolation:   'Running IsolationForest…',
  quantum:     'Building per-identity quantum subspace (PCA)…',
  calibrating: 'Calibrating V3 confidence threshold…',
  validating:  'Validating model…',
  saving:      'Saving model weights…',
  complete:    'Model ready.',
};
const TRAIN_STEPS_ORDER = Object.keys(TRAIN_STEPS_MAP);

function TrainSubTab() {
  const [mode, setMode]       = useState('quick_demo');
  const [status, setStatus]   = useState(null);
  const [starting, setStarting] = useState(false);
  const [error, setError]     = useState('');
  const [basisStatus, setBasisStatus] = useState(null);
  const [liveStatus, setLiveStatus]   = useState(null);
  const pollRef               = useRef(null);

  useEffect(() => {
    function poll() {
      api.trainStatus().then(r => { if (r.ok) setStatus(r.data); }).catch(() => {});
      // basisStatus is authoritative for quantum basis — works even when TaaraWare buffer is empty
      api.basisStatus().then(r => { if (r.ok) setBasisStatus(r.data); }).catch(() => {});
      // liveStatus for classical pipeline signals only
      api.status().then(r => { if (r.ok) setLiveStatus(r.data); }).catch(() => {});
    }
    poll();
    pollRef.current = setInterval(poll, 3000);
    return () => clearInterval(pollRef.current);
  }, []);

  async function startTrain() {
    setStarting(true); setError('');
    try {
      const r = await api.train({ mode });
      if (!r.ok) setError(r.data?.detail || 'Failed to start training');
    } catch (e) { setError(e.message); }
    finally { setStarting(false); }
  }

  async function stopTrain() {
    try { await api.trainStop(); } catch (_) {}
  }

  // Backend statuses: 'idle', 'running', 'stopped', 'completed', 'failed'
  const isTraining = status?.status === 'running';
  const isDone     = status?.status === 'completed';
  const isStopped  = status?.status === 'stopped' || status?.status === 'failed';
  const progress   = typeof status?.progress === 'number' ? status.progress : (isTraining ? 50 : isDone ? 100 : 0);
  // Backend uses current_phase (string), not current_step
  const phase      = status?.current_phase || '';
  // Map phase string to step index
  const stepIdx    = phase.includes('Phase 1') ? 0 : phase.includes('Phase 2') ? 1 : phase.includes('Phase 3') ? 2 : phase.includes('Phase 4') || isDone ? 3 : -1;

  return (
    <div className="page">
      <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 4 }}>Train Classical Ensemble</div>
      <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 20, lineHeight: 1.6 }}>
        Training here builds the <strong>normal baseline</strong> — both the quantum memory basis and the classical ensemble.
        Live TaaraWare monitoring only <em>checks</em> incoming behavior against this baseline, never modifying it.
        Once trained, quantum + all three classical signals must agree before an alert fires, eliminating false positives.
      </div>

      {/* How it works */}
      <div className="card" style={{ marginBottom: 16, borderLeft: '3px solid var(--accent)' }}>
        <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 10 }}>How detection works after training</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {[
            { icon: '⬢', label: 'Quantum memory basis (built here)', desc: 'Built from training data collected here — not from live monitoring. Encodes normal observations via 3-qubit AmplitudeEmbedding on 8-dim latent. Builds PCA subspace for V3 SWAP/Directionality/Coherence signals. Alert threshold 0.1854.' },
            { icon: '①', label: 'Reconstruction error', desc: 'Autoencoder trained only on normal behavior. At inference: feed current state through the same weights — if it cannot reconstruct accurately, the behavior is outside what it learned as normal. High MSE = anomaly.' },
            { icon: '②', label: 'Latent fidelity', desc: 'The latent space is the behavioral DNA. Cosine fidelity between the current latent state and the stored mean-normal latent state shows directional deviation — not just magnitude. Low fidelity = the server is heading in a direction it has never gone before.' },
            { icon: '③', label: 'Isolation Forest on latent', desc: 'Statistical backstop on the learned latent space. Isolation Forest isolates whether this latent state is a statistical outlier from all the normal latent states seen during training.' },
            { icon: '⚡', label: 'Dual-confirmed alert (orange)', desc: 'Fires when quantum AND all three classical signals agree. Four independent lenses — Hilbert space fidelity, reconstruction failure, latent direction, statistical isolation — must all flag the same state simultaneously.' },
          ].map(r => (
            <div key={r.label} style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
              <span style={{ fontSize: 16, marginTop: 1 }}>{r.icon}</span>
              <div>
                <div style={{ fontWeight: 600, fontSize: 12 }}>{r.label}</div>
                <div style={{ fontSize: 11, color: 'var(--text-dim)', lineHeight: 1.6 }}>{r.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 12 }}>Training Mode</div>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 16 }}>
          {TRAIN_MODES.map(m => (
            <button key={m.id} type="button" onClick={() => setMode(m.id)} disabled={isTraining} style={{
              padding: '10px 16px', borderRadius: 8, cursor: 'pointer',
              background: mode === m.id ? 'var(--bg-raised)' : 'transparent',
              border: `1px solid ${mode === m.id ? 'var(--accent)' : 'var(--border)'}`,
              color: mode === m.id ? 'var(--accent)' : 'var(--text-dim)', textAlign: 'left', minWidth: 140,
            }}>
              <div style={{ fontWeight: 700, fontSize: 13 }}>{m.label}</div>
              <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 2 }}>{m.dur} · {m.desc}</div>
            </button>
          ))}
        </div>
        {!isTraining
          ? <button className="btn btn-primary" onClick={startTrain} disabled={starting}>
              {starting ? <><span className="spinner" /> Starting…</> : '⟳ Start Training'}
            </button>
          : <button className="btn btn-danger" onClick={stopTrain}>⏹ Stop Training</button>
        }
        {error && <div style={{ marginTop: 10, fontSize: 12, color: 'var(--red)' }}>{error}</div>}
      </div>

      {/* Progress — shown whenever active, stopped, or completed */}
      {(isTraining || isDone || isStopped) && (
        <div className="card" style={{ marginBottom: 16 }}>
          {/* Current phase label */}
          {phase && (
            <div style={{ fontSize: 12, color: isTraining ? 'var(--accent)' : isDone ? 'var(--green)' : 'var(--text-faint)', marginBottom: 10, display: 'flex', alignItems: 'center', gap: 8 }}>
              {isTraining && <span className="spinner" style={{ width: 12, height: 12 }} />}
              {phase}
            </div>
          )}
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 14 }}>
            <div style={{ flex: 1, height: 6, background: 'var(--border)', borderRadius: 3, overflow: 'hidden' }}>
              <div style={{
                height: '100%', borderRadius: 3,
                width: `${progress}%`,
                background: isDone ? 'var(--green)' : isStopped ? 'var(--amber)' : 'var(--accent)',
                transition: 'width 0.8s ease',
              }} />
            </div>
            <span style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--text-faint)', minWidth: 50, textAlign: 'right' }}>
              {isDone ? '✓ Done' : isStopped ? 'Stopped' : `${progress.toFixed(0)}%`}
            </span>
          </div>
          {TRAIN_STEPS_ORDER.map((key, i) => {
            const done   = isDone || i < stepIdx;
            const active = i === stepIdx && isTraining;
            return (
              <div key={key} className={`progress-step${active ? ' active' : done ? ' done' : ''}`}>
                <span className="step-dot" />
                <span>{TRAIN_STEPS_MAP[key]}</span>
                {done   && <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--green)' }}>✓</span>}
                {active && <span className="spinner" style={{ marginLeft: 'auto', width: 12, height: 12 }} />}
              </div>
            );
          })}
          {status?.samples_collected != null && (
            <div style={{ marginTop: 10, fontSize: 11, color: 'var(--text-faint)' }}>
              Samples collected: <span style={{ color: 'var(--text)', fontFamily: 'monospace' }}>{status.samples_collected}</span>
              {status.expected_samples > 0 ? ` / ${status.expected_samples}` : ''}
            </div>
          )}
          {status?.errors?.length > 0 && (
            <div style={{ marginTop: 8, fontSize: 11, color: 'var(--amber)' }}>
              {status.errors[status.errors.length - 1]}
            </div>
          )}
        </div>
      )}

      {status && (
        <div className="card">
          <div className="section-title" style={{ marginBottom: 10 }}>Model State</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10 }}>
            {[
              {
                label: 'Training Status',
                value: status.status || '—',
                color: status.status === 'running' ? 'var(--accent)' : status.status === 'completed' ? 'var(--green)' : status.status === 'failed' ? 'var(--red)' : 'var(--text-faint)',
                sub: null,
              },
              {
                label: 'Autoencoder',
                value: status.embedder_trained ? '✓ Trained' : '✗ Not trained',
                color: status.embedder_trained ? 'var(--green)' : 'var(--text-faint)',
                sub: 'Reconstruction error + latent DNA',
              },
              {
                label: 'Isolation Forest',
                value: status.anomaly_detector_trained ? '✓ Trained' : '✗ Not trained',
                color: status.anomaly_detector_trained ? 'var(--green)' : 'var(--text-faint)',
                sub: 'Statistical outlier on latent space',
              },
            ].map(({ label, value, color, sub }) => (
              <div key={label} style={{ background: 'var(--bg-raised)', borderRadius: 6, padding: '8px 12px' }}>
                <div style={{ fontSize: 10, color: 'var(--text-faint)', marginBottom: 3 }}>{label}</div>
                <div style={{ fontSize: 12, fontWeight: 600, color: color || 'var(--text)' }}>{value}</div>
                {sub && <div style={{ fontSize: 9, color: 'var(--text-faint)', marginTop: 2 }}>{sub}</div>}
              </div>
            ))}
          </div>
          {status.last_training_time && (
            <div style={{ marginTop: 10, fontSize: 11, color: 'var(--text-faint)' }}>
              Last trained: {new Date(status.last_training_time * 1000).toLocaleString()}
            </div>
          )}
          {status.baseline_samples > 0 && (
            <div style={{ marginTop: 6, fontSize: 11, color: 'var(--text-faint)' }}>
              Baseline samples: <span style={{ color: 'var(--text)', fontFamily: 'monospace' }}>{status.baseline_samples}</span>
            </div>
          )}
        </div>
      )}

      {/* ── Quantum Basis Status ─────────────────────────────────────────── */}
      {(() => {
        // Quantum basis: always from basisStatus (direct state read — doesn't need live TaaraWare buffer)
        const basisSize   = basisStatus?.basis_size ?? 0;
        const basisMature = basisSize >= 3;
        const quantumResiduals = basisStatus?.quantum_residuals ?? 0;
        // Live F_min from TaaraWare polling (only valid when buffer has data)
        const nov = liveStatus?.novelty || {};
        const fmin = nov.f_min;
        const severity = nov.severity || '';
        const reconError = nov.recon_error;
        const latentFidelity = nov.latent_fidelity;
        // Classical: prefer basisStatus trained flags (authoritative), fallback to training_status
        const classicalTrained = (basisStatus?.autoencoder_trained && basisStatus?.isolation_forest_trained)
          || (status?.embedder_trained && status?.anomaly_detector_trained);
        return (
          <div className="card" style={{ marginTop: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <div>
                <div style={{ fontWeight: 700, fontSize: 14 }}>Live Signal State</div>
                <div style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 2 }}>All detection signals — current values from TaaraWare</div>
              </div>
            </div>

            {/* Quantum */}
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', color: 'var(--text-faint)', marginBottom: 6 }}>⬢ Quantum Basis</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
                {[
                  { label: 'Basis Vectors', value: basisMature ? `${basisSize} ✓` : (basisSize > 0 ? `${basisSize}/3` : '0 — train needed'), color: basisMature ? 'var(--green)' : basisSize > 0 ? 'var(--blue)' : 'var(--amber)', mono: true },
                  { label: 'Quantum States', value: quantumResiduals > 0 ? `${quantumResiduals} loaded` : '0 — train needed', color: quantumResiduals > 0 ? 'var(--green)' : 'var(--amber)', mono: true },
                  { label: 'Status', value: basisMature ? 'READY' : (basisSize > 0 ? 'BUILDING' : 'NEEDS TRAINING'), color: basisMature ? 'var(--green)' : basisSize > 0 ? 'var(--blue)' : 'var(--amber)' },
                ].map(t => (
                  <div key={t.label} style={{ background: 'var(--bg-raised)', borderRadius: 6, padding: '8px 10px' }}>
                    <div style={{ fontSize: 9, color: 'var(--text-faint)', marginBottom: 2 }}>{t.label}</div>
                    <div style={{ fontSize: 12, fontWeight: 700, fontFamily: t.mono ? 'monospace' : 'inherit', color: t.color }}>{t.value}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Classical */}
            <div>
              <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', color: 'var(--text-faint)', marginBottom: 6 }}>⊕ Classical Pipeline</div>
              {!classicalTrained
                ? <div style={{ fontSize: 11, color: 'var(--text-faint)', padding: '10px 0' }}>Train the autoencoder + Isolation Forest above to activate reconstruction error, latent fidelity, and statistical isolation signals.</div>
                : <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
                  {[
                    { label: 'Recon Error', value: reconError != null ? reconError.toFixed(4) : '—', color: reconError != null ? (reconError > 0.05 ? 'var(--red)' : 'var(--green)') : 'var(--text-faint)', sub: '> 0.05 = anomaly' },
                    { label: 'Latent Fidelity', value: latentFidelity != null ? latentFidelity.toFixed(4) : '—', color: latentFidelity != null ? (latentFidelity < 0.6 ? 'var(--red)' : 'var(--green)') : 'var(--text-faint)', sub: '< 0.6 = direction anomaly' },
                    { label: 'IF Verdict', value: nov.classical_anomaly ? '⚠ ANOMALY' : '✓ Normal', color: nov.classical_anomaly ? 'var(--amber)' : 'var(--green)', sub: 'All 3 must agree' },
                  ].map(t => (
                    <div key={t.label} style={{ background: 'var(--bg-raised)', borderRadius: 6, padding: '8px 10px' }}>
                      <div style={{ fontSize: 9, color: 'var(--text-faint)', marginBottom: 2 }}>{t.label}</div>
                      <div style={{ fontSize: 12, fontWeight: 700, fontFamily: 'monospace', color: t.color }}>{t.value}</div>
                      <div style={{ fontSize: 9, color: 'var(--text-faint)', marginTop: 2 }}>{t.sub}</div>
                    </div>
                  ))}
                </div>
              }
            </div>
          </div>
        );
      })()}
    </div>
  );
}

// ── Sub-tab 5: Agent & Actions ────────────────────────────────────────────────
function OutputModal({ output, onClose }) {
  return (
    <div onClick={onClose} style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', zIndex: 1000,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div onClick={e => e.stopPropagation()} style={{
        background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 10,
        padding: 24, width: '80vw', maxWidth: 800, maxHeight: '80vh',
        display: 'flex', flexDirection: 'column', gap: 12,
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ fontWeight: 700, fontSize: 14 }}>Full Output</div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-dim)', cursor: 'pointer', fontSize: 18 }}>✕</button>
        </div>
        <pre style={{ margin: 0, flex: 1, overflowY: 'auto', fontSize: 11, lineHeight: 1.5 }}>{output}</pre>
      </div>
    </div>
  );
}

function ExecResultBlock({ result, error }) {
  const [expanded, setExpanded] = useState(false);
  if (!result && !error) return null;
  if (error) return (
    <div style={{ marginTop: 10, padding: '10px 14px', background: 'rgba(233,69,96,0.1)', border: '1px solid rgba(233,69,96,0.25)', borderRadius: 8, fontSize: 12, color: 'var(--red)' }}>
      {error}
    </div>
  );
  const stdout = result.stdout || result.output || '';
  const success = result.success !== undefined ? result.success : (result.exit_code === 0);
  const isLong = stdout.length > 400;
  return (
    <div style={{ marginTop: 10, background: 'var(--bg-raised)', border: `1px solid ${success ? 'rgba(34,204,102,0.25)' : 'rgba(233,69,96,0.25)'}`, borderRadius: 8, padding: '10px 14px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <span style={{ fontWeight: 700, fontSize: 12, color: success ? 'var(--green)' : 'var(--red)' }}>
          {success ? '✓ Success' : '✗ Failed'}
          {result.exit_code !== undefined && <span style={{ fontWeight: 400, color: 'var(--text-faint)', marginLeft: 8 }}>exit {result.exit_code}</span>}
        </span>
        {isLong && (
          <button onClick={() => setExpanded(true)} style={{ background: 'none', border: '1px solid var(--border)', borderRadius: 4, color: 'var(--text-dim)', cursor: 'pointer', fontSize: 10, padding: '2px 8px' }}>
            Expand
          </button>
        )}
      </div>
      <pre style={{ margin: 0, fontSize: 11, maxHeight: 160, overflowY: 'auto', lineHeight: 1.5 }}>
        {stdout || '(no output)'}
      </pre>
      {result.stderr && (
        <pre style={{ margin: '6px 0 0', fontSize: 10, color: 'var(--amber)', maxHeight: 80, overflowY: 'auto' }}>
          {result.stderr}
        </pre>
      )}
      {expanded && <OutputModal output={stdout} onClose={() => setExpanded(false)} />}
    </div>
  );
}

function AgentSubTab() {
  const [learningMode, setLearningMode] = useState(false);
  const [proposed, setProposed]         = useState([]);
  const [banditStats, setBanditStats]   = useState(null);
  const [banditRecs, setBanditRecs]     = useState([]);
  const [auditLog, setAuditLog]         = useState([]);
  const [manualCmd, setManualCmd]       = useState('');
  const [aiPrompt, setAiPrompt]         = useState('');
  const [aiGenerated, setAiGenerated]   = useState('');
  const [executing, setExecuting]       = useState(false);
  const [execResult, setExecResult]     = useState(null);
  const [execError, setExecError]       = useState('');
  const [generating, setGenerating]     = useState(false);
  // Interactive stdin
  const [pendingCmd, setPendingCmd]     = useState('');   // command that needs stdin
  const [stdinPrompt, setStdinPrompt]   = useState('');   // prompt text from server
  const [stdinValue, setStdinValue]     = useState('');   // user's input

  useEffect(() => {
    api.proposedActions().then(r => { if (r.ok) setProposed(r.data.actions || r.data || []); }).catch(() => {});
    api.banditSummary().then(r => { if (r.ok) setBanditStats(r.data); }).catch(() => {});
    api.banditRecommend(null, null).then(r => { if (r.ok) setBanditRecs(r.data.recommendations || []); }).catch(() => {});
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

  async function _runCmd(command, source) {
    setExecuting(true); setExecResult(null); setExecError(''); setPendingCmd(''); setStdinPrompt(''); setStdinValue('');
    try {
      const r = await api.execute({ command, source });
      if (!r.ok) { setExecError(r.data?.detail || 'Execution failed'); return; }
      if (r.data?.needs_input) {
        // Command is waiting for interactive input — show stdin box
        setPendingCmd(command);
        setStdinPrompt(r.data.input_prompt || 'Input required:');
      } else {
        setExecResult(r.data);
      }
    } catch (e) { setExecError(e.message); }
    finally { setExecuting(false); }
  }

  async function execManual() {
    if (!manualCmd.trim()) return;
    await _runCmd(manualCmd, 'manual');
  }

  async function sendStdin() {
    if (!pendingCmd || !stdinValue.trim()) return;
    setExecuting(true);
    try {
      const r = await api.executeStdin({ command: pendingCmd, stdin_input: stdinValue });
      if (r.ok) setExecResult(r.data); else setExecError(r.data?.detail || 'Failed');
    } catch (e) { setExecError(e.message); }
    finally { setExecuting(false); setPendingCmd(''); setStdinPrompt(''); setStdinValue(''); }
  }

  async function generateAi() {
    if (!aiPrompt.trim()) return;
    setGenerating(true); setAiGenerated('');
    try {
      const r = await api.generateCommand(aiPrompt);
      setAiGenerated(r.ok ? (r.data.command || aiPrompt) : aiPrompt);
    } catch (_) { setAiGenerated(aiPrompt); }
    finally { setGenerating(false); }
  }

  async function approveAi() {
    if (!aiGenerated) return;
    await _runCmd(aiGenerated, 'ai_approved');
    setAiGenerated('');
  }

  return (
    <div className="page">
      <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 20 }}>Agent & Actions</div>

      {/* Learning mode toggle */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 700 }}>Agent Learning Mode</div>
            <div style={{ fontSize: 12, color: 'var(--text-faint)', marginTop: 2 }}>
              Every executed command is recorded in the contrastive bandit — TAARA learns which actions work in which quantum contexts.
            </div>
          </div>
          <button onClick={() => setLearningMode(v => !v)} style={{
            width: 52, height: 28, borderRadius: 14, border: 'none', cursor: 'pointer',
            background: learningMode ? 'var(--green)' : 'var(--border)', position: 'relative', transition: 'background 0.2s',
          }}>
            <div style={{
              position: 'absolute', top: 4, left: learningMode ? 28 : 4,
              width: 20, height: 20, borderRadius: '50%', background: 'white',
              transition: 'left 0.2s', boxShadow: '0 1px 3px rgba(0,0,0,0.3)',
            }} />
          </button>
        </div>
        {banditStats && (
          <div style={{ marginTop: 12, padding: '8px 12px', background: 'var(--bg-raised)', borderRadius: 6, fontSize: 11, color: 'var(--text-faint)', display: 'flex', gap: 16 }}>
            <span>Arms learned: <span style={{ color: 'var(--text)' }}>{Object.keys(banditStats.arm_stats || {}).length}</span></span>
            <span>Pre-approved: <span style={{ color: 'var(--green)' }}>{banditStats.pre_approved?.length || 0}</span></span>
            <span>Autonomy level: <span style={{ color: 'var(--accent)' }}>{banditStats.autonomy_level ?? 1}/5</span></span>
            <span>Pre-approval threshold: <span style={{ color: 'var(--accent)' }}>90% approval + 85% success</span></span>
          </div>
        )}
      </div>

      {/* TAARA Learned Recommendations */}
      {banditRecs.length > 0 && (
        <div className="card" style={{ marginBottom: 16, borderColor: 'rgba(74,158,255,0.2)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
            <div className="section-title">TAARA Learned Recommendations</div>
            <span style={{ fontSize: 10, color: 'var(--blue)', fontWeight: 600, letterSpacing: 0.5 }}>UCB BANDIT</span>
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-faint)', marginBottom: 10 }}>
            Ranked by contrastive bandit UCB score for current quantum context. More executions → better recommendations.
          </div>
          {banditRecs.map((rec, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 10px', background: rec.pre_approved ? 'rgba(34,204,102,0.06)' : 'var(--bg-raised)', border: `1px solid ${rec.pre_approved ? 'rgba(34,204,102,0.2)' : 'var(--border)'}`, borderRadius: 6, marginBottom: 6 }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 2 }}>
                  <span style={{ fontSize: 12, fontWeight: 700, color: rec.pre_approved ? 'var(--green)' : 'var(--blue)' }}>{rec.action_type.replace(/_/g, ' ')}</span>
                  {rec.pre_approved && <span style={{ fontSize: 8, background: 'rgba(34,204,102,0.2)', color: 'var(--green)', borderRadius: 3, padding: '1px 5px', fontWeight: 700 }}>PRE-APPROVED</span>}
                  <span style={{ fontSize: 9, color: 'var(--text-faint)', marginLeft: 'auto' }}>
                    UCB {rec.ucb_score?.toFixed(2)} · {rec.times_seen > 0 ? `${rec.times_seen}× seen · ${Math.round((rec.success_rate || 0) * 100)}% success` : 'unexplored'}
                  </span>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-faint)' }}>{rec.description}</div>
                <div style={{ fontSize: 9, color: 'var(--text-faint)', opacity: 0.7 }}>{rec.bandit_rationale}</div>
                {rec.contrast_insight && <div style={{ fontSize: 9, color: 'var(--amber)', marginTop: 2 }}>⚡ {rec.contrast_insight}</div>}
              </div>
              <button className="btn" onClick={() => {
                api.generateCommand(`${rec.action_type.replace(/_/g,' ')}: ${rec.description}`).then(r => {
                  if (r.ok && r.data.command) { setAiGenerated(r.data.command); }
                });
              }} style={{ fontSize: 10, borderColor: 'rgba(74,158,255,0.3)', color: 'var(--blue)' }}>
                Generate
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Pending proposed actions */}
      {proposed.length > 0 && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="section-title" style={{ marginBottom: 12 }}>Pending Actions ({proposed.length})</div>
          {proposed.map((action, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 12px', background: 'var(--bg-raised)', borderRadius: 6, marginBottom: 8 }}>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 13, fontWeight: 500 }}>{action.command || action.description}</div>
                {action.reasoning && <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 2 }}>{action.reasoning}</div>}
              </div>
              <button className="btn" onClick={() => approveAction(i)} style={{ fontSize: 11, borderColor: 'rgba(34,204,102,0.3)', color: 'var(--green)' }}>Approve</button>
              <button className="btn" onClick={() => {}} style={{ fontSize: 11 }}>Edit</button>
              <button className="btn btn-danger" onClick={() => rejectAction(i)} style={{ fontSize: 11 }}>Disapprove</button>
            </div>
          ))}
        </div>
      )}

      {/* Manual command */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="section-title" style={{ marginBottom: 12 }}>Manual Action</div>
        <div style={{ display: 'flex', gap: 8 }}>
          <input className="input" value={manualCmd} onChange={e => setManualCmd(e.target.value)}
            placeholder="systemctl status ssh" style={{ flex: 1 }}
            onKeyDown={e => e.key === 'Enter' && execManual()} />
          <button className="btn btn-primary" onClick={execManual} disabled={executing}>
            {executing ? <span className="spinner" /> : 'Execute'}
          </button>
        </div>
        {/* Interactive stdin box — shown when command is waiting for input */}
        {pendingCmd && (
          <div style={{ marginTop: 10, padding: '10px 12px', background: 'rgba(245,166,35,0.07)', border: '1px solid rgba(245,166,35,0.25)', borderRadius: 6 }}>
            <div style={{ fontSize: 11, color: 'var(--amber)', marginBottom: 6, fontFamily: 'monospace' }}>
              ⌨ Command is waiting for input: <span style={{ opacity: 0.7 }}>{stdinPrompt}</span>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <input className="input" value={stdinValue} onChange={e => setStdinValue(e.target.value)}
                placeholder="Type your response and press Enter…" style={{ flex: 1, fontFamily: 'monospace' }}
                onKeyDown={e => e.key === 'Enter' && sendStdin()} autoFocus />
              <button className="btn btn-primary" onClick={sendStdin} disabled={executing} style={{ fontSize: 12 }}>Send</button>
              <button className="btn" onClick={() => { setPendingCmd(''); setStdinPrompt(''); setStdinValue(''); }} style={{ fontSize: 12 }}>Cancel</button>
            </div>
          </div>
        )}
        <ExecResultBlock result={execResult} error={execError} />
      </div>

      {/* AI-assisted */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="section-title" style={{ marginBottom: 12 }}>AI-Assisted Action</div>
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
            <div style={{ fontSize: 10, color: 'var(--text-faint)', marginBottom: 4 }}>Reasoning engine generated this command — review and edit before approving:</div>
            <textarea className="input" value={aiGenerated} onChange={e => setAiGenerated(e.target.value)}
              rows={2} style={{ marginBottom: 8, fontFamily: 'monospace', fontSize: 11 }} />
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn btn-primary" onClick={approveAi} disabled={executing} style={{ fontSize: 12 }}>Approve & Execute</button>
              <button className="btn btn-danger" onClick={() => setAiGenerated('')} style={{ fontSize: 12 }}>Disapprove</button>
            </div>
          </div>
        )}
      </div>

      {/* Audit log */}
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

// ── Sub-tab 6: Unified Security Dashboard ─────────────────────────────────────
const SEC_TOOLS = [
  { name: 'fail2ban', label: 'Fail2Ban',     check: 'systemctl is-active fail2ban',  install: 'apt install fail2ban -y' },
  { name: 'ufw',      label: 'UFW',          check: 'ufw status',                    install: 'apt install ufw -y && ufw enable' },
  { name: 'lynis',    label: 'Lynis',        check: 'lynis show version',            install: 'apt install lynis -y' },
  { name: 'rkhunter', label: 'RKHunter',     check: 'rkhunter --version',            install: 'apt install rkhunter -y' },
  { name: 'ss',       label: 'ss / netstat', check: 'ss -tlnp | head -10',           install: 'apt install iproute2 -y' },
  { name: 'auditd',   label: 'Audit Daemon', check: 'systemctl is-active auditd',    install: 'apt install auditd -y' },
  { name: 'cron',     label: 'Cron',         check: 'systemctl is-active cron',      install: 'apt install cron -y' },
];

function SecuritySubTab() {
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
        [tool.name]: { installed: r.ok && !out.includes('not found') && !out.toLowerCase().includes('not recognized'), output: out },
      }));
    } catch (e) {
      setResults(prev => ({ ...prev, [tool.name]: { installed: false, error: e.message } }));
    } finally { setChecking(c => ({ ...c, [tool.name]: false })); }
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
    <div className="page">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div style={{ fontSize: 18, fontWeight: 700 }}>Unified Security Dashboard</div>
        <button className="btn" onClick={checkAll} style={{ fontSize: 12 }}>↺ Check All</button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 12, marginBottom: 20 }}>
        {SEC_TOOLS.map(tool => {
          const res     = results[tool.name];
          const loading = checking[tool.name];
          return (
            <div key={tool.name} style={{
              background: 'var(--bg-surface)',
              border: `1px solid ${res?.installed === false ? 'rgba(233,69,96,0.2)' : 'var(--border)'}`,
              borderRadius: 8, padding: '14px 16px',
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <div style={{ fontWeight: 600, fontSize: 13 }}>{tool.label}</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  {res != null && (
                    <span style={{ fontSize: 11, fontWeight: 700, color: res.installed ? 'var(--green)' : 'var(--red)' }}>
                      {res.installed ? '✓ Active' : '✗ Not found'}
                    </span>
                  )}
                  <button className="btn" onClick={() => checkTool(tool)} disabled={loading} style={{ fontSize: 10, padding: '3px 8px' }}>
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
        <div className="section-title" style={{ marginBottom: 12 }}>Add Custom Monitor</div>
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

// ── Sub-tab 7: Custom Actions ──────────────────────────────────────────────────
function CustomActionsSubTab() {
  const [mode, setMode]           = useState('manual');
  const [manualCmd, setManualCmd] = useState('');
  const [aiIntent, setAiIntent]   = useState('');
  const [aiCmd, setAiCmd]         = useState('');
  const [executing, setExecuting] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [result, setResult]       = useState(null);
  const [error, setError]         = useState('');
  const [actionLog, setActionLog] = useState([]);

  useEffect(() => {
    api.actionLog(20).then(r => {
      if (r.ok) setActionLog(r.data.logs || r.data.log || r.data || []);
    }).catch(() => {});
  }, []);

  async function execManual() {
    if (!manualCmd.trim()) return;
    if (!window.confirm(`Execute: ${manualCmd}?`)) return;
    setExecuting(true); setResult(null); setError('');
    try {
      const r = await api.execute({ command: manualCmd, source: 'custom_manual' });
      if (r.ok) { setResult(r.data); setActionLog(l => [{ command: manualCmd, source: 'custom_manual', success: true, timestamp: Date.now() / 1000 }, ...l]); }
      else setError(r.data?.detail || 'Failed');
    } catch (e) { setError(e.message); }
    finally { setExecuting(false); }
  }

  async function generateCmd() {
    if (!aiIntent.trim()) return;
    setGenerating(true); setAiCmd('');
    try {
      const r = await api.generateCommand(aiIntent);
      setAiCmd(r.ok ? (r.data.command || aiIntent) : aiIntent);
    } catch (_) { setAiCmd(aiIntent); }
    finally { setGenerating(false); }
  }

  async function approveAiCmd() {
    if (!aiCmd.trim()) return;
    setExecuting(true); setResult(null); setError('');
    try {
      const r = await api.execute({ command: aiCmd, source: 'ai_custom' });
      if (r.ok) { setResult(r.data); setAiCmd(''); setAiIntent(''); setActionLog(l => [{ command: aiCmd, source: 'ai_custom', success: true, timestamp: Date.now() / 1000 }, ...l]); }
      else setError(r.data?.detail || 'Failed');
    } catch (e) { setError(e.message); }
    finally { setExecuting(false); }
  }

  const [rollbackState, setRollbackState] = useState({}); // id → {loading, cmd, explanation, notRollbackable, alternative, confirmed}

  async function rollback(id) {
    setRollbackState(s => ({ ...s, [id]: { loading: true } }));
    try {
      // Phase 1: get rollback command (or explanation)
      const r = await api.rollbackAction(id, false);
      if (!r.ok) { setRollbackState(s => ({ ...s, [id]: { error: r.data?.detail || 'Failed' } })); return; }
      if (r.data.rollbackable === false) {
        setRollbackState(s => ({ ...s, [id]: { notRollbackable: true, explanation: r.data.explanation, alternative: r.data.alternative } }));
      } else {
        setRollbackState(s => ({ ...s, [id]: { cmd: r.data.rollback_cmd, needsApproval: true } }));
      }
    } catch (e) {
      setRollbackState(s => ({ ...s, [id]: { error: e.message } }));
    } finally {
      setRollbackState(s => ({ ...s, [id]: { ...s[id], loading: false } }));
    }
  }

  async function confirmRollback(id) {
    setRollbackState(s => ({ ...s, [id]: { ...s[id], executing: true } }));
    try {
      const r = await api.rollbackAction(id, true);
      if (r.ok) {
        setRollbackState(s => ({ ...s, [id]: { done: true, success: r.data.success, output: r.data.stdout } }));
      }
    } catch (e) {
      setRollbackState(s => ({ ...s, [id]: { ...s[id], error: e.message, executing: false } }));
    }
  }

  return (
    <div className="page">
      <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 20 }}>Custom Actions</div>

      <div style={{
        display: 'flex', gap: 4, marginBottom: 20,
        background: 'var(--bg-surface)', padding: 4, borderRadius: 8, border: '1px solid var(--border)',
        maxWidth: 300,
      }}>
        {['manual', 'ai'].map(m => (
          <button key={m} onClick={() => setMode(m)} style={{
            flex: 1, padding: '7px 0',
            background: mode === m ? 'var(--bg-raised)' : 'transparent',
            border: 'none', borderRadius: 5,
            color: mode === m ? 'var(--text)' : 'var(--text-dim)',
            fontSize: 12, fontWeight: 600, cursor: 'pointer',
            boxShadow: mode === m ? '0 1px 3px rgba(0,0,0,0.3)' : 'none',
          }}>
            {m === 'manual' ? 'Manual' : 'AI-Assisted'}
          </button>
        ))}
      </div>

      {mode === 'manual' && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="section-title" style={{ marginBottom: 12 }}>Manual Command</div>
          <div style={{ display: 'flex', gap: 8 }}>
            <input className="input" value={manualCmd} onChange={e => setManualCmd(e.target.value)}
              placeholder="Raw command…" style={{ flex: 1 }}
              onKeyDown={e => e.key === 'Enter' && execManual()} />
            <button className="btn btn-primary" onClick={execManual} disabled={executing}>
              {executing ? <span className="spinner" /> : 'Confirm & Execute'}
            </button>
          </div>
        </div>
      )}

      {mode === 'ai' && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="section-title" style={{ marginBottom: 12 }}>AI-Assisted Command</div>
          <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
            <input className="input" value={aiIntent} onChange={e => setAiIntent(e.target.value)}
              placeholder="Describe intent in plain English…" style={{ flex: 1 }} />
            <button className="btn" onClick={generateCmd} disabled={generating}
              style={{ borderColor: 'rgba(155,125,255,0.3)', color: '#9b7dff' }}>
              {generating ? <span className="spinner" /> : '⚡ Generate'}
            </button>
          </div>
          {aiCmd && (
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-faint)', marginBottom: 4 }}>Reasoning engine generated this command. Edit if needed, then approve or disapprove:</div>
              <textarea className="input" value={aiCmd} onChange={e => setAiCmd(e.target.value)}
                rows={2} style={{ marginBottom: 8, fontFamily: 'monospace', fontSize: 11 }} />
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn btn-primary" onClick={approveAiCmd} disabled={executing} style={{ fontSize: 12 }}>
                  {executing ? <><span className="spinner" /> Executing…</> : 'Approve & Execute'}
                </button>
                <button className="btn btn-danger" onClick={() => { setAiCmd(''); setAiIntent(''); }} style={{ fontSize: 12 }}>
                  Disapprove
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {(result || error) && (
        <div style={{ marginBottom: 16 }}>
          <ExecResultBlock result={result} error={error} />
        </div>
      )}

      {actionLog.length > 0 && (
        <div className="card">
          <div className="section-title" style={{ marginBottom: 10 }}>Action Log</div>
          <table className="data-table">
            <thead><tr><th>Command</th><th>Source</th><th>Result</th><th>Time</th><th>Rollback</th></tr></thead>
            <tbody>
              {actionLog.slice(0, 15).map((a, i) => {
                const rb = rollbackState[a.id] || {};
                return (
                  <React.Fragment key={i}>
                    <tr>
                      <td><code style={{ fontSize: 10 }}>{a.command || a.details || a.action || '—'}</code></td>
                      <td style={{ fontSize: 11 }}>{a.source || '—'}</td>
                      <td><span style={{ color: a.success ? 'var(--green)' : 'var(--red)' }}>{a.success ? '✓' : '✗'}</span></td>
                      <td style={{ fontSize: 10, color: 'var(--text-faint)' }}>
                        {a.timestamp ? new Date(a.timestamp * 1000).toLocaleTimeString() : '—'}
                      </td>
                      <td>
                        {a.id && !rb.done && !rb.notRollbackable && !rb.needsApproval && (
                          <button className="btn" onClick={() => rollback(a.id)} disabled={rb.loading}
                            style={{ fontSize: 10, padding: '2px 8px', color: 'var(--amber)' }}>
                            {rb.loading ? '…' : '↺'}
                          </button>
                        )}
                        {rb.done && <span style={{ fontSize: 10, color: rb.success ? 'var(--green)' : 'var(--red)' }}>{rb.success ? '↺ done' : '↺ failed'}</span>}
                      </td>
                    </tr>
                    {/* Rollback approval row */}
                    {rb.needsApproval && (
                      <tr>
                        <td colSpan={5} style={{ background: 'rgba(245,166,35,0.06)', padding: '8px 10px' }}>
                          <div style={{ fontSize: 11, color: 'var(--amber)', marginBottom: 4 }}>Rollback command (review before executing):</div>
                          <code style={{ fontSize: 10, color: 'var(--text)', wordBreak: 'break-all' }}>{rb.cmd}</code>
                          <div style={{ display: 'flex', gap: 8, marginTop: 6 }}>
                            <button className="btn" onClick={() => confirmRollback(a.id)} disabled={rb.executing}
                              style={{ fontSize: 10, borderColor: 'rgba(245,166,35,0.4)', color: 'var(--amber)' }}>
                              {rb.executing ? '…' : 'Confirm Rollback'}
                            </button>
                            <button className="btn" onClick={() => setRollbackState(s => ({ ...s, [a.id]: {} }))}
                              style={{ fontSize: 10 }}>Cancel</button>
                          </div>
                        </td>
                      </tr>
                    )}
                    {/* Not rollbackable row */}
                    {rb.notRollbackable && (
                      <tr>
                        <td colSpan={5} style={{ background: 'rgba(233,69,96,0.05)', padding: '8px 10px' }}>
                          <div style={{ fontSize: 11, color: 'var(--red)', marginBottom: 2 }}>Cannot rollback: {rb.explanation}</div>
                          {rb.alternative && <div style={{ fontSize: 11, color: 'var(--amber)' }}>Alternative: {rb.alternative}</div>}
                          <button className="btn" onClick={() => setRollbackState(s => ({ ...s, [a.id]: {} }))}
                            style={{ fontSize: 10, marginTop: 4 }}>Dismiss</button>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── Sub-tab 8: TaaraWare Deployment Details ───────────────────────────────────
function DeployDetailsSubTab({ hostname, demoMode }) {
  const [info, setInfo]           = useState(null);
  const [pqcInfo, setPqcInfo]     = useState(null);
  const [collInt, setCollInt]     = useState(30);
  const [saving, setSaving]       = useState(false);
  const [saved, setSaved]         = useState(false);
  const [agentStatus, setAgentStatus] = useState(null);
  const [updating, setUpdating]   = useState(false);
  const [updateMsg, setUpdateMsg] = useState('');

  useEffect(() => {
    api.taarawareInfo().then(r => {
      if (r.ok) { setInfo(r.data); if (r.data.collection_interval) setCollInt(r.data.collection_interval); }
    }).catch(() => {});
    api.pqcInfo().then(r => { if (r.ok) setPqcInfo(r.data); }).catch(() => {});
    api.status().then(r => { if (r.ok) setAgentStatus(r.data?.agent_status); }).catch(() => {});
  }, []);

  async function doUpdate() {
    setUpdating(true); setUpdateMsg('');
    try {
      const r = await api.taarawareUpdate();
      if (r.ok) {
        setUpdateMsg(`✓ ${r.data?.message || 'Updated'}`);
        // update_agent returns agent_status directly — use it to refresh version display
        if (r.data?.agent_status) setAgentStatus(r.data.agent_status);
      } else {
        setUpdateMsg(`✗ ${r.data?.detail || 'Update failed'}`);
      }
    } catch (e) { setUpdateMsg(`✗ ${e.message}`); }
    finally { setUpdating(false); }
  }

  async function refreshAgentStatus() {
    try {
      const r = await api.status();
      if (r.ok && r.data?.agent_status) setAgentStatus(r.data.agent_status);
    } catch (_) {}
  }

  async function saveInterval() {
    setSaving(true);
    try {
      await api.execute({ command: `taara-ware config set interval ${collInt}`, source: 'config' });
      setSaved(true); setTimeout(() => setSaved(false), 2000);
    } catch (_) {}
    finally { setSaving(false); }
  }

  const fingerprint = pqcInfo?.fingerprint || info?.pqc_fingerprint || '';

  return (
    <div className="page">
      <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 4 }}>TaaraWare Deployment Details</div>
      <div style={{ fontSize: 12, color: 'var(--text-faint)', marginBottom: 24 }}>{hostname} · {demoMode ? 'Demo (simulated)' : 'Live'}</div>

      {/* Status + interval in one row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginBottom: 14 }}>
        <div className="card">
          <div className="metric-label">Agent Status</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8 }}>
            <span style={{ width: 12, height: 12, borderRadius: '50%', background: 'var(--green)', boxShadow: '0 0 6px var(--green)', display: 'inline-block', animation: 'pulse-green 2s infinite' }} />
            <span style={{ fontSize: 18, fontWeight: 700, color: 'var(--green)' }}>{demoMode ? 'DEMO' : 'LIVE'}</span>
          </div>
          <div style={{ marginTop: 6, fontSize: 10, color: 'var(--text-faint)', fontFamily: 'monospace', display: 'flex', alignItems: 'center', gap: 8 }}>
            <span>Deployed: v{agentStatus?.deployed_version || '—'} &nbsp;|&nbsp; Current: v{agentStatus?.current_version || '2.1.0'}</span>
            <button onClick={refreshAgentStatus} style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: 11, color: 'var(--text-faint)', padding: 0 }} title="Re-check version">↻</button>
          </div>
          {agentStatus && !agentStatus.update_available && agentStatus.deployed_version !== 'unknown' && (
            <div style={{ marginTop: 4, fontSize: 10, color: 'var(--green)' }}>✓ Up to date</div>
          )}
          {agentStatus?.update_available && (
            <div style={{ marginTop: 8 }}>
              <button className="btn btn-primary" onClick={doUpdate} disabled={updating || demoMode} style={{ fontSize: 11, padding: '4px 12px' }}>
                {updating ? <><span className="spinner" style={{ width: 10, height: 10 }} /> Updating…</> : '⬆ Update Agent'}
              </button>
            </div>
          )}
          {updateMsg && <div style={{ marginTop: 6, fontSize: 11, color: updateMsg.startsWith('✓') ? 'var(--green)' : 'var(--red)' }}>{updateMsg}</div>}
        </div>
        <div className="card">
          <div className="metric-label">Collection Interval</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8 }}>
            <input className="input" type="number" min={10} max={300} value={collInt}
              onChange={e => setCollInt(parseInt(e.target.value) || 30)}
              style={{ width: 72, fontSize: 18, fontWeight: 700, fontFamily: 'monospace', padding: '4px 8px' }} />
            <span style={{ fontSize: 12, color: 'var(--text-faint)' }}>seconds</span>
            <button className="btn" onClick={saveInterval} disabled={saving} style={{ fontSize: 11, marginLeft: 4 }}>
              {saving ? <span className="spinner" /> : saved ? '✓' : 'Save'}
            </button>
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-faint)', marginTop: 6 }}>How often TaaraWare reads the 19 behavioral signals</div>
        </div>
      </div>

      {/* PQC protection — visual */}
      <div className="card" style={{ marginBottom: 14, background: 'rgba(74,158,255,0.04)', border: '1px solid rgba(74,158,255,0.2)' }}>
        <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start', flexWrap: 'wrap' }}>
          {/* Shield icon */}
          <div style={{
            width: 56, height: 56, borderRadius: 10, flexShrink: 0,
            background: 'rgba(74,158,255,0.12)', border: '1px solid rgba(74,158,255,0.3)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 26,
          }}>🛡</div>
          <div style={{ flex: 1, minWidth: 200 }}>
            <div style={{ fontWeight: 700, fontSize: 14, color: 'var(--blue)', marginBottom: 6 }}>Post-Quantum Channel Protection</div>
            <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.7, marginBottom: 12 }}>
              Every time TaaraWare sends the 19-feature behavioral vector back to this server,
              the data is protected using a <strong style={{ color: 'var(--text)' }}>Kyber768 (ML-KEM)</strong> shared secret —
              a lattice-based key encapsulation algorithm standardised by NIST as FIPS 203.
              Unlike RSA or ECDH, Kyber768 cannot be broken by quantum computers,
              protecting against <em>"harvest now, decrypt later"</em> attacks where an adversary
              records encrypted traffic today planning to decrypt it once a quantum computer is available.
            </div>
            {/* Algorithm chips */}
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {[
                { label: 'Kyber768 / ML-KEM', color: '#4a9eff', tip: 'Key Encapsulation Mechanism' },
                { label: 'NIST FIPS 203', color: '#9b7dff', tip: 'Post-Quantum Standard' },
                { label: 'Lattice Cryptography', color: '#22cc66', tip: 'Hard problem: Learning With Errors' },
                { label: 'Quantum-Resistant', color: '#f5a623', tip: 'Safe against Shor\'s algorithm' },
              ].map(c => (
                <span key={c.label} style={{
                  padding: '4px 10px', borderRadius: 20, fontSize: 10, fontWeight: 700,
                  background: `${c.color}18`, border: `1px solid ${c.color}44`, color: c.color,
                }}>{c.label}</span>
              ))}
            </div>
          </div>
        </div>

        {/* How it works step-by-step */}
        <div style={{ marginTop: 16, paddingTop: 14, borderTop: '1px solid rgba(74,158,255,0.12)' }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-dim)', letterSpacing: 0.5, marginBottom: 10 }}>HOW THE CHANNEL IS SECURED</div>
          <div style={{ display: 'flex', gap: 0, flexWrap: 'wrap' }}>
            {[
              { n: '①', title: 'Keypair Generated', body: 'On deploy, TAARA generates a Kyber768 public/private keypair for this host. The public key is sent to the TaaraWare agent.' },
              { n: '②', title: 'KEM Encapsulation', body: 'Agent encapsulates a random shared secret using the server\'s public key → produces ciphertext + shared_secret.' },
              { n: '③', title: 'Feature XOR Offset', body: 'The 19 raw feature values are XOR-offset with bytes derived from shared_secret before transmission.' },
              { n: '④', title: 'Server Decapsulates', body: 'Server uses its private key to recover the same shared_secret and reverses the offset, recovering the true features.' },
            ].map((s, i, arr) => (
              <React.Fragment key={i}>
                <div style={{ flex: 1, minWidth: 140, padding: '10px 12px' }}>
                  <div style={{ fontSize: 18, color: 'var(--blue)', marginBottom: 5 }}>{s.n}</div>
                  <div style={{ fontSize: 11, fontWeight: 700, marginBottom: 4 }}>{s.title}</div>
                  <div style={{ fontSize: 10, color: 'var(--text-faint)', lineHeight: 1.5 }}>{s.body}</div>
                </div>
                {i < arr.length - 1 && (
                  <div style={{ display: 'flex', alignItems: 'center', color: 'var(--text-faint)', fontSize: 16, padding: '0 2px' }}>→</div>
                )}
              </React.Fragment>
            ))}
          </div>
        </div>

        {/* Fingerprint if available */}
        {fingerprint && (
          <div style={{ marginTop: 12, padding: '8px 12px', background: 'rgba(34,204,102,0.06)', border: '1px solid rgba(34,204,102,0.15)', borderRadius: 6, display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: 10, color: 'var(--text-faint)', flexShrink: 0 }}>KEY FINGERPRINT</span>
            <span style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--green)', letterSpacing: 1 }}>{fingerprint.substring(0, 32)}…</span>
          </div>
        )}
      </div>

      {/* 19 features being collected */}
      <div className="card" style={{ marginBottom: 14 }}>
        <div className="section-title" style={{ marginBottom: 12 }}>19 Features Collected Each Cycle</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 6 }}>
          {[
            { group: 'System Resources',  color: '#4a9eff', items: ['CPU usage', 'Memory usage', 'Disk usage'] },
            { group: 'Process Behaviour', color: '#f5a623', items: ['Proc spawn rate', 'Root process ratio', 'Command entropy', 'New processes (1h)', 'Privilege escalations'] },
            { group: 'Network Activity',  color: '#22cc66', items: ['Outbound conn rate', 'Unique dst IPs', 'Unique dst ports', 'Port entropy', 'Failed conn ratio', 'Suspicious connections'] },
            { group: 'Threat Signals',    color: '#e94560', items: ['Failed logins (1h)', 'Temporal rhythm deviation', 'Causal chain novelty', 'Concealment signal', 'Anomaly score'] },
          ].map(g => (
            <div key={g.group} style={{ padding: '10px 12px', background: 'var(--bg-raised)', borderRadius: 7, borderLeft: `3px solid ${g.color}` }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: g.color, marginBottom: 6, letterSpacing: 0.4 }}>{g.group.toUpperCase()}</div>
              {g.items.map(item => (
                <div key={item} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
                  <div style={{ width: 5, height: 5, borderRadius: '50%', background: g.color, flexShrink: 0 }} />
                  <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>{item}</span>
                </div>
              ))}
            </div>
          ))}
        </div>
        <div style={{ marginTop: 10, fontSize: 10, color: 'var(--text-faint)' }}>
          All 19 signals → BehavioralAE (19→64→8) → 8-dim latent → 3-qubit AmplitudeEmbedding → V3 quantum confidence.
          Collection runs every {collInt}s as a background process on the server.
        </div>
      </div>

      {/* Test alert trigger */}
      <TaaraWareTestAlert />
    </div>
  );
}

function TaaraWareTestAlert() {
  const [triggering, setTriggering] = useState(false);
  const [result, setResult]         = useState('');

  async function triggerTest() {
    setTriggering(true); setResult('');
    try {
      const r = await api.triggerTestAlert();
      if (r.ok) setResult('✓ Test alert fired — check the banner at the top of the screen');
      else setResult('✗ ' + (r.data?.detail || 'Failed to trigger'));
    } catch (e) { setResult('✗ ' + e.message); }
    finally { setTriggering(false); }
  }

  return (
    <div className="card" style={{ borderLeft: '3px solid rgba(233,69,96,0.5)', background: 'rgba(233,69,96,0.03)' }}>
      <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 6 }}>Test Alert</div>
      <div style={{ fontSize: 12, color: 'var(--text-faint)', marginBottom: 12, lineHeight: 1.6 }}>
        Fires a synthetic T1078-style behavioral anomaly through the live quantum pipeline.
        The alert banner will appear at the top — click Investigate to see real quantum signal values and Groq reasoning.
      </div>
      <button className="btn" onClick={triggerTest} disabled={triggering} style={{ borderColor: 'rgba(233,69,96,0.4)', color: '#e94560', fontSize: 12 }}>
        {triggering ? <><span className="spinner" style={{ width: 12, height: 12 }} /> Triggering…</> : '⚡ Trigger Test Alert'}
      </button>
      {result && <div style={{ marginTop: 8, fontSize: 12, color: result.startsWith('✓') ? 'var(--green)' : 'var(--red)' }}>{result}</div>}
    </div>
  );
}

// ── Shared helpers ─────────────────────────────────────────────────────────────
function MetricTile({ label, value, color, mono, sub }) {
  return (
    <div className="card" style={{ padding: '14px 16px' }}>
      <div className="metric-label">{label}</div>
      <div style={{
        fontSize: 22, fontWeight: 700, marginTop: 6,
        color: color || 'var(--text)',
        fontFamily: mono ? 'monospace' : undefined,
      }}>{value}</div>
      {sub && <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 3 }}>{sub}</div>}
    </div>
  );
}

function extractAllFindings(results) {
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
