import React, { useState } from 'react';
import { api } from '../api';
import '../components/Sidebar.css';

const PLATFORMS = ['ssh', 'aws', 'gcp', 'azure'];

export default function ConnectView({ onConnected, onDemoStart, prefillClient }) {
  const [platform, setPlatform] = useState(prefillClient?.platform_type || 'ssh');
  const [form, setForm]   = useState({
    host:     prefillClient?.hostname || '',
    port:     String(prefillClient?.port || 22),
    username: prefillClient?.username || '',
    password: '', key_path: '', api_key: '',
  });
  const [authMode, setAuthMode] = useState('password'); // 'password' | 'key'
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState('');
  const [step, setStep]         = useState('');
  const [demoLoading, setDemoLoading] = useState(false);

  function set(k, v) { setForm(f => ({ ...f, [k]: v })); }

  async function handleConnect(e) {
    e.preventDefault();
    setLoading(true); setError(''); setStep('Connecting...');

    try {
      const body = {
        host: form.host.trim(),
        port: parseInt(form.port) || 22,
        username: form.username.trim(),
        password: authMode === 'password' ? form.password : '',
        key_path: authMode === 'key' ? form.key_path.trim() : '',
        platform_type: platform,
        api_key: form.api_key.trim(),
      };

      setStep('Establishing connection...');
      const res = await api.connect(body);

      if (!res.ok) {
        setError(res.data?.detail || 'Connection failed');
        return;
      }

      setStep('Connected ✓');
      const info = res.data.info || {};
      onConnected(info, platform, form.host.trim());
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
      setStep('');
    }
  }

  async function handleDemo() {
    setDemoLoading(true);
    setError('');
    try {
      const res = await api.demoStart('ssh_intrusion');
      if (!res.ok) { setError(res.data?.detail || 'Demo start failed'); return; }
      onDemoStart('demo-server.taara.local');
    } catch (e) {
      setError(e.message);
    } finally {
      setDemoLoading(false);
    }
  }

  const cloudFields = {
    aws:   ['Access Key ID', 'Secret Access Key', 'Region'],
    gcp:   ['Project ID', 'Service Account JSON path', 'Region'],
    azure: ['Tenant ID', 'Client ID', 'Client Secret', 'Subscription ID'],
  };

  return (
    <div className="page" style={{ maxWidth: 560 }}>
      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--text)', marginBottom: 6 }}>
          {prefillClient ? `Connect — ${prefillClient.name}` : 'Connect to Infrastructure'}
        </div>
        <div style={{ fontSize: 13, color: 'var(--text-dim)' }}>
          {prefillClient
            ? `${prefillClient.hostname} · ${(prefillClient.platform_type || 'ssh').toUpperCase()}`
            : 'SSH, AWS, GCP, or Azure. All credentials stay local — never leave your machine.'}
        </div>
      </div>

      {/* Platform tabs */}
      <div style={s.tabs}>
        {PLATFORMS.map(p => (
          <button
            key={p}
            style={{ ...s.tab, ...(platform === p ? s.tabActive : {}) }}
            onClick={() => { setPlatform(p); setError(''); }}
          >
            {p.toUpperCase()}
          </button>
        ))}
      </div>

      {/* SSH form */}
      {platform === 'ssh' && (
        <form onSubmit={handleConnect} style={s.form}>
          <div className="card">
            <div style={s.row}>
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

            <div style={{ marginTop: 14 }}>
              <label className="label">Username</label>
              <input className="input" value={form.username} onChange={e => set('username', e.target.value)}
                placeholder="root" required />
            </div>

            {/* Auth mode toggle */}
            <div style={s.authToggle}>
              <button type="button" style={{ ...s.authBtn, ...(authMode === 'password' ? s.authBtnActive : {}) }}
                onClick={() => setAuthMode('password')}>Password</button>
              <button type="button" style={{ ...s.authBtn, ...(authMode === 'key' ? s.authBtnActive : {}) }}
                onClick={() => setAuthMode('key')}>SSH Key</button>
            </div>

            {authMode === 'password' && (
              <div>
                <label className="label">Password</label>
                <input className="input" type="password" value={form.password}
                  onChange={e => set('password', e.target.value)} placeholder="••••••••" />
              </div>
            )}

            {authMode === 'key' && (
              <div>
                <label className="label">Key Path</label>
                <input className="input" value={form.key_path}
                  onChange={e => set('key_path', e.target.value)}
                  placeholder="~/.ssh/id_rsa" />
              </div>
            )}

            <div className="divider" />

            <details style={{ marginBottom: 14 }}>
              <summary style={{ fontSize: 12, color: 'var(--text-dim)', cursor: 'pointer' }}>
                Reasoning Engine Key (optional — Groq)
              </summary>
              <div style={{ marginTop: 10 }}>
                <input className="input" value={form.api_key}
                  onChange={e => set('api_key', e.target.value)}
                  placeholder="gsk_..." type="password" />
                <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 4 }}>
                  Overrides the .env key. Used for AI-powered analysis and report generation.
                </div>
              </div>
            </details>

            {error && <div style={s.error}>{error}</div>}
            {step  && <div style={s.step}>{step}</div>}

            <button type="submit" className="btn btn-primary" disabled={loading} style={{ width: '100%', justifyContent: 'center' }}>
              {loading ? <><span className="spinner" /> Connecting…</> : 'Connect →'}
            </button>
          </div>
        </form>
      )}

      {/* Cloud form (AWS/GCP/Azure) */}
      {platform !== 'ssh' && (
        <div className="card" style={{ marginTop: 0 }}>
          <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 14, lineHeight: 1.6 }}>
            <b style={{ color: 'var(--amber)' }}>Limited depth mode.</b>{' '}
            For {platform.toUpperCase()}, TAARA provides cost savings analysis,
            basic security agent, and quantum behavioral scoring.
            Full SSH-depth analysis is available when connecting directly to instances.
          </div>

          {(cloudFields[platform] || []).map(field => (
            <div key={field} style={{ marginBottom: 12 }}>
              <label className="label">{field}</label>
              <input className="input" placeholder={field} />
            </div>
          ))}

          {error && <div style={s.error}>{error}</div>}

          <button type="button" className="btn btn-primary"
            style={{ width: '100%', justifyContent: 'center', marginTop: 4 }}>
            Connect to {platform.toUpperCase()} →
          </button>
        </div>
      )}

      {/* Demo mode separator */}
      <div style={s.demoSection}>
        <div style={s.demoOr}>
          <div style={s.demoLine} />
          <span style={s.demoOrText}>no live server?</span>
          <div style={s.demoLine} />
        </div>

        <button
          type="button"
          className="btn"
          onClick={handleDemo}
          disabled={demoLoading}
          style={{ width: '100%', justifyContent: 'center', marginTop: 12,
                   borderColor: 'rgba(245,166,35,0.3)', color: 'var(--amber)' }}
        >
          {demoLoading
            ? <><span className="spinner" /> Starting demo…</>
            : '▶  Run Demo Mode (simulated ssh_intrusion scenario)'
          }
        </button>
        <div style={{ fontSize: 11, color: 'var(--text-faint)', textAlign: 'center', marginTop: 6 }}>
          Real quantum math, synthetic behavioral data. F_min drops at tick 8. Anomaly banner fires.
        </div>
      </div>
    </div>
  );
}

const s = {
  tabs: {
    display: 'flex',
    gap: 4,
    marginBottom: 16,
    background: 'var(--bg-surface)',
    padding: 4,
    borderRadius: 8,
    border: '1px solid var(--border)',
  },
  tab: {
    flex: 1,
    padding: '7px 0',
    background: 'transparent',
    border: 'none',
    borderRadius: 5,
    color: 'var(--text-dim)',
    fontSize: 12,
    fontWeight: 600,
    letterSpacing: 0.5,
    cursor: 'pointer',
    transition: 'all 0.12s',
  },
  tabActive: {
    background: 'var(--bg-raised)',
    color: 'var(--text)',
    boxShadow: '0 1px 3px rgba(0,0,0,0.3)',
  },
  form: { marginTop: 0 },
  row: { display: 'flex', gap: 12 },
  authToggle: {
    display: 'flex',
    gap: 4,
    marginTop: 14,
    marginBottom: 12,
    background: 'var(--bg-input)',
    padding: 3,
    borderRadius: 6,
    border: '1px solid var(--border)',
  },
  authBtn: {
    flex: 1,
    padding: '6px 0',
    background: 'transparent',
    border: 'none',
    borderRadius: 4,
    color: 'var(--text-dim)',
    fontSize: 12,
    fontWeight: 500,
    cursor: 'pointer',
  },
  authBtnActive: {
    background: 'var(--bg-raised)',
    color: 'var(--text)',
  },
  error: {
    marginBottom: 12,
    padding: '8px 12px',
    background: 'rgba(233,69,96,0.1)',
    border: '1px solid rgba(233,69,96,0.25)',
    borderRadius: 6,
    fontSize: 12,
    color: 'var(--red)',
  },
  step: {
    marginBottom: 12,
    fontSize: 12,
    color: 'var(--green)',
  },
  demoSection: { marginTop: 24 },
  demoOr: { display: 'flex', alignItems: 'center', gap: 12 },
  demoLine: { flex: 1, height: 1, background: 'var(--border)' },
  demoOrText: { fontSize: 11, color: 'var(--text-faint)', whiteSpace: 'nowrap' },
};
