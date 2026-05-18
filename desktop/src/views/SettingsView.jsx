import React, { useState, useEffect } from 'react';
import { api } from '../api';
import { THEMES, applyTheme } from '../theme';

export default function SettingsView({ onThemeChange, onNav }) {
  const [settings, setSettings] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState('');

  const [firmName, setFirmName] = useState('');
  const [groqKey, setGroqKey] = useState('');
  const [showKey, setShowKey] = useState(false);
  const [theme, setTheme] = useState('dark');
  const [autonomyLevel, setAutonomyLevel] = useState(0.5);
  const [scanDepth, setScanDepth] = useState('Standard');
  const [webhookUrl, setWebhookUrl] = useState('');
  const [alertEmail, setAlertEmail] = useState('');

  useEffect(() => {
    async function loadSettings() {
      try {
        const res = await api.getSettings();
        if (res.ok) {
          const s = res.data;
          setSettings(s);
          setFirmName(s.firm_name || '');
          setGroqKey(s.groq_key_set ? '••••••••••••••••' : '');
          setTheme(s.theme || 'dark');
          setAutonomyLevel(s.autonomy_level ?? 0.5);
          setScanDepth(s.scan_depth || 'Standard');
          setWebhookUrl(s.webhook_url || '');
          setAlertEmail(s.alert_email || '');
        }
      } catch { /* ok — defaults */ }
      finally { setLoading(false); }
    }
    loadSettings();
  }, []);

  function handleThemeChange(t) {
    setTheme(t);
    applyTheme(t);
    onThemeChange(t);
  }

  async function save() {
    setSaving(true); setError(''); setSaved(false);
    try {
      const body = {
        firm_name: firmName.trim(),
        theme,
        autonomy_level: autonomyLevel,
        scan_depth: scanDepth,
        webhook_url: webhookUrl.trim(),
        alert_email: alertEmail.trim(),
      };
      // Only send groq_key if user typed a new real value (not the masked placeholder)
      if (groqKey && !groqKey.startsWith('•')) {
        body.groq_key = groqKey.trim();
      }
      const res = await api.saveSettings(body);
      if (!res.ok) { setError(res.data?.detail || 'Save failed'); return; }
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    } catch (e) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  }

  if (loading) return (
    <div className="page">
      <div className="skeleton" style={{ height: 300, borderRadius: 8 }} />
    </div>
  );

  return (
    <div className="page" style={{ maxWidth: 600 }}>
      <div style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 20, fontWeight: 700 }}>Settings</div>
        <div style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 3 }}>
          Configuration, appearance, and agent behaviour.
        </div>
      </div>

      {/* Firm & Identity */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="section-title">Identity</div>
        <div style={{ marginTop: 12 }}>
          <label className="label">Firm / Organisation Name</label>
          <input
            className="input"
            value={firmName}
            onChange={e => setFirmName(e.target.value)}
            placeholder="GoodWinSun"
            style={{ marginTop: 6 }}
          />
          <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 4 }}>
            Shown in the sidebar header and PDF reports.
          </div>
        </div>
      </div>

      {/* API Keys */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="section-title">Reasoning Engine</div>
        <div style={{ marginTop: 12 }}>
          <label className="label">Groq API Key</label>
          <div style={{ display: 'flex', gap: 8, marginTop: 6 }}>
            <input
              className="input"
              type={showKey ? 'text' : 'password'}
              value={groqKey}
              onChange={e => setGroqKey(e.target.value)}
              onFocus={() => { if (groqKey.startsWith('•')) setGroqKey(''); }}
              placeholder="gsk_..."
              style={{ flex: 1 }}
            />
            <button
              type="button"
              className="btn"
              style={{ padding: '0 12px', fontSize: 11 }}
              onClick={() => setShowKey(s => !s)}
            >
              {showKey ? 'Hide' : 'Show'}
            </button>
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 4 }}>
            Used for per-finding analysis and executive reports. Stored locally in .env — never sent anywhere.
            {settings?.groq_key_set && <span style={{ color: 'var(--green)', marginLeft: 6 }}>● Key is set</span>}
          </div>
        </div>
      </div>

      {/* Theme */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="section-title">Appearance</div>
        <div style={{ display: 'flex', gap: 10, marginTop: 12 }}>
          {Object.keys(THEMES).map(t => (
            <button
              key={t}
              type="button"
              onClick={() => handleThemeChange(t)}
              style={{
                flex: 1,
                padding: '10px 8px',
                background: THEMES[t]['--bg-app'],
                border: theme === t
                  ? `2px solid ${THEMES[t]['--accent']}`
                  : '2px solid var(--border)',
                borderRadius: 8,
                cursor: 'pointer',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                gap: 6,
                transition: 'border-color 0.15s',
              }}
            >
              <div style={{ display: 'flex', gap: 4 }}>
                <div style={{ width: 8, height: 8, borderRadius: 2, background: THEMES[t]['--accent'] }} />
                <div style={{ width: 8, height: 8, borderRadius: 2, background: THEMES[t]['--green'] }} />
                <div style={{ width: 8, height: 8, borderRadius: 2, background: THEMES[t]['--blue'] }} />
              </div>
              <span style={{ fontSize: 11, color: THEMES[t]['--text'] || '#fff', textTransform: 'capitalize' }}>
                {t}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Agent behaviour */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="section-title">Agent Behaviour</div>

        <div style={{ marginTop: 12 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <label className="label" style={{ margin: 0 }}>Autonomy Level</label>
            <span style={{ fontSize: 13, fontWeight: 600, fontFamily: 'monospace', color: 'var(--accent)' }}>
              {(autonomyLevel * 100).toFixed(0)}%
            </span>
          </div>
          <input
            type="range"
            min="0"
            max="1"
            step="0.05"
            value={autonomyLevel}
            onChange={e => setAutonomyLevel(parseFloat(e.target.value))}
            style={{ width: '100%', accentColor: 'var(--accent)' }}
          />
          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4 }}>
            <span style={{ fontSize: 10, color: 'var(--text-faint)' }}>Suggest only (manual approval)</span>
            <span style={{ fontSize: 10, color: 'var(--text-faint)' }}>Full autonomy</span>
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 8, lineHeight: 1.5 }}>
            Contrastive bandit auto-executes actions that meet the approval rate and success rate thresholds.
            This slider sets the required threshold.
          </div>
        </div>

        <div style={{ marginTop: 18 }}>
          <label className="label">Default Scan Depth</label>
          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            {['Quick', 'Standard', 'Deep'].map(d => (
              <button
                key={d}
                type="button"
                onClick={() => setScanDepth(d)}
                style={{
                  flex: 1, padding: '8px 0',
                  background: scanDepth === d ? 'var(--bg-raised)' : 'transparent',
                  border: scanDepth === d ? '1px solid var(--accent)' : '1px solid var(--border)',
                  borderRadius: 6,
                  color: scanDepth === d ? 'var(--accent)' : 'var(--text-dim)',
                  fontSize: 12, fontWeight: scanDepth === d ? 600 : 400,
                  cursor: 'pointer',
                  transition: 'all 0.12s',
                }}
              >{d}</button>
            ))}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 6 }}>
            Deep: full log analysis, longer runtime. Quick: core checks only.
          </div>
        </div>
      </div>

      {/* Notifications */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="section-title">Notifications</div>
        <div style={{ marginTop: 12, display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div>
            <label className="label">Webhook URL</label>
            <input
              className="input"
              value={webhookUrl}
              onChange={e => setWebhookUrl(e.target.value)}
              placeholder="https://hooks.slack.com/services/..."
              style={{ marginTop: 6 }}
            />
            <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 4 }}>
              POST anomaly alerts to Slack, Discord, or any webhook endpoint.
            </div>
          </div>
          <div>
            <label className="label">Alert Email</label>
            <input
              className="input"
              type="email"
              value={alertEmail}
              onChange={e => setAlertEmail(e.target.value)}
              placeholder="you@example.com"
              style={{ marginTop: 6 }}
            />
            <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 4 }}>
              Receive email when F_min drops below 0.5 (requires SMTP config in .env).
            </div>
          </div>
        </div>
      </div>

      {/* Resources */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="section-title">Resources</div>
        <div style={{ marginTop: 12, display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div style={{ fontSize: 13, fontWeight: 600 }}>TAARA User Manual</div>
              <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 2 }}>
                Complete guide: F_min explained, autonomy levels, report generation, benchmark methodology.
              </div>
            </div>
            <UserManualButton onNav={onNav} />
          </div>
        </div>
      </div>

      {/* Save */}
      {error && (
        <div style={{
          marginBottom: 12, padding: '8px 12px',
          background: 'rgba(233,69,96,0.1)', border: '1px solid rgba(233,69,96,0.25)',
          borderRadius: 6, fontSize: 12, color: 'var(--red)',
        }}>{error}</div>
      )}

      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <button className="btn btn-primary" onClick={save} disabled={saving}>
          {saving ? <><span className="spinner" /> Saving…</> : 'Save Settings'}
        </button>
        {saved && <span style={{ fontSize: 12, color: 'var(--green)' }}>✓ Saved</span>}
      </div>
    </div>
  );
}

function UserManualButton({ onNav }) {
  return (
    <button
      className="btn"
      onClick={() => onNav && onNav('manual')}
      style={{ fontSize: 11, padding: '6px 14px', borderColor: 'rgba(74,158,255,0.3)', color: 'var(--blue)' }}
    >
      📖 Open Manual
    </button>
  );
}
