import React, { useState, useEffect, useCallback, useRef } from 'react';
import { applyTheme } from './theme';
import { api } from './api';
import AnomalyBanner from './components/AnomalyBanner';
import BootScreen from './components/BootScreen';
import LoginScreen from './views/LoginScreen';
import CodeAnalysisTab from './views/CodeAnalysisTab';
import SystemsTab from './views/SystemsTab';
import MultiClientTab from './views/MultiClientTab';
import SettingsView from './views/SettingsView';
import './App.css';

const ALERT_POLL_MS = 5000;
const TABS = [
  { id: 'code',     label: 'Code Analysis' },
  { id: 'systems',  label: 'Systems' },
  { id: 'clients',  label: 'Multi-Client' },
  { id: 'settings', label: 'Settings' },
];

export default function App() {
  const [serverReady, setServerReady]   = useState(false);
  const [serverError, setServerError]   = useState('');
  const [loggedIn, setLoggedIn]         = useState(false);
  const [apiKey, setApiKey]             = useState('');
  const [activeTab, setActiveTab]       = useState('clients');
  const [activeAlert, setActiveAlert]   = useState(null);
  const [theme, setTheme]               = useState('dark');
  const [settings, setSettings]         = useState({ firm_name: '' });
  const alertPollRef                    = useRef(null);

  // ── Boot ──────────────────────────────────────────────────────────────────
  useEffect(() => {
    applyTheme('dark');
    if (window.taara) {
      const unsubReady = window.taara.onServerReady(async () => { await handleServerReady(); });
      const unsubError = window.taara.onServerError((msg) => { setServerError(msg); });
      bootPoll();
      return () => { unsubReady(); unsubError(); };
    } else {
      bootPoll();
    }
  }, []);

  async function bootPoll() {
    for (let i = 0; i < 40; i++) {
      try {
        const res = await api.health();
        if (res.ok) { await handleServerReady(); return; }
      } catch (_) {}
      await sleep(1000);
    }
    setServerError('Server did not respond in 40 seconds.');
  }

  async function handleServerReady() {
    setServerReady(true);
    try {
      const res = await api.settings();
      if (res.ok) {
        setSettings(res.data);
        const t = res.data.theme || 'dark';
        setTheme(t);
        applyTheme(t);
      }
    } catch (_) {}
  }

  // ── Alert polling ─────────────────────────────────────────────────────────
  useEffect(() => {
    if (!loggedIn) return;
    alertPollRef.current = setInterval(pollAlerts, ALERT_POLL_MS);
    pollAlerts();
    return () => clearInterval(alertPollRef.current);
  }, [loggedIn]);

  async function pollAlerts() {
    try {
      const res = await api.alerts();
      if (res.ok) {
        if (res.data.has_anomaly) setActiveAlert(res.data.active_anomaly);
        else setActiveAlert(null);
      }
    } catch (_) {}
  }

  const handleLogin = useCallback((key) => {
    setApiKey(key || '');
    setLoggedIn(true);
  }, []);

  const handleDismissAlert = useCallback(async () => {
    try { await api.dismissAlert(); } catch (_) {}
    setActiveAlert(null);
  }, []);

  const handleThemeChange = useCallback((t) => {
    setTheme(t);
    applyTheme(t);
  }, []);

  const handleSettingsSaved = useCallback((s) => setSettings(s), []);

  if (!serverReady) return <BootScreen error={serverError} />;
  if (!loggedIn)    return <LoginScreen onLogin={handleLogin} />;

  return (
    <div className={`app-root${activeAlert ? ' app-root--alert' : ''}`}>
      {activeAlert && (
        <AnomalyBanner alert={activeAlert} onDismiss={handleDismissAlert} />
      )}

      {/* Top tab bar */}
      <div className="top-tabbar">
        <div className="top-tabbar-logo">TAARA</div>
        <div className="top-tabbar-tabs">
          {TABS.map(tab => (
            <button
              key={tab.id}
              className={`top-tab${activeTab === tab.id ? ' top-tab-active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
            >
              {tab.label}
            </button>
          ))}
        </div>
        <div className="top-tabbar-right">
          {settings.firm_name && (
            <span className="top-firm">{settings.firm_name}</span>
          )}
        </div>
      </div>

      {/* Tab content */}
      <main className="app-main">
        <div className="app-content">
          {activeTab === 'code'     && <CodeAnalysisTab />}
          {activeTab === 'systems'  && (
            <SystemsTab
              apiKey={apiKey}
              onAlertFired={setActiveAlert}
              onClientFocused={() => setActiveTab('clients')}
            />
          )}
          {activeTab === 'clients'  && (
            <MultiClientTab
              onFocusClient={() => setActiveTab('systems')}
            />
          )}
          {activeTab === 'settings' && (
            <SettingsView
              settings={settings}
              theme={theme}
              onThemeChange={handleThemeChange}
              onSaved={handleSettingsSaved}
              onNav={() => {}}
            />
          )}
        </div>
      </main>
    </div>
  );
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
