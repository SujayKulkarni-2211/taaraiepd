import React, { useState } from 'react';

export default function LoginScreen({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [apiKey, setApiKey]     = useState('');

  function handleSubmit(e) {
    e.preventDefault();
    onLogin(apiKey.trim());
  }

  return (
    <div style={{
      height: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'var(--bg-app)',
    }}>
      <div style={{ width: 380 }}>
        <div style={{ textAlign: 'center', marginBottom: 36 }}>
          <div style={{
            fontSize: 32,
            fontWeight: 800,
            letterSpacing: 4,
            color: 'var(--accent)',
            marginBottom: 6,
          }}>TAARA</div>
          <div style={{ fontSize: 12, color: 'var(--text-faint)', letterSpacing: 1 }}>
            QUANTUM BEHAVIORAL INTELLIGENCE
          </div>
        </div>

        <form onSubmit={handleSubmit} className="card" style={{ padding: 28 }}>
          <div style={{ marginBottom: 16 }}>
            <label className="label">Username</label>
            <input
              className="input"
              value={username}
              onChange={e => setUsername(e.target.value)}
              placeholder="admin"
              autoComplete="username"
            />
          </div>

          <div style={{ marginBottom: 16 }}>
            <label className="label">Password</label>
            <input
              className="input"
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="••••••••"
              autoComplete="current-password"
            />
          </div>

          <div style={{ marginBottom: 24 }}>
            <label className="label">Reasoning Engine API Key</label>
            <input
              className="input"
              type="password"
              value={apiKey}
              onChange={e => setApiKey(e.target.value)}
              placeholder="API key for AI-powered analysis"
            />
            <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 5 }}>
              Used for AI analysis and report generation. Leave blank to use server default.
            </div>
          </div>

          <button
            type="submit"
            className="btn btn-primary"
            style={{ width: '100%', justifyContent: 'center', padding: '10px 0', fontSize: 14 }}
          >
            Enter TAARA →
          </button>
        </form>
      </div>
    </div>
  );
}
