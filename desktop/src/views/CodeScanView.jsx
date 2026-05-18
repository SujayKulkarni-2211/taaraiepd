import React, { useState } from 'react';
import { api } from '../api';

export default function CodeScanView() {
  const [repoUrl, setRepoUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState('');
  const [progress, setProgress] = useState('');

  async function runScan(e) {
    e.preventDefault();
    setScanning(true); setError(''); setResults(null); setProgress('Initializing scan…');

    try {
      const steps = [
        'Cloning repository…',
        'Scanning dependencies for CVEs (OSV.dev)…',
        'Checking for EOL packages…',
        'Building dependency graph…',
        'Computing exploit chain scores…',
        'Running quantum fidelity on dependency graph…',
        'Querying knowledge base (2444 policy vectors)…',
        'Generating LLM analysis…',
      ];
      let si = 0;
      const progressTimer = setInterval(() => {
        si = Math.min(si + 1, steps.length - 1);
        setProgress(steps[si]);
      }, 2500);

      const res = await api.codeScan({ repo_url: repoUrl.trim() });
      clearInterval(progressTimer);
      setProgress('');

      if (!res.ok) {
        setError(res.data?.detail || 'Scan failed');
        return;
      }
      setResults(res.data);
    } catch (e) {
      setError(e.message);
    } finally {
      setScanning(false);
      setProgress('');
    }
  }

  const findings = results?.findings || [];
  const critCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.filter(f => f.severity === 'high').length;
  const fmin = results?.quantum_fidelity?.f_min;

  function fminColor(f) {
    if (f == null) return 'var(--text-faint)';
    if (f < 0.3) return 'var(--red)';
    if (f < 0.5) return '#f5a623';
    if (f < 0.7) return 'var(--blue)';
    return 'var(--green)';
  }

  return (
    <div className="page">
      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 20, fontWeight: 700 }}>Code Scan</div>
        <div style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 3 }}>
          CVE detection · EOL packages · exploit chain scoring · quantum fidelity on dependency graph
        </div>
      </div>

      {/* Repo input */}
      <form onSubmit={runScan}>
        <div className="card" style={{ marginBottom: 20 }}>
          <label className="label">GitHub Repository URL</label>
          <div style={{ display: 'flex', gap: 10, marginTop: 6 }}>
            <input
              className="input"
              style={{ flex: 1 }}
              value={repoUrl}
              onChange={e => setRepoUrl(e.target.value)}
              placeholder="https://github.com/owner/repo"
              required
              disabled={scanning}
            />
            <button type="submit" className="btn btn-primary" disabled={scanning || !repoUrl.trim()}>
              {scanning ? <><span className="spinner" /> Scanning…</> : '▶  Scan'}
            </button>
          </div>
          {progress && (
            <div style={{ marginTop: 10, fontSize: 12, color: 'var(--text-dim)', display: 'flex', alignItems: 'center', gap: 8 }}>
              <span className="spinner" style={{ width: 12, height: 12 }} />
              {progress}
            </div>
          )}
          {error && (
            <div style={{
              marginTop: 10, padding: '8px 12px',
              background: 'rgba(233,69,96,0.1)', border: '1px solid rgba(233,69,96,0.25)',
              borderRadius: 6, fontSize: 12, color: 'var(--red)',
            }}>{error}</div>
          )}
        </div>
      </form>

      {/* Results */}
      {results && (
        <>
          {/* Summary metrics */}
          <div className="grid-4" style={{ marginBottom: 16 }}>
            <div className="card" style={{ padding: '14px 18px' }}>
              <div className="metric-label">Critical CVEs</div>
              <div className="metric-value" style={{ color: critCount > 0 ? 'var(--red)' : 'var(--green)', marginTop: 4 }}>
                {critCount}
              </div>
            </div>
            <div className="card" style={{ padding: '14px 18px' }}>
              <div className="metric-label">High</div>
              <div className="metric-value" style={{ color: highCount > 0 ? 'var(--amber)' : 'var(--green)', marginTop: 4 }}>
                {highCount}
              </div>
            </div>
            <div className="card" style={{ padding: '14px 18px' }}>
              <div className="metric-label">Total Findings</div>
              <div className="metric-value" style={{ marginTop: 4 }}>{findings.length}</div>
            </div>
            <div className="card" style={{ padding: '14px 18px' }}>
              <div className="metric-label">Graph F_min</div>
              <div className="metric-value"
                style={{ color: fminColor(fmin), fontFamily: 'monospace', marginTop: 4 }}>
                {fmin != null ? fmin.toFixed(4) : '—'}
              </div>
              {fmin != null && (
                <div style={{ fontSize: 10, color: 'var(--text-faint)', marginTop: 2 }}>
                  {fmin < 0.5 ? 'Anomalous dep graph' : 'Normal dep graph'}
                </div>
              )}
            </div>
          </div>

          {/* Quantum detail */}
          {results.quantum_fidelity && (
            <div className="card" style={{ marginBottom: 16 }}>
              <div className="section-title">Quantum Dependency Graph Analysis</div>
              <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.7, marginTop: 6 }}>
                {results.quantum_fidelity.interpretation || (
                  fmin < 0.5
                    ? `Dependency graph F_min = ${fmin.toFixed(4)} — the package dependency relationships deviate significantly from a secure baseline. Exploit chain probability elevated.`
                    : `Dependency graph F_min = ${fmin.toFixed(4)} — graph topology within normal range.`
                )}
              </div>
              {results.quantum_fidelity.correlation_signal_detected && (
                <div style={{
                  marginTop: 10, padding: '8px 12px',
                  background: 'rgba(245,166,35,0.08)', border: '1px solid rgba(245,166,35,0.2)',
                  borderRadius: 6, fontSize: 12, color: 'var(--amber)',
                }}>
                  ⚡ Angle encoding detected correlated vulnerability cluster — multiple packages with
                  cross-cutting exploit paths.
                </div>
              )}
            </div>
          )}

          {/* AI summary */}
          {results.ai_summary && (
            <div className="card" style={{ marginBottom: 16 }}>
              <div className="section-title">AI Analysis</div>
              <p style={{ fontSize: 13, color: 'var(--text)', lineHeight: 1.7 }}>{results.ai_summary}</p>
            </div>
          )}

          {/* Exploit chain */}
          {results.exploit_chains && results.exploit_chains.length > 0 && (
            <div className="card" style={{ marginBottom: 16 }}>
              <div className="section-title">Exploit Chains</div>
              {results.exploit_chains.slice(0, 5).map((chain, i) => (
                <div key={i} style={{
                  padding: '10px 12px', borderRadius: 6,
                  background: 'var(--bg-raised)', border: '1px solid var(--border)',
                  marginBottom: 8,
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ fontWeight: 600, fontSize: 12 }}>{chain.entry_point} → {chain.target}</span>
                    <span style={{
                      fontSize: 10, color: chain.score > 7 ? 'var(--red)' : 'var(--amber)',
                      fontWeight: 700,
                    }}>Score {chain.score?.toFixed(1)}</span>
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-faint)' }}>
                    {chain.path?.join(' → ')}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Findings table */}
          {findings.length > 0 && (
            <div className="card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
                <div className="section-title" style={{ margin: 0 }}>CVE Findings</div>
                <span style={{ fontSize: 11, color: 'var(--text-faint)' }}>{findings.length} total</span>
              </div>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Package</th>
                    <th>CVE / Description</th>
                    <th>Fix</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.slice(0, 30).map((f, i) => (
                    <tr key={i}>
                      <td>
                        <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                      </td>
                      <td style={{ fontFamily: 'monospace', fontSize: 12 }}>
                        {f.package || f.title || '—'}
                        {f.version && (
                          <span style={{ color: 'var(--text-faint)', marginLeft: 4 }}>v{f.version}</span>
                        )}
                      </td>
                      <td>
                        <div style={{ fontWeight: 500, fontSize: 12 }}>{f.cve_id || f.title || f.description}</div>
                        {f.detail && (
                          <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 2 }}>{f.detail}</div>
                        )}
                      </td>
                      <td style={{ fontSize: 11, color: 'var(--text-dim)', maxWidth: 200 }}>
                        {f.remediation || f.fix_version ? `Upgrade to ${f.fix_version}` : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      {/* Empty state */}
      {!results && !scanning && (
        <div style={{
          display: 'flex', flexDirection: 'column', alignItems: 'center',
          justifyContent: 'center', padding: '80px 40px', textAlign: 'center',
        }}>
          <div style={{ fontSize: 40, color: 'var(--text-faint)', marginBottom: 16 }}>⟨/⟩</div>
          <div style={{ fontSize: 16, fontWeight: 600, marginBottom: 8 }}>No scan yet</div>
          <div style={{ fontSize: 13, color: 'var(--text-dim)', lineHeight: 1.7, maxWidth: 400 }}>
            Paste a GitHub repository URL above. TAARA scans all dependencies using OSV.dev,
            builds a dependency graph, scores exploit chains, and computes quantum fidelity
            on the graph topology.
          </div>
        </div>
      )}
    </div>
  );
}
