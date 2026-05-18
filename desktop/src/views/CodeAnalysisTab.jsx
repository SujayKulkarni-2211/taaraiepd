import React, { useState, useRef } from 'react';
import { api } from '../api';

function fminColor(f) {
  if (f == null) return 'var(--text-faint)';
  if (f < 0.3) return 'var(--red)';
  if (f < 0.5) return 'var(--amber)';
  if (f < 0.7) return 'var(--blue)';
  return 'var(--green)';
}

function severityClass(s) {
  const v = (s || '').toLowerCase();
  if (v === 'critical') return 'badge-critical';
  if (v === 'high')     return 'badge-high';
  if (v === 'medium')   return 'badge-medium';
  if (v === 'low')      return 'badge-low';
  return 'badge-info';
}

const SCAN_STEPS = [
  'Cloning repository…',
  'Parsing dependency graph…',
  'Querying OSV.dev for CVEs…',
  'Checking end-of-life components…',
  'Building exploit chain graph…',
  'Scanning cross-file failure paths…',
  'Running knowledge-base policy check…',
  'Computing quantum fidelity score…',
  'Generating Reasoning Engine summary…',
];

export default function CodeAnalysisTab() {
  const [url, setUrl]         = useState('');
  const [running, setRunning] = useState(false);
  const [stepIdx, setStepIdx] = useState(0);
  const [results, setResults] = useState(null);
  const [error, setError]     = useState('');
  const [dlState, setDlState] = useState('idle');
  const stepRef               = useRef(null);

  async function runScan() {
    if (!url.trim()) return;
    setRunning(true); setError(''); setResults(null); setStepIdx(0);
    let idx = 0;
    stepRef.current = setInterval(() => {
      idx = Math.min(idx + 1, SCAN_STEPS.length - 1);
      setStepIdx(idx);
    }, 3500);
    try {
      const res = await api.codeScan({ target: url.trim(), offline: false });
      clearInterval(stepRef.current);
      setStepIdx(SCAN_STEPS.length);
      if (!res.ok) { setError(res.data?.detail || 'Scan failed'); return; }
      setResults(res.data);
    } catch (e) {
      clearInterval(stepRef.current);
      setError(String(e.message || e));
    } finally {
      setRunning(false);
    }
  }

  async function downloadPDF() {
    setDlState('loading');
    try {
      if (window.taara) {
        const r = await window.taara.api('/api/generate-code-scan-report', 'POST', {});
        if (r.status >= 400) {
          setDlState('error');
          console.error('PDF error:', r.data?.detail);
          return;
        }
        await window.taara.openPDF(r.data.path);
        setDlState('done');
      } else {
        // Browser fallback: stream the PDF directly
        const resp = await fetch('http://127.0.0.1:8765/api/generate-code-scan-report', { method: 'POST' });
        if (!resp.ok) { setDlState('error'); return; }
        const json = await resp.json();
        // In browser mode we can't open local paths, just signal done
        setDlState('done');
        console.log('PDF saved at:', json.path);
      }
    } catch (e) {
      setDlState('error');
      console.error('PDF error:', e);
    }
  }

  React.useEffect(() => () => clearInterval(stepRef.current), []);

  return (
    <div className="page">
      <div style={{ fontSize: 20, fontWeight: 700, marginBottom: 6 }}>Code Analysis</div>
      <div style={{ fontSize: 13, color: 'var(--text-dim)', marginBottom: 24 }}>
        Scan a GitHub repository for CVEs, exploit chains, and quantum fidelity score.
      </div>

      <div className="card" style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', gap: 10 }}>
          <input
            className="input"
            value={url}
            onChange={e => setUrl(e.target.value)}
            placeholder="https://github.com/org/repo"
            style={{ flex: 1 }}
            onKeyDown={e => e.key === 'Enter' && !running && runScan()}
          />
          <button className="btn btn-primary" onClick={runScan} disabled={running || !url.trim()}>
            {running ? <><span className="spinner" /> Scanning…</> : '▶ Run Scan'}
          </button>
        </div>
      </div>

      {running && (
        <div className="card" style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-dim)', marginBottom: 14, letterSpacing: 0.5 }}>
            SCANNING REPOSITORY
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 14 }}>
            <div style={{ flex: 1, height: 3, background: 'var(--border)', borderRadius: 2, overflow: 'hidden' }}>
              <div style={{
                height: '100%', borderRadius: 2,
                width: `${(stepIdx / SCAN_STEPS.length) * 100}%`,
                background: 'var(--accent)', transition: 'width 0.5s ease',
              }} />
            </div>
            <span style={{ fontSize: 11, color: 'var(--text-faint)', fontFamily: 'monospace' }}>
              {stepIdx}/{SCAN_STEPS.length}
            </span>
          </div>
          {SCAN_STEPS.map((s, i) => (
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
        <div style={{
          marginBottom: 16, padding: '10px 14px',
          background: 'rgba(233,69,96,0.1)', border: '1px solid rgba(233,69,96,0.25)',
          borderRadius: 8, fontSize: 13, color: 'var(--red)',
        }}>
          {error}
        </div>
      )}

      {results && !running && (
        <ScanResults results={results} onDownloadPDF={downloadPDF} dlState={dlState} />
      )}
    </div>
  );
}

// API response shape from scan_repo.py:
// { target, repo, scanned_at, summary: {total_findings, critical, high, layer3_chains, exploit_chains_scored},
//   repo_quantum_fidelity, findings: [...], exploit_chains: [...], cross_file_chains: [...], ai_summary? }
function ScanResults({ results, onDownloadPDF, dlState }) {
  const summary   = results.summary || {};
  const findings  = results.findings || [];
  const chains    = results.exploit_chains || [];
  const xchains   = results.cross_file_chains || [];
  const fidelity  = results.repo_quantum_fidelity;
  const fmin      = typeof fidelity === 'number' ? fidelity
    : (fidelity && typeof fidelity === 'object') ? (fidelity.f_min ?? fidelity.fidelity) : null;
  const aiSummary = results.ai_summary || results.summary_text || '';

  const totalFindings = typeof summary.total_findings === 'number' ? summary.total_findings : findings.length;
  const critCount     = typeof summary.critical === 'number' ? summary.critical : 0;
  const highCount     = typeof summary.high === 'number' ? summary.high : 0;
  const chainCount    = typeof summary.exploit_chains_scored === 'number' ? summary.exploit_chains_scored : chains.length;

  return (
    <div>
      {/* Metric tiles */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(170px, 1fr))', gap: 14, marginBottom: 20 }}>
        <MetricTile label="Total Findings"  value={totalFindings} color={totalFindings > 0 ? 'var(--amber)' : 'var(--green)'} />
        <MetricTile label="Critical"        value={critCount}     color={critCount > 0 ? 'var(--red)' : 'var(--green)'} />
        <MetricTile label="High"            value={highCount}     color={highCount > 0 ? 'var(--amber)' : 'var(--green)'} />
        <MetricTile label="Exploit Chains"  value={chainCount}    color={chainCount > 0 ? 'var(--red)' : 'var(--green)'} />
        {fmin != null && (
          <MetricTile label="Quantum F_min" value={fmin.toFixed(4)} color={fminColor(fmin)} mono />
        )}
      </div>

      {/* Quantum fidelity bar */}
      {fmin != null && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="section-title" style={{ marginBottom: 8 }}>Quantum Fidelity</div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
            <span style={{ fontSize: 10, color: 'var(--text-faint)' }}>0.0 Critical</span>
            <span style={{ fontSize: 12, color: fminColor(fmin), fontWeight: 700 }}>
              F = |⟨ψ_t|ψ_m⟩|² = {fmin.toFixed(4)} — {((1 - fmin) * 100).toFixed(1)}% divergence from secure baseline
            </span>
            <span style={{ fontSize: 10, color: 'var(--text-faint)' }}>1.0 Normal</span>
          </div>
          <div style={{ height: 8, background: 'var(--bg-raised)', borderRadius: 4, overflow: 'hidden', border: '1px solid var(--border)' }}>
            <div style={{
              height: '100%', borderRadius: 4, width: `${fmin * 100}%`,
              background: 'linear-gradient(90deg, #e94560 0%, #f5a623 30%, #4a9eff 50%, #22cc66 70%)',
            }} />
          </div>
        </div>
      )}

      {/* AI summary */}
      {aiSummary && typeof aiSummary === 'string' && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="section-title" style={{ marginBottom: 8 }}>Reasoning Engine Summary</div>
          <div style={{ fontSize: 13, color: 'var(--text)', lineHeight: 1.7, whiteSpace: 'pre-wrap' }}>
            {aiSummary}
          </div>
        </div>
      )}

      {/* CVE / findings list */}
      {findings.length > 0 && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="section-title" style={{ marginBottom: 12 }}>
            Findings ({findings.length})
          </div>
          {findings.slice(0, 30).map((f, i) => (
            <FindingRow key={i} finding={f} last={i === Math.min(findings.length, 30) - 1} />
          ))}
          {findings.length > 30 && (
            <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 8 }}>
              …and {findings.length - 30} more. Download the PDF for the full report.
            </div>
          )}
        </div>
      )}

      {/* Exploit chains */}
      {chains.length > 0 && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="section-title" style={{ marginBottom: 12 }}>
            Exploit Chains ({chains.length})
          </div>
          {chains.slice(0, 10).map((c, i) => (
            <div key={i} style={{
              padding: '10px 12px', background: 'var(--bg-raised)', borderRadius: 6, marginBottom: 8,
              border: '1px solid rgba(233,69,96,0.15)',
            }}>
              <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 4 }}>
                {String(c.title || c.name || `Chain ${i + 1}`)}
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-faint)' }}>
                {String(c.description || c.detail || '')}
              </div>
              {c.cvss_score != null && (
                <div style={{ fontSize: 10, color: 'var(--amber)', marginTop: 4 }}>
                  CVSS {c.cvss_score}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Cross-file chains */}
      {xchains.length > 0 && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="section-title" style={{ marginBottom: 12 }}>
            Cross-File Failure Chains ({xchains.length})
          </div>
          {xchains.slice(0, 5).map((c, i) => (
            <div key={i} style={{
              padding: '10px 12px', background: 'var(--bg-raised)', borderRadius: 6, marginBottom: 8,
              border: '1px solid rgba(245,166,35,0.15)',
            }}>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 4 }}>
                <span className={`badge ${severityClass(c.severity)}`}>{String(c.severity || 'info').toUpperCase()}</span>
                <span style={{ fontSize: 12, fontWeight: 600 }}>{String(c.title || '')}</span>
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-faint)' }}>
                {String(c.detail || '').slice(0, 200)}
              </div>
              {Array.isArray(c.files) && c.files.length > 0 && (
                <div style={{ fontSize: 10, color: 'var(--text-faint)', marginTop: 4, fontFamily: 'monospace' }}>
                  Files: {c.files.slice(0, 3).map(String).join(', ')}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Download */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <button
          className="btn"
          onClick={onDownloadPDF}
          disabled={dlState === 'loading'}
          style={{ borderColor: 'rgba(74,158,255,0.3)', color: 'var(--blue)' }}
        >
          {dlState === 'loading' ? <><span className="spinner" /> Generating…</> : '⬇ Download PDF Report'}
        </button>
        {dlState === 'done'  && <span style={{ fontSize: 12, color: 'var(--green)' }}>✓ Report ready</span>}
        {dlState === 'error' && <span style={{ fontSize: 12, color: 'var(--red)' }}>✕ Failed</span>}
      </div>
    </div>
  );
}

function FindingRow({ finding, last }) {
  const [open, setOpen] = useState(false);
  const sev = String(finding.severity || finding.level || 'info').toLowerCase();

  // Safe string extraction — never render raw objects
  const title  = String(finding.title || finding.id || finding.osv_id || finding.cve_id || '—');
  const desc   = String(finding.description || finding.summary || finding.detail || '');
  const pkg    = String(finding.package || finding.name || '');
  const ver    = String(finding.version || finding.installed_version || '');
  const fix    = String(finding.fixed_in || finding.fix || finding.remediation || '');
  const cvss   = finding.cvss_score != null ? String(finding.cvss_score) : null;
  const osvId  = String(finding.osv_id || finding.cve_id || '');

  return (
    <div style={{
      borderBottom: last ? 'none' : '1px solid var(--border-dim)',
    }}>
      <div
        style={{ display: 'flex', gap: 10, alignItems: 'center', padding: '9px 0', cursor: desc ? 'pointer' : 'default' }}
        onClick={() => desc && setOpen(o => !o)}
      >
        <span className={`badge ${severityClass(sev)}`} style={{ flexShrink: 0 }}>
          {sev.toUpperCase()}
        </span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 12, fontWeight: 600, fontFamily: osvId ? 'monospace' : undefined }}>
            {title}
          </div>
          {pkg && (
            <div style={{ fontSize: 11, color: 'var(--text-faint)' }}>
              {pkg}{ver ? ` @ ${ver}` : ''}
            </div>
          )}
        </div>
        {cvss && (
          <span style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--text-faint)', flexShrink: 0 }}>
            CVSS {cvss}
          </span>
        )}
        {desc && (
          <span style={{ fontSize: 11, color: 'var(--text-faint)', flexShrink: 0 }}>{open ? '▲' : '▼'}</span>
        )}
      </div>
      {open && desc && (
        <div style={{ paddingBottom: 10, paddingLeft: 4 }}>
          <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.6, marginBottom: fix ? 8 : 0 }}>
            {desc.slice(0, 400)}{desc.length > 400 ? '…' : ''}
          </div>
          {fix && (
            <div>
              <div style={{ fontSize: 10, color: 'var(--text-faint)', fontWeight: 600, letterSpacing: 0.5, marginBottom: 3 }}>FIX</div>
              <code style={{ fontSize: 11, color: 'var(--blue)' }}>{fix}</code>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function MetricTile({ label, value, color, mono }) {
  return (
    <div className="card" style={{ padding: '14px 16px' }}>
      <div className="metric-label">{label}</div>
      <div style={{
        fontSize: 26, fontWeight: 700, marginTop: 6,
        color: color || 'var(--text)',
        fontFamily: mono ? 'monospace' : undefined,
      }}>
        {String(value ?? '—')}
      </div>
    </div>
  );
}
