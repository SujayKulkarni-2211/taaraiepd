import React, { useEffect, useState, useRef } from 'react';
import { api } from '../api';

// ── Shared colour helpers ─────────────────────────────────────────────────────
function fminColorShared(f) {
  if (f == null) return '#e94560';
  if (f < 0.3) return '#e94560';
  if (f < 0.5) return '#f5a623';
  return '#4a9eff';
}
function qcColorShared(qc) {
  if (qc == null) return '#e94560';
  if (qc >= 0.75) return '#e94560';
  if (qc >= 0.45) return '#f5a623';
  if (qc >= 0.1854) return '#4a9eff';
  return '#22cc66';
}

// ── Investigate Modal ─────────────────────────────────────────────────────────
function InvestigateModal({ onClose, onMarkNormal, onExecute }) {
  const [data, setData]         = useState(null);
  const [loading, setLoading]   = useState(true);
  const [pwd, setPwd]           = useState('');
  const [unlocked, setUnlocked] = useState(false);
  const [pwdErr, setPwdErr]     = useState('');
  const [aiCmd, setAiCmd]       = useState('');
  const [manualCmd, setManualCmd] = useState('');
  const [executing, setExecuting] = useState(false);
  const [execResult, setExecResult] = useState(null);
  const [marking, setMarking]   = useState(false);
  const [tab, setTab]           = useState('situation'); // situation | features | action
  const [pendingCmd, setPendingCmd]   = useState(null);
  const [stdinValue, setStdinValue]   = useState('');
  const DEMO_PWD = 'taara2026';

  useEffect(() => {
    api.investigateAlert().then(r => {
      if (r.ok) setData(r.data);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  useEffect(() => {
    // Generate AI recommended action when data arrives
    if (data && !aiCmd) {
      const qConf = data.quantum_confidence != null ? `quantum_conf=${data.quantum_confidence?.toFixed(4)}` : `F_min=${data.f_min}`;
      const intent = `Investigate anomaly on ${data.host}: ${qConf}, zone=${data.zone}, `
        + `swap_fidelity=${data.swap_fidelity?.toFixed(4)}, q_directionality=${data.q_directionality?.toFixed(4)}, phase_coherence=${data.phase_coherence?.toFixed(4)}. `
        + `Top signals: ${(data.top_signals || []).slice(0,3).map(s => `${s.key}=${s.value}`).join(', ')}. `
        + `What single shell command should I run to investigate or contain this?`;
      api.generateCommand(intent).then(r => {
        if (r.ok && r.data.command) setAiCmd(r.data.command);
      }).catch(() => {});
    }
  }, [data]);

  async function handleExecute(cmd) {
    if (!cmd.trim()) return;
    setExecuting(true);
    setExecResult(null);
    setPendingCmd(null);
    try {
      const r = await api.execute({ command: cmd, description: 'Anomaly investigation' });
      if (r.data?.needs_input) {
        setPendingCmd(cmd);
        setExecResult({ needs_input: true, prompt: r.data.input_prompt });
      } else {
        setExecResult(r.data);
      }
    } catch (e) {
      setExecResult({ success: false, stdout: '', stderr: e.message });
    } finally {
      setExecuting(false);
    }
  }

  async function sendStdin() {
    if (!pendingCmd) return;
    setExecuting(true);
    try {
      const r = await api.executeStdin({ command: pendingCmd, stdin_input: stdinValue, description: 'Investigation stdin' });
      setPendingCmd(null);
      setStdinValue('');
      setExecResult(r.data);
    } catch (e) {
      setExecResult({ success: false, stderr: e.message });
    } finally {
      setExecuting(false);
    }
  }

  async function handleMarkNormal() {
    setMarking(true);
    try {
      await api.markNormal();
      onMarkNormal && onMarkNormal();
      onClose();
    } finally {
      setMarking(false);
    }
  }

  function tryUnlock() {
    if (pwd === DEMO_PWD) { setUnlocked(true); setPwdErr(''); }
    else setPwdErr('Incorrect password');
  }

  const fminColor = fminColorShared;
  const qcColor   = qcColorShared;

  return (
    <div style={S.overlay} onClick={e => e.target === e.currentTarget && onClose()}>
      <div style={S.modal}>

        {/* Header */}
        <div style={S.header}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#e94560', boxShadow: '0 0 8px #e94560', animation: 'alertPulse 1.4s infinite' }} />
            <div>
              <div style={{ fontSize: 15, fontWeight: 800, color: '#fff', letterSpacing: 0.5 }}>
                QUANTUM ANOMALY INVESTIGATION
              </div>
              {data && (
                <div style={{ fontSize: 11, color: 'rgba(233,69,96,0.7)', marginTop: 1 }}>
                  {data.host} · {new Date(data.timestamp * 1000).toLocaleString()}
                </div>
              )}
            </div>
          </div>
          <button onClick={onClose} style={S.closeBtn}>✕</button>
        </div>

        {/* Tabs */}
        <div style={S.tabBar}>
          {[['situation','Situation & Reasoning'],['features','Behavioral Features'],['action','Take Action']].map(([id, label]) => (
            <button key={id} onClick={() => setTab(id)} style={{ ...S.tabBtn, ...(tab === id ? S.tabBtnActive : {}) }}>
              {label}
            </button>
          ))}
        </div>

        {/* Body */}
        <div style={S.body}>
          {loading && (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 200, color: 'rgba(255,255,255,0.3)', fontSize: 13 }}>
              Loading investigation…
            </div>
          )}

          {!loading && data && tab === 'situation' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

              {/* Quantum state card */}
              <div style={S.card}>
                <div style={{ display: 'flex', gap: 20, alignItems: 'center' }}>
                  {/* Quantum confidence dial */}
                  <div style={{ flexShrink: 0 }}>
                    {(() => {
                      const qc = data.quantum_confidence ?? data.f_min;
                      const col = data.quantum_confidence != null ? qcColor(data.quantum_confidence) : fminColor(data.f_min);
                      return (
                        <div style={{
                          width: 90, height: 90, borderRadius: '50%',
                          background: `conic-gradient(${col} 0% ${(qc ?? 0) * 100}%, rgba(255,255,255,0.05) ${(qc ?? 0) * 100}% 100%)`,
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                          boxShadow: `0 0 20px ${col}55`, border: `2px solid ${col}66`,
                        }}>
                          <div style={{ width: 68, height: 68, borderRadius: '50%', background: '#0d0d1a', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                            <div style={{ fontSize: 16, fontWeight: 800, fontFamily: 'monospace', color: col, lineHeight: 1 }}>
                              {((qc ?? 0) * 100).toFixed(0)}%
                            </div>
                            <div style={{ fontSize: 7, color: 'rgba(255,255,255,0.3)', marginTop: 2 }}>{data.quantum_confidence != null ? 'Q-CONF' : 'FIDELITY'}</div>
                          </div>
                        </div>
                      );
                    })()}
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                      <span style={{ fontSize: 12, fontWeight: 800, color: qcColor(data.quantum_confidence) || fminColor(data.f_min), letterSpacing: 1 }}>{data.zone}</span>
                      {data.quantum_confidence != null
                        ? <span style={{ fontSize: 11, fontFamily: 'monospace', color: 'rgba(255,255,255,0.4)' }}>conf = {data.quantum_confidence?.toFixed(4)} · thresh = 0.1854</span>
                        : <span style={{ fontSize: 11, fontFamily: 'monospace', color: 'rgba(255,255,255,0.4)' }}>F = {data.f_min?.toFixed(4)}</span>
                      }
                    </div>
                    <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.7)', lineHeight: 1.7 }}>
                      {data.zone_explain}
                    </div>
                    {/* 3 quantum signal mini-bars */}
                    {(data.swap_fidelity != null || data.q_directionality != null || data.phase_coherence != null) && (
                      <div style={{ marginTop: 10, display: 'flex', flexDirection: 'column', gap: 5 }}>
                        {[
                          { label: 'SWAP Fidelity', val: data.swap_fidelity, color: data.swap_fidelity >= 0.7 ? '#22cc66' : '#e94560', note: 'high=normal' },
                          { label: 'Directionality', val: data.q_directionality, color: data.q_directionality >= 0.3 ? '#e94560' : '#22cc66', note: 'high=attack drift' },
                          { label: 'Phase Coherence', val: data.phase_coherence, color: data.phase_coherence >= 0.8 ? '#e94560' : '#22cc66', note: 'high=sustained' },
                        ].filter(s => s.val != null).map(s => (
                          <div key={s.label} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <span style={{ fontSize: 8, color: 'rgba(255,255,255,0.3)', minWidth: 80 }}>{s.label}</span>
                            <div style={{ flex: 1, height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 2 }}>
                              <div style={{ height: '100%', width: `${Math.min(s.val, 1) * 100}%`, background: s.color, borderRadius: 2 }} />
                            </div>
                            <span style={{ fontSize: 9, fontFamily: 'monospace', color: s.color, minWidth: 38 }}>{s.val.toFixed(3)}</span>
                          </div>
                        ))}
                      </div>
                    )}
                    <div style={{ marginTop: 8, fontSize: 10, fontFamily: 'monospace', color: 'rgba(255,255,255,0.25)', letterSpacing: 0.5 }}>
                      {data.formula || 'α·swap_s + β·q_dir + γ·coh·√(swap_s·q_dir)'} · v3 threshold = 0.1854
                    </div>
                  </div>
                </div>
              </div>

              {/* Top deviating signals */}
              {data.top_signals?.length > 0 && (
                <div style={S.card}>
                  <div style={S.cardLabel}>TOP DEVIATING SIGNALS</div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginTop: 8 }}>
                    {data.top_signals.map(s => (
                      <div key={s.key} style={{ background: 'rgba(233,69,96,0.07)', border: '1px solid rgba(233,69,96,0.15)', borderRadius: 6, padding: '8px 10px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                          <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.5)' }}>{s.key.replace(/_/g, ' ')}</span>
                          <span style={{ fontSize: 10, color: '#e94560', fontWeight: 700 }}>{s.deviation.toFixed(1)}× normal</span>
                        </div>
                        <div style={{ height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 2 }}>
                          <div style={{ height: '100%', width: `${Math.min(s.deviation / 5 * 100, 100)}%`, background: s.deviation > 3 ? '#e94560' : s.deviation > 1.5 ? '#f5a623' : '#4a9eff', borderRadius: 2 }} />
                        </div>
                        <div style={{ fontSize: 12, fontFamily: 'monospace', color: '#fff', fontWeight: 700, marginTop: 3 }}>
                          {s.value} <span style={{ fontSize: 9, color: 'rgba(255,255,255,0.3)' }}>normal ~{s.normal}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* LLM Reasoning */}
              <div style={S.card}>
                <div style={S.cardLabel}>REASONING ENGINE ANALYSIS</div>
                {data.llm_reasoning ? (
                  <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.8)', lineHeight: 1.8, marginTop: 8 }}>
                    {data.llm_reasoning}
                  </div>
                ) : (
                  <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.3)', marginTop: 8, fontStyle: 'italic' }}>
                    Reasoning Engine not configured — add a key in Settings to enable AI-powered analysis.
                  </div>
                )}
              </div>

              {/* Historical context */}
              <div style={{ display: 'flex', gap: 10 }}>
                <div style={{ ...S.card, flex: 1, textAlign: 'center' }}>
                  <div style={S.cardLabel}>BASIS SIZE</div>
                  <div style={{ fontSize: 26, fontWeight: 800, color: data.basis_size >= 10 ? '#4a9eff' : '#f5a623', fontFamily: 'monospace', marginTop: 4 }}>{data.basis_size}</div>
                  <div style={{ fontSize: 9, color: 'rgba(255,255,255,0.3)', marginTop: 2 }}>observations in memory</div>
                  {data.basis_size < 10 && <div style={{ fontSize: 9, color: '#f5a623', marginTop: 4 }}>⚠ Still calibrating — {10 - data.basis_size} more needed</div>}
                </div>
                <div style={{ ...S.card, flex: 1, textAlign: 'center' }}>
                  <div style={S.cardLabel}>RISK SCORE</div>
                  <div style={{ fontSize: 26, fontWeight: 800, color: data.risk_score >= 75 ? '#e94560' : data.risk_score >= 50 ? '#f5a623' : '#4a9eff', fontFamily: 'monospace', marginTop: 4 }}>{data.risk_score?.toFixed(0)}</div>
                  <div style={{ fontSize: 9, color: 'rgba(255,255,255,0.3)', marginTop: 2 }}>/ 100</div>
                </div>
                <div style={{ ...S.card, flex: 1, textAlign: 'center' }}>
                  <div style={S.cardLabel}>PRIOR ANOMALIES</div>
                  <div style={{ fontSize: 26, fontWeight: 800, color: data.prior_anomalies > 0 ? '#f5a623' : '#22cc66', fontFamily: 'monospace', marginTop: 4 }}>{data.prior_anomalies}</div>
                  <div style={{ fontSize: 9, color: 'rgba(255,255,255,0.3)', marginTop: 2 }}>on this identity</div>
                </div>
              </div>
            </div>
          )}

          {!loading && data && tab === 'features' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.35)', lineHeight: 1.6 }}>
                The 19-dimensional behavioral DNA captured at time of alert. PQC-transformed → 8-dim latent → 3-qubit quantum state. Values are masked — enter the operator password to view exact readings.
              </div>

              {!unlocked ? (
                <div style={{ ...S.card, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12, padding: 28 }}>
                  <div style={{ fontSize: 22 }}>🔒</div>
                  <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.6)', textAlign: 'center' }}>Feature values are protected.<br />Enter operator password to reveal.</div>
                  <div style={{ display: 'flex', gap: 8, width: '100%', maxWidth: 300 }}>
                    <input
                      type="password" placeholder="Operator password" value={pwd}
                      onChange={e => setPwd(e.target.value)}
                      onKeyDown={e => e.key === 'Enter' && tryUnlock()}
                      style={{ ...S.input, flex: 1 }}
                    />
                    <button onClick={tryUnlock} style={S.btnPrimary}>Unlock</button>
                  </div>
                  {pwdErr && <div style={{ fontSize: 11, color: '#e94560' }}>{pwdErr}</div>}
                </div>
              ) : (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                  {Object.entries(data.features || {})
                    .filter(([k]) => !['anomaly_score','is_anomaly'].includes(k))
                    .map(([k, v]) => {
                      const sig = data.top_signals?.find(s => s.key === k);
                      const isHot = sig && sig.deviation > 1.5;
                      return (
                        <div key={k} style={{ background: isHot ? 'rgba(233,69,96,0.08)' : 'rgba(255,255,255,0.03)', border: `1px solid ${isHot ? 'rgba(233,69,96,0.2)' : 'rgba(255,255,255,0.06)'}`, borderRadius: 6, padding: '8px 10px' }}>
                          <div style={{ fontSize: 9, color: isHot ? '#e94560' : 'rgba(255,255,255,0.4)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 2 }}>
                            {k.replace(/_/g,' ')} {isHot && '↑'}
                          </div>
                          <div style={{ fontSize: 14, fontFamily: 'monospace', fontWeight: 700, color: isHot ? '#e94560' : '#fff' }}>
                            {typeof v === 'number' ? v.toFixed(4) : String(v)}
                          </div>
                          {sig && <div style={{ fontSize: 9, color: 'rgba(255,255,255,0.25)', marginTop: 2 }}>normal ~{sig.normal} · {sig.deviation.toFixed(1)}× deviation</div>}
                        </div>
                      );
                    })}
                </div>
              )}
            </div>
          )}

          {!loading && data && tab === 'action' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>

              {/* Bandit-learned recommendations */}
              {data.bandit_recommendations?.length > 0 && (
                <div style={S.card}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={S.cardLabel}>TAARA LEARNED — BANDIT RECOMMENDATIONS</div>
                    <span style={{ fontSize: 9, color: 'rgba(74,158,255,0.6)', fontWeight: 600, letterSpacing: 0.5 }}>ONLINE LEARNING</span>
                  </div>
                  <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginTop: 4, marginBottom: 10 }}>
                    UCB-ranked actions for this quantum context ({data.bandit_recommendations[0]?.quantum_context || 'current context'}). Scores improve with each execution.
                  </div>
                  {data.bandit_recommendations.map((rec, i) => (
                    <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 10px', background: rec.pre_approved ? 'rgba(34,204,102,0.07)' : 'rgba(74,158,255,0.05)', border: `1px solid ${rec.pre_approved ? 'rgba(34,204,102,0.2)' : 'rgba(74,158,255,0.12)'}`, borderRadius: 6, marginBottom: 6 }}>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 2 }}>
                          <span style={{ fontSize: 11, fontWeight: 700, color: rec.pre_approved ? '#22cc66' : '#4a9eff' }}>{rec.action_type.replace(/_/g,' ')}</span>
                          {rec.pre_approved && <span style={{ fontSize: 8, background: 'rgba(34,204,102,0.2)', color: '#22cc66', borderRadius: 3, padding: '1px 5px', fontWeight: 700 }}>PRE-APPROVED</span>}
                          <span style={{ fontSize: 9, color: 'rgba(255,255,255,0.25)', marginLeft: 'auto' }}>
                            {rec.times_seen > 0 ? `seen ${rec.times_seen}× · ${Math.round(rec.success_rate * 100)}% success` : 'unexplored'}
                          </span>
                        </div>
                        <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.5)' }}>{rec.description}</div>
                        <div style={{ fontSize: 9, color: 'rgba(255,255,255,0.25)', marginTop: 2 }}>{rec.bandit_rationale}</div>
                        {rec.contrast_insight && <div style={{ fontSize: 9, color: '#f5a623', marginTop: 2 }}>⚡ {rec.contrast_insight}</div>}
                      </div>
                      <button
                        onClick={() => api.generateCommand(`${rec.action_type.replace(/_/g,' ')} to address anomaly on ${data.host}: ${rec.description}`).then(r => { if (r.ok) handleExecute(r.data.command); })}
                        style={{ ...S.btnSecondary, fontSize: 10, padding: '5px 10px', flexShrink: 0 }}
                      >
                        Generate + Run
                      </button>
                    </div>
                  ))}
                </div>
              )}

              {/* AI recommended action */}
              <div style={S.card}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={S.cardLabel}>AI-GENERATED ACTION</div>
                  <span style={{ fontSize: 9, color: 'rgba(255,165,0,0.6)', fontWeight: 600, letterSpacing: 0.5 }}>GROQ</span>
                </div>
                <div style={{ marginTop: 8, background: 'rgba(0,0,0,0.3)', borderRadius: 6, padding: '10px 12px', fontFamily: 'monospace', fontSize: 12, color: '#22cc66', lineHeight: 1.6, wordBreak: 'break-all' }}>
                  {aiCmd || <span style={{ color: 'rgba(255,255,255,0.3)', fontStyle: 'italic' }}>Generating recommendation…</span>}
                </div>
                {aiCmd && (
                  <button
                    onClick={() => handleExecute(aiCmd)}
                    disabled={executing}
                    style={{ ...S.btnDanger, marginTop: 10, alignSelf: 'flex-start' }}
                  >
                    {executing ? 'Executing…' : '⚡ Execute on server'}
                  </button>
                )}
              </div>

              {/* Interactive stdin prompt */}
              {pendingCmd && (
                <div style={{ ...S.card, borderColor: 'rgba(245,166,35,0.3)', background: 'rgba(245,166,35,0.05)' }}>
                  <div style={S.cardLabel}>COMMAND REQUIRES INPUT</div>
                  <div style={{ fontSize: 11, color: '#f5a623', marginTop: 6, marginBottom: 8, fontFamily: 'monospace' }}>
                    {execResult?.prompt || 'Command is waiting for input:'}
                  </div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <input
                      value={stdinValue}
                      onChange={e => setStdinValue(e.target.value)}
                      onKeyDown={e => e.key === 'Enter' && sendStdin()}
                      placeholder="Enter response…"
                      style={{ ...S.input, flex: 1, fontFamily: 'monospace' }}
                      autoFocus
                    />
                    <button onClick={sendStdin} disabled={executing} style={S.btnPrimary}>Send</button>
                  </div>
                </div>
              )}

              {/* Manual command */}
              <div style={S.card}>
                <div style={S.cardLabel}>MANUAL COMMAND</div>
                <textarea
                  value={manualCmd}
                  onChange={e => setManualCmd(e.target.value)}
                  placeholder="Enter your own command to run on the server…"
                  rows={3}
                  style={{ ...S.input, marginTop: 8, resize: 'vertical', fontFamily: 'monospace', fontSize: 12 }}
                />
                <button
                  onClick={() => handleExecute(manualCmd)}
                  disabled={executing || !manualCmd.trim()}
                  style={{ ...S.btnSecondary, marginTop: 8, alignSelf: 'flex-start' }}
                >
                  {executing ? 'Executing…' : 'Run command'}
                </button>
              </div>

              {/* Execution result */}
              {execResult && !execResult.needs_input && (
                <div style={{ ...S.card, borderColor: execResult.exit_code === 0 ? 'rgba(34,204,102,0.3)' : 'rgba(233,69,96,0.3)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                    <span style={{ fontSize: 12, fontWeight: 700, color: execResult.exit_code === 0 ? '#22cc66' : '#e94560' }}>
                      {execResult.exit_code === 0 ? '✓ Success' : '✗ Failed'} · exit {execResult.exit_code}
                    </span>
                  </div>
                  {execResult.stdout && (
                    <pre style={{ fontSize: 11, color: 'rgba(255,255,255,0.6)', maxHeight: 150, overflow: 'auto', margin: 0 }}>
                      {execResult.stdout.slice(0, 2000)}
                    </pre>
                  )}
                  {execResult.stderr && (
                    <pre style={{ fontSize: 11, color: '#f5a623', maxHeight: 80, overflow: 'auto', margin: '6px 0 0' }}>
                      {execResult.stderr.slice(0, 500)}
                    </pre>
                  )}
                </div>
              )}

              {/* Divider */}
              <div style={{ height: 1, background: 'rgba(255,255,255,0.06)' }} />

              {/* Online learning options */}
              <div style={{ ...S.card, background: 'rgba(34,204,102,0.04)', borderColor: 'rgba(34,204,102,0.15)' }}>
                <div style={S.cardLabel}>ONLINE LEARNING</div>
                <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.6)', lineHeight: 1.7, marginTop: 6, marginBottom: 12 }}>
                  If this behavior is legitimate, teach TAARA to recognise it as normal.
                  <br />
                  <strong style={{ color: 'rgba(255,255,255,0.8)' }}>Mark as normal</strong> — adds this state to the memory basis. TAARA will be less likely to flag this exact pattern.
                  <br />
                  <strong style={{ color: '#22cc66' }}>Ignore (never alert)</strong> — adds to basis, raises the quantum confidence threshold, and records a false-positive signal in the contrastive bandit.
                </div>
                <div style={{ display: 'flex', gap: 10 }}>
                  <button onClick={handleMarkNormal} disabled={marking} style={{ ...S.btnSecondary, fontSize: 12 }}>
                    {marking ? 'Updating…' : '✓ Mark as normal'}
                  </button>
                  <button onClick={async () => {
                    setMarking(true);
                    try { await api.ignoreAlert(); onMarkNormal && onMarkNormal(); onClose(); }
                    finally { setMarking(false); }
                  }} disabled={marking} style={{ ...S.btnGreen, fontSize: 12 }}>
                    {marking ? 'Updating…' : '⊘ Ignore — never alert for this'}
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Styles ────────────────────────────────────────────────────────────────────
const S = {
  overlay: {
    position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)', zIndex: 9999,
    display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24,
  },
  modal: {
    background: '#0d0d1a', border: '1px solid rgba(233,69,96,0.3)',
    borderRadius: 12, width: '100%', maxWidth: 680, maxHeight: '88vh',
    display: 'flex', flexDirection: 'column', overflow: 'hidden',
    boxShadow: '0 0 60px rgba(233,69,96,0.2)',
  },
  header: {
    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
    padding: '16px 20px', borderBottom: '1px solid rgba(233,69,96,0.2)',
    flexShrink: 0,
  },
  closeBtn: {
    background: 'transparent', border: 'none', color: 'rgba(255,255,255,0.3)',
    fontSize: 16, cursor: 'pointer', padding: '2px 6px',
  },
  tabBar: {
    display: 'flex', borderBottom: '1px solid rgba(255,255,255,0.06)',
    flexShrink: 0, padding: '0 20px',
  },
  tabBtn: {
    padding: '10px 16px', background: 'transparent', border: 'none',
    borderBottom: '2px solid transparent', color: 'rgba(255,255,255,0.35)',
    fontSize: 12, fontWeight: 500, cursor: 'pointer',
  },
  tabBtnActive: {
    color: '#e94560', borderBottomColor: '#e94560', fontWeight: 700,
  },
  body: {
    flex: 1, overflowY: 'auto', padding: '20px',
  },
  card: {
    background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)',
    borderRadius: 8, padding: '14px 16px',
    display: 'flex', flexDirection: 'column',
  },
  cardLabel: {
    fontSize: 9, fontWeight: 700, letterSpacing: 1.2, textTransform: 'uppercase',
    color: 'rgba(255,255,255,0.25)',
  },
  input: {
    background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.12)',
    borderRadius: 6, color: '#fff', fontSize: 13, padding: '8px 10px', outline: 'none',
    width: '100%',
  },
  btnPrimary: {
    padding: '8px 16px', background: '#e94560', border: 'none', borderRadius: 6,
    color: '#fff', fontSize: 12, fontWeight: 600, cursor: 'pointer',
  },
  btnDanger: {
    padding: '7px 14px', background: 'rgba(233,69,96,0.15)',
    border: '1px solid rgba(233,69,96,0.4)', borderRadius: 6,
    color: '#e94560', fontSize: 12, fontWeight: 600, cursor: 'pointer',
  },
  btnSecondary: {
    padding: '7px 14px', background: 'rgba(255,255,255,0.06)',
    border: '1px solid rgba(255,255,255,0.12)', borderRadius: 6,
    color: 'rgba(255,255,255,0.7)', fontSize: 12, cursor: 'pointer',
  },
  btnGreen: {
    padding: '8px 16px', background: 'rgba(34,204,102,0.12)',
    border: '1px solid rgba(34,204,102,0.3)', borderRadius: 6,
    color: '#22cc66', fontSize: 12, fontWeight: 600, cursor: 'pointer',
  },
};

// ── AnomalyBanner ─────────────────────────────────────────────────────────────
// Alert type determines colour:
//   dual  = quantum + classical both fired → orange (#f5a623) — highest confidence
//   quantum = quantum alone fired → red (#e94560) — strong signal, unconfirmed classically
export default function AnomalyBanner({ alert, onDismiss }) {
  const [visible, setVisible]           = useState(false);
  const [showInvestigate, setShowInvestigate] = useState(false);
  const [ignoring, setIgnoring]         = useState(false);

  useEffect(() => {
    const t = setTimeout(() => setVisible(true), 80);
    return () => clearTimeout(t);
  }, []);

  if (!alert) return null;

  const isDual = !!alert.classical_confirmed;
  // dual = orange (ensemble confirmed, highest confidence); quantum-only = red
  const C = isDual
    ? { main: '#f5a623', glow: 'rgba(245,166,35,0.6)', bg: '#1a0e00', bg2: '#2a1a00', border: '#f5a623', dimText: '#ccbbaa', chipBg: 'rgba(245,166,35,0.1)', chipBorder: 'rgba(245,166,35,0.2)' }
    : { main: '#e94560', glow: 'rgba(233,69,96,0.6)',  bg: '#1a0008', bg2: '#2a000f', border: '#e94560', dimText: '#ccaaaa', chipBg: 'rgba(233,69,96,0.1)',  chipBorder: 'rgba(233,69,96,0.2)'  };

  const fmin   = typeof alert.f_min === 'number' ? alert.f_min.toFixed(4) : '—';
  const qConf  = typeof alert.quantum_confidence === 'number' ? alert.quantum_confidence : null;
  const bucket = qConf != null
    ? (qConf >= 0.75 ? 'CRITICAL' : qConf >= 0.45 ? 'HIGH' : qConf >= 0.1854 ? 'MEDIUM' : 'LOW')
    : (alert.f_min < 0.3 ? 'CRITICAL DIVERGENCE' : alert.f_min < 0.5 ? 'UNSAFE DIRECTION' : 'DRIFTING');
  const displayConf = qConf != null ? qConf.toFixed(4) : fmin;
  const displayLabel = qConf != null ? 'Q-CONF' : 'F_min';
  const displayColor = qConf != null ? qcColorShared(qConf) : (C.main);
  const alertType = isDual ? 'DUAL-CONFIRMED' : 'QUANTUM DETECTED';

  const features = alert.features || {};
  const offenders = Object.entries(features)
    .filter(([k]) => !['anomaly_score','is_anomaly'].includes(k))
    .filter(([, v]) => typeof v === 'number' && v > 0)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 4)
    .map(([k, v]) => ({ name: k.replace(/_/g,' '), value: v }));

  return (
    <>
      {showInvestigate && (
        <InvestigateModal
          onClose={() => setShowInvestigate(false)}
          onMarkNormal={onDismiss}
          onExecute={() => {}}
        />
      )}
      <div style={{
        width: '100%',
        background: `linear-gradient(135deg, ${C.bg} 0%, ${C.bg2} 50%, ${C.bg} 100%)`,
        borderBottom: `2px solid ${C.border}`,
        padding: '12px 24px',
        display: 'flex', alignItems: 'center', gap: 20,
        zIndex: 1000, flexShrink: 0,
        boxShadow: `0 4px 24px ${C.glow.replace('0.6','0.35')}`,
        transform: visible ? 'translateY(0)' : 'translateY(-100%)',
        opacity: visible ? 1 : 0,
        transition: 'transform 0.3s ease-out, opacity 0.3s ease-out',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexShrink: 0 }}>
          {/* Pulse dot */}
          <div style={{
            width: 10, height: 10, borderRadius: '50%', background: C.main,
            boxShadow: `0 0 0 0 ${C.glow}`, animation: 'alertPulse 1.4s ease-in-out infinite',
          }} />
          {/* Quantum confidence / F_min block */}
          <div style={{
            display: 'flex', flexDirection: 'column', alignItems: 'center',
            background: `${displayColor}22`, border: `1px solid ${displayColor}55`,
            borderRadius: 6, padding: '4px 10px',
          }}>
            <span style={{ fontSize: 9, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', color: `${displayColor}bb` }}>{displayLabel}</span>
            <span style={{ fontSize: 20, fontWeight: 700, color: displayColor, lineHeight: 1.1, fontFamily: 'monospace' }}>{displayConf}</span>
          </div>
          {/* Zone badge */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <span style={{
              fontSize: 9, fontWeight: 800, letterSpacing: 1.5, textTransform: 'uppercase', color: C.main,
              background: `${C.main}18`, border: `1px solid ${C.main}33`, borderRadius: 4, padding: '3px 8px',
            }}>{bucket}</span>
            {/* Alert type badge — key differentiator */}
            <span style={{
              fontSize: 9, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase',
              color: isDual ? '#f5a623' : 'rgba(233,69,96,0.7)',
              background: isDual ? 'rgba(245,166,35,0.15)' : 'rgba(233,69,96,0.08)',
              border: `1px solid ${isDual ? 'rgba(245,166,35,0.35)' : 'rgba(233,69,96,0.2)'}`,
              borderRadius: 4, padding: '2px 7px', display: 'flex', alignItems: 'center', gap: 4,
            }}>
              {isDual ? '⊕ ' : '⬢ '}{alertType}
            </span>
          </div>
        </div>

        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 5, minWidth: 0 }}>
          <div style={{ fontSize: 13, color: '#f0f0f0', lineHeight: 1.4 }}>
            <span style={{ fontWeight: 700, color: '#ffffff', fontFamily: 'monospace' }}>{alert.host || 'server'}</span>
            <span style={{ color: C.dimText }}>
              {isDual
                ? ' — quantum + classical ensemble both confirm behavioral anomaly.'
                : ' — quantum behavioral anomaly detected. Classical model not yet trained.'}
            </span>
          </div>
          {offenders.length > 0 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
              <span style={{ fontSize: 10, color: `${C.main}99`, fontWeight: 600, letterSpacing: 0.5, textTransform: 'uppercase' }}>Top signals:</span>
              {offenders.map(f => (
                <span key={f.name} style={{ fontSize: 11, color: '#dddddd', background: C.chipBg, border: `1px solid ${C.chipBorder}`, borderRadius: 4, padding: '1px 7px', fontFamily: 'monospace' }}>
                  {f.name} <span style={{ color: C.main, fontWeight: 700, marginLeft: 3 }}>{f.value > 999 ? `${(f.value/1000).toFixed(1)}k` : f.value.toFixed(1)}</span>
                </span>
              ))}
            </div>
          )}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, flexShrink: 0 }}>
          <button style={{
            padding: '6px 14px', borderRadius: 6, border: `1px solid ${C.main}80`,
            background: `${C.main}22`, color: C.main, fontSize: 12, fontWeight: 600, cursor: 'pointer',
          }} onClick={() => setShowInvestigate(true)}>
            Investigate →
          </button>
          <div style={{ display: 'flex', gap: 6 }}>
            {/* Close — dismiss only, no learning */}
            <button style={{
              flex: 1, padding: '5px 10px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.1)',
              background: 'transparent', color: 'rgba(255,255,255,0.35)', fontSize: 11, cursor: 'pointer',
            }} onClick={onDismiss} title="Dismiss without learning — alert disappears, TAARA still flags this pattern next time">
              Close
            </button>
            {/* Ignore — mark as normal + raise quantum threshold */}
            <button style={{
              flex: 1, padding: '5px 10px', borderRadius: 6,
              border: '1px solid rgba(34,204,102,0.3)',
              background: 'rgba(34,204,102,0.08)', color: '#22cc66', fontSize: 11, cursor: 'pointer',
              opacity: ignoring ? 0.6 : 1,
            }} onClick={async () => {
              setIgnoring(true);
              try { await api.ignoreAlert(); } catch (_) {}
              finally { setIgnoring(false); onDismiss(); }
            }} title="Mark as normal — TAARA learns this pattern is safe and won't flag it again">
              {ignoring ? '…' : 'Ignore'}
            </button>
          </div>
        </div>
      </div>
    </>
  );
}

if (!document.getElementById('alert-anim')) {
  const style = document.createElement('style');
  style.id = 'alert-anim';
  style.textContent = `@keyframes alertPulse { 0% { box-shadow: 0 0 0 0 rgba(233,69,96,0.6); } 70% { box-shadow: 0 0 0 8px rgba(233,69,96,0); } 100% { box-shadow: 0 0 0 0 rgba(233,69,96,0); } }`;
  document.head.appendChild(style);
}
