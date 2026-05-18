import React, { useEffect, useState } from 'react';

/**
 * AnomalyBanner — the most important visual in TAARA.
 * Fires when F_min < 0.5. Full-width red banner. Cannot be missed.
 * Shows: server, F_min, which features drove it, auto-executed vs proposed count.
 */
export default function AnomalyBanner({ alert, onDismiss }) {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    // Slight delay so the animation feels intentional, not glitchy
    const t = setTimeout(() => setVisible(true), 80);
    return () => clearTimeout(t);
  }, []);

  if (!alert) return null;

  const fmin = typeof alert.f_min === 'number' ? alert.f_min.toFixed(4) : '—';
  const bucket = alert.bucket || (alert.f_min < 0.3 ? 'critical_divergence' : 'unsafe_direction');
  const bucketLabel = bucket === 'critical_divergence'
    ? 'CRITICAL DIVERGENCE'
    : bucket === 'unsafe_direction'
    ? 'UNSAFE DIRECTION'
    : 'DRIFTING';

  // Find top offending features (values significantly above zero)
  const features = alert.features || {};
  const offenders = Object.entries(features)
    .filter(([k]) => !['anomaly_score', 'is_anomaly'].includes(k))
    .filter(([, v]) => typeof v === 'number' && v > 0)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 4)
    .map(([k, v]) => ({ name: k.replace(/_/g, ' '), value: v }));

  const correlationDetected = alert.correlation_detected || alert.correlation_signal_detected;
  const autoExec = alert.auto_executed_count || 0;
  const proposed = alert.pre_approved_count || 0;

  return (
    <div
      style={{
        ...styles.banner,
        transform: visible ? 'translateY(0)' : 'translateY(-100%)',
        opacity: visible ? 1 : 0,
        transition: 'transform 0.3s ease-out, opacity 0.3s ease-out',
      }}
    >
      {/* Left: severity + F_min ─────────────────────────────────────────── */}
      <div style={styles.left}>
        <div style={styles.pulse} />
        <div style={styles.fminBlock}>
          <span style={styles.fminLabel}>F_min</span>
          <span style={styles.fminValue}>{fmin}</span>
        </div>
        <div style={styles.bucketBadge}>{bucketLabel}</div>
      </div>

      {/* Center: details ─────────────────────────────────────────────────── */}
      <div style={styles.center}>
        <div style={styles.headline}>
          <span style={styles.serverName}>{alert.host || alert.hostname || 'server'}</span>
          <span style={styles.headlineText}>
            — quantum-confirmed behavioral anomaly.
            {correlationDetected && ' Angle encoding detected correlated multi-feature attack pattern.'}
          </span>
        </div>
        {offenders.length > 0 && (
          <div style={styles.features}>
            <span style={styles.featLabel}>Top signals:</span>
            {offenders.map(f => (
              <span key={f.name} style={styles.featChip}>
                {f.name} <span style={styles.featVal}>{f.value > 999 ? `${(f.value/1000).toFixed(1)}k` : f.value.toFixed(1)}</span>
              </span>
            ))}
          </div>
        )}
        {(autoExec > 0 || proposed > 0) && (
          <div style={styles.agentRow}>
            {autoExec > 0 && (
              <span style={styles.agentBadge}>
                ⚡ {autoExec} action{autoExec > 1 ? 's' : ''} auto-executed
              </span>
            )}
            {proposed > 0 && (
              <span style={styles.agentBadgePending}>
                ⏳ {proposed} action{proposed > 1 ? 's' : ''} awaiting approval
              </span>
            )}
          </div>
        )}
      </div>

      {/* Right: actions ──────────────────────────────────────────────────── */}
      <div style={styles.right}>
        <button style={styles.investigateBtn}>Investigate →</button>
        <button style={styles.dismissBtn} onClick={onDismiss}>Dismiss</button>
      </div>
    </div>
  );
}

const styles = {
  banner: {
    width: '100%',
    background: 'linear-gradient(135deg, #1a0008 0%, #2a000f 50%, #1a0008 100%)',
    borderBottom: '2px solid #e94560',
    padding: '12px 24px',
    display: 'flex',
    alignItems: 'center',
    gap: 20,
    zIndex: 1000,
    flexShrink: 0,
    boxShadow: '0 4px 24px rgba(233,69,96,0.35)',
    position: 'relative',
  },
  left: {
    display: 'flex',
    alignItems: 'center',
    gap: 12,
    flexShrink: 0,
  },
  pulse: {
    width: 10, height: 10,
    borderRadius: '50%',
    background: '#e94560',
    boxShadow: '0 0 0 0 rgba(233,69,96,0.6)',
    animation: 'alertPulse 1.4s ease-in-out infinite',
  },
  fminBlock: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    background: 'rgba(233,69,96,0.15)',
    border: '1px solid rgba(233,69,96,0.35)',
    borderRadius: 6,
    padding: '4px 10px',
  },
  fminLabel: {
    fontSize: 9,
    fontWeight: 700,
    letterSpacing: 1,
    textTransform: 'uppercase',
    color: 'rgba(233,69,96,0.7)',
  },
  fminValue: {
    fontSize: 20,
    fontWeight: 700,
    color: '#e94560',
    lineHeight: 1.1,
    fontFamily: 'monospace',
  },
  bucketBadge: {
    fontSize: 9,
    fontWeight: 800,
    letterSpacing: 1.5,
    textTransform: 'uppercase',
    color: '#e94560',
    background: 'rgba(233,69,96,0.12)',
    border: '1px solid rgba(233,69,96,0.25)',
    borderRadius: 4,
    padding: '3px 8px',
  },
  center: {
    flex: 1,
    display: 'flex',
    flexDirection: 'column',
    gap: 5,
    minWidth: 0,
  },
  headline: {
    fontSize: 13,
    color: '#f0d0d5',
    lineHeight: 1.4,
  },
  serverName: {
    fontWeight: 700,
    color: '#ffffff',
    fontFamily: 'monospace',
  },
  headlineText: {
    color: '#ccaaaa',
  },
  features: {
    display: 'flex',
    alignItems: 'center',
    gap: 6,
    flexWrap: 'wrap',
  },
  featLabel: {
    fontSize: 10,
    color: 'rgba(233,69,96,0.6)',
    fontWeight: 600,
    letterSpacing: 0.5,
    textTransform: 'uppercase',
  },
  featChip: {
    fontSize: 11,
    color: '#ddbbbb',
    background: 'rgba(233,69,96,0.1)',
    border: '1px solid rgba(233,69,96,0.2)',
    borderRadius: 4,
    padding: '1px 7px',
    fontFamily: 'monospace',
  },
  featVal: {
    color: '#e94560',
    fontWeight: 700,
    marginLeft: 3,
  },
  agentRow: {
    display: 'flex',
    gap: 8,
    flexWrap: 'wrap',
  },
  agentBadge: {
    fontSize: 10,
    color: '#ffaaaa',
    background: 'rgba(233,69,96,0.12)',
    border: '1px solid rgba(233,69,96,0.25)',
    borderRadius: 4,
    padding: '2px 8px',
  },
  agentBadgePending: {
    fontSize: 10,
    color: '#ffdd99',
    background: 'rgba(245,166,35,0.1)',
    border: '1px solid rgba(245,166,35,0.2)',
    borderRadius: 4,
    padding: '2px 8px',
  },
  right: {
    display: 'flex',
    flexDirection: 'column',
    gap: 6,
    flexShrink: 0,
  },
  investigateBtn: {
    padding: '6px 14px',
    borderRadius: 6,
    border: '1px solid rgba(233,69,96,0.5)',
    background: 'rgba(233,69,96,0.15)',
    color: '#e94560',
    fontSize: 12,
    fontWeight: 600,
    cursor: 'pointer',
  },
  dismissBtn: {
    padding: '5px 14px',
    borderRadius: 6,
    border: '1px solid rgba(255,255,255,0.1)',
    background: 'transparent',
    color: 'rgba(255,255,255,0.3)',
    fontSize: 11,
    cursor: 'pointer',
  },
};

// Inject pulse keyframe once
if (!document.getElementById('alert-anim')) {
  const style = document.createElement('style');
  style.id = 'alert-anim';
  style.textContent = `
    @keyframes alertPulse {
      0%   { box-shadow: 0 0 0 0 rgba(233,69,96,0.6); }
      70%  { box-shadow: 0 0 0 8px rgba(233,69,96,0); }
      100% { box-shadow: 0 0 0 0 rgba(233,69,96,0); }
    }`;
  document.head.appendChild(style);
}
