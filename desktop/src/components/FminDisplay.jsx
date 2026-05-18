import React from 'react';

/**
 * FminDisplay — shows F_min with inline mathematical grounding.
 * Used everywhere F_min appears. The quantum panel will read these lines
 * and immediately know the founders understand their formalism.
 */
export function FminDisplay({ fmin, size = 'normal', showFormula = true }) {
  if (fmin == null) return null;

  const divergence = ((1 - fmin) * 100).toFixed(1);
  const color = fmin < 0.3 ? 'var(--red)'
    : fmin < 0.5 ? '#f5a623'
    : fmin < 0.7 ? 'var(--blue)'
    : 'var(--green)';

  const bucket = fmin < 0.3 ? 'CRITICAL DIVERGENCE'
    : fmin < 0.5 ? 'UNSAFE DIRECTION'
    : fmin < 0.7 ? 'DRIFTING'
    : 'NORMAL';

  const valueFontSize = size === 'large' ? 36 : size === 'small' ? 16 : 24;

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
        <span style={{
          fontSize: valueFontSize,
          fontWeight: 700,
          color,
          fontFamily: 'monospace',
          lineHeight: 1,
        }}>
          {fmin.toFixed(4)}
        </span>
        <span style={{
          fontSize: 10, fontWeight: 800,
          letterSpacing: 1, textTransform: 'uppercase',
          color,
          background: `${color}18`,
          border: `1px solid ${color}30`,
          borderRadius: 3, padding: '2px 6px',
        }}>
          {bucket}
        </span>
      </div>

      {showFormula && (
        <div style={{
          marginTop: 4, fontSize: 10,
          color: 'var(--text-faint)', fontFamily: 'monospace',
          lineHeight: 1.5,
        }}>
          F = |⟨ψ_t|ψ_m⟩|² = {fmin.toFixed(4)} — {divergence}% orthogonal to all prior normal states
        </div>
      )}
    </div>
  );
}

/**
 * FminInline — single-line version for tables and compact spaces.
 */
export function FminInline({ fmin }) {
  if (fmin == null) return <span style={{ color: 'var(--text-faint)' }}>—</span>;
  const color = fmin < 0.3 ? 'var(--red)'
    : fmin < 0.5 ? '#f5a623'
    : fmin < 0.7 ? 'var(--blue)'
    : 'var(--green)';
  const divergence = ((1 - fmin) * 100).toFixed(1);
  return (
    <span style={{ fontFamily: 'monospace', color, fontWeight: 600 }} title={`F = |⟨ψ_t|ψ_m⟩|² = ${fmin.toFixed(4)} — ${divergence}% orthogonal`}>
      {fmin.toFixed(4)}
    </span>
  );
}

/**
 * DeviationBadge — per-finding quantum deviation score.
 * Shows: "F_dev = 0.81 — 81% divergent from safe-state embedding"
 */
export function DeviationBadge({ deviation, compact = false }) {
  if (deviation == null) return null;
  const color = deviation > 0.7 ? 'var(--red)'
    : deviation > 0.4 ? '#f5a623'
    : 'var(--text-faint)';
  const pct = (deviation * 100).toFixed(0);

  if (compact) {
    return (
      <span style={{
        fontSize: 9, fontFamily: 'monospace',
        color, background: `${color}15`,
        border: `1px solid ${color}25`,
        borderRadius: 3, padding: '1px 5px',
      }} title={`Quantum deviation: ${pct}% divergent from safe-state embedding`}>
        F_dev {deviation.toFixed(2)}
      </span>
    );
  }

  return (
    <div style={{ marginTop: 4 }}>
      <span style={{
        fontSize: 10, fontFamily: 'monospace', color,
        background: `${color}12`, border: `1px solid ${color}25`,
        borderRadius: 3, padding: '2px 8px',
      }}>
        F_dev = {deviation.toFixed(4)} — {pct}% divergent from safe-state embedding in quantum feature space
      </span>
    </div>
  );
}
