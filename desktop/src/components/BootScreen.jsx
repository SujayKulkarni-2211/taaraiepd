import React, { useState, useEffect } from 'react';

const MESSAGES = [
  'Starting reasoning engine...',
  'Initialising quantum validator...',
  'Loading knowledge base...',
  'Connecting to TAARA core...',
];

export default function BootScreen({ error }) {
  const [msgIdx, setMsgIdx] = useState(0);
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    const msgTimer = setInterval(() => setMsgIdx(i => (i + 1) % MESSAGES.length), 1800);
    const elapsedTimer = setInterval(() => setElapsed(s => s + 1), 1000);
    return () => { clearInterval(msgTimer); clearInterval(elapsedTimer); };
  }, []);

  return (
    <div style={s.root}>
      <div style={s.inner}>
        <div style={s.logo}>TAARA</div>
        <div style={s.sub}>Quantum Infrastructure Intelligence</div>
        {error ? (
          <div style={s.error}>{error}</div>
        ) : (
          <>
            <div style={s.barWrap}><div style={s.bar} /></div>
            <div style={s.msg}>{MESSAGES[msgIdx]}</div>
            {elapsed > 5 && (
              <div style={s.elapsed}>{elapsed}s — loading models…</div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

const s = {
  root: {
    height: '100vh', background: 'var(--bg-app)',
    display: 'flex', alignItems: 'center', justifyContent: 'center',
  },
  inner: {
    display: 'flex', flexDirection: 'column',
    alignItems: 'center', gap: 16,
  },
  logo: {
    fontSize: 52, fontWeight: 700,
    color: 'var(--accent)', letterSpacing: 4,
  },
  sub: {
    fontSize: 12, color: 'var(--text-faint)',
    letterSpacing: 2, textTransform: 'uppercase',
  },
  barWrap: {
    width: 200, height: 2,
    background: 'var(--bg-raised)',
    borderRadius: 2, overflow: 'hidden',
    position: 'relative', marginTop: 8,
  },
  bar: {
    position: 'absolute', left: '-60%',
    width: '60%', height: '100%',
    background: 'linear-gradient(90deg, transparent, var(--accent), transparent)',
    animation: 'bootPulse 1.4s ease-in-out infinite',
  },
  msg: { fontSize: 12, color: 'var(--text-faint)' },
  elapsed: { fontSize: 11, color: 'var(--text-faint)', opacity: 0.6 },
  error: {
    fontSize: 12, color: 'var(--red)',
    background: 'rgba(233,69,96,0.1)',
    border: '1px solid rgba(233,69,96,0.25)',
    borderRadius: 6, padding: '10px 16px',
    maxWidth: 400, textAlign: 'center',
  },
};

// Inject the keyframe once
if (!document.getElementById('boot-anim')) {
  const style = document.createElement('style');
  style.id = 'boot-anim';
  style.textContent = `@keyframes bootPulse { 0% { left: -60%; } 100% { left: 110%; } }`;
  document.head.appendChild(style);
}
