import React, { useState } from 'react';

export default function Sidebar({
  connected, hostname, platformType, activeView,
  onNav, taarawareDeployed, sidebarStats, demoMode,
  onDisconnect, firmName, onQuantumPanel,
  onContextMenu, onTriggerAnomaly, onDismissAlert, hasAlert,
}) {
  const [taarawareExpanded, setTaarawareExpanded] = useState(false);

  // Auto-expand TaaraWare sub-nav when a taaraware-* view is active
  const isTaarawareActive = activeView && activeView.startsWith('taaraware');

  const NAV_ITEMS = [
    { id: 'clients',   label: 'Clients',       icon: '⬡', always: true },
    { id: 'connect',   label: 'Connect',        icon: '⊕', always: true },
    { id: 'analysis',  label: 'TAARA Analysis', icon: '◈', requireConnect: true },
    {
      id: 'taaraware', label: 'TaaraWare',      icon: '⬢', requireConnect: true,
      sub: [
        { id: 'taaraware-status',    icon: '◎', label: 'Status' },
        { id: 'taaraware-train',     icon: '⟳', label: 'Train' },
        { id: 'taaraware-agent',     icon: '⚡', label: 'Agent & Actions' },
        { id: 'taaraware-security',  icon: '⛨', label: 'Security Tools' },
        { id: 'taaraware-dashboard', icon: '▦', label: 'Dashboard' },
        { id: 'taaraware-rollback',  icon: '↺', label: 'Rollback Log' },
        { id: 'taaraware-details',   icon: '⬥', label: 'Deployment Details' },
      ],
    },
    { id: 'codescan',  label: 'Code Scan',      icon: '⟨/⟩', always: true },
    { id: 'settings',  label: 'Settings',        icon: '⚙',  always: true },
  ];

  const fmin = sidebarStats?.f_min;
  const fminColor = fmin == null ? 'var(--text-faint)'
    : fmin < 0.3  ? 'var(--red)'
    : fmin < 0.5  ? 'var(--amber)'
    : fmin < 0.7  ? 'var(--blue)'
    : 'var(--green)';

  function isVisible(item) {
    if (item.always) return true;
    if (item.requireConnect && !connected && !demoMode) return false;
    return true;
  }

  return (
    <aside className="sidebar">
      {/* Header */}
      <div className="sidebar-header">
        <span className="sidebar-logo">TAARA</span>
        {firmName && <span className="sidebar-firm">{firmName}</span>}
      </div>

      {/* Connection status */}
      <div className="sidebar-conn">
        <span className={`conn-dot${connected ? ' connected' : ''}`} />
        {connected ? (
          <>
            <span className="conn-host">{hostname}</span>
            {demoMode && <span className="conn-demo">DEMO</span>}
            {platformType && platformType !== 'demo' && (
              <span className="conn-type">{platformType.toUpperCase()}</span>
            )}
          </>
        ) : (
          <span className="conn-host" style={{ color: 'var(--text-faint)' }}>Not connected</span>
        )}
      </div>

      <div className="sidebar-divider" />

      {/* Navigation */}
      <nav className="sidebar-nav">
        {NAV_ITEMS.filter(isVisible).map(item => {
          const active = activeView === item.id || (item.id === 'taaraware' && isTaarawareActive);
          const hasExpand = item.sub;
          const expanded = item.id === 'taaraware' && (taarawareExpanded || isTaarawareActive);

          return (
            <div key={item.id}>
              <button
                className={`nav-item${active ? ' nav-active' : ''}`}
                onClick={() => {
                  if (hasExpand) {
                    setTaarawareExpanded(e => !e);
                    onNav(item.id);
                  } else {
                    onNav(item.id);
                  }
                }}
                onContextMenu={(e) => {
                  e.preventDefault();
                  if (onContextMenu) onContextMenu(item.id, item.label);
                }}
                title={`${item.label}${onContextMenu ? ' (right-click to open in new window)' : ''}`}
              >
                <span className="nav-icon">{item.icon}</span>
                <span className="nav-label">{item.label}</span>
                {demoMode && item.id === 'analysis' && (
                  <span className="nav-badge demo">DEMO</span>
                )}
                {hasExpand && (
                  <span className="nav-expand">{expanded ? '▾' : '▸'}</span>
                )}
              </button>
              {hasExpand && expanded && (
                <div className="nav-sub">
                  {item.sub.map(sub => (
                    <button
                      key={sub.id}
                      className={`nav-sub-item${activeView === sub.id ? ' nav-active' : ''}`}
                      onClick={() => onNav(sub.id)}
                      onContextMenu={(e) => {
                        e.preventDefault();
                        if (onContextMenu) onContextMenu(sub.id, sub.label);
                      }}
                      title={sub.label}
                    >
                      <span>{sub.icon}</span>
                      <span>{sub.label}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </nav>

      <div style={{ flex: 1 }} />

      {/* Live stats footer */}
      {connected && (
        <div className="sidebar-stats">
          {sidebarStats ? (
            <>
              <div className="stat-row">
                <span className="stat-label">CPU</span>
                <span className="stat-bar-wrap">
                  <span className="stat-bar" style={{
                    width: `${Math.min(sidebarStats.cpu || 0, 100)}%`,
                    background: (sidebarStats.cpu || 0) > 80 ? 'var(--red)'
                      : (sidebarStats.cpu || 0) > 60 ? 'var(--amber)' : 'var(--green)',
                  }} />
                </span>
                <span className="stat-val">{(sidebarStats.cpu || 0).toFixed(0)}%</span>
              </div>
              <div className="stat-row">
                <span className="stat-label">MEM</span>
                <span className="stat-bar-wrap">
                  <span className="stat-bar" style={{
                    width: `${Math.min(sidebarStats.memory || 0, 100)}%`,
                    background: (sidebarStats.memory || 0) > 85 ? 'var(--red)'
                      : (sidebarStats.memory || 0) > 70 ? 'var(--amber)' : 'var(--blue)',
                  }} />
                </span>
                <span className="stat-val">{(sidebarStats.memory || 0).toFixed(0)}%</span>
              </div>
              {fmin != null && (
                <div className="stat-row">
                  <span className="stat-label">F_min</span>
                  <span className="stat-val" style={{ color: fminColor, fontFamily: 'monospace' }}>
                    {fmin.toFixed(4)}
                  </span>
                </div>
              )}
              <div className="stat-ts">
                {new Date(sidebarStats.timestamp).toLocaleTimeString()}
              </div>
            </>
          ) : (
            <div className="stat-skeleton">
              <div className="skeleton" style={{ height: 10, width: '80%' }} />
              <div className="skeleton" style={{ height: 10, width: '60%' }} />
            </div>
          )}
        </div>
      )}

      {/* Alert toggle — only when connected and alert active */}
      {connected && hasAlert && (
        <button
          className="sidebar-disconnect"
          onClick={onDismissAlert}
          style={{ borderColor: 'rgba(233,69,96,0.4)', color: 'var(--red)', background: 'rgba(233,69,96,0.08)' }}
        >
          ⚠ Dismiss Alert
        </button>
      )}

      {/* Demo: trigger anomaly */}
      {demoMode && onTriggerAnomaly && (
        <button
          className="sidebar-disconnect"
          onClick={onTriggerAnomaly}
          style={{ borderColor: 'rgba(155,125,255,0.3)', color: '#9b7dff', fontSize: 11 }}
        >
          ⚡ Trigger Anomaly
        </button>
      )}

      {/* Quantum explainer */}
      {onQuantumPanel && (
        <button
          className="sidebar-disconnect"
          onClick={onQuantumPanel}
          style={{ borderColor: 'rgba(74,158,255,0.2)', color: 'var(--blue)' }}
        >
          ◈ How TAARA works
        </button>
      )}

      {/* Disconnect */}
      {connected && (
        <button className="sidebar-disconnect" onClick={onDisconnect}>
          ⏻ Disconnect
        </button>
      )}
    </aside>
  );
}
