import React, { useState, useEffect, useRef } from 'react';
import { api } from '../api';

function healthColor(score) {
  if (score == null) return 'var(--text-faint)';
  if (score < 40) return 'var(--red)';
  if (score < 65) return '#f5a623';
  if (score < 80) return 'var(--blue)';
  return 'var(--green)';
}

function healthLabel(score) {
  if (score == null) return '—';
  if (score < 40) return 'Critical';
  if (score < 65) return 'At Risk';
  if (score < 80) return 'Fair';
  return 'Healthy';
}

function healthRing(score, size = 52) {
  const r = (size - 8) / 2;
  const circ = 2 * Math.PI * r;
  const filled = score != null ? (score / 100) * circ : 0;
  const color = healthColor(score);
  return (
    <svg width={size} height={size} style={{ flexShrink: 0 }}>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="var(--bg-raised)" strokeWidth={6} />
      <circle
        cx={size/2} cy={size/2} r={r} fill="none"
        stroke={color} strokeWidth={6}
        strokeDasharray={`${filled} ${circ}`}
        strokeLinecap="round"
        transform={`rotate(-90 ${size/2} ${size/2})`}
        style={{ transition: 'stroke-dasharray 0.6s ease' }}
      />
      <text x={size/2} y={size/2 + 5} textAnchor="middle"
        style={{ fontSize: 12, fontWeight: 700, fill: color, fontFamily: 'monospace' }}>
        {score != null ? score : '—'}
      </text>
    </svg>
  );
}

export default function ClientDashboard({ onClientSelected, onAddNew, activeClientId, onDemoStart }) {
  const [clients, setClients] = useState([]);
  const [loading, setLoading] = useState(true);
  const [addOpen, setAddOpen] = useState(false);
  const [deleting, setDeleting] = useState(null);
  const pollRef = useRef(null);

  async function load(silent = false) {
    if (!silent) setLoading(true);
    try {
      const res = await api.getClients();
      if (res.ok) {
        setClients(res.data.clients || []);
      }
    } catch { /* network error — keep current state */ }
    finally { if (!silent) setLoading(false); }
  }

  useEffect(() => {
    load();
    pollRef.current = setInterval(() => load(true), 30000);
    return () => clearInterval(pollRef.current);
  }, []);

  async function handleDelete(e, id) {
    e.stopPropagation();
    setDeleting(id);
    try { await api.deleteClient(id); } catch (_) {}
    setClients(prev => prev.filter(c => c.id !== id));
    setDeleting(null);
  }

  const totalAlerts = clients.reduce((s, c) => s + (c.active_alerts || 0), 0);
  const deployed   = clients.filter(c => c.taaraware_deployed).length;
  const critCount  = clients.filter(c => c.last_health_score != null && c.last_health_score < 40).length;

  return (
    <div className="page">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
        <div>
          <div style={{ fontSize: 20, fontWeight: 700 }}>Client Portfolio</div>
          <div style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 3 }}>
            {clients.length} client{clients.length !== 1 ? 's' : ''} monitored
            {totalAlerts > 0 && (
              <span style={{ marginLeft: 10, color: 'var(--red)', fontWeight: 600 }}>
                ● {totalAlerts} active alert{totalAlerts > 1 ? 's' : ''}
              </span>
            )}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          {onDemoStart && (
            <button
              className="btn"
              onClick={onDemoStart}
              style={{
                borderColor: 'rgba(155,125,255,0.35)',
                color: '#9b7dff',
                background: 'rgba(155,125,255,0.08)',
                fontSize: 12,
              }}
              title="Run TAARA demo without an SSH connection"
            >
              ▶ Demo Mode
            </button>
          )}
          <button className="btn btn-primary" onClick={() => setAddOpen(true)}>
            + Add Client
          </button>
        </div>
      </div>

      {clients.length > 0 && (
        <div className="grid-4" style={{ marginBottom: 20 }}>
          <SummaryTile label="Total Clients" value={clients.length} />
          <SummaryTile label="Active Alerts" value={totalAlerts}
            color={totalAlerts > 0 ? 'var(--red)' : 'var(--green)'} />
          <SummaryTile label="TaaraWare Live" value={deployed}
            color={deployed > 0 ? 'var(--green)' : 'var(--text-faint)'} />
          <SummaryTile label="Critical Risk" value={critCount}
            color={critCount > 0 ? 'var(--red)' : 'var(--green)'} />
        </div>
      )}

      {loading ? (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px,1fr))', gap: 14 }}>
          {[1,2,3].map(i => <div key={i} className="skeleton" style={{ height: 140, borderRadius: 10 }} />)}
        </div>
      ) : clients.length === 0 ? (
        <EmptyState onAdd={() => setAddOpen(true)} onDemo={onDemoStart} />
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px,1fr))', gap: 14 }}>
          {clients.map(client => (
            <ClientCard
              key={client.id}
              client={client}
              active={activeClientId === client.id}
              deleting={deleting === client.id}
              onClick={() => onClientSelected(client)}
              onDelete={(e) => handleDelete(e, client.id)}
            />
          ))}
        </div>
      )}

      {clients.length > 0 && (
        <div style={{ marginTop: 28 }}>
          <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase',
            color: 'var(--text-faint)', marginBottom: 12 }}>
            Recent Agent Activity
          </div>
          <ActivityFeed />
        </div>
      )}

      {addOpen && (
        <AddClientModal
          onClose={() => setAddOpen(false)}
          onSaved={(client) => {
            setClients(prev => [...prev, client]);
            setAddOpen(false);
          }}
        />
      )}
    </div>
  );
}

function ClientCard({ client, active, onClick, onDelete, deleting }) {
  const score = client.last_health_score;
  const prev  = client.prev_health_score;
  const delta = (score != null && prev != null) ? score - prev : null;
  const color = healthColor(score);

  const lastScan = client.last_scan_time
    ? new Date(client.last_scan_time).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: '2-digit' })
    : 'Never scanned';

  return (
    <div
      onClick={onClick}
      style={{
        background: 'var(--bg-surface)',
        border: `1px solid ${active ? 'var(--accent)' : client.active_alerts > 0 ? 'rgba(233,69,96,0.3)' : 'var(--border)'}`,
        borderRadius: 10,
        padding: '16px 18px',
        cursor: 'pointer',
        transition: 'border-color 0.15s, background 0.15s',
        position: 'relative',
      }}
      onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-raised)'}
      onMouseLeave={e => e.currentTarget.style.background = 'var(--bg-surface)'}
    >
      {client.active_alerts > 0 && (
        <div style={{
          position: 'absolute', top: 12, right: 12,
          fontSize: 9, fontWeight: 800, padding: '2px 6px', borderRadius: 3,
          background: 'rgba(233,69,96,0.15)', border: '1px solid rgba(233,69,96,0.3)',
          color: 'var(--red)', letterSpacing: 0.5,
        }}>
          {client.active_alerts} ALERT{client.active_alerts > 1 ? 'S' : ''}
        </div>
      )}

      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        {healthRing(score)}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 2,
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {client.name}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-faint)', fontFamily: 'monospace', marginBottom: 4 }}>
            {client.hostname}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{
              fontSize: 10, fontWeight: 700, color: color,
              background: `${color}18`, border: `1px solid ${color}30`,
              borderRadius: 3, padding: '1px 6px',
            }}>
              {healthLabel(score)}
            </span>
            {delta != null && (
              <span style={{ fontSize: 10, fontWeight: 600, color: delta >= 0 ? 'var(--green)' : 'var(--red)' }}>
                {delta >= 0 ? '↑' : '↓'}{Math.abs(delta)} from last
              </span>
            )}
            <span style={{
              fontSize: 9, fontWeight: 700, letterSpacing: 0.5,
              color: client.taaraware_deployed ? 'var(--blue)' : 'var(--text-faint)',
              border: `1px solid ${client.taaraware_deployed ? 'rgba(74,158,255,0.25)' : 'var(--border)'}`,
              borderRadius: 3, padding: '1px 5px',
            }}>
              {client.taaraware_deployed ? '⬢ LIVE' : '⬢ NOT DEPLOYED'}
            </span>
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 12 }}>
        <span style={{ fontSize: 10, color: 'var(--text-faint)' }}>Last scan: {lastScan}</span>
        <button
          onClick={onDelete}
          disabled={deleting}
          style={{
            background: 'transparent', border: 'none',
            color: 'var(--text-faint)', fontSize: 10, cursor: 'pointer',
            padding: '2px 6px', borderRadius: 3,
          }}
          onMouseEnter={e => e.currentTarget.style.color = 'var(--red)'}
          onMouseLeave={e => e.currentTarget.style.color = 'var(--text-faint)'}
          title="Remove client"
        >
          {deleting ? '…' : '✕ Remove'}
        </button>
      </div>

      {client.notes && (
        <div style={{ marginTop: 8, fontSize: 10, color: 'var(--text-faint)',
          borderTop: '1px solid var(--border)', paddingTop: 8, lineHeight: 1.5 }}>
          {client.notes}
        </div>
      )}
    </div>
  );
}

function SummaryTile({ label, value, color }) {
  return (
    <div className="card" style={{ padding: '12px 16px' }}>
      <div className="metric-label">{label}</div>
      <div style={{ fontSize: 26, fontWeight: 700, marginTop: 4, color: color || 'var(--text)' }}>{value}</div>
    </div>
  );
}

function ActivityFeed() {
  const [entries, setEntries] = useState([]);

  useEffect(() => {
    api.actionLog(15).then(res => {
      if (res.ok) setEntries(res.data.logs || res.data.log || res.data || []);
    }).catch(() => {});
  }, []);

  if (entries.length === 0) {
    return (
      <div style={{ padding: '16px 20px', background: 'var(--bg-surface)', borderRadius: 10,
        border: '1px solid var(--border)', fontSize: 12, color: 'var(--text-faint)' }}>
        No agent activity yet. Activity appears here after TaaraWare runs its first collection cycle.
      </div>
    );
  }

  return (
    <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 10 }}>
      {entries.slice(0, 10).map((e, i) => {
        const ts = e.timestamp
          ? new Date(e.timestamp * 1000).toLocaleString('en-IN', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })
          : e.datetime
          ? new Date(e.datetime).toLocaleString('en-IN', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })
          : '—';
        const isAlert = (e.severity === 'critical' || e.severity === 'high' || e.category === 'anomaly');
        return (
          <div key={e.id || i} style={{
            display: 'flex', alignItems: 'flex-start', gap: 12,
            padding: '10px 16px',
            borderBottom: i < Math.min(entries.length, 10) - 1 ? '1px solid var(--border)' : 'none',
          }}>
            <div style={{
              width: 6, height: 6, borderRadius: '50%', marginTop: 5, flexShrink: 0,
              background: isAlert ? 'var(--red)' : e.severity === 'info' ? 'var(--text-faint)' : 'var(--green)',
            }} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 12, color: isAlert ? 'var(--text)' : 'var(--text-dim)', fontWeight: isAlert ? 600 : 400 }}>
                {e.details || e.action}
              </div>
            </div>
            <span style={{ fontSize: 10, color: 'var(--text-faint)', flexShrink: 0, whiteSpace: 'nowrap' }}>
              {ts}
            </span>
          </div>
        );
      })}
    </div>
  );
}

function EmptyState({ onAdd, onDemo }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center',
      justifyContent: 'center', padding: '80px 40px', textAlign: 'center' }}>
      <div style={{ fontSize: 40, color: 'var(--text-faint)', marginBottom: 16 }}>⬡</div>
      <div style={{ fontSize: 16, fontWeight: 600, marginBottom: 8 }}>No clients yet</div>
      <div style={{ fontSize: 13, color: 'var(--text-dim)', lineHeight: 1.7, maxWidth: 400, marginBottom: 20 }}>
        Add your first client to begin monitoring. TAARA connects via SSH over ZeroTier
        and immediately begins quantum behavioral analysis.
      </div>
      <div style={{ display: 'flex', gap: 10 }}>
        <button className="btn btn-primary" onClick={onAdd}>+ Add Client</button>
        {onDemo && (
          <button className="btn" onClick={onDemo}
            style={{ borderColor: 'rgba(155,125,255,0.35)', color: '#9b7dff' }}>
            ▶ Try Demo Mode
          </button>
        )}
      </div>
    </div>
  );
}

function AddClientModal({ onClose, onSaved }) {
  const [form, setForm] = useState({ name: '', hostname: '', port: '22', username: '', platform_type: 'ssh' });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  function set(k, v) { setForm(f => ({ ...f, [k]: v })); }

  async function handleSave(e) {
    e.preventDefault();
    setSaving(true); setError('');
    try {
      const res = await api.addClient({
        name: form.name.trim(),
        hostname: form.hostname.trim(),
        port: parseInt(form.port) || 22,
        username: form.username.trim(),
        platform_type: form.platform_type,
      });
      if (res.ok) {
        onSaved(res.data.client);
      } else {
        setError(res.data?.detail || 'Failed to save');
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', zIndex: 2000,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={e => e.target === e.currentTarget && onClose()}>
      <div style={{
        background: 'var(--bg-surface)', border: '1px solid var(--border)',
        borderRadius: 12, padding: 28, width: 420, maxWidth: '90vw',
      }}>
        <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 20 }}>Add Client</div>
        <form onSubmit={handleSave}>
          <div style={{ marginBottom: 14 }}>
            <label className="label">Client / Company Name</label>
            <input className="input" value={form.name}
              onChange={e => set('name', e.target.value)}
              placeholder="Company name" required />
          </div>
          <div style={{ display: 'flex', gap: 10, marginBottom: 14 }}>
            <div style={{ flex: 2 }}>
              <label className="label">Host / IP (ZeroTier)</label>
              <input className="input" value={form.hostname}
                onChange={e => set('hostname', e.target.value)}
                placeholder="10.x.x.x or hostname" required />
            </div>
            <div style={{ flex: 1 }}>
              <label className="label">SSH Port</label>
              <input className="input" value={form.port}
                onChange={e => set('port', e.target.value)}
                placeholder="22" type="number" />
            </div>
          </div>
          <div style={{ marginBottom: 14 }}>
            <label className="label">SSH Username</label>
            <input className="input" value={form.username}
              onChange={e => set('username', e.target.value)}
              placeholder="root" />
          </div>
          <div style={{ marginBottom: 14 }}>
            <label className="label">Platform</label>
            <div style={{ display: 'flex', gap: 6, marginTop: 6 }}>
              {['ssh', 'aws', 'gcp', 'azure'].map(p => (
                <button key={p} type="button"
                  onClick={() => set('platform_type', p)}
                  style={{
                    flex: 1, padding: '6px 0', borderRadius: 5, fontSize: 11, fontWeight: 600,
                    background: form.platform_type === p ? 'var(--accent)' : 'transparent',
                    color: form.platform_type === p ? 'white' : 'var(--text-dim)',
                    border: `1px solid ${form.platform_type === p ? 'var(--accent)' : 'var(--border)'}`,
                    cursor: 'pointer',
                  }}>{p.toUpperCase()}</button>
              ))}
            </div>
          </div>
          {error && <div style={{ marginBottom: 12, fontSize: 12, color: 'var(--red)' }}>{error}</div>}
          <div style={{ display: 'flex', gap: 10 }}>
            <button type="submit" className="btn btn-primary" disabled={saving} style={{ flex: 1, justifyContent: 'center' }}>
              {saving ? <><span className="spinner" /> Saving…</> : 'Save Client'}
            </button>
            <button type="button" className="btn" onClick={onClose} style={{ flex: 1, justifyContent: 'center' }}>
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
