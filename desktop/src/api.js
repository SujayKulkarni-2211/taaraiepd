/**
 * TAARA API client
 * Wraps window.taara.api (Electron IPC) with a fetch fallback for browser dev.
 * All calls return { data, status, ok }.
 * Throws on network error — callers handle it.
 */

const BASE = 'http://127.0.0.1:8765';

async function call(endpoint, method = 'GET', body = null) {
  if (window.taara) {
    // Electron path — IPC bridge, no CORS
    const result = await window.taara.api(endpoint, method, body);
    return { data: result.data, status: result.status, ok: result.status < 400 };
  }
  // Browser fallback (dev without Electron)
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(BASE + endpoint, opts);
  const data = await res.json().catch(() => ({}));
  return { data, status: res.status, ok: res.ok };
}

export const api = {
  health:          ()         => call('/api/health'),
  connect:         (body)     => call('/api/connect', 'POST', body),
  disconnect:      ()         => call('/api/disconnect', 'POST'),
  analyze:         (body)     => call('/api/analyze', 'POST', body),
  status:          ()         => call('/api/status'),
  train:           (body)     => call('/api/train', 'POST', body),
  trainStatus:     ()         => call('/api/train/status'),
  trainStop:       ()         => call('/api/train/stop', 'POST'),
  alerts:          ()         => call('/api/alerts'),
  dismissAlert:    ()         => call('/api/alerts/dismiss', 'POST'),
  investigateAlert: ()        => call('/api/alerts/investigate'),
  markNormal:      ()         => call('/api/alerts/mark-normal', 'POST'),
  ignoreAlert:     ()         => call('/api/alerts/ignore', 'POST'),
  triggerTestAlert: ()        => call('/api/demo/trigger-test-alert', 'POST'),
  execute:         (body)     => call('/api/execute', 'POST', body),
  executeStdin:    (body)     => call('/api/execute/stdin', 'POST', body),
  actionLog:       (limit)    => call(`/api/action-log?limit=${limit || 100}`),
  rollback:        (id)       => call(`/api/action-log/rollback/${id}`, 'POST'),
  deployTaara:     (body)     => call('/api/deploy-taaraware', 'POST', body),
  deployTaaraware: (body)     => call('/api/deploy-taaraware', 'POST', body),
  taarawareInfo:   ()         => call('/api/taaraware/info'),
  taarawareDeployed: ()       => call('/api/taaraware/deployed'),
  taarawareStatus: ()         => call('/api/taaraware/status'),
  taarawareActions: ()        => call('/api/taaraware/actions'),
  taarawareDashboard: ()      => call('/api/taaraware/dashboard'),
  taarawareRollbackLog: ()    => call('/api/taaraware/rollback-log'),
  taarawareUpdate:     ()    => call('/api/taaraware/update', 'POST'),
  basisStatus:         ()    => call('/api/taara/basis-status'),
  getSettings:     ()         => call('/api/settings'),
  // Quantum legibility
  quantumExplain:  (fmin)     => call(`/api/quantum/explain?f_min=${fmin}`),
  quantumCircuit:  ()         => call('/api/quantum/circuit'),
  pqcInfo:         ()         => call('/api/pqc/info'),
  // Client list
  getClients:      ()         => call('/api/clients'),
  addClient:       (body)     => call('/api/clients', 'POST', body),
  updateClient:    (id, body) => call(`/api/clients/${id}`, 'PATCH', body),
  deleteClient:    (id)       => call(`/api/clients/${id}`, 'DELETE'),
  clientActivity:  (id)       => call(`/api/clients/${id}/activity`),
  codeScan:        (body)     => call('/api/code-scan', 'POST', body),
  generateReport:  (body)     => call('/api/generate-report', 'POST', body || {}),
  settings:        ()         => call('/api/settings'),
  saveSettings:    (body)     => call('/api/settings', 'POST', body),
  generateCommand: (intent)   => call('/api/generate-command', 'POST', { intent }),
  proposedActions: ()         => call('/api/actions/proposed'),
  approveAction:   (i)        => call(`/api/actions/approve/${i}`, 'POST'),
  rejectAction:    (i)        => call(`/api/actions/reject/${i}`, 'POST'),
  rollbackAction:  (i)        => call(`/api/actions/rollback/${i}`, 'POST'),
  auditTrail:      (limit)    => call(`/api/actions/audit-trail?limit=${limit || 50}`),
  banditSummary:   ()         => call('/api/actions/bandit-summary'),
  banditRecommend: (fMin, platformType) => call(`/api/actions/bandit-recommend?f_min=${fMin ?? ''}&platform_type=${platformType ?? ''}`, 'GET'),
  rollbackAction:  (logId, execute) => call(`/api/action-log/rollback/${logId}?execute=${execute ? 'true' : 'false'}`, 'POST'),
  setAutonomy:     (level)    => call(`/api/actions/autonomy-level/${level}`, 'POST'),
  agentStats:      ()         => call('/api/agent/stats'),
  listIdentities:  ()         => call('/api/identities'),
  runAutonomous:   ()         => call('/api/actions/autonomous', 'POST'),
  // Demo mode
  triggerAnomaly:  (fmin)     => call(`/api/demo/trigger-anomaly?f_min=${fmin || 0.23}`, 'POST'),
  demoStart:       (scenario) => call(`/api/demo/start?scenario=${scenario || 'ssh_intrusion'}`, 'POST'),
  demoTick:        ()         => call('/api/demo/tick', 'POST'),
  demoState:       ()         => call('/api/demo/state'),
  demoFullScan:    (scenario) => call(`/api/demo/full-scan?scenario=${scenario || 'ssh_intrusion'}`, 'POST'),
  demoIsActive:    ()         => call('/api/demo/is-active'),
};
