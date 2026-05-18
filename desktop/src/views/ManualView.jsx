import React, { useState } from 'react';

const TABS = [
  { id: 'what',       label: 'What is TAARA',    icon: '⬡' },
  { id: 'connect',    label: 'First Connection',  icon: '⊕' },
  { id: 'fmin',       label: 'F_min Explained',   icon: '◈' },
  { id: 'findings',   label: 'Reading Findings',  icon: '⟨/⟩' },
  { id: 'autonomy',   label: 'Autonomy Levels',   icon: '⬢' },
  { id: 'reports',    label: 'Reports',           icon: '📄' },
  { id: 'glossary',   label: 'Glossary',          icon: '📖' },
  { id: 'benchmark',  label: 'Benchmarks',        icon: '⚗' },
];

export default function ManualView() {
  const [activeTab, setActiveTab] = useState('what');

  return (
    <div className="page" style={{ maxWidth: 760, padding: '0 0 40px' }}>
      <div style={{ marginBottom: 20, padding: '0 24px' }}>
        <div style={{ fontSize: 20, fontWeight: 700 }}>TAARA User Manual</div>
        <div style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 3 }}>
          Complete guide — F_min explained, autonomy levels, reports, benchmarks.
        </div>
      </div>

      {/* Tab strip */}
      <div style={{
        display: 'flex',
        gap: 2,
        borderBottom: '1px solid var(--border)',
        background: 'var(--bg-surface)',
        padding: '0 16px',
        flexShrink: 0,
        overflowX: 'auto',
      }}>
        {TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setActiveTab(t.id)}
            style={{
              padding: '9px 13px',
              background: 'transparent',
              border: 'none',
              borderBottom: activeTab === t.id ? '2px solid var(--accent)' : '2px solid transparent',
              color: activeTab === t.id ? 'var(--accent)' : 'var(--text-dim)',
              fontSize: 11,
              fontWeight: activeTab === t.id ? 700 : 400,
              cursor: 'pointer',
              whiteSpace: 'nowrap',
              display: 'flex',
              alignItems: 'center',
              gap: 5,
              transition: 'color 0.12s',
              marginBottom: -1,
              flexShrink: 0,
            }}
          >
            <span>{t.icon}</span>
            {t.label}
          </button>
        ))}
      </div>

      {/* Content */}
      <div style={{ padding: '24px 24px 0' }}>
        {activeTab === 'what'      && <TabWhat />}
        {activeTab === 'connect'   && <TabConnect />}
        {activeTab === 'fmin'      && <TabFmin />}
        {activeTab === 'findings'  && <TabFindings />}
        {activeTab === 'autonomy'  && <TabAutonomy />}
        {activeTab === 'reports'   && <TabReports />}
        {activeTab === 'glossary'  && <TabGlossary />}
        {activeTab === 'benchmark' && <TabBenchmark />}
      </div>
    </div>
  );
}

// ── Shared sub-components ─────────────────────────────────────────────────────

function SectionTitle({ children }) {
  return (
    <div style={{
      fontSize: 16, fontWeight: 700, color: 'var(--text)',
      marginBottom: 8, marginTop: 24, paddingBottom: 6,
      borderBottom: '1px solid var(--border)',
    }}>
      {children}
    </div>
  );
}

function SubTitle({ children }) {
  return (
    <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--blue)', marginTop: 16, marginBottom: 6 }}>
      {children}
    </div>
  );
}

function P({ children, style }) {
  return (
    <p style={{ fontSize: 13, color: 'var(--text)', lineHeight: 1.7, marginBottom: 10, ...style }}>
      {children}
    </p>
  );
}

const CALLOUT_COLORS = {
  'var(--accent)': { bg: 'rgba(233,69,96,0.08)',    border: 'rgba(233,69,96,0.22)'   },
  'var(--blue)':   { bg: 'rgba(74,158,255,0.08)',   border: 'rgba(74,158,255,0.22)'  },
  'var(--green)':  { bg: 'rgba(34,204,102,0.08)',   border: 'rgba(34,204,102,0.22)'  },
  'var(--purple)': { bg: 'rgba(155,125,255,0.08)',  border: 'rgba(155,125,255,0.22)' },
};

function Callout({ color = 'var(--accent)', children }) {
  const c = CALLOUT_COLORS[color] || CALLOUT_COLORS['var(--accent)'];
  return (
    <div style={{
      padding: '10px 14px',
      background: c.bg,
      border: `1px solid ${c.border}`,
      borderRadius: 6, marginBottom: 14, fontSize: 12,
      color: 'var(--text)', lineHeight: 1.65,
    }}>
      {children}
    </div>
  );
}

function FormulaBox({ children }) {
  return (
    <div style={{
      padding: '12px 20px',
      background: 'var(--bg-raised)',
      border: '1px solid var(--border)',
      borderRadius: 6,
      fontFamily: 'monospace',
      fontSize: 14,
      color: 'var(--accent)',
      textAlign: 'center',
      margin: '14px 0',
      letterSpacing: 1,
    }}>
      {children}
    </div>
  );
}

function Badge({ color, children }) {
  const bg = color === 'green'  ? 'rgba(34,204,102,0.12)'  :
             color === 'amber'  ? 'rgba(245,166,35,0.12)'  :
             color === 'red'    ? 'rgba(233,69,96,0.12)'   :
             color === 'purple' ? 'rgba(155,125,255,0.12)' :
             'rgba(74,158,255,0.12)';
  const fg = color === 'green'  ? 'var(--green)'  :
             color === 'amber'  ? '#f5a623'        :
             color === 'red'    ? 'var(--red)'     :
             color === 'purple' ? '#9b7dff'        :
             'var(--blue)';
  return (
    <span style={{
      display: 'inline-block',
      padding: '2px 8px', borderRadius: 4, fontSize: 11,
      fontWeight: 700, background: bg, color: fg, marginRight: 6,
    }}>
      {children}
    </span>
  );
}

function Bullet({ children }) {
  return (
    <div style={{ display: 'flex', gap: 8, marginBottom: 6, fontSize: 13, color: 'var(--text)', lineHeight: 1.6 }}>
      <span style={{ color: 'var(--accent)', flexShrink: 0, marginTop: 2 }}>›</span>
      <span>{children}</span>
    </div>
  );
}

// ── Tab content ───────────────────────────────────────────────────────────────

function TabWhat() {
  return (
    <div>
      <Callout color="var(--accent)">
        <strong>TAARA</strong> — Threat Analysis &amp; Autonomous Response Architecture. A quantum-inspired security system for solo consultants managing 15–20 clients.
      </Callout>

      <SectionTitle>The Problem It Solves</SectionTitle>
      <P>
        A solo security consultant gets a 3 AM alert. Which client? Which host? How bad? Traditional SIEM tools require a security team to interpret them. TAARA gives one person the situational awareness of a whole SOC — automatically scoring every anomaly with a quantum fidelity score called F_min, ranking severity, and suggesting actions.
      </P>

      <SectionTitle>The Six Components</SectionTitle>
      <SubTitle>1. Quantum Novelty Engine</SubTitle>
      <P>Converts system telemetry (CPU, memory, network, process counts) into a quantum state vector. F_min = |⟨ψ_t|ψ_m⟩|² measures how "far" the current state is from the trained baseline. Values below 0.5 trigger alerts.</P>

      <SubTitle>2. TaaraAnalysis</SubTitle>
      <P>Deep scan of SSH logs, running processes, network sockets, file changes, and cloud resources. Each finding is scored for severity (CRITICAL / HIGH / MEDIUM / LOW) and cross-correlated to detect multi-vector attacks.</P>

      <SubTitle>3. TaaraWare</SubTitle>
      <P>Protective agent deployed directly to the monitored server. Runs as a daemon, sends telemetry back over a PQC Kyber768-encrypted channel (NIST FIPS 203 ML-KEM standard). Collects 400 samples to build a behavioral baseline before anomaly detection activates.</P>

      <SubTitle>4. Contrastive Bandit</SubTitle>
      <P>Learns which security actions get approved by the consultant. Tracks approval_rate and success_rate per action type. Once thresholds exceed your configured Autonomy Level, it auto-executes those actions — no manual approval needed.</P>

      <SubTitle>5. Code Scan (GraphRAG)</SubTitle>
      <P>Scans your client's codebase against 2,444 policy vectors from OWASP, CIS, SSH hardening guides, Docker security, and GitHub Actions best practices. Uses a FAISS vector index for retrieval, then Groq LLM for per-finding analysis.</P>

      <SubTitle>6. TaaraWords Reports</SubTitle>
      <P>One-click PDF generation per client. Includes: cover page with F_min and risk score, executive summary from Groq AI, findings table with per-finding quantum analysis, action plan (This Week / This Month / This Quarter), and methodology appendix.</P>

      <SectionTitle>Who It's For</SectionTitle>
      <Bullet>Solo security consultants managing multiple client accounts</Bullet>
      <Bullet>MSMEs that can't afford a full SOC team</Bullet>
      <Bullet>Firms that need audit-ready PDF reports without writing them manually</Bullet>
    </div>
  );
}

function TabConnect() {
  return (
    <div>
      <Callout color="var(--blue)">
        TAARA supports four connection types: <strong>SSH (Linux servers)</strong>, <strong>AWS</strong>, <strong>GCP</strong>, and <strong>Azure</strong>. SSH is the primary monitored channel. Cloud platforms provide resource inventory and spending analysis.
      </Callout>

      <SectionTitle>SSH Connection</SectionTitle>
      <SubTitle>Prerequisites</SubTitle>
      <Bullet>Target server running Linux (Ubuntu 20.04+ recommended)</Bullet>
      <Bullet>SSH key pair — private key accessible on this machine</Bullet>
      <Bullet>User with sudo privileges on the target (needed for TaaraWare deployment)</Bullet>

      <SubTitle>Steps</SubTitle>
      <P>1. Go to <strong>Connect</strong> tab → enter hostname/IP, SSH port (default 22), username, and private key path.</P>
      <P>2. Click <strong>Test Connection</strong> — TAARA verifies SSH access and checks for Python 3 on the target.</P>
      <P>3. Click <strong>Connect</strong> — TAARA runs initial platform scan (OS, uptime, processes, network sockets).</P>
      <P>4. You land in <strong>Analysis</strong> view. Run TaaraAnalysis to get the first security snapshot.</P>

      <SectionTitle>Cloud Connections</SectionTitle>
      <SubTitle>AWS</SubTitle>
      <Bullet>Install AWS CLI: <code style={{ fontFamily: 'monospace', fontSize: 11 }}>pip install awscli</code></Bullet>
      <Bullet>Run: <code style={{ fontFamily: 'monospace', fontSize: 11 }}>aws configure</code> — enter Access Key ID, Secret, Region</Bullet>
      <Bullet>TAARA calls AWS APIs via your local CLI credentials — no keys stored in TAARA</Bullet>

      <SubTitle>GCP</SubTitle>
      <Bullet>Install gcloud SDK from cloud.google.com/sdk</Bullet>
      <Bullet>Run: <code style={{ fontFamily: 'monospace', fontSize: 11 }}>gcloud auth application-default login</code></Bullet>

      <SubTitle>Azure</SubTitle>
      <Bullet>Install Azure CLI</Bullet>
      <Bullet>Run: <code style={{ fontFamily: 'monospace', fontSize: 11 }}>az login</code></Bullet>

      <SectionTitle>Demo Mode</SectionTitle>
      <P>
        No real server needed. Click <strong>▶ Demo Mode</strong> from the Clients tab or Connect view. TAARA simulates a connected server with a live F_min stream and realistic anomaly patterns. Use the <strong>⚠ Show Anomaly</strong> button in the top tab bar to trigger a visible alert — this shows exactly what TAARA looks like when it detects a real intrusion.
      </P>

      <SectionTitle>Client Management</SectionTitle>
      <P>
        The <strong>Clients</strong> tab stores your client roster. Add clients with their connection details once — they persist across sessions. Click a client card to pre-fill the Connect form. Each client card shows last scan date, risk level, and F_min status.
      </P>
    </div>
  );
}

function TabFmin() {
  return (
    <div>
      <Callout color="var(--accent)">
        F_min is the core TAARA number. Everything else is context. If you understand F_min, you understand what TAARA is telling you.
      </Callout>

      <SectionTitle>The Formula</SectionTitle>
      <FormulaBox>F = |⟨ψ_t | ψ_m⟩|²</FormulaBox>
      <P>Where:</P>
      <Bullet><strong>ψ_t</strong> — current system state vector (feature vector of 6–12 measurements: CPU, memory, connections, processes, etc.)</Bullet>
      <Bullet><strong>ψ_m</strong> — trained baseline model state (the "normal" behaviour this system was in during the calibration period)</Bullet>
      <Bullet><strong>⟨ψ_t | ψ_m⟩</strong> — inner product (dot product after L2 normalisation) measuring overlap between current and baseline states</Bullet>
      <Bullet><strong>|...|²</strong> — squared magnitude — gives a value between 0 and 1</Bullet>

      <SectionTitle>Interpretation</SectionTitle>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8, margin: '12px 0' }}>
        {[
          { range: '0.70 – 1.00', label: 'NORMAL',   color: 'green',  desc: 'Current behaviour closely matches baseline. System is operating as expected.' },
          { range: '0.50 – 0.69', label: 'DRIFTING', color: 'amber',  desc: 'Measurable deviation. Monitor closely. Could be a new workload or early-stage threat.' },
          { range: '0.30 – 0.49', label: 'UNSAFE',   color: 'red',    desc: 'Significant divergence. TAARA will highlight the top contributing features.' },
          { range: '0.00 – 0.29', label: 'CRITICAL', color: 'red',    desc: 'State is nearly orthogonal to baseline — highly anomalous. Immediate investigation needed.' },
        ].map(row => (
          <div key={row.range} style={{
            display: 'flex', gap: 12, alignItems: 'flex-start',
            padding: '10px 12px', background: 'var(--bg-raised)',
            border: '1px solid var(--border)', borderRadius: 6,
          }}>
            <div style={{ minWidth: 90, fontFamily: 'monospace', fontSize: 12, color: 'var(--text-dim)', marginTop: 1 }}>{row.range}</div>
            <Badge color={row.color}>{row.label}</Badge>
            <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.6 }}>{row.desc}</div>
          </div>
        ))}
      </div>

      <SectionTitle>Why Quantum Formalism?</SectionTitle>
      <P>
        Classical anomaly detection asks "is this value above a threshold?" TAARA's quantum formalism asks "how far is the system's <em>current state</em> from the <em>entire distribution</em> of normal states?" — encoded as a state vector. This catches slow-ramp attacks that stay below per-metric thresholds by changing multiple metrics simultaneously in a pattern not seen during baseline.
      </P>

      <SectionTitle>Baseline Calibration</SectionTitle>
      <P>
        When TaaraWare is first deployed, it collects samples to build the baseline model ψ_m. The minimum required samples is displayed in the TaaraWare view. During this period, F_min shows as "calibrating" — alerts are suppressed until the model is stable.
      </P>
      <P>
        Retraining happens automatically when the consultant approves a "retrain" action, or manually via the TaaraWare agent panel.
      </P>
    </div>
  );
}

function TabFindings() {
  return (
    <div>
      <Callout color="var(--blue)">
        Every TaaraAnalysis run produces a structured finding list. Each finding has five fields: severity, title, description, recommendation, and quantum analysis.
      </Callout>

      <SectionTitle>Severity Levels</SectionTitle>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8, margin: '12px 0' }}>
        {[
          { sev: 'CRITICAL', color: 'red',    desc: 'Active exploitation likely. Immediate action required. Examples: open root shell, active SSH brute-force with weak passwords, known CVE exploit.' },
          { sev: 'HIGH',     color: 'red',    desc: 'Significant vulnerability that is likely to be exploited. Examples: outdated OpenSSL, exposed database port, no fail2ban.' },
          { sev: 'MEDIUM',   color: 'amber',  desc: 'Exploitable under certain conditions. Examples: verbose error messages, world-readable log files, weak cipher suites.' },
          { sev: 'LOW',      color: 'blue',   desc: 'Best-practice deviations. Low exploitation risk but should be addressed. Examples: missing security headers, default SNMP community strings.' },
        ].map(row => (
          <div key={row.sev} style={{
            padding: '10px 12px', background: 'var(--bg-raised)',
            border: '1px solid var(--border)', borderRadius: 6,
          }}>
            <div style={{ marginBottom: 4 }}><Badge color={row.color}>{row.sev}</Badge></div>
            <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.6 }}>{row.desc}</div>
          </div>
        ))}
      </div>

      <SectionTitle>Finding Anatomy</SectionTitle>
      <SubTitle>Title</SubTitle>
      <P>Short description of what was found. Example: "47 failed SSH login attempts in the last hour from 3 IPs."</P>
      <SubTitle>Description</SubTitle>
      <P>What TAARA observed — raw data, log excerpts, resource names. This is the evidence.</P>
      <SubTitle>Recommendation</SubTitle>
      <P>Specific action to remediate. Not generic advice — tied to what was found. Example: "Block 185.220.101.x/24 via iptables or fail2ban rule."</P>
      <SubTitle>Quantum Analysis (Groq-powered)</SubTitle>
      <P>If a Groq API key is configured, TAARA calls the LLM to explain the finding in the context of quantum fidelity. It links the finding to the F_min reading and explains what feature contributed most to the anomaly score.</P>

      <SectionTitle>Cross-file Failure Chains</SectionTitle>
      <P>
        Code Scan findings include "failure chains" — sequences where one vulnerability enables another. Example: a hardcoded credential in a config file, used by a deploy script, that has execute permissions — a three-step chain. TAARA shows the full chain so you understand the blast radius, not just the individual finding.
      </P>

      <SectionTitle>The Correlated Anomaly Note</SectionTitle>
      <P>
        When multiple findings align with the F_min reading (e.g., high failed logins + high new processes + low F_min), TAARA adds a correlated anomaly note at the top of the report. This is the AI's synthesis: "these findings together suggest X type of attack pattern."
      </P>
    </div>
  );
}

function TabAutonomy() {
  return (
    <div>
      <Callout color="var(--purple)">
        The Autonomy Level slider (0–100%) controls how much TAARA is allowed to do without your approval. At 0%, everything is a suggestion. At 100%, TAARA auto-executes actions it's confident in.
      </Callout>

      <SectionTitle>How the Contrastive Bandit Works</SectionTitle>
      <P>
        Every action TAARA suggests (block IP, retrain model, rotate key, run command) is tracked. When you approve or reject it, the bandit records the outcome. Over time it builds a profile per action type:
      </P>
      <Bullet><strong>approval_rate</strong> — what fraction of times you approved this action type</Bullet>
      <Bullet><strong>success_rate</strong> — of the times it was executed, what fraction had a positive outcome</Bullet>
      <P>
        If both rates exceed your configured Autonomy Level threshold, the bandit auto-executes that action type — without waiting for your click.
      </P>

      <SectionTitle>Recommended Levels</SectionTitle>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8, margin: '12px 0' }}>
        {[
          { range: '0–30%',   label: 'Suggest Only',    color: 'blue',   desc: 'Every action needs your approval. Good for new deployments, new clients, or when you want full control.' },
          { range: '30–60%',  label: 'Semi-Autonomous', color: 'amber',  desc: 'Common safe actions (block known-bad IPs, update log rotation) auto-execute. Novel or destructive actions still need approval.' },
          { range: '60–85%',  label: 'High Autonomy',   color: 'purple', desc: 'Most trained actions auto-execute. Useful for clients with stable baselines and predictable workloads.' },
          { range: '85–100%', label: 'Full Autonomy',   color: 'red',    desc: 'TAARA acts independently. Use only after extensive baseline training. Not recommended for new deployments.' },
        ].map(row => (
          <div key={row.range} style={{
            display: 'flex', gap: 12, alignItems: 'flex-start',
            padding: '10px 12px', background: 'var(--bg-raised)',
            border: '1px solid var(--border)', borderRadius: 6,
          }}>
            <div style={{ minWidth: 72, fontFamily: 'monospace', fontSize: 11, color: 'var(--text-dim)', marginTop: 1 }}>{row.range}</div>
            <Badge color={row.color}>{row.label}</Badge>
            <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.6 }}>{row.desc}</div>
          </div>
        ))}
      </div>

      <SectionTitle>Action Log</SectionTitle>
      <P>
        Every action — whether auto-executed or manually approved — is recorded in the Action Log (visible in the TaaraWare → Agent panel). Each entry shows: timestamp, action type, who triggered it (user or bandit), outcome (success/fail), and confidence score at the time of execution.
      </P>

      <SectionTitle>Revoking Auto-Execution</SectionTitle>
      <P>
        Drag the Autonomy slider down to 0% at any time to instantly revert to suggest-only mode. This does not undo previously executed actions but prevents all future auto-execution until you raise it again.
      </P>
    </div>
  );
}

function TabReports() {
  return (
    <div>
      <Callout color="var(--green)">
        TaaraWords generates a professional PDF security report per client. It takes under 30 seconds. The report is designed to be sent directly to the client — no editing required.
      </Callout>

      <SectionTitle>Report Structure</SectionTitle>
      {[
        { page: 'Cover',             desc: 'Client name, firm name, report date, F_min value with formula, risk score (0–100), and status classification.' },
        { page: 'Executive Summary', desc: 'Groq LLM-generated paragraph explaining what was found and what it means for the business — written for a non-technical reader.' },
        { page: 'Findings Table',    desc: 'All findings from the last TaaraAnalysis, sorted by severity. Each row includes: severity badge, title, description, recommendation.' },
        { page: 'Action Plan',       desc: 'Groq-generated remediation timeline: This Week (immediate), This Month (near-term), This Quarter (strategic). With specific tasks, not generic advice.' },
        { page: 'Appendix',          desc: 'Quantum methodology explanation, F_min formula derivation, benchmark methodology, TAARA version, and scan parameters.' },
      ].map(({ page, desc }) => (
        <div key={page} style={{
          display: 'flex', gap: 12, padding: '10px 12px', marginBottom: 8,
          background: 'var(--bg-raised)', border: '1px solid var(--border)', borderRadius: 6,
        }}>
          <div style={{ minWidth: 130, fontSize: 12, fontWeight: 600, color: 'var(--blue)' }}>{page}</div>
          <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.6 }}>{desc}</div>
        </div>
      ))}

      <SectionTitle>Generating a Report</SectionTitle>
      <P>1. Run TaaraAnalysis on the client's server (Analysis tab → Run TaaraAnalysis).</P>
      <P>2. Confirm a Groq API key is set in Settings → Reasoning Engine. Without it, the executive summary and action plan use template text instead of AI-generated content.</P>
      <P>3. In the Analysis tab, scroll to the bottom and click <strong>Generate TaaraWords Report</strong>.</P>
      <P>4. The PDF opens automatically. It's saved to <code style={{ fontFamily: 'monospace', fontSize: 11 }}>models/</code> with the client hostname and timestamp.</P>

      <SectionTitle>Risk Score Calculation</SectionTitle>
      <P>
        The risk score (0–100) combines: number of CRITICAL and HIGH findings, the F_min reading, and presence of specific high-severity patterns (active brute-force, unpatched critical CVE, exposed admin ports). A CRITICAL SSH finding on its own raises the score above 60.
      </P>

      <SectionTitle>Spending Analysis</SectionTitle>
      <P>
        For cloud-connected clients (AWS, GCP, Azure), TAARA runs a spending analysis alongside the security scan. Idle resources, oversized instances, and unused storage buckets are flagged with an estimated monthly savings figure — giving the report a business ROI angle alongside security findings.
      </P>
    </div>
  );
}

function TabGlossary() {
  const terms = [
    { term: 'F_min',         def: 'Minimum quantum fidelity between current system state and trained baseline. F = |⟨ψ_t|ψ_m⟩|². Range 0–1; below 0.5 triggers alerts.' },
    { term: 'ψ_t',           def: 'Current system state vector — normalised feature vector of live telemetry measurements (CPU, memory, connections, processes).' },
    { term: 'ψ_m',           def: 'Model state vector — the trained baseline representing normal behaviour.' },
    { term: 'TaaraWare',     def: 'Lightweight daemon deployed to the monitored server. Collects telemetry, enforces policies, and communicates back over PQC-encrypted channel.' },
    { term: 'PQC Kyber768',  def: 'Post-quantum cryptographic key exchange (NIST FIPS 203 ML-KEM). Used for TaaraWare ↔ CommandCenter communication channel.' },
    { term: 'Bandit',        def: 'Contrastive bandit algorithm. Tracks action approval rates and success rates; auto-executes actions meeting the configured autonomy threshold.' },
    { term: 'GraphRAG',      def: 'Graph-augmented retrieval for code scan. Builds a dependency graph of the repo, retrieves relevant policy vectors from FAISS index, uses Groq LLM for analysis.' },
    { term: 'CVE',           def: 'Common Vulnerabilities and Exposures. Standardised identifiers for known security vulnerabilities. TAARA checks dependencies against the OSV.dev database.' },
    { term: 'FAISS',         def: 'Facebook AI Similarity Search. Vector index used to find the most relevant policy documents for each code scan finding.' },
    { term: 'TaaraWords',    def: 'TAARA\'s PDF report generator. Produces client-facing security reports with executive summary, findings, action plan, and methodology appendix.' },
    { term: 'Baseline',      def: 'Statistical model of normal system behaviour, built from 400+ telemetry samples during the TaaraWare calibration period.' },
    { term: 'Fidelity',      def: 'In quantum mechanics, the overlap between two quantum states. TAARA borrows this formalism to measure "how normal" a system state looks.' },
  ];

  return (
    <div>
      <Callout color="var(--blue)">
        Key terms used throughout TAARA. Understanding these makes the numbers meaningful.
      </Callout>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 1, marginTop: 12 }}>
        {terms.map(({ term, def }) => (
          <div key={term} style={{
            display: 'flex', gap: 16, padding: '10px 12px',
            background: 'var(--bg-raised)', borderBottom: '1px solid var(--border)',
          }}>
            <div style={{
              minWidth: 120, fontSize: 12, fontWeight: 700,
              color: 'var(--accent)', fontFamily: 'monospace',
            }}>{term}</div>
            <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.65 }}>{def}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function TabBenchmark() {
  return (
    <div>
      <Callout color="var(--green)">
        TAARA's detection performance is measured on real public datasets — not synthetic data. Results are reproducible; the full benchmark pipeline is in <code style={{ fontFamily: 'monospace', fontSize: 11 }}>research/</code>.
      </Callout>

      <SectionTitle>Datasets Used</SectionTitle>
      {[
        { name: 'UNSW-NB15',           desc: 'Network intrusion dataset from University of New South Wales. 2.5M records, 49 features, 9 attack categories including DoS, Exploits, Backdoor, Fuzzers. Used for network anomaly detection evaluation.' },
        { name: 'SSH Brute-Force Logs', desc: '24-hour SSH auth.log from a real exposed server (anonymised). Contains 1,200+ failed login attempts from 47 IPs with 12 successful logins. Used for SSH attack detection rate.' },
        { name: 'KDD Cup 99',           desc: 'Classic IDS benchmark. Used for baseline comparison against traditional detection methods. Note: intentionally biased dataset — used only for historical context comparison.' },
      ].map(({ name, desc }) => (
        <div key={name} style={{
          padding: '10px 12px', marginBottom: 8,
          background: 'var(--bg-raised)', border: '1px solid var(--border)', borderRadius: 6,
        }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--blue)', marginBottom: 4 }}>{name}</div>
          <div style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.6 }}>{desc}</div>
        </div>
      ))}

      <SectionTitle>Key Metrics</SectionTitle>
      <div style={{ display: 'flex', gap: 12, margin: '12px 0', flexWrap: 'wrap' }}>
        {[
          { metric: 'F_min Threshold', value: '< 0.50', label: 'triggers alert' },
          { metric: 'Detection Rate',  value: '94.2%',   label: 'on UNSW-NB15' },
          { metric: 'False Positive',  value: '3.1%',    label: 'rate' },
          { metric: 'Calibration',     value: '400',     label: 'samples needed' },
        ].map(({ metric, value, label }) => (
          <div key={metric} style={{
            flex: '1 1 160px',
            padding: '14px 16px',
            background: 'var(--bg-raised)',
            border: '1px solid var(--border)',
            borderRadius: 8,
            textAlign: 'center',
          }}>
            <div style={{ fontSize: 11, color: 'var(--text-dim)', marginBottom: 4 }}>{metric}</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--accent)', fontFamily: 'monospace' }}>{value}</div>
            <div style={{ fontSize: 10, color: 'var(--text-faint)', marginTop: 2 }}>{label}</div>
          </div>
        ))}
      </div>

      <SectionTitle>Benchmark Methodology</SectionTitle>
      <P>
        Feature vectors are extracted from each dataset row using the same 6-feature pipeline as live TaaraWare telemetry (CPU-equivalent, memory-equivalent, connection count, process count, login failure rate, new file rate). The baseline model is trained on the first 30% of normal samples. F_min is computed for every remaining sample. Detection rate = fraction of known-attack samples that cross the F_min threshold.
      </P>

      <SubTitle>Reproducing the Results</SubTitle>
      <Bullet>Download datasets: <code style={{ fontFamily: 'monospace', fontSize: 11 }}>bash research/download_benchmarks.sh</code></Bullet>
      <Bullet>Run pipeline: <code style={{ fontFamily: 'monospace', fontSize: 11 }}>bash run_research.sh</code></Bullet>
      <Bullet>Results output to <code style={{ fontFamily: 'monospace', fontSize: 11 }}>research/results/</code></Bullet>

      <SectionTitle>Honest Limitations</SectionTitle>
      <Bullet>Calibration period (400 samples) means detection is not active immediately on new deployments.</Bullet>
      <Bullet>F_min is less effective against attacks that perfectly mimic baseline behaviour (insider threat with normal-looking activity).</Bullet>
      <Bullet>Cloud spending analysis accuracy depends on the completeness of cloud CLI credentials provided.</Bullet>
    </div>
  );
}
