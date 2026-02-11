# TAARA — Worked Examples

*Work through these examples yourself. Do the math. When the numbers click, you'll see why TAARA catches what others miss.*

---

## Example 1: The Quiet Insider (SSH Server)

### Setup

You're monitoring a Linux server via SSH. `AtomicDNACollector` captures 19 behavioral features every 60 seconds.

User `devops_raj` has been observed for 10 windows. After the bootstrap phase (3 windows), his memory basis stabilized at:

```
m_1 = [95, 1, 12, 42, 18, 4, 0, 800, 400, 1500, 2200, 0, 7, 1, 8, 350, 1.5, 0.4, 2160]
       Features: 95 processes, 1 user, 12% CPU, 42% mem, 18 connections,
       4 ports, 0 failed logins, moderate I/O, 1 SSH session, 8 crons

m_2 = [110, 1, 35, 55, 22, 4, 0, 2500, 1200, 5000, 4000, 0, 9, 1, 8, 500, 3, 0.8, 2184]
       Features: Busy period — higher CPU, memory, I/O

m_3 = [70, 1, 4, 30, 8, 4, 0, 150, 80, 300, 800, 0, 5, 0, 8, 180, 0.5, 0.15, 2208]
       Features: Night/idle — minimal activity
```

Max residual from windows 4-10: `||Delta_max|| = 8.7`

### The Attack

Window 11 arrives. An attacker has compromised `devops_raj`'s SSH key and is performing reconnaissance:

```
x_11 = [98, 1, 14, 44, 55, 4, 0, 900, 6500, 12000, 1800, 0, 8, 3, 8, 750, 2, 0.5, 2232]
```

**What changed?**
- Connections: 18 -> 55 (but global range across all users is 5-80, so within IQR)
- SSH sessions: 1 -> 3 (global range 0-5, within IQR)
- Disk write: 400 -> 6500 (global range 50-10000, within IQR)
- Net send: 1500 -> 12000 (global range 200-15000, within IQR)

**Every individual feature is within the global interquartile range.**
A traditional UEBA system sees nothing wrong.

### Do the Math

**Step 1: Build the memory matrix**

```
M = [m_1 | m_2 | m_3]    (19 x 3 matrix)
```

**Step 2: Compute the reconstruction**

Find coefficients alpha that minimize `||x_11 - M*alpha||^2`:

```
M^T M = | m_1.m_1  m_1.m_2  m_1.m_3 |
        | m_2.m_1  m_2.m_2  m_2.m_3 |
        | m_3.m_1  m_3.m_2  m_3.m_3 |
```

Computing dot products (you can verify with a calculator):

```
m_1.m_1 = 95^2 + 1 + 144 + 1764 + 324 + 16 + 0 + 640000 + 160000 + 2250000 + 4840000 + 0 + 49 + 1 + 64 + 122500 + 2.25 + 0.16 + 4665600
        ≈ 12,678,558

(Continue for all entries — or trust the computer and verify the result)
```

The least-squares solution gives approximately:

```
alpha ≈ [0.48, 0.35, 0.17]

x_hat_11 = 0.48 * m_1 + 0.35 * m_2 + 0.17 * m_3
         ≈ [96.6, 1, 15.4, 46.4, 19.7, 4, 0, 1301, 626, 3521, 3498, 0, 7.6, 0.8, 8, 439, 1.9, 0.5, 2190]
```

**Step 3: Compute the residual**

```
Delta_11 = x_11 - x_hat_11
         = [1.4, 0, -1.4, -2.4, 35.3, 0, 0, -401, 5874, 8479, -1698, 0, 0.4, 2.2, 0, 311, 0.1, 0, 42]

||Delta_11|| = sqrt(1.96 + 0 + 1.96 + 5.76 + 1246 + 0 + 0 + 160801 + 34504276 + 71893441 + 2883204 + ... )
            ≈ 10,442
```

**Step 4: Check novelty**

```
||Delta_11|| = 10,442  >>  ||Delta_max|| = 8.7

NOVEL!  (1,200x larger than any prior residual)
```

**Why?** The memory basis spans a subspace of "normal Raj" — workday, busy, idle. The attacker's combination of [high connections + 3 SSH sessions + massive disk write + high net send] creates a vector that **cannot be projected** onto that subspace. The residual is enormous because these feature relationships have never co-occurred for this identity.

### Quantum Validation

Now encode the residual into a 4-qubit quantum state:

```
Delta_11_truncated = [1.4, 0, -1.4, -2.4, 35.3, 0, 0, -401, 5874, 8479, -1698, 0, 0.4, 2.2, 0, 311]
norm = 10,440.8
alpha_q = Delta_11_truncated / norm   (unit vector)

|psi_11> = QuantumCircuit(alpha_q)
         = AmplitudeEmbed -> Hadamard -> Ring_CNOT -> RX(pi/4) -> RY(pi/4) -> RZ(pi/4)
```

Compare against memory residuals (from windows 4-10 which had small residuals):

```
F(|psi_11>, |psi_4>) = |<psi_11|psi_4>|^2 = 0.04
F(|psi_11>, |psi_7>) = |<psi_11|psi_7>|^2 = 0.09
F(|psi_11>, |psi_9>) = |<psi_11|psi_9>|^2 = 0.06

F_min = 0.04 < 0.5  -->  QUANTUM-CONFIRMED NOVELTY
```

**Risk Score:**
```
quantum_novelty = (1 - 0.04) * 100 = 96.0
magnitude_score = min(10442 * 10, 100) = 100.0
risk_score = 0.6 * 96.0 + 0.4 * 100.0 = 97.6  -->  CRITICAL
```

### The Takeaway

Every single feature was within normal bounds for the global population. An Isolation Forest trained on all users would score this as normal. A z-score detector would not flag it. A threshold-based system would miss it.

TAARA caught it because **for devops_raj specifically**, this combination of behaviors has never been representable from his prior behavioral repertoire.

---

## Example 2: AWS IAM Lateral Movement

### Setup

You've connected TAARA to an AWS account. The platform manager collects security data and extracts features:

```
features = {
    'total_findings': 12,
    'weighted_severity_score': 45,
    'iam_users_no_mfa': 3,
    'stale_access_keys': 2,
    'public_security_groups': 1,
    'public_s3_buckets': 0,
    'cloudtrail_disabled': 0,
    'imdsv2_missing': 4,
    'stopped_instances': 2
}
```

Feature vector: `x = [12, 45, 3, 2, 1, 0, 0, 4, 2]` (9 dimensions, padded to 19 with zeros)

### After 5 Scans (Daily)

Memory basis for identity `aws_system`:

```
m_1 = [12, 45, 3, 2, 1, 0, 0, 4, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]  (day 1)
m_2 = [13, 48, 3, 2, 1, 0, 0, 4, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]  (day 2, minor drift)
m_3 = [11, 42, 3, 2, 1, 0, 0, 3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]  (day 3)
```

Max prior residual: `||Delta_max|| = 3.2`

### Day 6: Attacker Creates New IAM User

An attacker with compromised credentials creates a new IAM user with admin access:

```
x_6 = [18, 95, 4, 5, 3, 1, 0, 4, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
```

Changes: total_findings 12->18, severity 45->95, no_mfa 3->4, stale_keys 2->5, public_sgs 1->3, public_s3 0->1.

### Reconstruction

```
alpha = (M^T M)^{-1} M^T x_6

Best approximation: x_hat_6 ≈ [12.7, 46.5, 3, 2, 1, 0, 0, 3.8, 2, ...]
Delta_6 = x_6 - x_hat_6 = [5.3, 48.5, 1, 3, 2, 1, 0, 0.2, 0, ...]
||Delta_6|| ≈ 49.1

||Delta_6|| = 49.1  >>  ||Delta_max|| = 3.2  -->  NOVEL!
```

The severity score jumped from ~45 to 95, and new finding categories appeared (public S3, more public SGs) — the memory basis cannot represent this.

### What TAARA Tells the Admin

```
QUANTUM-CONFIRMED NOVELTY DETECTED
Risk Score: 92.4 (CRITICAL)

This AWS account's security posture has shifted in ways never observed before:
- 6 new security findings appeared
- Severity score doubled (45 -> 95)
- New public S3 bucket detected
- 3 new stale access keys
- 2 additional public security groups

Recommended: Run TaaraAnalysis for detailed findings, then Taara Words for client report.
```

---

## Example 3: Docker Container Escape Attempt

### Setup

TAARA connected to Docker. Features extracted from container audit:

```
Typical scan: [3, 15, 0, 0, 0, 0, 2, 0, 0, ...]
  (3 findings, severity 15, no privileged, no host PID, no host net, no socket, 2 root containers)
```

### Novel Event

New container deployed with privileged mode + Docker socket mount:

```
x_new = [7, 55, 1, 1, 1, 1, 3, 0, 0, ...]
  (7 findings, severity 55, privileged=1, host_pid=1, host_net=1, socket_mount=1, 3 root)
```

### Math

```
||Delta|| = sqrt((7-3.2)^2 + (55-15.5)^2 + 1 + 1 + 1 + 1 + 1 + ...)
          = sqrt(14.4 + 1560.25 + 4)
          ≈ 39.7

max_prior = 2.1

39.7 >> 2.1  -->  NOVEL

F_min = 0.08  -->  QUANTUM CONFIRMED
Risk = 93.2   -->  CRITICAL
```

TAARA detects the container escape setup because this combination of [privileged + host PID + host network + socket mount] has never been representable from prior Docker scans for this environment.

---

## Example 4: Kubernetes RBAC Escalation

### Feature Space

```
features = [rbac_findings, pod_security_findings, netpol_findings, secret_findings,
            total_findings, weighted_severity, ...]
```

### Normal State (3 scans)

```
m_1 = [2, 1, 3, 0, 6, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
m_2 = [2, 1, 3, 1, 7, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
m_3 = [2, 2, 3, 0, 7, 22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
```

### Attack: ServiceAccount Gets cluster-admin

```
x_attack = [5, 3, 3, 2, 13, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
```

RBAC findings jumped from 2 to 5 (new cluster-admin bindings), secrets exposure doubled, total severity tripled.

```
Reconstruction gives x_hat ≈ [2, 1.5, 3, 0.4, 6.9, 20.5, ...]
Delta = [3, 1.5, 0, 1.6, 6.1, 44.5, ...]
||Delta|| ≈ 45.0

max_prior = 2.8

NOVEL! QUANTUM CONFIRMED! Risk = 91.7 (CRITICAL)
```

---

## Example 5: Why Isolation Forest Misses It (The IQR Problem)

This is the core insight from the paper. Let's prove it.

### Setup: 100 Users on SSH

Across 100 users, the global distributions are:

```
failed_logins:   mean=5, std=8,   IQR=[0, 8]
connections:     mean=30, std=20, IQR=[15, 45]
disk_write:      mean=3000, std=2500, IQR=[1000, 5000]
net_send:        mean=5000, std=4000, IQR=[2000, 8000]
```

### Isolation Forest's View

Isolation Forest builds random trees and measures how quickly each point gets isolated. Points that are "easy to isolate" (far from others) are anomalies.

For a point with `failed_logins=2, connections=40, disk_write=4500, net_send=7000`:
- Every feature is within the IQR
- Isolation depth is high (hard to isolate) = **normal**
- IF score: -0.12 (normal)

### TAARA's View

For user `bob` specifically, the memory basis is:

```
bob_m_1 = [0, 15, 500, 1000, ...]   (bob is a light user)
bob_m_2 = [0, 18, 600, 1200, ...]
bob_m_3 = [1, 12, 400, 900, ...]
```

Now `bob` shows: `[2, 40, 4500, 7000, ...]`

```
||Delta|| = sqrt(4 + 484 + 15210000 + 33640000) ≈ 6988

bob's max_prior = 3.1

6988 >> 3.1  -->  NOVEL!
```

**Isolation Forest**: "Looks normal globally."
**TAARA**: "Bob has NEVER behaved like this. His behavioral trajectory has entered an entirely new region of state space."

This is why the paper found 295 states (5.1%) that IF missed, with 79% of them falling within the global IQR. **Novelty is not anomaly. Novelty is representational failure.**

---

## Example 6: Understanding Quantum Fidelity

### Why Direction Matters

Consider two novel residuals:

```
Delta_A = [0, 0, 0, 0, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
           (pure network connection spike)

Delta_B = [0, 0, 0, 0, 0, 0, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
           (pure root process spike)
```

Both have `||Delta|| = 50`. A classical system says "same severity."

### Quantum Encoding

Truncate to 16 dims, normalize:

```
alpha_A = [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]  (unit vector along dim 4)
alpha_B = [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]  (unit vector along dim 6)
```

After the quantum circuit (AmplitudeEmbed -> H -> CNOT_ring -> Rotations), these become entangled states `|psi_A>` and `|psi_B>`.

### Fidelity Computation

```
F(|psi_A>, |psi_B>) = |<psi_A|psi_B>|^2
```

Because the input vectors are orthogonal and the circuit preserves orthogonality structure:

```
F ≈ 0.02  (very low — nearly orthogonal quantum states)
```

**The quantum layer reveals**: These are **completely different types of incidents** despite having the same magnitude. One is a network reconnaissance pattern, the other is a privilege escalation pattern. The quantum fidelity encodes this directional information that classical magnitude comparison loses.

### Practical Impact

If you have memory residuals from past network incidents, a new network incident will have high fidelity (F > 0.5) with those — meaning "we've seen this type before." But a new privilege escalation will have low fidelity (F < 0.5) — meaning "this is a genuinely new attack direction."

---

## Example 7: Cloud Spending — Preserve Cash

### AWS Cost Data

```
Monthly costs by service:
  EC2:        $2,450
  RDS:        $890
  S3:         $120
  Lambda:     $45
  CloudWatch: $80
  Total:      $3,585
```

### TAARA Cloud Analyzer Detects

```
Waste Detected:
  - 3 stopped EC2 instances with 6 attached EBS volumes ($108/month)
  - 2 unused Elastic IPs ($7.20/month)
  - RDS instance oversized (db.r5.2xlarge for 15% avg CPU, could use db.r5.large)
  - S3 bucket without lifecycle policy (2TB of logs older than 90 days)

Potential Savings: $650/month ($7,800/year)
Preserve Cash Score: 72/100 (room for improvement)
```

### For an MSME Client

```
Annual IT spend:        ~INR 30,00,000
Potential annual savings: ~INR 6,50,000
TAARA report cost:       INR 75,000

ROI: 8.7x in first year
```

This is the "Preserve Cash" value proposition — the report pays for itself many times over.

---

## Try It Yourself

1. **Connect to any server via SSH** and run TaaraAnalysis
2. **Watch the bootstrap** (first 3 observations build the basis)
3. **Run training** in Quick Demo mode (2 minutes)
4. **Observe the detection funnel** in Command Center -> TAARA Statistics
5. **Create a novel event** (e.g., start many SSH sessions, run a port scan, spawn lots of processes)
6. **Watch TAARA detect it** even if individual features look normal
7. **Check the quantum validation** — F_min should be low for genuinely novel events
8. **Generate a PDF report** with Taara Words
9. **Try the AI Chat** — ask it to harden the server, approve the commands
10. **Check the Action Log** — see the full audit trail with rollback options

---

*The math doesn't lie. Work through the numbers. When ||Delta_t|| >> max_prior, you've found something no traditional system would catch.*

*TAARA: Trajectory-Aware Adaptive Residual Analysis — Prevent Crash, Preserve Cash*
