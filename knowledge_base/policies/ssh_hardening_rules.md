# SSH Hardening Rules — Structured for Knowledge Graph
## Sources: Mozilla OpSec, CIS Benchmark Linux, NIST SP 800-123

## CRITICAL violations (immediate risk)
- PermitRootLogin yes — allows direct root SSH, bypasses sudo audit trail
- PasswordAuthentication yes — enables brute force attacks
- Port 22 exposed publicly — default port, targeted by automated scanners
- PermitEmptyPasswords yes — allows login with no password

## HIGH violations
- Protocol 1 enabled — SSH v1 has known cryptographic weaknesses
- X11Forwarding yes — enables remote display attacks
- AllowTcpForwarding yes without restriction — enables tunneling attacks
- MaxAuthTries > 3 — allows extended brute force attempts
- LoginGraceTime > 60 — allows slow attacks on connection establishment

## MEDIUM violations  
- Banner not set — no legal warning, may affect prosecution ability
- ClientAliveInterval not set — idle sessions left open indefinitely
- AllowUsers or AllowGroups not configured — no access restriction
- UsePAM no — bypasses system authentication controls
- Subsystem sftp not using internal-sftp — harder to audit file transfers

## Secure configuration baseline
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
AllowTcpForwarding no
X11Forwarding no
Banner /etc/issue.net

## Attack patterns this prevents
- Brute force: MaxAuthTries 3 + PasswordAuthentication no
- Credential stuffing: PubkeyAuthentication only
- Lateral movement via root: PermitRootLogin no
- Port scanning exploitation: non-default port + fail2ban
- Session hijacking: ClientAliveInterval + key-only auth
