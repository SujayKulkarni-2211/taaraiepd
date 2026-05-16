# Mozilla SSH Hardening Guide — Structured Rules

Source: Mozilla OpSec SSH Guidelines (https://infosec.mozilla.org/guidelines/openssh)

## Authentication Rules

**Disable password authentication entirely:**
```
PasswordAuthentication no
ChallengeResponseAuthentication no
```
Passwords are brute-forceable. SSH keys with 4096-bit RSA or Ed25519 only.

**Disable root login:**
```
PermitRootLogin no
```
All admin actions via sudo from a named user account for auditability.

**Use AllowUsers or AllowGroups to whitelist:**
```
AllowGroups sshusers
```
Default-deny — if not explicitly permitted, no SSH access.

## Protocol and Cipher Rules

**Force SSHv2:**
```
Protocol 2
```
SSHv1 has known cryptographic breaks (BEAST, padding oracle attacks).

**Strong ciphers only (Mozilla Modern):**
```
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
```
Removes: 3DES, RC4, MD5-based MACs, diffie-hellman-group1 (Logjam-vulnerable).

## Connection Rules

**Idle timeout:**
```
ClientAliveInterval 300
ClientAliveCountMax 2
```
10 minutes max idle — prevents abandoned sessions used in lateral movement.

**Login grace time:**
```
LoginGraceTime 30
```
30 seconds to authenticate — limits slow brute force.

**Max auth attempts:**
```
MaxAuthTries 3
```
3 failures = connection drop. Combined with fail2ban = automatic IP ban.

**Disable X11 forwarding:**
```
X11Forwarding no
```
X11 forwarding creates a local socket attackers can use for privilege escalation.

**Disable TCP forwarding unless required:**
```
AllowTcpForwarding no
AllowAgentForwarding no
```
Prevents SSH tunneling used in lateral movement.

## Key Management Rules

**Minimum key sizes:**
- RSA: 4096 bits minimum (2048 is too small by 2025 standards)
- Ed25519: preferred — 256-bit equivalent of RSA-4096 with faster operations
- ECDSA: acceptable with curve P-521
- DSA: FORBIDDEN — broken

**Authorized keys hygiene:**
- One key per user, per machine — no shared keys
- Remove keys immediately when employee leaves
- Rotate keys every 2 years minimum
- Keys with no expiry in authorized_keys = permanent backdoor risk

## Logging Rules

```
LogLevel VERBOSE
SyslogFacility AUTH
```
Log every authentication attempt, key fingerprint used, source IP. Without VERBOSE, you cannot determine WHICH key was used for a login.

## Common Misconfigurations Found in Real Breaches

1. **PermitRootLogin yes** — direct root access, no audit trail
2. **PasswordAuthentication yes** — enables brute force
3. **Weak ciphers still enabled** — diffie-hellman-group1-sha1 present (Logjam)
4. **No idle timeout** — abandoned sessions visible in `who` output, exploitable for lateral movement
5. **AuthorizedKeysFile in world-readable location** — allows key enumeration
6. **Port 22 exposed on public interface** — unnecessary attack surface; move to non-standard port + firewall whitelist
