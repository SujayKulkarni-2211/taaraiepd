# TAARA Demo Guide

## Network
- ZeroTier network: `88c5b1f33907fd78`
- Phone (target): `10.248.248.67` port `8022` user `u0_a134` pass `demo1234`
- Laptop (attacker): `10.248.248.59`

## Laptop ZeroTier Setup (run once before demo)
```bash
# ZeroTier is already installed. Service should be running:
sudo systemctl status zerotier-one

# Join the demo network:
sudo zerotier-cli join 88c5b1f33907fd78

# Verify connected and IP assigned:
sudo zerotier-cli listnetworks
# Should show: 88c5b1f33907fd78  my-first-network  OK  PRIVATE  ztpp6lmdsb  10.248.248.59/24

# Verify phone is reachable:
nc -zv 10.248.248.67 8022
# Should show: Connection to 10.248.248.67 8022 port [tcp/*] succeeded!
```

## Scenario 1 — Live Server Monitoring
1. Start TAARA: `cd ~/projects/IEPD/taaraiepd && source venv/bin/activate && python server.py`
2. Open Electron app
3. Connect → host `10.248.248.67` port `8022` user `u0_a134` pass `demo1234`
4. Dashboard shows live Q CONFIDENCE / SWAP FIDELITY / DIRECTIONALITY / PHASE COHERENCE
5. Go to TaaraWare tab → Deploy TaaraWare → agent installs and starts collecting every 30s

## Scenario 2 — Code Analysis
- Connect to any server → TaaraAnalysis tab → Run Analysis
- Shows CVEs, policy violations, exploit chains, AI executive summary

## Scenario 3 — ZeroTier T1078 Attack
**What TAARA detects that classical IDS misses:** valid credentials, normal-looking commands, no malware — signature IDS sees nothing. TAARA's quantum behavioral engine catches the subspace deviation.

**Validated numbers:** normal confidence ~0.20, attack confidence ~0.48, threshold 0.4382

### Steps
1. Phone: ensure `sshd` running in Termux
2. Laptop: ensure ZeroTier connected (`sudo zerotier-cli listnetworks` shows `88c5b1f33907fd78 OK`)
3. Connect TAARA to phone (see Scenario 1 step 3)
4. Wait one 30s poll cycle — quantum signals populate
5. Open second terminal, run attack:
```bash
cd ~/projects/IEPD/taaraiepd
./demo/zerotier_run_attack.sh
```
6. Within next poll cycle TAARA dashboard shows alert — Q CONFIDENCE spikes above 0.4382
7. Point: "Classical IDS logged CLEAN. TAARA caught it via quantum behavioral subspace deviation."

### What the attack does
- Phase 1: System fingerprinting
- Phase 2: File enumeration (`find ~`)
- Phase 3: Sensitive data access (`company_data/customers`, `finance`, `config`)
- Phase 4: Data staging (`/tmp/.stage/`)
- Phase 5: Network probe (port scan)
- Phase 6: Privilege escalation probe
- Phase 7: Cover tracks (history clear)


attack script that was tried: 
cd ~/projects/IEPD/taaraiepd
chmod +x demo/zerotier_run_attack.sh
./demo/zerotier_run_attack.sh
