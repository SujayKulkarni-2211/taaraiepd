"""
TAARA T1078 Benchmark on LogHub SSH Dataset
=============================================
Compares TAARA quantum pipeline vs IsolationForest baseline on real-world SSH logs.

Dataset: LogHub SSH (655k lines, Zenodo) — public, citable
Threat: T1078 Valid Account compromise (MITRE ATT&CK T1078.003)
Key test: Detection rate INSIDE the statistical normal range (where classical fails)

Usage:
    python benchmark/scripts/run_benchmark.py

Output:
    benchmark/results/benchmark_results.json  — machine-readable
    benchmark/results/benchmark_report.txt    — human-readable summary
"""

import sys
import os
import re
import json
import time
import numpy as np
from collections import defaultdict
from typing import List, Dict, Tuple, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from components.dna_autoencoder import DNAEmbedder
from components.taara_core import TAARAnalyzer as TaaraAnalyzer
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

DATASET_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "datasets", "SSH.log")
RESULTS_DIR  = os.path.join(os.path.dirname(os.path.dirname(__file__)), "results")
MODELS_DIR   = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "models")

os.makedirs(RESULTS_DIR, exist_ok=True)

# ── SSH Log Parser ─────────────────────────────────────────────────────────────

ACCEPTED_RE = re.compile(
    r'(\w+\s+\d+\s+\d+:\d+:\d+).*?sshd\[(\d+)\].*?'
    r'Accepted\s+(\w+)\s+for\s+(\w+)\s+from\s+([\d.]+)\s+port\s+(\d+)'
)
FAILED_RE = re.compile(
    r'(\w+\s+\d+\s+\d+:\d+:\d+).*?sshd\[(\d+)\].*?'
    r'(?:Failed|Invalid user)\s+(?:\w+\s+for\s+)?(\w+)\s+from\s+([\d.]+)\s+port\s+(\d+)'
)
SESSION_OPEN_RE  = re.compile(r'session opened for user (\w+)')
SESSION_CLOSE_RE = re.compile(r'session closed for user (\w+)')

def parse_ssh_log(path: str):
    """
    Parse LogHub SSH.log into per-identity session records.
    Returns: list of session dicts with behavioral features.
    """
    sessions = []
    user_history = defaultdict(lambda: {
        'total_sessions': 0, 'failed_attempts': 0, 'unique_ips': set(),
        'ports_used': [], 'last_seen': None, 'auth_methods': [],
        'session_gaps': [], 'ip_history': [],
    })
    pending = {}  # pid → {user, src_ip, port, start_time, auth_method}

    print(f"[benchmark] Parsing {path} ...")
    t0 = time.time()

    with open(path, 'r', errors='replace') as f:
        for lineno, line in enumerate(f):
            # Accepted login
            m = ACCEPTED_RE.search(line)
            if m:
                ts_str, pid, auth_method, user, src_ip, port = m.groups()
                pending[pid] = {
                    'user': user, 'src_ip': src_ip, 'port': int(port),
                    'auth_method': auth_method, 'lineno': lineno,
                }
                continue

            # Session opened (start of actual session after auth)
            m2 = SESSION_OPEN_RE.search(line)
            if m2:
                user = m2.group(1)
                # Find matching pending auth
                for pid, info in list(pending.items()):
                    if info['user'] == user:
                        info['session_start_line'] = lineno
                        break
                continue

            # Session closed (end of session)
            m3 = SESSION_CLOSE_RE.search(line)
            if m3:
                user = m3.group(1)
                for pid, info in list(pending.items()):
                    if info['user'] == user and 'session_start_line' in info:
                        duration_lines = lineno - info['session_start_line']
                        h = user_history[user]

                        # Compute features for this session
                        gap = (lineno - h['last_seen']) if h['last_seen'] else 0
                        h['session_gaps'].append(gap)
                        is_new_ip = info['src_ip'] not in h['unique_ips']
                        h['unique_ips'].add(info['src_ip'])
                        h['ip_history'].append(info['src_ip'])
                        h['total_sessions'] += 1
                        h['auth_methods'].append(info['auth_method'])
                        h['last_seen'] = lineno

                        session = {
                            'user': user,
                            'src_ip': info['src_ip'],
                            'port': info['port'],
                            'auth_method': info['auth_method'],
                            'duration_lines': duration_lines,
                            'session_index': h['total_sessions'],
                            'gap_from_last': gap,
                            'unique_ip_count': len(h['unique_ips']),
                            'is_new_ip': int(is_new_ip),
                            'failed_before': h['failed_attempts'],
                            'ip_diversity': len(h['unique_ips']) / max(h['total_sessions'], 1),
                            'mean_gap': float(np.mean(h['session_gaps'])) if h['session_gaps'] else 0,
                            'gap_variance': float(np.var(h['session_gaps'])) if len(h['session_gaps']) > 1 else 0,
                            'auth_method_numeric': 1 if info['auth_method'] == 'publickey' else 0,
                        }
                        sessions.append(session)
                        del pending[pid]
                        break
                continue

            # Failed attempt
            m4 = FAILED_RE.search(line)
            if m4:
                try:
                    user_val = m4.group(3)
                    user_history[user_val]['failed_attempts'] += 1
                except:
                    pass

    elapsed = time.time() - t0
    print(f"[benchmark] Parsed {len(sessions)} sessions in {elapsed:.1f}s")
    return sessions


def sessions_to_features(sessions: List[Dict]) -> np.ndarray:
    """
    Convert session records to 19-feature behavioral DNA vectors.

    19 features matching TaaraWare agent collection:
    [0]  session_duration        [1]  failed_attempts_before
    [2]  unique_ip_count         [3]  ip_diversity
    [4]  port_number             [5]  session_index (sequence position)
    [6]  gap_from_last           [7]  mean_gap
    [8]  gap_variance            [9]  is_new_ip
    [10] auth_method             [11] gap_normalized
    [12] session_freq            [13] ip_reuse_rate
    [14] gap_deviation           [15] auth_consistency
    [16] session_density         [17] port_entropy
    [18] timing_regularity
    """
    features = []
    for s in sessions:
        idx = max(s['session_index'], 1)
        gap = s['gap_from_last']
        mean_g = s['mean_gap']

        f = [
            float(s['duration_lines']),                          # 0
            float(s['failed_before']),                           # 1
            float(s['unique_ip_count']),                         # 2
            float(s['ip_diversity']),                            # 3
            float(s['port']) / 65535.0,                          # 4 normalized
            float(idx),                                          # 5
            float(gap),                                          # 6
            float(mean_g),                                       # 7
            float(s['gap_variance']),                            # 8
            float(s['is_new_ip']),                               # 9
            float(s['auth_method_numeric']),                     # 10
            float(gap) / (mean_g + 1e-6),                        # 11 gap ratio
            1.0 / (mean_g + 1e-6),                               # 12 session freq
            1.0 - float(s['ip_diversity']),                      # 13 ip reuse
            abs(gap - mean_g) / (np.sqrt(s['gap_variance']) + 1e-6),  # 14 gap deviation
            float(s['auth_method_numeric']),                     # 15 consistency proxy
            float(idx) / (float(gap) + 1e-6),                   # 16 density
            float(s['port'] % 100) / 100.0,                     # 17 port entropy proxy
            1.0 / (abs(gap - mean_g) + 1e-6),                   # 18 timing regularity
        ]
        features.append(f)

    return np.array(features, dtype=np.float32)


# ── T1078 Attack Simulation ────────────────────────────────────────────────────

def inject_t1078_sessions(normal_sessions: List[Dict], users: List[str],
                           attack_rate: float = 0.15) -> Tuple[List[Dict], List[int]]:
    """
    Simulate T1078 Valid Account attacks INSIDE the statistical normal range.

    This is the hard test: the attack must be within global statistical thresholds
    (mean ± 2σ) so that threshold-based detectors cannot fire.
    T1078 represents: adversary using compromised valid credentials.
    Key behavioral shifts: slightly different timing, slightly different commands,
    IP from different subnet but plausible, slightly faster session.

    Returns: (augmented_sessions, attack_labels)
    Labels: 0 = normal, 1 = T1078 attack
    """
    rng = np.random.RandomState(42)
    augmented = []
    labels = []

    # Compute global feature stats for "within normal range" constraint
    all_gaps = [s['gap_from_last'] for s in normal_sessions if s['gap_from_last'] > 0]
    all_durs = [s['duration_lines'] for s in normal_sessions]
    gap_mean, gap_std = np.mean(all_gaps), np.std(all_gaps)
    dur_mean, dur_std = np.mean(all_durs), np.std(all_durs)

    for i, session in enumerate(normal_sessions):
        augmented.append(session)
        labels.append(0)

        # Inject T1078 attack session for this user occasionally
        if (session['user'] in users and
                session['session_index'] >= 5 and  # must have history to exploit
                rng.random() < attack_rate):

            # T1078 behavioral signature: WITHIN statistical normal range but directionally new
            # - Timing: slightly off the user's personal pattern (within 1σ globally)
            # - IP: same subnet but different last octet (plausible)
            # - Duration: slightly shorter (attacker more purposeful)
            # - Gap: within ±2σ of GLOBAL mean (passes classical threshold)
            user_mean_gap = session['mean_gap']
            user_gap_var  = session['gap_variance']

            # Attacker uses gap that is WITHIN global normal but different from user's personal pattern
            global_normal_gap = gap_mean + rng.uniform(-1.5, 1.5) * gap_std
            # But user's personal z-score is high (attacker timing differs from user's habit)
            personal_z = abs(global_normal_gap - user_mean_gap) / (np.sqrt(user_gap_var) + 1e-6)

            attack_session = session.copy()
            attack_session['gap_from_last'] = max(global_normal_gap, 1.0)
            attack_session['duration_lines'] = max(dur_mean * rng.uniform(0.3, 0.7), 1.0)  # shorter
            attack_session['is_new_ip'] = 1  # slight IP variation
            attack_session['unique_ip_count'] = session['unique_ip_count'] + 1
            attack_session['ip_diversity'] = attack_session['unique_ip_count'] / (session['session_index'] + 1)
            attack_session['failed_before'] = session['failed_before'] + rng.randint(0, 3)  # slight recon
            attack_session['auth_method'] = 'password'  # attacker has password, not key
            attack_session['auth_method_numeric'] = 0
            attack_session['_is_attack'] = True
            attack_session['_personal_z'] = float(personal_z)
            attack_session['_global_within_normal'] = abs(global_normal_gap - gap_mean) < 2 * gap_std

            augmented.append(attack_session)
            labels.append(1)

    print(f"[benchmark] Injected {sum(labels)} T1078 attacks out of {len(labels)} total sessions")
    attack_sessions = [augmented[i] for i, l in enumerate(labels) if l == 1]
    within_normal = sum(1 for s in attack_sessions if s.get('_global_within_normal', False))
    print(f"[benchmark]   {within_normal}/{len(attack_sessions)} attacks are within global ±2σ "
          f"(these are the ones classical threshold detectors miss)")
    return augmented, labels


# ── Baseline: IsolationForest ──────────────────────────────────────────────────

def run_isolation_forest(X_train: np.ndarray, X_test: np.ndarray,
                          labels_test: List[int]) -> Dict:
    """Standard IsolationForest baseline — what commercial tools approximate."""
    print("[benchmark] Running IsolationForest baseline...")
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    clf = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    clf.fit(X_train_s)

    scores = clf.score_samples(X_test_s)
    # IsolationForest: lower score = more anomalous. Threshold = 5th percentile of train scores.
    train_scores = clf.score_samples(X_train_s)
    threshold = np.percentile(train_scores, 5)

    preds = [1 if s < threshold else 0 for s in scores]
    return evaluate(preds, labels_test, scores, "IsolationForest")


# ── TAARA Pipeline ─────────────────────────────────────────────────────────────

def run_taara_pipeline(sessions_train: List[Dict], features_train: np.ndarray,
                       sessions_test: List[Dict],  features_test: np.ndarray,
                       labels_test: List[int]) -> Dict:
    """
    TAARA full pipeline: DNA Autoencoder → 8-dim latent → Quantum fidelity → V3 fusion.
    Uses the pretrained model — no training from scratch.
    """
    print("[benchmark] Loading pretrained DNA autoencoder...")
    embedder = DNAEmbedder()
    loaded = embedder.load()
    if not loaded:
        print("[benchmark] WARNING: pretrained model not found — running with untrained embedder")
    else:
        print(f"[benchmark]   Loaded. is_ready={embedder.is_ready()}")

    # Fit scaler on training features if not already fitted
    if not embedder.is_ready():
        print("[benchmark]   Fitting scaler on training data...")
        embedder.scaler.fit(features_train)

    analyzer = TaaraAnalyzer()

    # Build per-identity basis from training data (first TRAIN_FRAC of each user's sessions)
    print("[benchmark] Building per-identity quantum basis from training sessions...")
    user_train = defaultdict(list)
    for sess, feat in zip(sessions_train, features_train):
        user_train[sess['user']].append(feat)

    for user, feats in user_train.items():
        identity_id = f"benchmark_{user}"
        for feat in feats:
            analyzer.add_training_observation(feat, identity_id)

    # Inference on test set
    print("[benchmark] Running TAARA inference on test sessions...")
    taara_scores = []
    taara_preds  = []

    for i, (sess, feat) in enumerate(zip(sessions_test, features_test)):
        identity_id = f"benchmark_{sess['user']}"
        try:
            result = analyzer.get_quantum_risk_assessment(feat, identity_id)
            conf   = result.get('quantum_confidence') or 0.0
            thresh = result.get('threshold') or 0.4382
            taara_scores.append(conf)
            taara_preds.append(1 if conf > thresh else 0)
        except Exception as e:
            taara_scores.append(0.0)
            taara_preds.append(0)

        if (i + 1) % 200 == 0:
            print(f"[benchmark]   {i+1}/{len(sessions_test)} sessions processed...")

    return evaluate(taara_preds, labels_test, taara_scores, "TAARA_V3")


# ── Evaluation ────────────────────────────────────────────────────────────────

def evaluate(preds: List[int], labels: List[int], scores: List[float], name: str) -> Dict:
    """Compute TPR, FPR, Precision, F1, and the critical T1078-specific metric."""
    tp = sum(1 for p, l in zip(preds, labels) if p == 1 and l == 1)
    fp = sum(1 for p, l in zip(preds, labels) if p == 1 and l == 0)
    tn = sum(1 for p, l in zip(preds, labels) if p == 0 and l == 0)
    fn = sum(1 for p, l in zip(preds, labels) if p == 0 and l == 1)

    tpr  = tp / (tp + fn) if (tp + fn) > 0 else 0.0   # Recall / Detection Rate
    fpr  = fp / (fp + tn) if (fp + tn) > 0 else 0.0   # False Positive Rate
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0   # Precision
    f1   = 2 * prec * tpr / (prec + tpr) if (prec + tpr) > 0 else 0.0

    result = {
        'method': name,
        'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
        'tpr': round(tpr, 4),
        'fpr': round(fpr, 4),
        'precision': round(prec, 4),
        'f1': round(f1, 4),
        'total_attacks': tp + fn,
        'total_normal': tn + fp,
    }

    print(f"\n[{name}]")
    print(f"  TPR (Detection Rate): {tpr:.3f}  ({tp}/{tp+fn} attacks detected)")
    print(f"  FPR (False Alarm Rate): {fpr:.3f}  ({fp}/{fp+tn} false alarms)")
    print(f"  Precision: {prec:.3f}")
    print(f"  F1: {f1:.3f}")

    return result


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    t_start = time.time()
    print("=" * 70)
    print("TAARA T1078 Benchmark — LogHub SSH Dataset")
    print("=" * 70)

    # 1. Parse logs
    sessions = parse_ssh_log(DATASET_PATH)
    if len(sessions) < 50:
        print(f"[ERROR] Only {len(sessions)} sessions parsed. Check dataset path.")
        sys.exit(1)

    # 2. Filter to users with enough history (≥ 8 sessions) for per-identity basis
    user_counts = defaultdict(int)
    for s in sessions:
        user_counts[s['user']] += 1
    eligible_users = [u for u, c in user_counts.items() if c >= 8]
    sessions = [s for s in sessions if s['user'] in eligible_users]
    print(f"[benchmark] {len(eligible_users)} eligible users with ≥8 sessions, {len(sessions)} total sessions")

    # 3. Inject T1078 attacks
    sessions_aug, labels = inject_t1078_sessions(sessions, eligible_users, attack_rate=0.12)

    # 4. Train/test split — first 70% of each user's sessions = train, rest = test
    sessions_train, features_train_list = [], []
    sessions_test,  features_test_list  = [], []
    labels_test = []

    user_session_idx = defaultdict(int)
    user_total = defaultdict(int)
    for s in sessions:
        user_total[s['user']] += 1

    # We re-partition the augmented set
    user_seen = defaultdict(int)
    for sess, label in zip(sessions_aug, labels):
        user = sess['user']
        cutoff = int(user_total[user] * 0.70)
        if label == 0 and user_seen[user] < cutoff:  # only normal sessions in train
            sessions_train.append(sess)
            features_train_list.append(None)  # fill after
            user_seen[user] += 1
        else:
            sessions_test.append(sess)
            labels_test.append(label)

    features_train = sessions_to_features(sessions_train)
    features_test  = sessions_to_features(sessions_test)
    features_train_list = list(features_train)

    print(f"\n[benchmark] Train: {len(sessions_train)} normal sessions")
    print(f"[benchmark] Test:  {len(sessions_test)} sessions ({sum(labels_test)} attacks, "
          f"{len(labels_test)-sum(labels_test)} normal)")

    # 5. Run both methods
    results = {}
    results['IsolationForest'] = run_isolation_forest(features_train, features_test, labels_test)
    results['TAARA_V3']        = run_taara_pipeline(sessions_train, features_train,
                                                     sessions_test,  features_test, labels_test)

    # 6. Key comparison
    print("\n" + "=" * 70)
    print("BENCHMARK SUMMARY")
    print("=" * 70)
    print(f"{'Method':<20} {'TPR':>8} {'FPR':>8} {'Precision':>10} {'F1':>8}")
    print("-" * 60)
    for name, r in results.items():
        print(f"{name:<20} {r['tpr']:>8.3f} {r['fpr']:>8.3f} {r['precision']:>10.3f} {r['f1']:>8.3f}")

    taara = results['TAARA_V3']
    iso   = results['IsolationForest']
    tpr_delta  = taara['tpr']  - iso['tpr']
    fpr_delta  = taara['fpr']  - iso['fpr']

    print(f"\nTPR improvement: {tpr_delta:+.3f}  ({'TAARA better' if tpr_delta > 0 else 'IF better'})")
    print(f"FPR change:      {fpr_delta:+.3f}  ({'TAARA fewer false alarms' if fpr_delta < 0 else 'IF fewer false alarms'})")

    elapsed = time.time() - t_start

    # 7. Save results
    output = {
        'dataset': 'LogHub_SSH_655k',
        'dataset_url': 'https://zenodo.org/record/8196385',
        'threat': 'T1078_Valid_Accounts',
        'mitre': 'T1078.003 Local Accounts',
        'attack_simulation': 'Within global ±2σ statistical range (classical threshold evasion)',
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'runtime_seconds': round(elapsed, 1),
        'results': results,
        'summary': {
            'taara_tpr': taara['tpr'],
            'if_tpr':    iso['tpr'],
            'taara_fpr': taara['fpr'],
            'if_fpr':    iso['fpr'],
            'taara_f1':  taara['f1'],
            'if_f1':     iso['f1'],
            'tpr_improvement': round(tpr_delta, 4),
        }
    }

    results_path = os.path.join(RESULTS_DIR, 'benchmark_results.json')
    with open(results_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\n[benchmark] Results saved to {results_path}")

    report = f"""TAARA T1078 Benchmark Report
============================
Dataset:   LogHub SSH (655,146 lines, Zenodo 8196385)
Threat:    MITRE ATT&CK T1078 Valid Account Compromise
Test:      Attacks injected WITHIN global ±2σ statistical range
           (the exact scenario where classical threshold detectors fail)

Results
-------
                     TPR        FPR     Precision        F1
IsolationForest    {iso['tpr']:.3f}      {iso['fpr']:.3f}       {iso['precision']:.3f}      {iso['f1']:.3f}
TAARA V3           {taara['tpr']:.3f}      {taara['fpr']:.3f}       {taara['precision']:.3f}      {taara['f1']:.3f}

TPR improvement over IsolationForest: {tpr_delta:+.3f}
FPR change:                           {fpr_delta:+.3f}

Attack counts:
  TAARA detected:  {taara['tp']} / {taara['total_attacks']}
  IF detected:     {iso['tp']} / {iso['total_attacks']}
  TAARA false alarms: {taara['fp']} / {taara['total_normal']}
  IF false alarms:    {iso['fp']} / {iso['total_normal']}

Runtime: {elapsed:.1f}s
"""

    report_path = os.path.join(RESULTS_DIR, 'benchmark_report.txt')
    with open(report_path, 'w') as f:
        f.write(report)
    print(f"[benchmark] Report saved to {report_path}")
    print(report)


if __name__ == '__main__':
    main()
