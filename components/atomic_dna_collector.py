"""
Atomic Digital DNA Collector
=============================

Collects low-level, observable, composable system behaviors.

Atomic criteria:
1. Directly observable (from /proc, ps, netstat, ls)
2. Low-level (not semantic, not inferred)
3. Composable (can be combined to infer higher behavior)
4. Hard to spoof independently

Categories:
- Process Behavior (6 features)
- Network Behavior (6 features)
- File System Behavior (4 features)
- Temporal Behavior (3 features)

Total: 19 atomic features
"""

import time
import json
import math
from typing import Dict, Any, List
from collections import defaultdict
import numpy as np


class AtomicDNACollector:
    """Collects atomic behavioral features from a remote system via SSH."""

    def __init__(self, ssh_manager):
        self.ssh_manager = ssh_manager
        self.history = []  # For temporal analysis
        self.last_collection_time = None

    def collect(self) -> Dict[str, float]:
        """
        Collect all atomic DNA features.

        Returns:
            dict: Atomic feature vector with 19+ features
        """
        features = {}

        # Collect each category
        features.update(self._collect_process_behavior())
        features.update(self._collect_network_behavior())
        features.update(self._collect_filesystem_behavior())
        features.update(self._collect_temporal_behavior())

        # Store for temporal analysis
        current_time = time.time()
        self.history.append({
            'timestamp': current_time,
            'features': features.copy()
        })

        # Keep only last 30 samples (for temporal analysis)
        if len(self.history) > 30:
            self.history = self.history[-30:]

        self.last_collection_time = current_time

        return features

    # ========================================================================
    # PROCESS BEHAVIOR (6 features)
    # ========================================================================

    def _collect_process_behavior(self) -> Dict[str, float]:
        """Collect atomic process behavior features."""
        features = {}

        try:
            # Get all processes with details
            cmd = "ps -eo pid,ppid,uid,etime,comm --no-headers"
            stdout, _, _ = self.ssh_manager.execute_command(cmd)

            if not stdout:
                return self._get_fallback_process_features()

            processes = []
            for line in stdout.strip().split('\n'):
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        processes.append({
                            'pid': int(parts[0]),
                            'ppid': int(parts[1]),
                            'uid': int(parts[2]),
                            'etime': parts[3],
                            'comm': ' '.join(parts[4:])
                        })
                    except ValueError:
                        continue

            if not processes:
                return self._get_fallback_process_features()

            # Feature 1: Process spawn rate (processes per minute)
            # Estimate: count processes < 1 minute old
            short_lived = 0
            for p in processes:
                if self._parse_etime_seconds(p['etime']) < 60:
                    short_lived += 1
            features['proc_spawn_rate'] = float(short_lived)

            # Feature 2: Short-lived process ratio
            very_short = sum(1 for p in processes if self._parse_etime_seconds(p['etime']) < 5)
            features['proc_short_lived_ratio'] = very_short / max(len(processes), 1)

            # Feature 3: Max process tree depth
            features['proc_tree_depth_max'] = float(self._compute_max_tree_depth(processes))

            # Feature 4: UID diversity
            unique_uids = len(set(p['uid'] for p in processes))
            features['proc_uid_diversity'] = float(unique_uids)

            # Feature 5: Root process ratio
            root_procs = sum(1 for p in processes if p['uid'] == 0)
            features['proc_root_ratio'] = root_procs / max(len(processes), 1)

            # Feature 6: Command entropy
            commands = [p['comm'] for p in processes]
            features['proc_cmd_entropy'] = self._compute_entropy(commands)

        except Exception as e:
            print(f"[AtomicDNA] Process collection error: {e}")
            features.update(self._get_fallback_process_features())

        return features

    # ========================================================================
    # NETWORK BEHAVIOR (6 features)
    # ========================================================================

    def _collect_network_behavior(self) -> Dict[str, float]:
        """Collect atomic network behavior features."""
        features = {}

        try:
            # Get network connections
            # ss is more reliable than netstat
            cmd = "ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null || echo 'SKIP'"
            stdout, _, _ = self.ssh_manager.execute_command(cmd)

            if not stdout or stdout.strip() == 'SKIP':
                return self._get_fallback_network_features()

            connections = stdout.strip().split('\n')[1:]  # Skip header

            # Parse connections
            outbound = []
            failed = 0
            dst_ips = set()
            dst_ports = set()

            for line in connections:
                parts = line.split()
                if len(parts) < 5:
                    continue

                state = parts[0] if 'tcp' in parts[0].lower() else 'UNKNOWN'
                local_addr = parts[3] if len(parts) > 3 else ''
                remote_addr = parts[4] if len(parts) > 4 else ''

                # Skip listening sockets
                if 'LISTEN' in state or '*:*' in remote_addr:
                    continue

                # Extract remote IP and port
                if ':' in remote_addr:
                    ip_port = remote_addr.rsplit(':', 1)
                    if len(ip_port) == 2:
                        dst_ips.add(ip_port[0])
                        try:
                            dst_ports.add(int(ip_port[1]))
                        except ValueError:
                            pass

                outbound.append(line)

                # Count failed connections (time-wait, close-wait)
                if any(x in state.upper() for x in ['TIME-WAIT', 'CLOSE-WAIT', 'FIN-WAIT']):
                    failed += 1

            # Feature 1: Outbound connection rate (active connections per sample)
            features['net_outbound_conn_rate'] = float(len(outbound))

            # Feature 2: Unique destination IPs
            features['net_unique_dst_ips'] = float(len(dst_ips))

            # Feature 3: Unique destination ports
            features['net_unique_dst_ports'] = float(len(dst_ports))

            # Feature 4: Port entropy
            features['net_port_entropy'] = self._compute_entropy(list(dst_ports))

            # Feature 5: DNS query rate (estimate from /etc/resolv.conf usage)
            # Note: This is a crude estimate; real DNS monitoring needs tcpdump
            features['net_dns_query_rate'] = 0.0  # Placeholder - safe to skip

            # Feature 6: Failed connection ratio
            features['net_failed_conn_ratio'] = failed / max(len(outbound), 1)

        except Exception as e:
            print(f"[AtomicDNA] Network collection error: {e}")
            features.update(self._get_fallback_network_features())

        return features

    # ========================================================================
    # FILESYSTEM BEHAVIOR (4 features)
    # ========================================================================

    def _collect_filesystem_behavior(self) -> Dict[str, float]:
        """Collect atomic filesystem behavior features."""
        features = {}

        try:
            # Feature 1: Sensitive file access (check recent access to /etc, /root, ~/.ssh)
            # We check modification times in last 5 minutes
            sensitive_paths = ['/etc', '/root', '$HOME/.ssh']
            sensitive_touched = 0

            for path in sensitive_paths:
                cmd = f"find {path} -type f -mmin -5 2>/dev/null | wc -l"
                stdout, _, _ = self.ssh_manager.execute_command(cmd)
                try:
                    count = int(stdout.strip())
                    if count > 0:
                        sensitive_touched = 1
                        break
                except (ValueError, AttributeError):
                    pass

            features['fs_sensitive_access'] = float(sensitive_touched)

            # Feature 2: File write rate (files modified in last minute)
            cmd = "find /tmp /var/tmp /home -type f -mmin -1 2>/dev/null | wc -l"
            stdout, _, _ = self.ssh_manager.execute_command(cmd)
            try:
                features['fs_write_rate'] = float(stdout.strip())
            except (ValueError, AttributeError):
                features['fs_write_rate'] = 0.0

            # Feature 3: Execution from tmp (check for executables in /tmp, /dev/shm)
            cmd = "find /tmp /dev/shm -type f -executable 2>/dev/null | wc -l"
            stdout, _, _ = self.ssh_manager.execute_command(cmd)
            try:
                exec_count = int(stdout.strip())
                features['fs_exec_from_tmp'] = float(min(exec_count, 1))  # Boolean-like
            except (ValueError, AttributeError):
                features['fs_exec_from_tmp'] = 0.0

            # Feature 4: Hidden file ratio (in /tmp)
            cmd_total = "find /tmp -maxdepth 2 -type f 2>/dev/null | wc -l"
            cmd_hidden = "find /tmp -maxdepth 2 -type f -name '.*' 2>/dev/null | wc -l"

            stdout_total, _, _ = self.ssh_manager.execute_command(cmd_total)
            stdout_hidden, _, _ = self.ssh_manager.execute_command(cmd_hidden)

            try:
                total = int(stdout_total.strip())
                hidden = int(stdout_hidden.strip())
                features['fs_hidden_file_ratio'] = hidden / max(total, 1)
            except (ValueError, AttributeError):
                features['fs_hidden_file_ratio'] = 0.0

        except Exception as e:
            print(f"[AtomicDNA] Filesystem collection error: {e}")
            features.update(self._get_fallback_filesystem_features())

        return features

    # ========================================================================
    # TEMPORAL BEHAVIOR (3 features)
    # ========================================================================

    def _collect_temporal_behavior(self) -> Dict[str, float]:
        """Collect temporal rhythm features."""
        features = {}

        try:
            # Feature 1: Time of day deviation (distance from typical activity hours)
            current_hour = time.localtime().tm_hour

            # Compute historical activity distribution
            if len(self.history) >= 5:
                historical_hours = [time.localtime(h['timestamp']).tm_hour for h in self.history]
                avg_hour = sum(historical_hours) / len(historical_hours)
                hour_std = np.std(historical_hours)

                # Deviation in standard deviations
                deviation = abs(current_hour - avg_hour) / max(hour_std, 1.0)
                features['time_of_day_deviation'] = min(deviation, 10.0)  # Cap at 10
            else:
                features['time_of_day_deviation'] = 0.0

            # Feature 2: Burstiness score (variance in activity)
            if len(self.history) >= 3:
                # Use process spawn rate variance as proxy
                spawn_rates = [h['features'].get('proc_spawn_rate', 0) for h in self.history[-10:]]
                features['burstiness_score'] = float(np.var(spawn_rates))
            else:
                features['burstiness_score'] = 0.0

            # Feature 3: Sequence compactness (how tightly actions cluster)
            if len(self.history) >= 3:
                timestamps = [h['timestamp'] for h in self.history[-5:]]
                time_diffs = np.diff(timestamps)
                # Lower variance = more compact
                features['sequence_compactness'] = 1.0 / (1.0 + float(np.var(time_diffs)))
            else:
                features['sequence_compactness'] = 0.0

        except Exception as e:
            print(f"[AtomicDNA] Temporal collection error: {e}")
            features.update(self._get_fallback_temporal_features())

        return features

    # ========================================================================
    # HELPER METHODS
    # ========================================================================

    def _parse_etime_seconds(self, etime: str) -> int:
        """Parse ps etime (elapsed time) to seconds."""
        try:
            # Format can be: MM:SS, HH:MM:SS, DD-HH:MM:SS
            parts = etime.replace('-', ':').split(':')
            parts = [int(p) for p in parts]

            if len(parts) == 2:  # MM:SS
                return parts[0] * 60 + parts[1]
            elif len(parts) == 3:  # HH:MM:SS
                return parts[0] * 3600 + parts[1] * 60 + parts[2]
            elif len(parts) == 4:  # DD-HH:MM:SS
                return parts[0] * 86400 + parts[1] * 3600 + parts[2] * 60 + parts[3]
            else:
                return 0
        except (ValueError, IndexError):
            return 0

    def _compute_max_tree_depth(self, processes: List[Dict]) -> int:
        """Compute maximum process tree depth."""
        # Build parent map
        children = defaultdict(list)
        for p in processes:
            children[p['ppid']].append(p['pid'])

        # DFS to find max depth
        def dfs(pid, depth=0):
            if pid not in children:
                return depth
            return max(dfs(child, depth + 1) for child in children[pid])

        # Start from init (pid 1) or find roots
        roots = [p['pid'] for p in processes if p['ppid'] == 0 or p['ppid'] == 1]
        if not roots:
            roots = [1]

        return max(dfs(root) for root in roots)

    def _compute_entropy(self, items: List) -> float:
        """Compute Shannon entropy of a list."""
        if not items:
            return 0.0

        # Count frequencies
        freq = defaultdict(int)
        for item in items:
            freq[str(item)] += 1

        total = len(items)
        entropy = 0.0

        for count in freq.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy

    # ========================================================================
    # FALLBACK METHODS (for safe degradation)
    # ========================================================================

    def _get_fallback_process_features(self) -> Dict[str, float]:
        """Return safe defaults for process features."""
        return {
            'proc_spawn_rate': 0.0,
            'proc_short_lived_ratio': 0.0,
            'proc_tree_depth_max': 1.0,
            'proc_uid_diversity': 1.0,
            'proc_root_ratio': 0.0,
            'proc_cmd_entropy': 0.0
        }

    def _get_fallback_network_features(self) -> Dict[str, float]:
        """Return safe defaults for network features."""
        return {
            'net_outbound_conn_rate': 0.0,
            'net_unique_dst_ips': 0.0,
            'net_unique_dst_ports': 0.0,
            'net_port_entropy': 0.0,
            'net_dns_query_rate': 0.0,
            'net_failed_conn_ratio': 0.0
        }

    def _get_fallback_filesystem_features(self) -> Dict[str, float]:
        """Return safe defaults for filesystem features."""
        return {
            'fs_sensitive_access': 0.0,
            'fs_write_rate': 0.0,
            'fs_exec_from_tmp': 0.0,
            'fs_hidden_file_ratio': 0.0
        }

    def _get_fallback_temporal_features(self) -> Dict[str, float]:
        """Return safe defaults for temporal features."""
        return {
            'time_of_day_deviation': 0.0,
            'burstiness_score': 0.0,
            'sequence_compactness': 0.0
        }

    def get_feature_vector(self) -> np.ndarray:
        """
        Collect and normalize features into a vector.

        Returns:
            np.ndarray: Normalized feature vector (19 dimensions)
        """
        features = self.collect()

        # Feature order (must be consistent!)
        feature_names = [
            # Process (6)
            'proc_spawn_rate', 'proc_short_lived_ratio', 'proc_tree_depth_max',
            'proc_uid_diversity', 'proc_root_ratio', 'proc_cmd_entropy',
            # Network (6)
            'net_outbound_conn_rate', 'net_unique_dst_ips', 'net_unique_dst_ports',
            'net_port_entropy', 'net_dns_query_rate', 'net_failed_conn_ratio',
            # Filesystem (4)
            'fs_sensitive_access', 'fs_write_rate', 'fs_exec_from_tmp', 'fs_hidden_file_ratio',
            # Temporal (3)
            'time_of_day_deviation', 'burstiness_score', 'sequence_compactness'
        ]

        vector = [features.get(name, 0.0) for name in feature_names]
        return np.array(vector, dtype=np.float32)

    def get_feature_names(self) -> List[str]:
        """Return ordered list of feature names."""
        return [
            'proc_spawn_rate', 'proc_short_lived_ratio', 'proc_tree_depth_max',
            'proc_uid_diversity', 'proc_root_ratio', 'proc_cmd_entropy',
            'net_outbound_conn_rate', 'net_unique_dst_ips', 'net_unique_dst_ports',
            'net_port_entropy', 'net_dns_query_rate', 'net_failed_conn_ratio',
            'fs_sensitive_access', 'fs_write_rate', 'fs_exec_from_tmp', 'fs_hidden_file_ratio',
            'time_of_day_deviation', 'burstiness_score', 'sequence_compactness'
        ]
