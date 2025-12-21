"""
Safe Execution Engine
=====================

CRITICAL: VPS SAFETY

Only ONE automated action allowed:
    - Enhanced Monitoring Mode

Enhanced Monitoring includes:
    - Short tcpdump (10 seconds, 100 packets max)
    - Verbose logging (increase log level temporarily)
    - Process tree snapshot
    - Network connection snapshot

NO:
    - Firewall changes
    - Process killing
    - Service restarts
    - Configuration modifications
    - Package installations

All actions:
    - Reversible
    - Low blast-radius
    - Logged
    - Time-limited
"""

import time
from typing import Dict, Any


class SafeExecutor:
    """Executes ONLY safe, read-only monitoring actions."""

    def __init__(self):
        self.allowed_actions = ['enhanced_monitoring']

    def execute_enhanced_monitoring(self, ssh_manager) -> Dict[str, Any]:
        """
        Execute enhanced monitoring (SAFE auto-action).

        Actions:
            1. Capture 10 seconds of network traffic (tcpdump)
            2. Snapshot process tree
            3. Snapshot network connections
            4. Snapshot open files

        Returns:
            dict: {
                'status': 'success' or 'error',
                'timestamp': float,
                'duration': float,
                'results': {
                    'network_capture': str,
                    'process_tree': str,
                    'connections': str,
                    'open_files': str
                },
                'message': str
            }
        """
        start_time = time.time()
        results = {}

        try:
            print("[SafeExecutor] Starting enhanced monitoring...")

            # 1. Network capture (10 seconds, 100 packets max)
            # Check if tcpdump is available
            stdout, stderr, code = ssh_manager.execute_command("which tcpdump")

            if code == 0 and stdout.strip():
                # tcpdump available
                cmd = "timeout 10 sudo tcpdump -c 100 -nn -q 2>/dev/null || echo 'tcpdump not available or requires sudo'"
                stdout, stderr, code = ssh_manager.execute_command(cmd)
                results['network_capture'] = stdout.strip() if stdout else "No network data captured"
            else:
                results['network_capture'] = "tcpdump not available (skipped)"

            # 2. Process tree snapshot
            cmd = "ps auxf --forest 2>/dev/null || ps auxf 2>/dev/null || ps aux"
            stdout, stderr, code = ssh_manager.execute_command(cmd)
            results['process_tree'] = stdout.strip() if stdout else "Process tree unavailable"

            # 3. Network connections snapshot
            cmd = "ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null"
            stdout, stderr, code = ssh_manager.execute_command(cmd)
            results['connections'] = stdout.strip() if stdout else "Network connections unavailable"

            # 4. Open files (top 20 by process)
            cmd = "lsof -n 2>/dev/null | head -100 || echo 'lsof not available'"
            stdout, stderr, code = ssh_manager.execute_command(cmd)
            results['open_files'] = stdout.strip() if stdout else "Open files unavailable"

            duration = time.time() - start_time

            print(f"[SafeExecutor] Enhanced monitoring complete ({duration:.2f}s)")

            return {
                'status': 'success',
                'timestamp': start_time,
                'duration': duration,
                'results': results,
                'message': f'Enhanced monitoring completed in {duration:.2f}s'
            }

        except Exception as e:
            duration = time.time() - start_time

            return {
                'status': 'error',
                'timestamp': start_time,
                'duration': duration,
                'results': results,
                'message': f'Enhanced monitoring failed: {str(e)}'
            }

    def is_safe_action(self, action: str) -> bool:
        """Check if action is allowed for automatic execution."""
        return action in self.allowed_actions

    def get_allowed_actions(self) -> list:
        """Return list of allowed auto-actions."""
        return self.allowed_actions.copy()
