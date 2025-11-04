"""
Comprehensive System Monitor Agent
Collects real-time data: containers, services, processes, network, resources
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import json


class MonitorAgent:
    """Collects comprehensive system metrics and container data."""

    def __init__(self, ssh_manager):
        self.ssh_manager = ssh_manager
        self.last_collection = None

    def collect_all_metrics(self) -> Dict[str, Any]:
        """Collect comprehensive system state."""
        data = {
            "timestamp": datetime.now().isoformat(),
            "containers": self.get_docker_containers(),
            "services": self.get_system_services(),
            "processes": self.get_top_processes(),
            "network": self.get_network_connections(),
            "resources": self.get_resource_usage(),
            "disk": self.get_disk_usage(),
            "security": self.get_security_status()
        }
        self.last_collection = data
        return data

    def get_docker_containers(self) -> List[Dict[str, Any]]:
        """Get all Docker containers with details."""
        try:
            # Get container list with formatting
            cmd = """docker ps -a --format '{"id":"{{.ID}}", "name":"{{.Names}}", "image":"{{.Image}}", "status":"{{.Status}}", "ports":"{{.Ports}}"}'"""
            out, err, code = self.ssh_manager.execute_command(cmd)

            if code != 0 or not out.strip():
                return []

            containers = []
            for line in out.strip().split('\n'):
                if line.strip():
                    try:
                        container = json.loads(line)

                        # Get container stats
                        stats_cmd = f"docker stats {container['id']} --no-stream --format '{{{{json .}}}}'"
                        stats_out, _, stats_code = self.ssh_manager.execute_command(stats_cmd)

                        if stats_code == 0 and stats_out.strip():
                            stats = json.loads(stats_out.strip())
                            container['cpu'] = stats.get('CPUPerc', 'N/A')
                            container['memory'] = stats.get('MemPerc', 'N/A')
                            container['net_io'] = stats.get('NetIO', 'N/A')
                            container['block_io'] = stats.get('BlockIO', 'N/A')

                        # Determine status color
                        status_lower = container['status'].lower()
                        if 'up' in status_lower:
                            container['status_color'] = '🟢'
                            container['state'] = 'running'
                        elif 'exited' in status_lower:
                            container['status_color'] = '🔴'
                            container['state'] = 'stopped'
                        elif 'paused' in status_lower:
                            container['status_color'] = '🟡'
                            container['state'] = 'paused'
                        else:
                            container['status_color'] = '⚪'
                            container['state'] = 'unknown'

                        containers.append(container)
                    except json.JSONDecodeError:
                        continue

            return containers
        except Exception as e:
            print(f"[Monitor] Docker collection error: {e}")
            return []

    def get_system_services(self) -> List[Dict[str, Any]]:
        """Get systemd services status."""
        try:
            cmd = "systemctl list-units --type=service --state=running --no-pager --no-legend | head -20"
            out, err, code = self.ssh_manager.execute_command(cmd)

            if code != 0:
                return []

            services = []
            for line in out.strip().split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 4:
                        services.append({
                            'name': parts[0].replace('.service', ''),
                            'load': parts[1],
                            'active': parts[2],
                            'sub': parts[3],
                            'status_color': '🟢' if parts[2] == 'active' else '🔴'
                        })

            return services
        except Exception as e:
            print(f"[Monitor] Services collection error: {e}")
            return []

    def get_top_processes(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top CPU-consuming processes."""
        try:
            cmd = "ps aux --sort=-%cpu | head -11 | tail -10"
            out, err, code = self.ssh_manager.execute_command(cmd)

            if code != 0:
                return []

            processes = []
            for line in out.strip().split('\n'):
                if line.strip():
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        processes.append({
                            'user': parts[0],
                            'pid': parts[1],
                            'cpu': parts[2],
                            'mem': parts[3],
                            'vsz': parts[4],
                            'rss': parts[5],
                            'tty': parts[6],
                            'stat': parts[7],
                            'start': parts[8],
                            'time': parts[9],
                            'command': parts[10][:50]  # Truncate long commands
                        })

            return processes
        except Exception as e:
            print(f"[Monitor] Process collection error: {e}")
            return []

    def get_network_connections(self) -> Dict[str, Any]:
        """Get network connection statistics."""
        try:
            # Listening ports
            listen_cmd = "netstat -tuln 2>/dev/null | grep LISTEN | wc -l"
            listen_out, _, _ = self.ssh_manager.execute_command(listen_cmd)

            # Established connections
            estab_cmd = "netstat -tun 2>/dev/null | grep ESTABLISHED | wc -l"
            estab_out, _, _ = self.ssh_manager.execute_command(estab_cmd)

            # Get specific listening services
            services_cmd = "netstat -tulnp 2>/dev/null | grep LISTEN | head -10"
            services_out, _, _ = self.ssh_manager.execute_command(services_cmd)

            listening_services = []
            for line in services_out.strip().split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 4:
                        listening_services.append({
                            'proto': parts[0],
                            'local_address': parts[3],
                            'port': parts[3].split(':')[-1],
                            'program': parts[-1] if len(parts) > 6 else 'unknown'
                        })

            return {
                'listening_ports': int(listen_out.strip()) if listen_out.strip().isdigit() else 0,
                'established_connections': int(estab_out.strip()) if estab_out.strip().isdigit() else 0,
                'listening_services': listening_services
            }
        except Exception as e:
            print(f"[Monitor] Network collection error: {e}")
            return {'listening_ports': 0, 'established_connections': 0, 'listening_services': []}

    def get_resource_usage(self) -> Dict[str, Any]:
        """Get detailed resource usage."""
        try:
            resources = {}

            # CPU usage
            cpu_cmd = "top -bn1 | grep 'Cpu(s)' | awk '{print $2}'"
            cpu_out, _, _ = self.ssh_manager.execute_command(cpu_cmd)
            cpu_val = cpu_out.strip().replace('%us,', '').replace('us,', '')
            resources['cpu_percent'] = float(cpu_val) if cpu_val else 0.0

            # Memory usage
            mem_cmd = "free | grep Mem | awk '{printf \"%.1f %.1f %.1f\", $3/$2*100, $2/1024/1024, $3/1024/1024}'"
            mem_out, _, _ = self.ssh_manager.execute_command(mem_cmd)
            if mem_out.strip():
                parts = mem_out.strip().split()
                resources['memory_percent'] = float(parts[0]) if len(parts) > 0 else 0.0
                resources['memory_total_gb'] = float(parts[1]) if len(parts) > 1 else 0.0
                resources['memory_used_gb'] = float(parts[2]) if len(parts) > 2 else 0.0

            # Load average
            load_cmd = "uptime | awk -F'load average:' '{print $2}'"
            load_out, _, _ = self.ssh_manager.execute_command(load_cmd)
            if load_out.strip():
                loads = load_out.strip().split(',')
                resources['load_1min'] = float(loads[0].strip()) if len(loads) > 0 else 0.0
                resources['load_5min'] = float(loads[1].strip()) if len(loads) > 1 else 0.0
                resources['load_15min'] = float(loads[2].strip()) if len(loads) > 2 else 0.0

            # Process count
            proc_cmd = "ps aux | wc -l"
            proc_out, _, _ = self.ssh_manager.execute_command(proc_cmd)
            resources['process_count'] = int(proc_out.strip()) if proc_out.strip().isdigit() else 0

            return resources
        except Exception as e:
            print(f"[Monitor] Resource collection error: {e}")
            return {}

    def get_disk_usage(self) -> List[Dict[str, Any]]:
        """Get disk usage for all mounted filesystems."""
        try:
            cmd = "df -h | grep -E '^/dev/' | awk '{print $1, $2, $3, $4, $5, $6}'"
            out, err, code = self.ssh_manager.execute_command(cmd)

            if code != 0:
                return []

            disks = []
            for line in out.strip().split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 6:
                        usage_percent = int(parts[4].replace('%', ''))
                        disks.append({
                            'device': parts[0],
                            'size': parts[1],
                            'used': parts[2],
                            'available': parts[3],
                            'usage_percent': usage_percent,
                            'mount': parts[5],
                            'status_color': '🔴' if usage_percent > 90 else '🟡' if usage_percent > 75 else '🟢'
                        })

            return disks
        except Exception as e:
            print(f"[Monitor] Disk collection error: {e}")
            return []

    def get_security_status(self) -> Dict[str, Any]:
        """Get quick security indicators."""
        try:
            security = {}

            # Check for failed SSH attempts (last 100 lines)
            ssh_fail_cmd = "grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -100 | wc -l"
            ssh_out, _, _ = self.ssh_manager.execute_command(ssh_fail_cmd)
            security['recent_ssh_failures'] = int(ssh_out.strip()) if ssh_out.strip().isdigit() else 0

            # Check for active firewall (UFW, iptables, or firewalld) - WITH SUDO
            firewall_active = False
            firewall_type = "none"

            # Check UFW with sudo
            ufw_cmd = "sudo ufw status 2>/dev/null"
            ufw_out, _, ufw_code = self.ssh_manager.execute_command(ufw_cmd)
            if "Status: active" in ufw_out:
                firewall_active = True
                firewall_type = "ufw"

            # Check iptables if UFW not active
            if not firewall_active:
                # Count iptables rules - more reliable
                ipt_cmd = "sudo iptables -L INPUT -n 2>/dev/null | grep -v 'Chain\|target' | wc -l"
                ipt_out, _, ipt_code = self.ssh_manager.execute_command(ipt_cmd)
                if ipt_code == 0 and ipt_out.strip().isdigit():
                    rule_count = int(ipt_out.strip())
                    # If there are actual rules (not just default), firewall is active
                    if rule_count > 0:
                        firewall_active = True
                        firewall_type = "iptables"
                    else:
                        # Double-check total line count
                        ipt_cmd2 = "sudo iptables -L 2>/dev/null | wc -l"
                        ipt_out2, _, _ = self.ssh_manager.execute_command(ipt_cmd2)
                        if ipt_out2.strip().isdigit() and int(ipt_out2.strip()) > 10:
                            firewall_active = True
                            firewall_type = "iptables"

            # Check firewalld
            if not firewall_active:
                fwd_cmd = "sudo systemctl is-active firewalld 2>/dev/null"
                fwd_out, _, fwd_code = self.ssh_manager.execute_command(fwd_cmd)
                if "active" in fwd_out.lower():
                    firewall_active = True
                    firewall_type = "firewalld"

            security['firewall_active'] = firewall_active
            security['firewall_type'] = firewall_type

            # Check for rootkit scanner (rkhunter)
            rkhunter_cmd = "which rkhunter 2>/dev/null | wc -l"
            rkh_out, _, _ = self.ssh_manager.execute_command(rkhunter_cmd)
            security['rootkit_scanner'] = int(rkh_out.strip()) > 0 if rkh_out.strip().isdigit() else False

            # Check for ClamAV
            clam_cmd = "which clamscan 2>/dev/null"
            clam_out, _, _ = self.ssh_manager.execute_command(clam_cmd)
            security['clamav_installed'] = bool(clam_out.strip())

            # Check for CrowdSec
            crowdsec_cmd = "which cscli 2>/dev/null"
            crowdsec_out, _, _ = self.ssh_manager.execute_command(crowdsec_cmd)
            security['crowdsec_installed'] = bool(crowdsec_out.strip())

            # Check last login
            lastlog_cmd = "last -1 | head -1"
            last_out, _, _ = self.ssh_manager.execute_command(lastlog_cmd)
            security['last_login'] = last_out.strip()[:100] if last_out.strip() else "Unknown"

            return security
        except Exception as e:
            print(f"[Monitor] Security status error: {e}")
            return {}

    def get_container_logs(self, container_id: str, lines: int = 50) -> str:
        """Get recent logs from a specific container."""
        try:
            cmd = f"docker logs {container_id} --tail {lines} 2>&1"
            out, err, code = self.ssh_manager.execute_command(cmd)
            return out if code == 0 else err
        except Exception as e:
            return f"Error fetching logs: {e}"

    def get_service_logs(self, service_name: str, lines: int = 50) -> str:
        """Get recent logs from a systemd service."""
        try:
            cmd = f"journalctl -u {service_name} -n {lines} --no-pager"
            out, err, code = self.ssh_manager.execute_command(cmd)
            return out if code == 0 else err
        except Exception as e:
            return f"Error fetching logs: {e}"
