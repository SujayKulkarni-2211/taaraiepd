"""
Multi-Platform Connection Manager
==================================

Unified interface for connecting to and collecting data from:
- SSH (Linux/Unix servers)
- AWS (EC2, IAM, S3, CloudWatch, CloudTrail, Cost Explorer)
- GCP (Compute Engine, IAM, Cloud Monitoring, Cloud Billing)
- Azure (VMs, Active Directory, Monitor, Cost Management)
- Docker (containers, images, networks)
- Kubernetes (pods, services, RBAC, network policies)

Each platform implements a common interface for security data collection,
metrics collection, and cost data collection.
"""

import json
import time
import os
from typing import Dict, List, Optional, Tuple, Any
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
import numpy as np


class PlatformBase(ABC):
    """Abstract base class for all platform connectors."""

    def __init__(self, platform_type: str, config: Dict):
        self.platform_type = platform_type
        self.config = config
        self.connected = False
        self.connection_time = None
        self.last_error = None

    @abstractmethod
    def connect(self) -> bool:
        """Establish connection to the platform."""
        pass

    @abstractmethod
    def disconnect(self):
        """Close connection."""
        pass

    @abstractmethod
    def collect_security_data(self) -> Dict:
        """Collect security-relevant data from the platform."""
        pass

    @abstractmethod
    def collect_metrics(self) -> Dict:
        """Collect system/service metrics."""
        pass

    @abstractmethod
    def collect_cost_data(self) -> Dict:
        """Collect cost/spending data (for cloud platforms)."""
        pass

    @abstractmethod
    def get_platform_info(self) -> Dict:
        """Get platform metadata and status."""
        pass

    def get_feature_vector(self, security_data: Dict) -> np.ndarray:
        """Extract a numerical feature vector from security data for ML analysis."""
        features = []
        for key, value in sorted(security_data.get('features', {}).items()):
            if isinstance(value, (int, float)):
                features.append(float(value))
        if not features:
            features = [0.0] * 19
        return np.array(features, dtype=np.float32)


class SSHPlatform(PlatformBase):
    """SSH-based Linux/Unix server platform."""

    def __init__(self, config: Dict):
        super().__init__('ssh', config)
        self.client = None

    def connect(self) -> bool:
        try:
            import paramiko
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                self.config['host'],
                port=self.config.get('port', 22),
                username=self.config['username'],
                password=self.config.get('password'),
                key_filename=self.config.get('key_file'),
                timeout=15
            )
            self.connected = True
            self.connection_time = time.time()
            return True
        except Exception as e:
            self.last_error = str(e)
            self.connected = False
            return False

    def disconnect(self):
        if self.client:
            self.client.close()
        self.connected = False

    def execute_command(self, cmd: str) -> Tuple[str, str, int]:
        if not self.client:
            return "", "Not connected", 1
        try:
            stdin, stdout, stderr = self.client.exec_command(cmd, timeout=30)
            out = stdout.read().decode('utf-8', errors='ignore')
            err = stderr.read().decode('utf-8', errors='ignore')
            code = stdout.channel.recv_exit_status()
            return out, err, code
        except Exception as e:
            return "", str(e), 1

    def collect_security_data(self) -> Dict:
        findings = {
            'platform': 'ssh',
            'host': self.config.get('host', 'unknown'),
            'timestamp': time.time(),
            'categories': {},
            'features': {},
            'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        }

        findings['categories']['open_ports'] = self._scan_open_ports()
        findings['categories']['user_audit'] = self._audit_users()
        findings['categories']['auth_logs'] = self._check_auth_logs()
        findings['categories']['file_permissions'] = self._check_file_permissions()
        findings['categories']['running_processes'] = self._check_processes()
        findings['categories']['network_connections'] = self._check_network()
        findings['categories']['system_info'] = self._get_system_info()

        findings['features'] = self._extract_features(findings['categories'])

        for cat in findings['categories'].values():
            for finding in cat.get('findings', []):
                sev = finding.get('severity', 'info').lower()
                if sev in findings['summary']:
                    findings['summary'][sev] += 1

        return findings

    def _scan_open_ports(self) -> Dict:
        result = {'name': 'Open Ports Scan', 'findings': [], 'raw': ''}
        out, _, _ = self.execute_command("ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null")
        result['raw'] = out

        dangerous_ports = {21: 'FTP', 23: 'Telnet', 25: 'SMTP', 3306: 'MySQL',
                          5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB',
                          9200: 'Elasticsearch', 11211: 'Memcached'}

        for line in out.strip().split('\n')[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            local_addr = parts[4] if len(parts) > 4 else parts[3]
            try:
                port = int(local_addr.rsplit(':', 1)[-1])
                is_public = '0.0.0.0' in local_addr or ':::' in local_addr or '*' in local_addr
                if port in dangerous_ports and is_public:
                    result['findings'].append({
                        'title': f'{dangerous_ports[port]} ({port}) exposed publicly',
                        'severity': 'critical' if port in [23, 6379, 27017, 11211] else 'high',
                        'detail': f'Port {port} ({dangerous_ports[port]}) is listening on all interfaces',
                        'remediation': f'Restrict {dangerous_ports[port]} to localhost or use firewall rules'
                    })
                elif is_public and port not in [22, 80, 443]:
                    result['findings'].append({
                        'title': f'Port {port} open publicly',
                        'severity': 'medium',
                        'detail': f'Non-standard port {port} is listening on all interfaces',
                        'remediation': 'Review if this port needs to be publicly accessible'
                    })
            except (ValueError, IndexError):
                continue

        return result

    def _audit_users(self) -> Dict:
        result = {'name': 'User Account Audit', 'findings': [], 'raw': ''}

        out, _, _ = self.execute_command("cat /etc/passwd")
        result['raw'] = out
        shell_users = []
        for line in out.strip().split('\n'):
            parts = line.split(':')
            if len(parts) >= 7:
                shell = parts[6]
                if shell in ['/bin/bash', '/bin/sh', '/bin/zsh', '/usr/bin/bash']:
                    uid = int(parts[2]) if parts[2].isdigit() else 0
                    shell_users.append({'user': parts[0], 'uid': uid, 'shell': shell, 'home': parts[5]})

        for user in shell_users:
            if user['uid'] == 0 and user['user'] != 'root':
                result['findings'].append({
                    'title': f'Non-root user with UID 0: {user["user"]}',
                    'severity': 'critical',
                    'detail': f'User {user["user"]} has UID 0 (root equivalent)',
                    'remediation': 'Remove or change UID of this user'
                })

        shadow_out, _, _ = self.execute_command("cat /etc/shadow 2>/dev/null | grep -v '!' | grep -v '*'")
        if shadow_out:
            for line in shadow_out.strip().split('\n'):
                parts = line.split(':')
                if len(parts) >= 2 and parts[0] and (not parts[1] or parts[1] == ''):
                    result['findings'].append({
                        'title': f'User {parts[0]} has empty password',
                        'severity': 'critical',
                        'detail': f'Account {parts[0]} can be accessed without a password',
                        'remediation': 'Set a strong password or lock the account'
                    })

        sudoers_out, _, _ = self.execute_command("grep -rn 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null")
        if sudoers_out:
            for line in sudoers_out.strip().split('\n'):
                if line.strip():
                    result['findings'].append({
                        'title': 'NOPASSWD sudo rule found',
                        'severity': 'high',
                        'detail': line.strip(),
                        'remediation': 'Remove NOPASSWD directives from sudoers'
                    })

        return result

    def _check_auth_logs(self) -> Dict:
        result = {'name': 'Authentication Log Analysis', 'findings': [], 'raw': ''}
        out, _, _ = self.execute_command(
            "tail -1000 /var/log/auth.log 2>/dev/null || tail -1000 /var/log/secure 2>/dev/null"
        )
        result['raw'] = out[:5000]

        failed_count = out.lower().count('failed')
        accepted_count = out.lower().count('accepted')
        invalid_user = out.lower().count('invalid user')

        if failed_count > 100:
            result['findings'].append({
                'title': f'High failed authentication attempts: {failed_count}',
                'severity': 'critical',
                'detail': f'{failed_count} failed login attempts in recent 1000 log lines. Possible brute force attack.',
                'remediation': 'Implement fail2ban, use key-based auth, change SSH port'
            })
        elif failed_count > 20:
            result['findings'].append({
                'title': f'Elevated failed authentication: {failed_count}',
                'severity': 'high',
                'detail': f'{failed_count} failed login attempts detected',
                'remediation': 'Monitor source IPs and consider implementing rate limiting'
            })

        if invalid_user > 10:
            result['findings'].append({
                'title': f'Multiple invalid user attempts: {invalid_user}',
                'severity': 'high',
                'detail': f'{invalid_user} login attempts with non-existent usernames',
                'remediation': 'SSH scanning detected - implement IP blocking'
            })

        result['metrics'] = {
            'failed_logins': failed_count,
            'accepted_logins': accepted_count,
            'invalid_users': invalid_user
        }

        return result

    def _check_file_permissions(self) -> Dict:
        result = {'name': 'File Permission Audit', 'findings': [], 'raw': ''}

        critical_files = {
            '/etc/passwd': '644', '/etc/shadow': '640', '/etc/group': '644',
            '/etc/ssh/sshd_config': '600', '/root/.ssh': '700'
        }
        for filepath, expected_perm in critical_files.items():
            out, _, code = self.execute_command(f"stat -c '%a' {filepath} 2>/dev/null")
            if code == 0 and out.strip():
                actual_perm = out.strip()
                if int(actual_perm) > int(expected_perm):
                    result['findings'].append({
                        'title': f'Weak permissions on {filepath}',
                        'severity': 'high',
                        'detail': f'{filepath} has permissions {actual_perm} (expected {expected_perm} or stricter)',
                        'remediation': f'chmod {expected_perm} {filepath}'
                    })

        suid_out, _, _ = self.execute_command("find / -perm -4000 -type f 2>/dev/null | head -20")
        known_suid = ['/usr/bin/sudo', '/usr/bin/passwd', '/usr/bin/su', '/usr/bin/newgrp',
                      '/usr/bin/chsh', '/usr/bin/chfn', '/usr/bin/mount', '/usr/bin/umount',
                      '/usr/bin/gpasswd', '/usr/lib/openssh/ssh-keysign']
        if suid_out:
            for line in suid_out.strip().split('\n'):
                path = line.strip()
                if path and path not in known_suid:
                    result['findings'].append({
                        'title': f'Unusual SUID binary: {path}',
                        'severity': 'medium',
                        'detail': f'SUID binary found at {path} - not in standard list',
                        'remediation': f'Review if SUID is needed: chmod u-s {path}'
                    })

        world_out, _, _ = self.execute_command(
            "find /etc /root /home -type f -perm -o+w 2>/dev/null | head -10"
        )
        if world_out:
            for line in world_out.strip().split('\n'):
                if line.strip():
                    result['findings'].append({
                        'title': f'World-writable file: {line.strip()}',
                        'severity': 'high',
                        'detail': f'{line.strip()} is writable by any user',
                        'remediation': f'chmod o-w {line.strip()}'
                    })

        return result

    def _check_processes(self) -> Dict:
        result = {'name': 'Running Process Analysis', 'findings': [], 'raw': ''}
        out, _, _ = self.execute_command("ps auxf --no-headers 2>/dev/null | head -100")
        result['raw'] = out[:3000]

        suspicious_procs = ['nc ', 'ncat', 'netcat', 'socat', 'cryptominer', 'xmrig',
                           'kdevtmpfsi', 'kinsing', '.hidden', '/tmp/']
        for line in out.strip().split('\n'):
            for proc in suspicious_procs:
                if proc in line.lower():
                    result['findings'].append({
                        'title': f'Suspicious process detected: {proc.strip()}',
                        'severity': 'critical',
                        'detail': line.strip()[:200],
                        'remediation': 'Investigate and kill process if unauthorized'
                    })
                    break

        cpu_out, _, _ = self.execute_command(
            "ps aux --sort=-%cpu --no-headers | head -5"
        )
        for line in cpu_out.strip().split('\n'):
            parts = line.split()
            if len(parts) >= 3:
                try:
                    cpu_usage = float(parts[2])
                    if cpu_usage > 80:
                        result['findings'].append({
                            'title': f'High CPU process: {" ".join(parts[10:])}',
                            'severity': 'medium',
                            'detail': f'Process using {cpu_usage}% CPU',
                            'remediation': 'Investigate process for potential cryptomining or runaway'
                        })
                except ValueError:
                    pass

        return result

    def _check_network(self) -> Dict:
        result = {'name': 'Network Connection Analysis', 'findings': [], 'raw': ''}
        out, _, _ = self.execute_command("ss -tunap 2>/dev/null | head -50")
        result['raw'] = out[:3000]

        established = 0
        outbound_ips = set()
        for line in out.strip().split('\n')[1:]:
            if 'ESTAB' in line:
                established += 1
                parts = line.split()
                if len(parts) >= 5:
                    remote = parts[4] if 'ESTAB' not in parts[4] else parts[5] if len(parts) > 5 else ''
                    if ':' in remote:
                        ip = remote.rsplit(':', 1)[0]
                        outbound_ips.add(ip)

        if established > 50:
            result['findings'].append({
                'title': f'High number of established connections: {established}',
                'severity': 'medium',
                'detail': f'{established} established TCP connections to {len(outbound_ips)} unique IPs',
                'remediation': 'Review connections for unauthorized outbound communication'
            })

        result['metrics'] = {
            'established_connections': established,
            'unique_outbound_ips': len(outbound_ips)
        }
        return result

    def _get_system_info(self) -> Dict:
        result = {'name': 'System Information', 'findings': [], 'raw': ''}
        hostname, _, _ = self.execute_command("hostname")
        uname, _, _ = self.execute_command("uname -a")
        uptime, _, _ = self.execute_command("uptime -p 2>/dev/null || uptime")
        disk, _, _ = self.execute_command("df -h / | tail -1")
        mem, _, _ = self.execute_command("free -h | grep Mem")

        result['info'] = {
            'hostname': hostname.strip(),
            'kernel': uname.strip(),
            'uptime': uptime.strip(),
            'disk': disk.strip(),
            'memory': mem.strip()
        }
        return result

    def _extract_features(self, categories: Dict) -> Dict:
        features = {}
        auth = categories.get('auth_logs', {}).get('metrics', {})
        features['failed_logins'] = auth.get('failed_logins', 0)
        features['accepted_logins'] = auth.get('accepted_logins', 0)
        features['invalid_users'] = auth.get('invalid_users', 0)

        net = categories.get('network_connections', {}).get('metrics', {})
        features['established_connections'] = net.get('established_connections', 0)
        features['unique_outbound_ips'] = net.get('unique_outbound_ips', 0)

        total_findings = 0
        severity_scores = {'critical': 10, 'high': 5, 'medium': 2, 'low': 1}
        weighted_score = 0
        for cat in categories.values():
            for finding in cat.get('findings', []):
                total_findings += 1
                sev = finding.get('severity', 'info').lower()
                weighted_score += severity_scores.get(sev, 0)

        features['total_findings'] = total_findings
        features['weighted_severity_score'] = weighted_score

        return features

    def collect_metrics(self) -> Dict:
        if not self.connected:
            return {'error': 'Not connected'}

        metrics = {}
        cpu_out, _, _ = self.execute_command(
            "top -bn1 | grep 'Cpu(s)' | awk '{print $2}'"
        )
        try:
            metrics['cpu_usage'] = float(cpu_out.strip())
        except (ValueError, AttributeError):
            metrics['cpu_usage'] = 0.0

        mem_out, _, _ = self.execute_command(
            "free | grep Mem | awk '{printf \"%.1f\", $3/$2 * 100.0}'"
        )
        try:
            metrics['memory_usage'] = float(mem_out.strip())
        except (ValueError, AttributeError):
            metrics['memory_usage'] = 0.0

        disk_out, _, _ = self.execute_command(
            "df / | tail -1 | awk '{print $5}' | tr -d '%'"
        )
        try:
            metrics['disk_usage'] = float(disk_out.strip())
        except (ValueError, AttributeError):
            metrics['disk_usage'] = 0.0

        load_out, _, _ = self.execute_command("cat /proc/loadavg")
        parts = load_out.strip().split() if load_out else []
        metrics['load_1m'] = float(parts[0]) if len(parts) > 0 else 0.0
        metrics['load_5m'] = float(parts[1]) if len(parts) > 1 else 0.0
        metrics['load_15m'] = float(parts[2]) if len(parts) > 2 else 0.0

        proc_out, _, _ = self.execute_command("ps aux --no-headers | wc -l")
        try:
            metrics['process_count'] = int(proc_out.strip())
        except (ValueError, AttributeError):
            metrics['process_count'] = 0

        metrics['timestamp'] = time.time()
        return metrics

    def collect_cost_data(self) -> Dict:
        return {
            'platform': 'ssh',
            'note': 'Cost data not applicable for SSH-only servers',
            'estimated_monthly_cost': 0,
            'recommendations': []
        }

    def get_platform_info(self) -> Dict:
        info = {
            'type': 'ssh',
            'host': self.config.get('host', 'unknown'),
            'connected': self.connected,
            'connection_time': self.connection_time
        }
        if self.connected:
            hostname, _, _ = self.execute_command("hostname")
            info['hostname'] = hostname.strip()
        return info


class AWSPlatform(PlatformBase):
    """AWS Cloud Platform connector."""

    def __init__(self, config: Dict):
        super().__init__('aws', config)
        self.session = None
        self.region = config.get('region', 'us-east-1')

    def connect(self) -> bool:
        try:
            import boto3
            self.session = boto3.Session(
                aws_access_key_id=self.config.get('access_key'),
                aws_secret_access_key=self.config.get('secret_key'),
                region_name=self.region
            )
            sts = self.session.client('sts')
            identity = sts.get_caller_identity()
            self.connected = True
            self.connection_time = time.time()
            self.account_id = identity['Account']
            return True
        except Exception as e:
            self.last_error = str(e)
            self.connected = False
            return False

    def disconnect(self):
        self.session = None
        self.connected = False

    def collect_security_data(self) -> Dict:
        findings = {
            'platform': 'aws',
            'account': getattr(self, 'account_id', 'unknown'),
            'region': self.region,
            'timestamp': time.time(),
            'categories': {},
            'features': {},
            'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        }

        findings['categories']['iam_audit'] = self._audit_iam()
        findings['categories']['security_groups'] = self._audit_security_groups()
        findings['categories']['s3_buckets'] = self._audit_s3()
        findings['categories']['cloudtrail'] = self._check_cloudtrail()
        findings['categories']['ec2_instances'] = self._audit_ec2()

        findings['features'] = self._extract_features(findings['categories'])

        for cat in findings['categories'].values():
            for finding in cat.get('findings', []):
                sev = finding.get('severity', 'info').lower()
                if sev in findings['summary']:
                    findings['summary'][sev] += 1

        return findings

    def _audit_iam(self) -> Dict:
        result = {'name': 'IAM Security Audit', 'findings': []}
        try:
            iam = self.session.client('iam')

            users = iam.list_users()['Users']
            for user in users:
                username = user['UserName']
                keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
                for key in keys:
                    if key['Status'] == 'Active':
                        created = key['CreateDate']
                        age_days = (datetime.now(created.tzinfo) - created).days
                        if age_days > 90:
                            result['findings'].append({
                                'title': f'Stale access key for {username} ({age_days} days old)',
                                'severity': 'high',
                                'detail': f'Access key {key["AccessKeyId"]} is {age_days} days old',
                                'remediation': f'Rotate access key for {username}'
                            })

                mfa = iam.list_mfa_devices(UserName=username)['MFADevices']
                if not mfa:
                    result['findings'].append({
                        'title': f'No MFA for user: {username}',
                        'severity': 'high',
                        'detail': f'User {username} does not have MFA enabled',
                        'remediation': f'Enable MFA for {username}'
                    })

            policies = iam.list_policies(Scope='Local', OnlyAttached=True)['Policies']
            for policy in policies:
                versions = iam.get_policy(PolicyArn=policy['Arn'])
                version_id = versions['Policy']['DefaultVersionId']
                doc = iam.get_policy_version(
                    PolicyArn=policy['Arn'], VersionId=version_id
                )['PolicyVersion']['Document']
                statements = doc.get('Statement', [])
                for stmt in statements:
                    if stmt.get('Effect') == 'Allow' and stmt.get('Action') == '*' and stmt.get('Resource') == '*':
                        result['findings'].append({
                            'title': f'Overly permissive policy: {policy["PolicyName"]}',
                            'severity': 'critical',
                            'detail': 'Policy grants * on * (full admin access)',
                            'remediation': 'Apply least-privilege principle'
                        })
        except Exception as e:
            result['error'] = str(e)
        return result

    def _audit_security_groups(self) -> Dict:
        result = {'name': 'Security Group Audit', 'findings': []}
        try:
            ec2 = self.session.client('ec2')
            sgs = ec2.describe_security_groups()['SecurityGroups']
            for sg in sgs:
                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            port = rule.get('FromPort', 'all')
                            if port in [22, 3389, 3306, 5432, 6379, 27017]:
                                result['findings'].append({
                                    'title': f'SG {sg["GroupId"]}: Port {port} open to world',
                                    'severity': 'critical',
                                    'detail': f'{sg["GroupName"]} allows 0.0.0.0/0 on port {port}',
                                    'remediation': f'Restrict port {port} to specific IP ranges'
                                })
                            elif port != 80 and port != 443:
                                result['findings'].append({
                                    'title': f'SG {sg["GroupId"]}: Port {port} open to world',
                                    'severity': 'high',
                                    'detail': f'{sg["GroupName"]} allows 0.0.0.0/0 on port {port}',
                                    'remediation': f'Restrict inbound access on port {port}'
                                })
        except Exception as e:
            result['error'] = str(e)
        return result

    def _audit_s3(self) -> Dict:
        result = {'name': 'S3 Bucket Audit', 'findings': []}
        try:
            s3 = self.session.client('s3')
            buckets = s3.list_buckets()['Buckets']
            for bucket in buckets:
                name = bucket['Name']
                try:
                    acl = s3.get_bucket_acl(Bucket=name)
                    for grant in acl.get('Grants', []):
                        grantee = grant.get('Grantee', {})
                        if grantee.get('URI', '') in [
                            'http://acs.amazonaws.com/groups/global/AllUsers',
                            'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
                        ]:
                            result['findings'].append({
                                'title': f'Publicly accessible S3 bucket: {name}',
                                'severity': 'critical',
                                'detail': f'Bucket {name} grants access to {grantee.get("URI", "")}',
                                'remediation': f'Remove public access from bucket {name}'
                            })
                except Exception:
                    pass

                try:
                    enc = s3.get_bucket_encryption(Bucket=name)
                except Exception:
                    result['findings'].append({
                        'title': f'S3 bucket without encryption: {name}',
                        'severity': 'medium',
                        'detail': f'Bucket {name} does not have default encryption enabled',
                        'remediation': f'Enable default encryption on bucket {name}'
                    })
        except Exception as e:
            result['error'] = str(e)
        return result

    def _check_cloudtrail(self) -> Dict:
        result = {'name': 'CloudTrail Audit', 'findings': []}
        try:
            ct = self.session.client('cloudtrail')
            trails = ct.describe_trails()['trailList']
            if not trails:
                result['findings'].append({
                    'title': 'No CloudTrail trails configured',
                    'severity': 'critical',
                    'detail': 'AWS API activity is not being logged',
                    'remediation': 'Create a CloudTrail trail to log all API activity'
                })
            else:
                for trail in trails:
                    status = ct.get_trail_status(Name=trail['TrailARN'])
                    if not status.get('IsLogging', False):
                        result['findings'].append({
                            'title': f'CloudTrail logging disabled: {trail["Name"]}',
                            'severity': 'critical',
                            'detail': f'Trail {trail["Name"]} is not currently logging',
                            'remediation': 'Enable logging on the trail'
                        })
        except Exception as e:
            result['error'] = str(e)
        return result

    def _audit_ec2(self) -> Dict:
        result = {'name': 'EC2 Instance Audit', 'findings': []}
        try:
            ec2 = self.session.client('ec2')
            reservations = ec2.describe_instances()['Reservations']
            for reservation in reservations:
                for instance in reservation['Instances']:
                    iid = instance['InstanceId']
                    state = instance['State']['Name']
                    if state != 'running':
                        continue

                    if instance.get('PublicIpAddress'):
                        has_imdsv2 = instance.get('MetadataOptions', {}).get('HttpTokens') == 'required'
                        if not has_imdsv2:
                            result['findings'].append({
                                'title': f'Public instance without IMDSv2: {iid}',
                                'severity': 'high',
                                'detail': f'Instance {iid} has public IP but IMDSv2 not enforced',
                                'remediation': f'Enable IMDSv2 (HttpTokens=required) on {iid}'
                            })

                    monitoring = instance.get('Monitoring', {}).get('State', '')
                    if monitoring != 'enabled':
                        result['findings'].append({
                            'title': f'Detailed monitoring disabled: {iid}',
                            'severity': 'low',
                            'detail': f'Instance {iid} uses basic monitoring only',
                            'remediation': f'Enable detailed monitoring for {iid}'
                        })
        except Exception as e:
            result['error'] = str(e)
        return result

    def _extract_features(self, categories: Dict) -> Dict:
        features = {}
        total_findings = 0
        severity_scores = {'critical': 10, 'high': 5, 'medium': 2, 'low': 1}
        weighted_score = 0
        for cat in categories.values():
            for finding in cat.get('findings', []):
                total_findings += 1
                sev = finding.get('severity', 'info').lower()
                weighted_score += severity_scores.get(sev, 0)
        features['total_findings'] = total_findings
        features['weighted_severity_score'] = weighted_score
        return features

    def collect_metrics(self) -> Dict:
        metrics = {'timestamp': time.time(), 'platform': 'aws'}
        try:
            cw = self.session.client('cloudwatch')
            ec2 = self.session.client('ec2')
            reservations = ec2.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
            )['Reservations']
            instance_count = sum(len(r['Instances']) for r in reservations)
            metrics['running_instances'] = instance_count
        except Exception as e:
            metrics['error'] = str(e)
        return metrics

    def collect_cost_data(self) -> Dict:
        cost_data = {
            'platform': 'aws',
            'timestamp': time.time(),
            'monthly_costs': [],
            'total_monthly': 0,
            'recommendations': [],
            'services': {}
        }
        try:
            ce = self.session.client('ce')
            end = datetime.now().strftime('%Y-%m-%d')
            start = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')

            result = ce.get_cost_and_usage(
                TimePeriod={'Start': start, 'End': end},
                Granularity='MONTHLY',
                Metrics=['UnblendedCost'],
                GroupBy=[{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
            )

            total = 0
            for group in result.get('ResultsByTime', [{}])[0].get('Groups', []):
                service = group['Keys'][0]
                amount = float(group['Metrics']['UnblendedCost']['Amount'])
                cost_data['services'][service] = round(amount, 2)
                total += amount

            cost_data['total_monthly'] = round(total, 2)

            ec2 = self.session.client('ec2')
            reservations = ec2.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['stopped']}]
            )['Reservations']
            stopped = sum(len(r['Instances']) for r in reservations)
            if stopped > 0:
                cost_data['recommendations'].append({
                    'type': 'waste',
                    'title': f'{stopped} stopped EC2 instances with attached EBS',
                    'potential_savings': f'Check for orphaned EBS volumes',
                    'severity': 'medium'
                })

            try:
                eips = ec2.describe_addresses()['Addresses']
                unused_eips = [eip for eip in eips if 'InstanceId' not in eip]
                if unused_eips:
                    cost_data['recommendations'].append({
                        'type': 'waste',
                        'title': f'{len(unused_eips)} unused Elastic IPs',
                        'potential_savings': f'${len(unused_eips) * 3.60:.2f}/month',
                        'severity': 'low'
                    })
            except Exception:
                pass

        except Exception as e:
            cost_data['error'] = str(e)
        return cost_data

    def get_platform_info(self) -> Dict:
        return {
            'type': 'aws',
            'account_id': getattr(self, 'account_id', 'unknown'),
            'region': self.region,
            'connected': self.connected,
            'connection_time': self.connection_time
        }


class GCPPlatform(PlatformBase):
    """Google Cloud Platform connector."""

    def __init__(self, config: Dict):
        super().__init__('gcp', config)
        self.project_id = config.get('project_id', '')
        self.credentials = None

    def connect(self) -> bool:
        try:
            from google.oauth2 import service_account
            from google.cloud import compute_v1

            cred_path = self.config.get('credentials_file', '')
            if cred_path and os.path.exists(cred_path):
                self.credentials = service_account.Credentials.from_service_account_file(
                    cred_path,
                    scopes=['https://www.googleapis.com/auth/cloud-platform']
                )
            else:
                import google.auth
                self.credentials, self.project_id = google.auth.default()

            client = compute_v1.InstancesClient(credentials=self.credentials)
            self.connected = True
            self.connection_time = time.time()
            return True
        except Exception as e:
            self.last_error = str(e)
            self.connected = False
            return False

    def disconnect(self):
        self.credentials = None
        self.connected = False

    def collect_security_data(self) -> Dict:
        findings = {
            'platform': 'gcp',
            'project': self.project_id,
            'timestamp': time.time(),
            'categories': {},
            'features': {},
            'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        }

        findings['categories']['iam_audit'] = self._audit_iam()
        findings['categories']['firewall_rules'] = self._audit_firewall()
        findings['categories']['storage_buckets'] = self._audit_storage()
        findings['categories']['compute_instances'] = self._audit_compute()

        total_findings = 0
        severity_scores = {'critical': 10, 'high': 5, 'medium': 2, 'low': 1}
        weighted_score = 0
        for cat in findings['categories'].values():
            for finding in cat.get('findings', []):
                total_findings += 1
                sev = finding.get('severity', 'info').lower()
                weighted_score += severity_scores.get(sev, 0)
                if sev in findings['summary']:
                    findings['summary'][sev] += 1

        findings['features'] = {
            'total_findings': total_findings,
            'weighted_severity_score': weighted_score
        }
        return findings

    def _audit_iam(self) -> Dict:
        result = {'name': 'GCP IAM Audit', 'findings': []}
        try:
            from google.cloud import resourcemanager_v3

            client = resourcemanager_v3.ProjectsClient(credentials=self.credentials)
            policy = client.get_iam_policy(resource=f'projects/{self.project_id}')

            for binding in policy.bindings:
                if 'allUsers' in binding.members or 'allAuthenticatedUsers' in binding.members:
                    result['findings'].append({
                        'title': f'Public IAM binding: {binding.role}',
                        'severity': 'critical',
                        'detail': f'Role {binding.role} is bound to allUsers/allAuthenticatedUsers',
                        'remediation': 'Remove public IAM bindings'
                    })
                if 'roles/owner' in binding.role or 'roles/editor' in binding.role:
                    sa_members = [m for m in binding.members if 'serviceAccount' in m]
                    if sa_members:
                        result['findings'].append({
                            'title': f'Service account with {binding.role}',
                            'severity': 'high',
                            'detail': f'{len(sa_members)} service accounts have {binding.role}',
                            'remediation': 'Apply least-privilege roles to service accounts'
                        })
        except Exception as e:
            result['error'] = str(e)
        return result

    def _audit_firewall(self) -> Dict:
        result = {'name': 'GCP Firewall Rules Audit', 'findings': []}
        try:
            from google.cloud import compute_v1
            client = compute_v1.FirewallsClient(credentials=self.credentials)
            firewalls = client.list(project=self.project_id)

            for fw in firewalls:
                if fw.direction == 'INGRESS' and '0.0.0.0/0' in (fw.source_ranges or []):
                    for allowed in (fw.allowed or []):
                        ports = allowed.ports or ['all']
                        for port in ports:
                            if port in ['22', '3389', '3306', '5432']:
                                result['findings'].append({
                                    'title': f'Firewall {fw.name}: Port {port} open to world',
                                    'severity': 'critical',
                                    'detail': f'Rule allows 0.0.0.0/0 on port {port}',
                                    'remediation': f'Restrict source ranges for port {port}'
                                })
        except Exception as e:
            result['error'] = str(e)
        return result

    def _audit_storage(self) -> Dict:
        result = {'name': 'GCS Storage Audit', 'findings': []}
        try:
            from google.cloud import storage
            client = storage.Client(project=self.project_id, credentials=self.credentials)
            for bucket in client.list_buckets():
                policy = bucket.get_iam_policy()
                for binding in policy.bindings:
                    if 'allUsers' in binding['members'] or 'allAuthenticatedUsers' in binding['members']:
                        result['findings'].append({
                            'title': f'Public GCS bucket: {bucket.name}',
                            'severity': 'critical',
                            'detail': f'Bucket {bucket.name} is publicly accessible via {binding["role"]}',
                            'remediation': f'Remove public access from bucket {bucket.name}'
                        })
        except Exception as e:
            result['error'] = str(e)
        return result

    def _audit_compute(self) -> Dict:
        result = {'name': 'GCP Compute Audit', 'findings': []}
        try:
            from google.cloud import compute_v1
            client = compute_v1.InstancesClient(credentials=self.credentials)
            zones_client = compute_v1.ZonesClient(credentials=self.credentials)
            zones = zones_client.list(project=self.project_id)

            for zone in zones:
                instances = client.list(project=self.project_id, zone=zone.name)
                for inst in instances:
                    if inst.status != 'RUNNING':
                        continue
                    for iface in (inst.network_interfaces or []):
                        for access in (iface.access_configs or []):
                            if access.nat_i_p:
                                result['findings'].append({
                                    'title': f'Public IP on instance: {inst.name}',
                                    'severity': 'medium',
                                    'detail': f'Instance {inst.name} has external IP {access.nat_i_p}',
                                    'remediation': 'Use Cloud NAT or IAP instead of public IPs'
                                })
        except Exception as e:
            result['error'] = str(e)
        return result

    def collect_metrics(self) -> Dict:
        return {'timestamp': time.time(), 'platform': 'gcp', 'project': self.project_id}

    def collect_cost_data(self) -> Dict:
        cost_data = {
            'platform': 'gcp',
            'project': self.project_id,
            'timestamp': time.time(),
            'services': {},
            'total_monthly': 0,
            'recommendations': []
        }
        try:
            from google.cloud import billing_v1
            client = billing_v1.CloudBillingClient(credentials=self.credentials)
            billing_info = client.get_project_billing_info(name=f'projects/{self.project_id}')
            cost_data['billing_account'] = billing_info.billing_account_name
            cost_data['billing_enabled'] = billing_info.billing_enabled
        except Exception as e:
            cost_data['error'] = str(e)
        return cost_data

    def get_platform_info(self) -> Dict:
        return {
            'type': 'gcp',
            'project_id': self.project_id,
            'connected': self.connected,
            'connection_time': self.connection_time
        }


class AzurePlatform(PlatformBase):
    """Microsoft Azure Platform connector."""

    def __init__(self, config: Dict):
        super().__init__('azure', config)
        self.subscription_id = config.get('subscription_id', '')
        self.credential = None

    def connect(self) -> bool:
        try:
            from azure.identity import ClientSecretCredential, DefaultAzureCredential
            from azure.mgmt.resource import ResourceManagementClient

            if self.config.get('tenant_id') and self.config.get('client_id'):
                self.credential = ClientSecretCredential(
                    tenant_id=self.config['tenant_id'],
                    client_id=self.config['client_id'],
                    client_secret=self.config.get('client_secret', '')
                )
            else:
                self.credential = DefaultAzureCredential()

            rm_client = ResourceManagementClient(self.credential, self.subscription_id)
            list(rm_client.resource_groups.list())
            self.connected = True
            self.connection_time = time.time()
            return True
        except Exception as e:
            self.last_error = str(e)
            self.connected = False
            return False

    def disconnect(self):
        self.credential = None
        self.connected = False

    def collect_security_data(self) -> Dict:
        findings = {
            'platform': 'azure',
            'subscription': self.subscription_id,
            'timestamp': time.time(),
            'categories': {},
            'features': {},
            'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        }

        findings['categories']['nsg_audit'] = self._audit_nsgs()
        findings['categories']['storage_audit'] = self._audit_storage()
        findings['categories']['vm_audit'] = self._audit_vms()

        total_findings = 0
        severity_scores = {'critical': 10, 'high': 5, 'medium': 2, 'low': 1}
        weighted_score = 0
        for cat in findings['categories'].values():
            for finding in cat.get('findings', []):
                total_findings += 1
                sev = finding.get('severity', 'info').lower()
                weighted_score += severity_scores.get(sev, 0)
                if sev in findings['summary']:
                    findings['summary'][sev] += 1

        findings['features'] = {
            'total_findings': total_findings,
            'weighted_severity_score': weighted_score
        }
        return findings

    def _audit_nsgs(self) -> Dict:
        result = {'name': 'Network Security Group Audit', 'findings': []}
        try:
            from azure.mgmt.network import NetworkManagementClient
            client = NetworkManagementClient(self.credential, self.subscription_id)
            for nsg in client.network_security_groups.list_all():
                for rule in (nsg.security_rules or []):
                    if (rule.direction == 'Inbound' and rule.access == 'Allow'
                            and rule.source_address_prefix in ['*', '0.0.0.0/0', 'Internet']):
                        port = rule.destination_port_range or 'all'
                        if port in ['22', '3389', '3306', '5432', '*']:
                            result['findings'].append({
                                'title': f'NSG {nsg.name}: Port {port} open to Internet',
                                'severity': 'critical',
                                'detail': f'Rule {rule.name} allows inbound from Internet on port {port}',
                                'remediation': f'Restrict source addresses for port {port}'
                            })
        except Exception as e:
            result['error'] = str(e)
        return result

    def _audit_storage(self) -> Dict:
        result = {'name': 'Azure Storage Audit', 'findings': []}
        try:
            from azure.mgmt.storage import StorageManagementClient
            client = StorageManagementClient(self.credential, self.subscription_id)
            for account in client.storage_accounts.list():
                if account.allow_blob_public_access:
                    result['findings'].append({
                        'title': f'Public blob access enabled: {account.name}',
                        'severity': 'high',
                        'detail': f'Storage account {account.name} allows public blob access',
                        'remediation': f'Disable public blob access on {account.name}'
                    })
                if not account.encryption or not account.encryption.key_vault_properties:
                    result['findings'].append({
                        'title': f'Storage using Microsoft-managed keys: {account.name}',
                        'severity': 'low',
                        'detail': f'{account.name} uses Microsoft-managed encryption keys',
                        'remediation': 'Consider using customer-managed keys (CMK)'
                    })
        except Exception as e:
            result['error'] = str(e)
        return result

    def _audit_vms(self) -> Dict:
        result = {'name': 'Azure VM Audit', 'findings': []}
        try:
            from azure.mgmt.compute import ComputeManagementClient
            client = ComputeManagementClient(self.credential, self.subscription_id)
            for vm in client.virtual_machines.list_all():
                if not vm.os_profile or not getattr(vm.os_profile, 'linux_configuration', None):
                    continue
                linux_conf = vm.os_profile.linux_configuration
                if linux_conf and not linux_conf.disable_password_authentication:
                    result['findings'].append({
                        'title': f'Password auth enabled on VM: {vm.name}',
                        'severity': 'medium',
                        'detail': f'VM {vm.name} allows password authentication',
                        'remediation': f'Disable password auth and use SSH keys for {vm.name}'
                    })
        except Exception as e:
            result['error'] = str(e)
        return result

    def collect_metrics(self) -> Dict:
        return {'timestamp': time.time(), 'platform': 'azure', 'subscription': self.subscription_id}

    def collect_cost_data(self) -> Dict:
        cost_data = {
            'platform': 'azure',
            'subscription': self.subscription_id,
            'timestamp': time.time(),
            'services': {},
            'total_monthly': 0,
            'recommendations': []
        }
        try:
            from azure.mgmt.costmanagement import CostManagementClient
            client = CostManagementClient(self.credential)
            scope = f'/subscriptions/{self.subscription_id}'
            end = datetime.now()
            start = end - timedelta(days=30)

            query = {
                'type': 'ActualCost',
                'timeframe': 'Custom',
                'time_period': {'from': start.isoformat(), 'to': end.isoformat()},
                'dataset': {
                    'granularity': 'Monthly',
                    'aggregation': {
                        'totalCost': {'name': 'Cost', 'function': 'Sum'}
                    },
                    'grouping': [{'type': 'Dimension', 'name': 'ServiceName'}]
                }
            }

            result = client.query.usage(scope, query)
            for row in (result.rows or []):
                if len(row) >= 2:
                    cost_data['services'][str(row[1])] = float(row[0])
                    cost_data['total_monthly'] += float(row[0])

            cost_data['total_monthly'] = round(cost_data['total_monthly'], 2)
        except Exception as e:
            cost_data['error'] = str(e)
        return cost_data

    def get_platform_info(self) -> Dict:
        return {
            'type': 'azure',
            'subscription_id': self.subscription_id,
            'connected': self.connected,
            'connection_time': self.connection_time
        }


class DockerPlatform(PlatformBase):
    """Docker Platform connector."""

    def __init__(self, config: Dict):
        super().__init__('docker', config)
        self.docker_client = None

    def connect(self) -> bool:
        try:
            import docker
            base_url = self.config.get('base_url', 'unix:///var/run/docker.sock')
            self.docker_client = docker.DockerClient(base_url=base_url)
            self.docker_client.ping()
            self.connected = True
            self.connection_time = time.time()
            return True
        except Exception as e:
            self.last_error = str(e)
            self.connected = False
            return False

    def disconnect(self):
        if self.docker_client:
            self.docker_client.close()
        self.connected = False

    def collect_security_data(self) -> Dict:
        findings = {
            'platform': 'docker',
            'timestamp': time.time(),
            'categories': {},
            'features': {},
            'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        }

        result = {'name': 'Container Security Audit', 'findings': []}
        try:
            containers = self.docker_client.containers.list()
            for c in containers:
                attrs = c.attrs
                host_config = attrs.get('HostConfig', {})

                if host_config.get('Privileged', False):
                    result['findings'].append({
                        'title': f'Privileged container: {c.name}',
                        'severity': 'critical',
                        'detail': f'Container {c.name} is running in privileged mode',
                        'remediation': 'Remove --privileged flag and use specific capabilities'
                    })

                if host_config.get('PidMode') == 'host':
                    result['findings'].append({
                        'title': f'Host PID namespace: {c.name}',
                        'severity': 'high',
                        'detail': f'Container {c.name} shares host PID namespace',
                        'remediation': 'Remove --pid=host unless absolutely necessary'
                    })

                if host_config.get('NetworkMode') == 'host':
                    result['findings'].append({
                        'title': f'Host network mode: {c.name}',
                        'severity': 'high',
                        'detail': f'Container {c.name} shares host network',
                        'remediation': 'Use bridge or custom networks instead'
                    })

                binds = host_config.get('Binds', []) or []
                for bind in binds:
                    if bind.startswith('/var/run/docker.sock'):
                        result['findings'].append({
                            'title': f'Docker socket mounted: {c.name}',
                            'severity': 'critical',
                            'detail': f'Container {c.name} has Docker socket access',
                            'remediation': 'Remove Docker socket mount or use TLS'
                        })

                user = attrs.get('Config', {}).get('User', '')
                if not user or user == 'root' or user == '0':
                    result['findings'].append({
                        'title': f'Container running as root: {c.name}',
                        'severity': 'medium',
                        'detail': f'Container {c.name} runs as root user',
                        'remediation': 'Set USER in Dockerfile or --user flag'
                    })
        except Exception as e:
            result['error'] = str(e)

        findings['categories']['container_audit'] = result

        total_findings = 0
        severity_scores = {'critical': 10, 'high': 5, 'medium': 2, 'low': 1}
        weighted_score = 0
        for finding in result.get('findings', []):
            total_findings += 1
            sev = finding.get('severity', 'info').lower()
            weighted_score += severity_scores.get(sev, 0)
            if sev in findings['summary']:
                findings['summary'][sev] += 1

        findings['features'] = {
            'total_findings': total_findings,
            'weighted_severity_score': weighted_score
        }
        return findings

    def collect_metrics(self) -> Dict:
        metrics = {'timestamp': time.time(), 'platform': 'docker'}
        try:
            containers = self.docker_client.containers.list()
            metrics['running_containers'] = len(containers)
            metrics['images'] = len(self.docker_client.images.list())
        except Exception as e:
            metrics['error'] = str(e)
        return metrics

    def collect_cost_data(self) -> Dict:
        return {
            'platform': 'docker',
            'note': 'Cost data not applicable for Docker',
            'recommendations': []
        }

    def get_platform_info(self) -> Dict:
        info = {'type': 'docker', 'connected': self.connected, 'connection_time': self.connection_time}
        try:
            if self.docker_client:
                version = self.docker_client.version()
                info['docker_version'] = version.get('Version', 'unknown')
                info['api_version'] = version.get('ApiVersion', 'unknown')
        except Exception:
            pass
        return info


class KubernetesPlatform(PlatformBase):
    """Kubernetes Platform connector."""

    def __init__(self, config: Dict):
        super().__init__('kubernetes', config)
        self.api_client = None
        self.core_v1 = None
        self.rbac_v1 = None
        self.networking_v1 = None

    def connect(self) -> bool:
        try:
            from kubernetes import client, config as k8s_config

            kubeconfig = self.config.get('kubeconfig')
            context = self.config.get('context')

            if kubeconfig:
                k8s_config.load_kube_config(config_file=kubeconfig, context=context)
            else:
                try:
                    k8s_config.load_incluster_config()
                except Exception:
                    k8s_config.load_kube_config(context=context)

            self.core_v1 = client.CoreV1Api()
            self.rbac_v1 = client.RbacAuthorizationV1Api()
            self.networking_v1 = client.NetworkingV1Api()

            self.core_v1.list_namespace()
            self.connected = True
            self.connection_time = time.time()
            return True
        except Exception as e:
            self.last_error = str(e)
            self.connected = False
            return False

    def disconnect(self):
        self.core_v1 = None
        self.rbac_v1 = None
        self.networking_v1 = None
        self.connected = False

    def collect_security_data(self) -> Dict:
        findings = {
            'platform': 'kubernetes',
            'timestamp': time.time(),
            'categories': {},
            'features': {},
            'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        }

        findings['categories']['rbac_audit'] = self._audit_rbac()
        findings['categories']['pod_security'] = self._audit_pods()
        findings['categories']['network_policies'] = self._audit_network_policies()
        findings['categories']['secrets'] = self._audit_secrets()

        total_findings = 0
        severity_scores = {'critical': 10, 'high': 5, 'medium': 2, 'low': 1}
        weighted_score = 0
        for cat in findings['categories'].values():
            for finding in cat.get('findings', []):
                total_findings += 1
                sev = finding.get('severity', 'info').lower()
                weighted_score += severity_scores.get(sev, 0)
                if sev in findings['summary']:
                    findings['summary'][sev] += 1

        findings['features'] = {
            'total_findings': total_findings,
            'weighted_severity_score': weighted_score
        }
        return findings

    def _audit_rbac(self) -> Dict:
        result = {'name': 'RBAC Audit', 'findings': []}
        try:
            crbs = self.rbac_v1.list_cluster_role_binding()
            for crb in crbs.items:
                if crb.role_ref.name in ['cluster-admin']:
                    for subject in (crb.subjects or []):
                        if subject.kind == 'ServiceAccount' and subject.namespace != 'kube-system':
                            result['findings'].append({
                                'title': f'cluster-admin bound to SA: {subject.namespace}/{subject.name}',
                                'severity': 'critical',
                                'detail': f'ServiceAccount {subject.name} in {subject.namespace} has cluster-admin',
                                'remediation': 'Use more restrictive ClusterRole'
                            })
        except Exception as e:
            result['error'] = str(e)
        return result

    def _audit_pods(self) -> Dict:
        result = {'name': 'Pod Security Audit', 'findings': []}
        try:
            pods = self.core_v1.list_pod_for_all_namespaces()
            for pod in pods.items:
                ns = pod.metadata.namespace
                if ns in ['kube-system', 'kube-public']:
                    continue
                for container in (pod.spec.containers or []):
                    sc = container.security_context
                    if sc:
                        if sc.privileged:
                            result['findings'].append({
                                'title': f'Privileged pod: {ns}/{pod.metadata.name}',
                                'severity': 'critical',
                                'detail': f'Container {container.name} is privileged',
                                'remediation': 'Remove privileged: true'
                            })
                        if sc.run_as_user == 0:
                            result['findings'].append({
                                'title': f'Root container: {ns}/{pod.metadata.name}',
                                'severity': 'high',
                                'detail': f'Container {container.name} runs as root (UID 0)',
                                'remediation': 'Set runAsNonRoot: true'
                            })
        except Exception as e:
            result['error'] = str(e)
        return result

    def _audit_network_policies(self) -> Dict:
        result = {'name': 'Network Policy Audit', 'findings': []}
        try:
            namespaces = self.core_v1.list_namespace()
            netpols = self.networking_v1.list_network_policy_for_all_namespaces()
            ns_with_policies = set()
            for pol in netpols.items:
                ns_with_policies.add(pol.metadata.namespace)

            for ns in namespaces.items:
                name = ns.metadata.name
                if name in ['kube-system', 'kube-public', 'kube-node-lease']:
                    continue
                if name not in ns_with_policies:
                    result['findings'].append({
                        'title': f'No NetworkPolicy in namespace: {name}',
                        'severity': 'medium',
                        'detail': f'Namespace {name} has no NetworkPolicies - all traffic is allowed',
                        'remediation': f'Create default-deny NetworkPolicy for {name}'
                    })
        except Exception as e:
            result['error'] = str(e)
        return result

    def _audit_secrets(self) -> Dict:
        result = {'name': 'Secrets Audit', 'findings': []}
        try:
            secrets = self.core_v1.list_secret_for_all_namespaces()
            for secret in secrets.items:
                if secret.metadata.namespace in ['kube-system']:
                    continue
                if secret.type == 'Opaque':
                    annotations = secret.metadata.annotations or {}
                    if 'kubectl.kubernetes.io/last-applied-configuration' in annotations:
                        result['findings'].append({
                            'title': f'Secret in kubectl annotations: {secret.metadata.namespace}/{secret.metadata.name}',
                            'severity': 'high',
                            'detail': 'Secret data may be exposed in last-applied-configuration',
                            'remediation': 'Use sealed-secrets or external secret management'
                        })
        except Exception as e:
            result['error'] = str(e)
        return result

    def collect_metrics(self) -> Dict:
        metrics = {'timestamp': time.time(), 'platform': 'kubernetes'}
        try:
            pods = self.core_v1.list_pod_for_all_namespaces()
            metrics['total_pods'] = len(pods.items)
            running = sum(1 for p in pods.items if p.status.phase == 'Running')
            metrics['running_pods'] = running
            namespaces = self.core_v1.list_namespace()
            metrics['namespaces'] = len(namespaces.items)
        except Exception as e:
            metrics['error'] = str(e)
        return metrics

    def collect_cost_data(self) -> Dict:
        return {
            'platform': 'kubernetes',
            'note': 'Cost data requires cloud provider integration',
            'recommendations': []
        }

    def get_platform_info(self) -> Dict:
        info = {
            'type': 'kubernetes',
            'connected': self.connected,
            'connection_time': self.connection_time
        }
        try:
            if self.core_v1:
                version = self.core_v1.get_code()
                info['k8s_version'] = f"{version.major}.{version.minor}"
        except Exception:
            pass
        return info


# Platform factory
PLATFORM_REGISTRY = {
    'ssh': SSHPlatform,
    'aws': AWSPlatform,
    'gcp': GCPPlatform,
    'azure': AzurePlatform,
    'docker': DockerPlatform,
    'kubernetes': KubernetesPlatform
}

PLATFORM_DISPLAY_NAMES = {
    'ssh': 'Linux/Unix Server (SSH)',
    'aws': 'Amazon Web Services (AWS)',
    'gcp': 'Google Cloud Platform (GCP)',
    'azure': 'Microsoft Azure',
    'docker': 'Docker Containers',
    'kubernetes': 'Kubernetes Cluster'
}

PLATFORM_ICONS = {
    'ssh': '🖥️',
    'aws': '☁️',
    'gcp': '🌐',
    'azure': '🔷',
    'docker': '🐳',
    'kubernetes': '☸️'
}


def create_platform(platform_type: str, config: Dict) -> PlatformBase:
    """Factory function to create platform instances."""
    cls = PLATFORM_REGISTRY.get(platform_type)
    if not cls:
        raise ValueError(f"Unknown platform type: {platform_type}")
    return cls(config)
