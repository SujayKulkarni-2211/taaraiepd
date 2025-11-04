import paramiko
import io
from typing import Optional, Tuple

class SSHManager:
    """Handles SSH connections and remote command execution."""
    
    def __init__(self, host: str, username: str, password: str):
        self.host = host
        self.username = username
        self.password = password
        self.client = None
    
    def connect(self) -> bool:
        """Establish SSH connection."""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(self.host, username=self.username, password=self.password, timeout=10)
            return True
        except Exception as e:
            print(f"[v0] SSH connection failed: {e}")
            return False
    
    def execute_command(self, command: str) -> Tuple[str, str, int]:
        """Execute command on remote server and return output."""
        try:
            if not self.client:
                return "", "Not connected", 1
            
            stdin, stdout, stderr = self.client.exec_command(command)
            out = stdout.read().decode('utf-8', errors='ignore')
            err = stderr.read().decode('utf-8', errors='ignore')
            exit_code = stdout.channel.recv_exit_status()
            
            return out, err, exit_code
        except Exception as e:
            return "", str(e), 1
    
    def disconnect(self):
        """Close SSH connection."""
        if self.client:
            self.client.close()
    
    def __del__(self):
        self.disconnect()
