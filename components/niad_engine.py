from typing import Dict, List, Any, Optional
from datetime import datetime

class NIADEngine:
    """
    Non-Invasive Adaptive Deception (NIAD) - spawns honeypots on detection.
    Creates sandboxed environments to observe and analyze attacker behavior.
    """
    
    def __init__(self, ssh_manager):
        self.ssh_manager = ssh_manager
        self.active_honeypots = []
    
    def create_honeypot(self, original_container: str, honeypot_type: str = "alpine") -> Dict[str, Any]:
        """
        Spawn a honeypot container with minimal interaction.
        - Isolates suspicious container from network
        - Creates deceptive "clone" for monitoring
        """
        try:
            honeypot_name = f"honeypot-{original_container}-{datetime.now().strftime('%s')}"
            
            # Step 1: Disconnect original from network (isolate production)
            isolate_cmd = f"docker network disconnect bridge {original_container} 2>/dev/null || true"
            
            # Step 2: Create honeypot with monitoring
            create_honeypot_cmd = (
                f"docker run -d --name {honeypot_name} "
                f"--network none "
                f"-e MONITORED=1 "
                f"{honeypot_type} "
                f"sh -c 'echo \"Honeypot active\" && sleep infinity'"
            )
            
            # Step 3: Log all honeypot activity
            log_cmd = f"docker logs -f {honeypot_name} > /var/log/niad-{honeypot_name}.log 2>&1 &"
            
            return {
                "honeypot_name": honeypot_name,
                "original_container": original_container,
                "commands": [
                    {"cmd": isolate_cmd, "description": "Isolate original container"},
                    {"cmd": create_honeypot_cmd, "description": "Create honeypot"},
                    {"cmd": log_cmd, "description": "Start activity logging"}
                ],
                "rollback_cmd": f"docker network connect bridge {original_container} && docker rm -f {honeypot_name}",
                "status": "pending"
            }
        except Exception as e:
            return {
                "error": str(e),
                "status": "failed"
            }
    
    def execute_niad_deployment(self, honeypot_config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute honeypot deployment commands."""
        results = []
        
        for cmd_config in honeypot_config.get("commands", []):
            cmd = cmd_config["cmd"]
            description = cmd_config["description"]
            
            out, err, code = self.ssh_manager.execute_command(cmd)
            
            results.append({
                "description": description,
                "command": cmd,
                "success": code == 0,
                "output": out,
                "error": err if code != 0 else ""
            })
        
        return {
            "honeypot_name": honeypot_config.get("honeypot_name"),
            "execution_results": results,
            "overall_success": all(r["success"] for r in results),
            "timestamp": datetime.now().isoformat()
        }
    
    def monitor_honeypot(self, honeypot_name: str) -> Dict[str, Any]:
        """Monitor activity in honeypot."""
        try:
            # Get recent honeypot logs
            cmd = f"docker logs {honeypot_name} 2>/dev/null | tail -50"
            out, err, _ = self.ssh_manager.execute_command(cmd)
            
            # Check honeypot process status
            status_cmd = f"docker ps | grep {honeypot_name}"
            status_out, _, _ = self.ssh_manager.execute_command(status_cmd)
            
            return {
                "honeypot_name": honeypot_name,
                "is_active": bool(status_out.strip()),
                "recent_activity": out,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {
                "error": str(e),
                "honeypot_name": honeypot_name
            }
    
    def cleanup_honeypot(self, honeypot_name: str) -> Dict[str, Any]:
        """Clean up honeypot and restore original container."""
        try:
            # Get original container name from honeypot name
            original = honeypot_name.replace("honeypot-", "").rsplit("-", 1)[0]
            
            # Remove honeypot
            remove_cmd = f"docker rm -f {honeypot_name}"
            
            # Restore network connection
            restore_cmd = f"docker network connect bridge {original} 2>/dev/null || true"
            
            out1, _, code1 = self.ssh_manager.execute_command(remove_cmd)
            out2, _, code2 = self.ssh_manager.execute_command(restore_cmd)
            
            return {
                "honeypot_name": honeypot_name,
                "cleaned_up": code1 == 0,
                "restored": code2 == 0,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {"error": str(e)}
