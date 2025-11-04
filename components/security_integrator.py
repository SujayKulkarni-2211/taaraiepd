from typing import List, Dict, Any
from datetime import datetime

class SecurityIntegrator:
    """Integrates CrowdSec and ClamAV security tools."""
    
    def __init__(self, ssh_manager):
        self.ssh_manager = ssh_manager
    
    def scan_with_clamav(self, path: str = "/") -> List[Dict[str, Any]]:
        """Scan system with ClamAV for malware."""
        try:
            cmd = f"clamscan -r --json {path} 2>/dev/null | head -100"
            out, err, _ = self.ssh_manager.execute_command(cmd)
            
            alerts = []
            if "FOUND" in out:
                alerts.append({
                    "type": "malware",
                    "timestamp": datetime.now().isoformat(),
                    "message": "ClamAV detected potential threats",
                    "details": out[:200]
                })
            
            return alerts
        except Exception as e:
            print(f"[v0] ClamAV scan error: {e}")
            return []
    
    def check_crowdsec(self) -> List[Dict[str, Any]]:
        """Fetch alerts from CrowdSec (mocked for MVP)."""
        # In production, would call CrowdSec API
        alerts = []
        try:
            # Mock CrowdSec check
            out, _, _ = self.ssh_manager.execute_command("tail -50 /var/log/auth.log 2>/dev/null | grep 'Failed password'")
            if out:
                alerts.append({
                    "type": "brute_force",
                    "timestamp": datetime.now().isoformat(),
                    "message": "Multiple failed login attempts detected",
                    "severity": "high"
                })
        except Exception as e:
            print(f"[v0] CrowdSec check error: {e}")
        
        return alerts
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get combined security status."""
        clamav_alerts = self.scan_with_clamav()
        crowdsec_alerts = self.check_crowdsec()
        
        return {
            "clamav_alerts": clamav_alerts,
            "crowdsec_alerts": crowdsec_alerts,
            "threat_level": "high" if (clamav_alerts or crowdsec_alerts) else "low"
        }
