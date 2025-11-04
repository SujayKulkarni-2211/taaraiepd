from typing import Dict, List, Any
from datetime import datetime

class RollbackManager:
    """Manages action logging and rollback commands."""
    
    def __init__(self, ssh_manager=None):
        self.ssh_manager = ssh_manager
        self.actions_log = []
    
    def log_action(self, command: str, rollback: str, status: str, output: str = "") -> Dict[str, Any]:
        """Log an executed action with its rollback command."""
        action = {
            "timestamp": datetime.now().isoformat(),
            "command_executed": command,
            "rollback_command": rollback,
            "status": status,
            "output": output[:500]  # Truncate output
        }
        self.actions_log.append(action)
        return action
    
    def get_actions_log(self) -> List[Dict[str, Any]]:
        """Retrieve full actions log."""
        return self.actions_log
    
    def rollback_action(self, action_index: int) -> tuple[str, str, int]:
        """Execute rollback for a previous action."""
        try:
            if action_index < 0 or action_index >= len(self.actions_log):
                return "", "Invalid action index", 1
            
            action = self.actions_log[action_index]
            rollback_cmd = action.get("rollback_command")
            
            if not rollback_cmd:
                return "", "No rollback available for this action", 1
            
            out, err, code = self.ssh_manager.execute_command(rollback_cmd)
            return out, err, code
        except Exception as e:
            return "", str(e), 1
