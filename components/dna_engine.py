import numpy as np
from typing import List, Dict, Any
import json

class DNAEngine:
    """System DNA (Digital System Fingerprint) using quantum-inspired similarity."""
    
    def __init__(self, ssh_manager):
        self.ssh_manager = ssh_manager
        self.anomaly_threshold = 0.80  # Similarity score threshold
    
    def collect_system_dna(self) -> List[float]:
        """Collect system metrics and build DNA vector."""
        try:
            metrics = {}
            
            # CPU usage
            out, _, _ = self.ssh_manager.execute_command("top -bn1 | grep 'Cpu(s)' | awk '{print $2}'")
            metrics["cpu"] = float(out.strip().replace('%us,', '')) if out.strip() else 0.0
            
            # Memory usage
            out, _, _ = self.ssh_manager.execute_command("free | grep Mem | awk '{print ($3/$2) * 100}'")
            metrics["memory"] = float(out.strip()) if out.strip() else 0.0
            
            # Process count
            out, _, _ = self.ssh_manager.execute_command("ps aux | wc -l")
            metrics["processes"] = float(out.strip()) if out.strip() else 0.0
            
            # Open ports
            out, _, _ = self.ssh_manager.execute_command("netstat -tuln 2>/dev/null | grep LISTEN | wc -l")
            metrics["open_ports"] = float(out.strip()) if out.strip() else 0.0
            
            # Normalize to [0, 1]
            dna_vector = [
                min(metrics.get("cpu", 0) / 100, 1.0),
                min(metrics.get("memory", 0) / 100, 1.0),
                min(metrics.get("processes", 0) / 500, 1.0),
                min(metrics.get("open_ports", 0) / 30, 1.0),
            ]
            
            return dna_vector
        except Exception as e:
            print(f"[v0] DNA collection error: {e}")
            return [0.0, 0.0, 0.0, 0.0]
    
    def compute_similarity(self, vector1: List[float], vector2: List[float]) -> float:
        """Quantum-inspired similarity: S = |<ψ|φ>|²"""
        try:
            v1 = np.array(vector1)
            v2 = np.array(vector2)
            
            # Normalize
            v1 = v1 / (np.linalg.norm(v1) + 1e-8)
            v2 = v2 / (np.linalg.norm(v2) + 1e-8)
            
            # Dot product (inner product)
            dot = np.dot(v1, v2)
            # Square for quantum-inspired effect
            similarity = dot ** 2
            
            return float(similarity)
        except Exception as e:
            print(f"[v0] Similarity computation error: {e}")
            return 0.5
    
    def detect_drift(self, baseline: List[float], current: List[float]) -> Dict[str, Any]:
        """Check for behavioral drift."""
        similarity = self.compute_similarity(baseline, current)
        is_anomaly = similarity < self.anomaly_threshold
        
        return {
            "similarity_score": similarity,
            "is_anomaly": is_anomaly,
            "drift_magnitude": 1.0 - similarity
        }
