from typing import Dict, List, Any, Optional
from components.llm_service import LLMService

class ReasoningEngine:
    """
    Causal reasoning engine combining heuristics + LLM intelligence.
    Correlates DNA drift, security alerts, and metrics for explainable recommendations.
    """
    
    def __init__(self, llm_api_key: str = None):
        self.llm_api_key = llm_api_key
        self.llm_service = LLMService(llm_api_key) if llm_api_key else None
    
    def correlate_events(self, dna_drift: Dict, security_alerts: List, 
                        metrics: Dict = None) -> Dict[str, Any]:
        """
        Correlate all signals and generate reasoning.
        Uses heuristics for immediate response + LLM for deep analysis.
        """
        
        # Quick heuristic analysis
        heuristic_analysis = self._heuristic_analysis(dna_drift, security_alerts)
        
        # LLM-based deep analysis if available
        if self.llm_service:
            try:
                llm_analysis = self.llm_service.analyze_threat(dna_drift, security_alerts, metrics or {})
                return {
                    "heuristic_analysis": heuristic_analysis,
                    "llm_analysis": llm_analysis,
                    "combined_confidence": min(
                        heuristic_analysis.get("confidence", 0.5) * 1.2,
                        1.0
                    )
                }
            except Exception as e:
                return {
                    "heuristic_analysis": heuristic_analysis,
                    "llm_error": str(e),
                    "confidence": heuristic_analysis.get("confidence", 0.5)
                }
        
        return {
            "analysis": heuristic_analysis,
            "confidence": heuristic_analysis.get("confidence", 0.5),
            "llm_available": False
        }
    
    def _heuristic_analysis(self, dna_drift: Dict, security_alerts: List) -> Dict[str, Any]:
        """Quick heuristic-based analysis (fallback if LLM unavailable)."""
        analysis = {
            "likely_causes": [],
            "recommended_actions": [],
            "risk_level": "low",
            "confidence": 0.0
        }
        
        # DNA drift analysis
        if dna_drift.get("is_anomaly"):
            drift_mag = dna_drift.get("drift_magnitude", 0)
            
            if drift_mag > 0.3:
                analysis["likely_causes"].append("Major system behavior change")
                analysis["recommended_actions"].append("Investigate running processes: ps aux")
                analysis["recommended_actions"].append("Check recent log changes: find / -mmin -5 -type f")
                analysis["confidence"] = 0.7
                analysis["risk_level"] = "high" if drift_mag > 0.5 else "medium"
        
        # Security alerts analysis
        for alert in security_alerts:
            alert_type = alert.get("type", "").lower()
            
            if alert_type == "malware":
                analysis["likely_causes"].append("Possible malware compromise")
                analysis["recommended_actions"].extend([
                    "Isolate affected service",
                    "Run full system scan: clamscan -r /",
                    "Review recent file modifications"
                ])
                analysis["confidence"] = 0.95
                analysis["risk_level"] = "critical"
            
            elif alert_type == "brute_force":
                analysis["likely_causes"].append("Brute force attack detected")
                analysis["recommended_actions"].extend([
                    "Review SSH logs: tail -100 /var/log/auth.log",
                    "Block suspicious IPs",
                    "Enable fail2ban"
                ])
                analysis["confidence"] = 0.85
                analysis["risk_level"] = "high"
            
            elif alert_type == "privilege_escalation":
                analysis["likely_causes"].append("Privilege escalation attempt")
                analysis["recommended_actions"].extend([
                    "Check sudo logs: grep sudo /var/log/auth.log",
                    "Review user groups: getent group",
                    "Audit file permissions: find / -perm -4000"
                ])
                analysis["confidence"] = 0.9
                analysis["risk_level"] = "critical"
        
        return analysis
    
    def generate_explanation(self, correlation: Dict) -> str:
        """Generate human-readable explanation from correlation analysis."""
        
        # Use LLM explanation if available
        if correlation.get("llm_analysis", {}).get("success"):
            return correlation["llm_analysis"].get("explanation", "Analysis complete.")
        
        # Fallback to heuristic explanation
        analysis = correlation.get("heuristic_analysis") or correlation.get("analysis", {})
        
        causes = ", ".join(analysis.get("likely_causes", ["No anomalies detected"]))
        actions = "\n".join([f"- {a}" for a in analysis.get("recommended_actions", ["Monitor system"])])
        risk = analysis.get("risk_level", "unknown").upper()
        confidence = analysis.get("confidence", correlation.get("confidence", 0)) * 100
        
        return (
            f"**Risk Level:** {risk}\n"
            f"**Detected Issues:** {causes}\n"
            f"**Recommended Actions:**\n{actions}\n"
            f"**Confidence:** {confidence:.0f}%"
        )
