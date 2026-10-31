from datetime import datetime, timezone
from app.agents.base import BaseSecurityAgent
from app.agents.state import InvestigationGraphState

class TriageAgent(BaseSecurityAgent):
    """
    Triage Agent (Phase 1: Deterministic Heuristic Engine).
    Analyzes alert taxonomy, filters noise, and assigns severity.
    """

    def __init__(self):
        super().__init__(name="TriageAgent", role="Telemetry Assessment & Noise Filtering")

    def run(self, state: InvestigationGraphState) -> InvestigationGraphState:
        alerts = state.get("alerts", [])
        
        # Rule-based triage evaluation
        has_critical = any(a.get("severity") == "CRITICAL" for a in alerts)
        has_auth_fail = any("auth" in a.get("title", "").lower() for a in alerts)
        
        calculated_severity = "CRITICAL" if has_critical else "HIGH" if has_auth_fail else "MEDIUM"
        
        log_entry = {
            "agent": self.name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": f"Deterministic triage evaluated {len(alerts)} alerts. Assessed severity: {calculated_severity}."
        }
        
        state["current_phase"] = "CORRELATION"
        state["agent_logs"].append(log_entry)
        return state
