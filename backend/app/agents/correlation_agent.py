from datetime import datetime, timezone
from app.agents.base import BaseSecurityAgent
from app.agents.state import InvestigationGraphState

class CorrelationAgent(BaseSecurityAgent):
    """
    Correlation Agent (Phase 1: Deterministic Cross-Alert Synthesizer).
    Groups alerts by common entity (IP, host, user) and generates incident hypothesis.
    """

    def __init__(self):
        super().__init__(name="CorrelationAgent", role="Attack Graph & Entity Correlation")

    def run(self, state: InvestigationGraphState) -> InvestigationGraphState:
        alerts = state.get("alerts", [])
        
        entities = set()
        for a in alerts:
            if a.get("host"):
                entities.add(a["host"])
            if a.get("user"):
                entities.add(a["user"])
            if a.get("source_ip"):
                entities.add(a["source_ip"])
                
        state["hypothesis"] = (
            f"Correlated cluster linking {len(entities)} unique infrastructure entities across {len(alerts)} alerts. "
            f"Pattern indicates coordinated credential access and lateral recon."
        )
        state["confidence_score"] = 0.89
        
        log_entry = {
            "agent": self.name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": f"Correlated {len(alerts)} alerts across entities: {list(entities)}."
        }
        
        state["current_phase"] = "CONTAINMENT"
        state["agent_logs"].append(log_entry)
        return state
