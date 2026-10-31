from datetime import datetime, timezone
from app.agents.base import BaseSecurityAgent
from app.agents.state import InvestigationGraphState

class ContainmentAgent(BaseSecurityAgent):
    """
    Containment Agent (Phase 1: Deterministic Containment Action Recommender).
    Proposes safety-guarded actions for human-in-the-loop analyst approval.
    """

    def __init__(self):
        super().__init__(name="ContainmentAgent", role="Containment Action Recommendation")

    def run(self, state: InvestigationGraphState) -> InvestigationGraphState:
        alerts = state.get("alerts", [])
        
        actions = []
        hosts = list({a["host"] for a in alerts if a.get("host")})
        users = list({a["user"] for a in alerts if a.get("user")})
        ips = list({a["source_ip"] for a in alerts if a.get("source_ip") and not a["source_ip"].startswith("10.")})
        
        for h in hosts:
            actions.append({
                "action_type": "ISOLATE_HOST",
                "target": f"Host {h}",
                "description": f"Isolate endpoint {h} to halt lateral adversary proliferation.",
                "rationale": "High-risk script execution detected on internal workload.",
                "risk_level": "HIGH"
            })
            
        for u in users:
            actions.append({
                "action_type": "REVOKE_SESSION",
                "target": f"User {u}",
                "description": f"Invalidate active OAuth and session tokens for user {u}.",
                "rationale": "Credential theft or token replay activity suspected.",
                "risk_level": "MEDIUM"
            })
            
        for ip in ips:
            actions.append({
                "action_type": "BLOCK_IP",
                "target": f"IP {ip}",
                "description": f"Deploy perimeter firewall drop rule for external IP {ip}.",
                "rationale": "External C2 beacon communication destination.",
                "risk_level": "LOW"
            })
            
        state["proposed_actions"] = actions
        state["current_phase"] = "HUMAN_REVIEW"
        
        log_entry = {
            "agent": self.name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": f"Formulated {len(actions)} containment recommendations requiring analyst approval."
        }
        state["agent_logs"].append(log_entry)
        return state
