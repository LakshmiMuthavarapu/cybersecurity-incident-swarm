"""
Investigation Swarm Workflow (Phase 1 Execution & Phase 2 LangGraph Scaffolding).

Coordinates the multi-agent investigation sequence.
In Phase 1, runs the deterministic agent pipeline.
In Phase 2, this module compiles into a LangGraph StateGraph with LLM nodes.
"""

from typing import List, Dict, Any
from app.agents.state import InvestigationGraphState
from app.agents.triage_agent import TriageAgent
from app.agents.correlation_agent import CorrelationAgent
from app.agents.containment_agent import ContainmentAgent

class InvestigationSwarmWorkflow:
    def __init__(self):
        self.triage_agent = TriageAgent()
        self.correlation_agent = CorrelationAgent()
        self.containment_agent = ContainmentAgent()

    def run(self, incident_id: str, alerts: List[Dict[str, Any]]) -> InvestigationGraphState:
        """Executes the sequential agent swarm pipeline."""
        initial_state: InvestigationGraphState = {
            "incident_id": incident_id,
            "session_id": f"sess-{incident_id}",
            "current_phase": "TRIAGE",
            "alerts": alerts,
            "extracted_iocs": [],
            "timeline_events": [],
            "hypothesis": None,
            "confidence_score": 0.0,
            "risk_score": 50,
            "proposed_actions": [],
            "analyst_decision": None,
            "audit_trail": [],
            "agent_logs": [],
            "is_simulated": True,
        }

        # Step 1: Triage
        state_after_triage = self.triage_agent.run(initial_state)

        # Step 2: Correlation
        state_after_corr = self.correlation_agent.run(state_after_triage)

        # Step 3: Containment
        final_state = self.containment_agent.run(state_after_corr)

        return final_state
