"""
LangGraph Investigation State Definition (Phase 1 Scaffolding).

Defines the shared state schema for the multi-agent cybersecurity investigation swarm.
"""

from typing import TypedDict, List, Dict, Any, Optional
from datetime import datetime

class InvestigationGraphState(TypedDict):
    """Shared state structure passed between swarm nodes in LangGraph."""
    incident_id: str
    session_id: str
    current_phase: str  # TRIAGE, CORRELATION, ENRICHMENT, CONTAINMENT, HUMAN_REVIEW
    alerts: List[Dict[str, Any]]
    extracted_iocs: List[Dict[str, Any]]
    timeline_events: List[Dict[str, Any]]
    hypothesis: Optional[str]
    confidence_score: float
    risk_score: int
    proposed_actions: List[Dict[str, Any]]
    analyst_decision: Optional[str]
    audit_trail: List[Dict[str, Any]]
    agent_logs: List[Dict[str, Any]]
    is_simulated: bool
