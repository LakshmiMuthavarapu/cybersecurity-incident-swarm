from pydantic import BaseModel
from typing import Dict, List, Any
from app.schemas.incident import IncidentResponse
from app.schemas.alert import AlertResponse
from app.schemas.approval import ApprovalResponse

class SeverityCount(BaseModel):
    severity: str
    count: int

class CategoryCount(BaseModel):
    category: str
    count: int

class DashboardStatsResponse(BaseModel):
    total_alerts: int
    open_incidents: int
    critical_incidents: int
    incidents_awaiting_review: int
    pending_approvals: int
    verified_threat_indicators: int
    simulation_mode: bool
    active_agent_swarm: str  # e.g., "Swarm Triage & Correlation Engine (Deterministic v1)"
    alerts_by_severity: List[SeverityCount]
    alerts_by_category: List[CategoryCount]
    recent_incidents: List[IncidentResponse]
    recent_alerts: List[AlertResponse]
    pending_approval_items: List[ApprovalResponse]
