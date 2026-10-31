from pydantic import BaseModel, ConfigDict, Field
from datetime import datetime
from typing import Literal, Optional, List, Any

class TimelineEventResponse(BaseModel):
    id: str
    incident_id: str
    timestamp: datetime
    title: str
    description: str
    event_type: str
    severity: str
    actor: str
    mitre_technique: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class EvidenceResponse(BaseModel):
    id: str
    incident_id: str
    evidence_type: str
    label: str
    value: str
    verdict: str
    source: str
    notes: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class InvestigationResponse(BaseModel):
    id: str
    incident_id: str
    hypothesis: str
    confidence_score: float
    summary: str
    findings: List[Any]  # Parsed JSON
    recommended_containment: List[Any]  # Parsed JSON
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IncidentBase(BaseModel):
    title: str
    severity: str
    status: str = "OPEN"
    lead_analyst: str = "SecOps Swarm / Analyst Rivera"
    summary: str
    attack_vector: str
    risk_score: int = 75
    is_simulated: bool = True


class IncidentResponse(IncidentBase):
    id: str
    created_at: datetime
    updated_at: datetime
    affected_assets: List[str]  # Parsed JSON list
    mitre_tactics: List[str]  # Parsed JSON list
    alert_count: Optional[int] = 0

    model_config = ConfigDict(from_attributes=True)


class IncidentDetailResponse(IncidentResponse):
    timeline_events: List[TimelineEventResponse] = Field(default_factory=list)
    evidence_items: List[EvidenceResponse] = Field(default_factory=list)
    investigation: Optional[InvestigationResponse] = None

    model_config = ConfigDict(from_attributes=True)


class IncidentUpdate(BaseModel):
    status: Optional[Literal["OPEN", "INVESTIGATING", "AWAITING_REVIEW", "CONTAINED", "RESOLVED", "CLOSED"]] = None
    severity: Optional[Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]] = None
    lead_analyst: Optional[str] = Field(default=None, min_length=1, max_length=120)
    risk_score: Optional[int] = Field(default=None, ge=0, le=100)
