from sqlalchemy import Column, String, DateTime, Text, Boolean, Integer, Float, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from app.database import Base

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True, index=True)
    title = Column(String, nullable=False, index=True)
    severity = Column(String, nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW
    status = Column(String, default="OPEN", index=True)  # OPEN, INVESTIGATING, AWAITING_REVIEW, CONTAINED, RESOLVED, CLOSED
    lead_analyst = Column(String, default="SecOps Swarm / Analyst Rivera")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    summary = Column(Text, nullable=False)
    affected_assets = Column(Text, nullable=False)  # JSON-serialized list of assets
    attack_vector = Column(String, nullable=False)
    mitre_tactics = Column(Text, nullable=False)  # JSON-serialized list of MITRE tactics
    risk_score = Column(Integer, default=75)  # 0 to 100
    is_simulated = Column(Boolean, default=True, nullable=False)

    # Relationships
    alerts = relationship("Alert", back_populates="incident")
    timeline_events = relationship("IncidentTimelineEvent", back_populates="incident", cascade="all, delete-orphan", order_by="IncidentTimelineEvent.timestamp")
    evidence_items = relationship("IncidentEvidence", back_populates="incident", cascade="all, delete-orphan")
    investigation = relationship("IncidentInvestigation", back_populates="incident", uselist=False, cascade="all, delete-orphan")
    approvals = relationship("ApprovalAction", back_populates="incident", cascade="all, delete-orphan")


class IncidentTimelineEvent(Base):
    __tablename__ = "incident_timeline_events"

    id = Column(String, primary_key=True, index=True)
    incident_id = Column(String, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    event_type = Column(String, nullable=False)  # ALERT, OBSERVATION, ARTIFACT_ANALYSIS, AGENT_ACTION, CONTAINMENT_TRIGGER
    severity = Column(String, default="INFO")  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    actor = Column(String, default="Swarm Triage Engine")
    mitre_technique = Column(String, nullable=True)  # e.g., "T1059.001 - PowerShell"

    incident = relationship("Incident", back_populates="timeline_events")


class IncidentEvidence(Base):
    __tablename__ = "incident_evidence"

    id = Column(String, primary_key=True, index=True)
    incident_id = Column(String, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_type = Column(String, nullable=False)  # IP_ADDRESS, FILE_HASH, USER_ACCOUNT, COMMAND_LINE, NETWORK_BEACON, REGISTRY_KEY
    label = Column(String, nullable=False)
    value = Column(String, nullable=False)
    verdict = Column(String, default="SUSPICIOUS")  # MALICIOUS, SUSPICIOUS, BENIGN, UNKNOWN
    source = Column(String, nullable=False)  # CrowdStrike EDR, Proxy Logs, Active Directory
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    incident = relationship("Incident", back_populates="evidence_items")


class IncidentInvestigation(Base):
    __tablename__ = "incident_investigations"

    id = Column(String, primary_key=True, index=True)
    incident_id = Column(String, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    hypothesis = Column(Text, nullable=False)
    confidence_score = Column(Float, default=0.85)  # 0.0 to 1.0
    summary = Column(Text, nullable=False)
    findings = Column(Text, nullable=False)  # JSON-serialized list of finding objects
    recommended_containment = Column(Text, nullable=False)  # JSON-serialized list of recommended actions
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    incident = relationship("Incident", back_populates="investigation")
