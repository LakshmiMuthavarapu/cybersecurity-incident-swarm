from sqlalchemy import Column, String, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from app.database import Base

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    title = Column(String, nullable=False, index=True)
    source = Column(String, nullable=False, index=True)  # e.g., "CrowdStrike EDR", "Suricata NIDS", "Okta IdP", "AWS GuardDuty"
    severity = Column(String, nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    status = Column(String, default="NEW", index=True)  # NEW, INVESTIGATING, ESCALATED, RESOLVED, FALSE_POSITIVE
    category = Column(String, nullable=False, index=True)  # Execution, Initial Access, Credential Access, Lateral Movement, etc.
    
    source_ip = Column(String, nullable=True, index=True)
    destination_ip = Column(String, nullable=True, index=True)
    user = Column(String, nullable=True, index=True)
    host = Column(String, nullable=True, index=True)
    
    description = Column(Text, nullable=False)
    raw_payload = Column(Text, nullable=True)  # JSON-encoded raw event payload
    
    incident_id = Column(String, ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    is_simulated = Column(Boolean, default=True, nullable=False)

    # Relationship to incident
    incident = relationship("Incident", back_populates="alerts")
