from sqlalchemy import Column, String, DateTime, Text, Boolean
from datetime import datetime, timezone
from app.database import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    actor = Column(String, nullable=False, index=True)  # analyst.alex, TriageAgent, System, Analyst
    action = Column(String, nullable=False, index=True)  # APPROVAL_DECISION, INCIDENT_UPDATED, ALERT_CORRELATED, IOC_VERIFIED
    target_type = Column(String, nullable=False, index=True)  # INCIDENT, APPROVAL, ALERT, THREAT_INTEL, SYSTEM
    target_id = Column(String, nullable=False, index=True)
    details = Column(Text, nullable=False)
    client_ip = Column(String, default="127.0.0.1 (Local Analyst Session)")
    is_simulated = Column(Boolean, default=True, nullable=False)
