from sqlalchemy import Column, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from app.database import Base

class ApprovalAction(Base):
    __tablename__ = "approval_actions"

    id = Column(String, primary_key=True, index=True)
    incident_id = Column(String, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    action_type = Column(String, nullable=False, index=True)  # ISOLATE_HOST, REVOKE_SESSION, BLOCK_IP, RESET_CREDENTIALS, QUARANTINE_FILE
    target = Column(String, nullable=False)  # e.g., "FINANCE-SRV-02 (10.0.4.15)", "j.smith@enterprise.corp"
    description = Column(Text, nullable=False)
    rationale = Column(Text, nullable=False)
    risk_level = Column(String, default="HIGH", index=True)  # CRITICAL, HIGH, MEDIUM, LOW
    proposed_by = Column(String, default="Containment Agent (Simulated Swarm)")
    status = Column(String, default="PENDING", index=True)  # PENDING, APPROVED, REJECTED, SIMULATED_EXECUTED
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    decided_at = Column(DateTime, nullable=True)
    decided_by = Column(String, nullable=True)
    decision_reason = Column(Text, nullable=True)
    simulation_execution_notes = Column(Text, nullable=True)

    incident = relationship("Incident", back_populates="approvals")
