from datetime import datetime, timezone
from sqlalchemy.orm import Session
from typing import Optional, List, Dict, Any
from app.models.approval import ApprovalAction
from app.models.incident import Incident
from app.schemas.approval import ApprovalDecisionRequest
from app.services.audit_service import log_action
from fastapi import HTTPException

def get_approvals(
    db: Session,
    status: Optional[str] = None,
    incident_id: Optional[str] = None,
) -> List[ApprovalAction]:
    query = db.query(ApprovalAction)
    if status and status.upper() != "ALL":
        query = query.filter(ApprovalAction.status == status.upper())
    if incident_id:
        query = query.filter(ApprovalAction.incident_id == incident_id)
    return query.order_by(ApprovalAction.created_at.desc()).all()

def get_approval_by_id(db: Session, approval_id: str) -> Optional[ApprovalAction]:
    return db.query(ApprovalAction).filter(ApprovalAction.id == approval_id).first()

def process_approval_decision(
    db: Session,
    approval_id: str,
    decision_in: ApprovalDecisionRequest
) -> Optional[ApprovalAction]:
    approval = get_approval_by_id(db, approval_id)
    if not approval:
        return None

    if approval.status != "PENDING":
        raise HTTPException(status_code=409, detail="This approval has already been decided.")
    
    decision = decision_in.decision.upper()
    now = datetime.now(timezone.utc)
    
    approval.status = decision
    approval.decided_at = now
    approval.decided_by = decision_in.analyst_name
    approval.decision_reason = decision_in.reason

    # Synthetic / Simulated containment execution safety guardrail
    if decision == "APPROVED":
        approval.simulation_execution_notes = (
            f"[SIMULATION ONLY - NO REAL INFRASTRUCTURE MODIFIED]\n"
            f"Simulated execution for action '{approval.action_type}' on target '{approval.target}' completed.\n"
            f"Agent: Playbook Containment Runner (Simulated)\n"
            f"Result: {dict(ISOLATE_HOST='Endpoint isolation', REVOKE_SESSION='Session revocation', BLOCK_IP='Perimeter IP block', RESET_CREDENTIALS='Credential reset', QUARANTINE_FILE='File quarantine').get(approval.action_type, 'Mock response')} simulation recorded.\n"
            f"Execution Timestamp: {now.isoformat()}"
        )
        
        # Mark contained only when every proposed action has been approved.
        incident = db.query(Incident).filter(Incident.id == approval.incident_id).first()
        db.flush()
        remaining_count = db.query(ApprovalAction).filter(
            ApprovalAction.incident_id == approval.incident_id,
            ApprovalAction.status != "APPROVED",
        ).count()
        if incident and remaining_count == 0 and incident.status != "CONTAINED":
            incident.status = "CONTAINED"
            incident.updated_at = now
    elif decision == "REJECTED":
        approval.simulation_execution_notes = (
            f"Action rejected by analyst {decision_in.analyst_name}. Reason: {decision_in.reason}. "
            f"No containment simulation was dispatched."
        )

    log_action(
        db=db,
        actor=decision_in.analyst_name,
        action=f"APPROVAL_{decision}",
        target_type="APPROVAL",
        target_id=approval.id,
        details=(
            f"Analyst {decision_in.analyst_name} evaluated proposal {approval.action_type} on {approval.target}: "
            f"Decision={decision}. Reason: {decision_in.reason}"
        )
    )
    db.refresh(approval)

    return approval
