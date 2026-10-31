from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional, List
from app.database import get_db
from app.schemas.approval import ApprovalResponse, ApprovalDecisionRequest
from app.services.approval_service import (
    get_approvals,
    get_approval_by_id,
    process_approval_decision,
)

router = APIRouter(prefix="/approvals", tags=["Approvals"])

@router.get("", response_model=List[ApprovalResponse])
def list_approvals(
    status: Optional[str] = Query(None, description="Filter: PENDING, APPROVED, REJECTED, SIMULATED_EXECUTED"),
    incident_id: Optional[str] = Query(None, description="Filter by incident ID"),
    db: Session = Depends(get_db)
):
    return get_approvals(db=db, status=status, incident_id=incident_id)

@router.get("/{approval_id}", response_model=ApprovalResponse)
def get_single_approval(approval_id: str, db: Session = Depends(get_db)):
    approval = get_approval_by_id(db, approval_id)
    if not approval:
        raise HTTPException(status_code=404, detail=f"Approval action {approval_id} not found.")
    return approval

@router.post("/{approval_id}/decision", response_model=ApprovalResponse)
def submit_decision(
    approval_id: str,
    decision_in: ApprovalDecisionRequest,
    db: Session = Depends(get_db)
):
    current = get_approval_by_id(db, approval_id)
    if not current:
        raise HTTPException(status_code=404, detail=f"Approval action {approval_id} not found.")
    if current.status != "PENDING":
        raise HTTPException(status_code=409, detail="This approval has already been decided.")
    approval = process_approval_decision(db=db, approval_id=approval_id, decision_in=decision_in)
    if not approval:
        raise HTTPException(status_code=404, detail=f"Approval action {approval_id} not found.")
    return approval
