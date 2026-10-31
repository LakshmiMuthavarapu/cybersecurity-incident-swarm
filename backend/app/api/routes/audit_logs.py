from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import Optional, List
from app.database import get_db
from app.schemas.audit_log import AuditLogResponse
from app.services.audit_service import get_audit_logs

router = APIRouter(prefix="/audit-logs", tags=["Audit Logs"])

@router.get("", response_model=List[AuditLogResponse])
def list_audit_logs(
    actor: Optional[str] = Query(None, description="Filter by actor name"),
    action: Optional[str] = Query(None, description="Filter by action name"),
    target_type: Optional[str] = Query(None, description="Filter by target type: INCIDENT, APPROVAL, ALERT, THREAT_INTEL"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db)
):
    return get_audit_logs(
        db=db,
        limit=limit,
        offset=skip,
        actor=actor,
        action=action,
        target_type=target_type
    )
