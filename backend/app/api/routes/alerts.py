from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional
from app.database import get_db
from app.schemas.alert import AlertResponse, AlertListResponse, AlertUpdate
from app.services.alert_service import get_alerts, get_alert_by_id, update_alert

router = APIRouter(prefix="/alerts", tags=["Alerts"])

@router.get("", response_model=AlertListResponse)
def list_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL"),
    source: Optional[str] = Query(None, description="Filter by source"),
    status: Optional[str] = Query(None, description="Filter by status: NEW, INVESTIGATING, ESCALATED, RESOLVED, FALSE_POSITIVE"),
    search: Optional[str] = Query(None, description="Search keyword in title, host, user, description, or IPs"),
    incident_id: Optional[str] = Query(None, description="Filter by associated incident ID"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    result = get_alerts(
        db=db,
        skip=skip,
        limit=limit,
        severity=severity,
        source=source,
        status=status,
        search=search,
        incident_id=incident_id
    )
    return result

@router.get("/{alert_id}", response_model=AlertResponse)
def get_single_alert(alert_id: str, db: Session = Depends(get_db)):
    alert = get_alert_by_id(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert with ID {alert_id} not found.")
    return alert

@router.patch("/{alert_id}", response_model=AlertResponse)
def modify_alert(
    alert_id: str,
    update_data: AlertUpdate,
    analyst: str = Query("analyst.alex", description="Analyst identifier"),
    db: Session = Depends(get_db)
):
    updated = update_alert(db=db, alert_id=alert_id, alert_in=update_data, actor=analyst)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Alert with ID {alert_id} not found.")
    return updated
