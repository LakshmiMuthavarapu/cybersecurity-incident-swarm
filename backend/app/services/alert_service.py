from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import Optional, List, Dict, Any
from app.models.alert import Alert
from app.schemas.alert import AlertCreate, AlertUpdate
from app.services.audit_service import log_action

def get_alerts(
    db: Session,
    skip: int = 0,
    limit: int = 50,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    incident_id: Optional[str] = None,
) -> Dict[str, Any]:
    query = db.query(Alert)
    
    if severity and severity.upper() != "ALL":
        query = query.filter(Alert.severity == severity.upper())
    if source and source.upper() != "ALL":
        query = query.filter(Alert.source.ilike(f"%{source}%"))
    if status and status.upper() != "ALL":
        query = query.filter(Alert.status == status.upper())
    if incident_id:
        query = query.filter(Alert.incident_id == incident_id)
    if search:
        search_fmt = f"%{search}%"
        query = query.filter(
            or_(
                Alert.title.ilike(search_fmt),
                Alert.description.ilike(search_fmt),
                Alert.source_ip.ilike(search_fmt),
                Alert.destination_ip.ilike(search_fmt),
                Alert.user.ilike(search_fmt),
                Alert.host.ilike(search_fmt),
            )
        )
    
    total = query.count()
    items = query.order_by(Alert.timestamp.desc()).offset(skip).limit(limit).all()
    return {"total": total, "items": items}

def get_alert_by_id(db: Session, alert_id: str) -> Optional[Alert]:
    return db.query(Alert).filter(Alert.id == alert_id).first()

def update_alert(db: Session, alert_id: str, alert_in: AlertUpdate, actor: str = "analyst.alex") -> Optional[Alert]:
    alert = get_alert_by_id(db, alert_id)
    if not alert:
        return None
    
    changes = []
    if alert_in.status is not None:
        changes.append(f"status: {alert.status} -> {alert_in.status}")
        alert.status = alert_in.status
    if alert_in.severity is not None:
        changes.append(f"severity: {alert.severity} -> {alert_in.severity}")
        alert.severity = alert_in.severity
    if alert_in.incident_id is not None:
        changes.append(f"incident_id: {alert.incident_id} -> {alert_in.incident_id}")
        alert.incident_id = alert_in.incident_id

    db.commit()
    db.refresh(alert)
    
    if changes:
        log_action(
            db=db,
            actor=actor,
            action="ALERT_UPDATED",
            target_type="ALERT",
            target_id=alert.id,
            details=f"Alert updated ({', '.join(changes)})"
        )

    return alert
