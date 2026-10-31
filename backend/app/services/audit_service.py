from sqlalchemy.orm import Session
from datetime import datetime, timezone
import uuid
from app.models.audit_log import AuditLog

def log_action(
    db: Session,
    actor: str,
    action: str,
    target_type: str,
    target_id: str,
    details: str,
    client_ip: str = "127.0.0.1 (Local Analyst Session)",
    is_simulated: bool = True
) -> AuditLog:
    """Records an audit event in the database for SOC audit trail compliance."""
    log_id = f"AUD-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    log_entry = AuditLog(
        id=log_id,
        timestamp=datetime.now(timezone.utc),
        actor=actor,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=details,
        client_ip=client_ip,
        is_simulated=is_simulated,
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry

def get_audit_logs(
    db: Session,
    limit: int = 100,
    offset: int = 0,
    actor: str = None,
    action: str = None,
    target_type: str = None,
):
    query = db.query(AuditLog)
    if actor:
        query = query.filter(AuditLog.actor.ilike(f"%{actor}%"))
    if action:
        query = query.filter(AuditLog.action == action)
    if target_type:
        query = query.filter(AuditLog.target_type == target_type)
    
    return query.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit).all()
