from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database import get_db
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.approval import ApprovalAction
from app.models.threat_intel import ThreatIndicator
from app.services.incident_service import format_incident_response
from app.config import settings

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    total_alerts = db.query(Alert).count()
    open_incidents = db.query(Incident).filter(Incident.status.in_(["OPEN", "INVESTIGATING"])).count()
    critical_incidents = db.query(Incident).filter(Incident.severity == "CRITICAL").count()
    incidents_awaiting_review = db.query(Incident).filter(Incident.status == "AWAITING_REVIEW").count()
    pending_approvals = db.query(ApprovalAction).filter(ApprovalAction.status == "PENDING").count()
    verified_threat_indicators = db.query(ThreatIndicator).filter(ThreatIndicator.verification_status == "VERIFIED").count()

    # Alerts by severity
    severity_rows = (
        db.query(Alert.severity, func.count(Alert.id))
        .group_by(Alert.severity)
        .all()
    )
    alerts_by_severity = [{"severity": s, "count": c} for s, c in severity_rows]

    # Alerts by category
    category_rows = (
        db.query(Alert.category, func.count(Alert.id))
        .group_by(Alert.category)
        .all()
    )
    alerts_by_category = [{"category": c, "count": cnt} for c, cnt in category_rows]

    # Recent incidents
    recent_inc_objs = db.query(Incident).order_by(Incident.updated_at.desc()).limit(5).all()
    recent_incidents = [format_incident_response(i) for i in recent_inc_objs]

    # Recent alerts
    recent_alert_objs = db.query(Alert).order_by(Alert.timestamp.desc()).limit(5).all()
    recent_alerts = [
        {
            "id": a.id,
            "title": a.title,
            "source": a.source,
            "severity": a.severity,
            "status": a.status,
            "category": a.category,
            "source_ip": a.source_ip,
            "destination_ip": a.destination_ip,
            "user": a.user,
            "host": a.host,
            "description": a.description,
            "timestamp": a.timestamp,
            "is_simulated": a.is_simulated,
            "incident_id": a.incident_id,
        }
        for a in recent_alert_objs
    ]

    # Pending approvals items
    pending_approval_objs = (
        db.query(ApprovalAction)
        .filter(ApprovalAction.status == "PENDING")
        .order_by(ApprovalAction.created_at.desc())
        .limit(5)
        .all()
    )
    pending_approval_items = [
        {
            "id": ap.id,
            "incident_id": ap.incident_id,
            "action_type": ap.action_type,
            "target": ap.target,
            "description": ap.description,
            "rationale": ap.rationale,
            "risk_level": ap.risk_level,
            "proposed_by": ap.proposed_by,
            "status": ap.status,
            "created_at": ap.created_at,
            "decided_at": ap.decided_at,
            "decided_by": ap.decided_by,
            "decision_reason": ap.decision_reason,
            "simulation_execution_notes": ap.simulation_execution_notes,
        }
        for ap in pending_approval_objs
    ]

    return {
        "total_alerts": total_alerts,
        "open_incidents": open_incidents,
        "critical_incidents": critical_incidents,
        "incidents_awaiting_review": incidents_awaiting_review,
        "pending_approvals": pending_approvals,
        "verified_threat_indicators": verified_threat_indicators,
        "simulation_mode": settings.SIMULATION_MODE,
        "active_agent_swarm": "Investigation Swarm Core (Deterministic Engine v1.0)",
        "alerts_by_severity": alerts_by_severity,
        "alerts_by_category": alerts_by_category,
        "recent_incidents": recent_incidents,
        "recent_alerts": recent_alerts,
        "pending_approval_items": pending_approval_items,
    }
