import json
from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import Optional, List, Dict, Any
from app.models.incident import Incident, IncidentTimelineEvent, IncidentEvidence, IncidentInvestigation
from app.schemas.incident import IncidentUpdate, IncidentResponse, IncidentDetailResponse
from app.services.audit_service import log_action

def _parse_json_field(field_val: Any, default: Any):
    if not field_val:
        return default
    if isinstance(field_val, (list, dict)):
        return field_val
    try:
        return json.loads(field_val)
    except Exception:
        return default

def format_incident_response(inc: Incident) -> Dict[str, Any]:
    return {
        "id": inc.id,
        "title": inc.title,
        "severity": inc.severity,
        "status": inc.status,
        "lead_analyst": inc.lead_analyst,
        "created_at": inc.created_at,
        "updated_at": inc.updated_at,
        "summary": inc.summary,
        "affected_assets": _parse_json_field(inc.affected_assets, []),
        "attack_vector": inc.attack_vector,
        "mitre_tactics": _parse_json_field(inc.mitre_tactics, []),
        "risk_score": inc.risk_score,
        "is_simulated": inc.is_simulated,
        "alert_count": len(inc.alerts) if inc.alerts else 0,
    }

def format_incident_detail(inc: Incident) -> Dict[str, Any]:
    data = format_incident_response(inc)
    
    # Timeline
    timeline = []
    if inc.timeline_events:
        for t in inc.timeline_events:
            timeline.append({
                "id": t.id,
                "incident_id": t.incident_id,
                "timestamp": t.timestamp,
                "title": t.title,
                "description": t.description,
                "event_type": t.event_type,
                "severity": t.severity,
                "actor": t.actor,
                "mitre_technique": t.mitre_technique,
            })
    data["timeline_events"] = timeline

    # Evidence
    evidence = []
    if inc.evidence_items:
        for e in inc.evidence_items:
            evidence.append({
                "id": e.id,
                "incident_id": e.incident_id,
                "evidence_type": e.evidence_type,
                "label": e.label,
                "value": e.value,
                "verdict": e.verdict,
                "source": e.source,
                "notes": e.notes,
                "created_at": e.created_at,
            })
    data["evidence_items"] = evidence

    # Investigation
    investigation = None
    if inc.investigation:
        investigation = {
            "id": inc.investigation.id,
            "incident_id": inc.investigation.incident_id,
            "hypothesis": inc.investigation.hypothesis,
            "confidence_score": inc.investigation.confidence_score,
            "summary": inc.investigation.summary,
            "findings": _parse_json_field(inc.investigation.findings, []),
            "recommended_containment": _parse_json_field(inc.investigation.recommended_containment, []),
            "updated_at": inc.investigation.updated_at,
        }
    data["investigation"] = investigation

    return data

def get_incidents(
    db: Session,
    skip: int = 0,
    limit: int = 50,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
) -> Dict[str, Any]:
    query = db.query(Incident)
    
    if severity and severity.upper() != "ALL":
        query = query.filter(Incident.severity == severity.upper())
    if status and status.upper() != "ALL":
        query = query.filter(Incident.status == status.upper())
    if search:
        search_fmt = f"%{search}%"
        query = query.filter(
            or_(
                Incident.title.ilike(search_fmt),
                Incident.summary.ilike(search_fmt),
                Incident.attack_vector.ilike(search_fmt),
                Incident.affected_assets.ilike(search_fmt),
            )
        )
    
    total = query.count()
    items = query.order_by(Incident.updated_at.desc()).offset(skip).limit(limit).all()
    formatted = [format_incident_response(i) for i in items]
    return {"total": total, "items": formatted}

def get_incident_by_id(db: Session, incident_id: str) -> Optional[Incident]:
    return db.query(Incident).filter(Incident.id == incident_id).first()

def get_incident_detail(db: Session, incident_id: str) -> Optional[Dict[str, Any]]:
    inc = get_incident_by_id(db, incident_id)
    if not inc:
        return None
    return format_incident_detail(inc)

def update_incident(
    db: Session,
    incident_id: str,
    update_in: IncidentUpdate,
    actor: str = "analyst.alex"
) -> Optional[Dict[str, Any]]:
    inc = get_incident_by_id(db, incident_id)
    if not inc:
        return None
    
    changes = []
    if update_in.status is not None:
        changes.append(f"status: {inc.status} -> {update_in.status}")
        inc.status = update_in.status
    if update_in.severity is not None:
        changes.append(f"severity: {inc.severity} -> {update_in.severity}")
        inc.severity = update_in.severity
    if update_in.lead_analyst is not None:
        changes.append(f"lead_analyst: {inc.lead_analyst} -> {update_in.lead_analyst}")
        inc.lead_analyst = update_in.lead_analyst
    if update_in.risk_score is not None:
        changes.append(f"risk_score: {inc.risk_score} -> {update_in.risk_score}")
        inc.risk_score = update_in.risk_score
        
    db.commit()
    db.refresh(inc)

    if changes:
        log_action(
            db=db,
            actor=actor,
            action="INCIDENT_STATUS_CHANGE",
            target_type="INCIDENT",
            target_id=inc.id,
            details=f"Incident updated ({', '.join(changes)})"
        )
        
    return format_incident_detail(inc)

def get_incident_timeline(db: Session, incident_id: str) -> List[IncidentTimelineEvent]:
    return (
        db.query(IncidentTimelineEvent)
        .filter(IncidentTimelineEvent.incident_id == incident_id)
        .order_by(IncidentTimelineEvent.timestamp.asc())
        .all()
    )

def get_incident_evidence(db: Session, incident_id: str) -> List[IncidentEvidence]:
    return (
        db.query(IncidentEvidence)
        .filter(IncidentEvidence.incident_id == incident_id)
        .order_by(IncidentEvidence.created_at.desc())
        .all()
    )

def get_incident_investigation(db: Session, incident_id: str) -> Optional[Dict[str, Any]]:
    inv = db.query(IncidentInvestigation).filter(IncidentInvestigation.incident_id == incident_id).first()
    if not inv:
        return None
    return {
        "id": inv.id,
        "incident_id": inv.incident_id,
        "hypothesis": inv.hypothesis,
        "confidence_score": inv.confidence_score,
        "summary": inv.summary,
        "findings": _parse_json_field(inv.findings, []),
        "recommended_containment": _parse_json_field(inv.recommended_containment, []),
        "updated_at": inv.updated_at,
    }
