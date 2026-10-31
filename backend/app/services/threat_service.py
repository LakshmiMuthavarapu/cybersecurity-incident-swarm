import json
import uuid
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from fastapi import HTTPException
from typing import Optional, List, Dict, Any
from app.models.threat_intel import ThreatIndicator
from app.schemas.threat_intel import ThreatIndicatorCreate, ThreatIndicatorUpdate
from app.services.audit_service import log_action

def _parse_tags(tags_val: Any) -> List[str]:
    if not tags_val:
        return []
    if isinstance(tags_val, list):
        return tags_val
    try:
        return json.loads(tags_val)
    except Exception:
        return []

def format_indicator(ti: ThreatIndicator) -> Dict[str, Any]:
    return {
        "id": ti.id,
        "indicator_type": ti.indicator_type,
        "value": ti.value,
        "reputation": ti.reputation,
        "threat_actor": ti.threat_actor,
        "confidence": ti.confidence,
        "verification_status": ti.verification_status,
        "first_seen": ti.first_seen,
        "last_seen": ti.last_seen,
        "tags": _parse_tags(ti.tags),
        "description": ti.description,
        "is_simulated": ti.is_simulated,
    }

def get_threat_indicators(
    db: Session,
    skip: int = 0,
    limit: int = 50,
    indicator_type: Optional[str] = None,
    reputation: Optional[str] = None,
    verification_status: Optional[str] = None,
    search: Optional[str] = None,
) -> Dict[str, Any]:
    query = db.query(ThreatIndicator)
    
    if indicator_type and indicator_type.upper() != "ALL":
        query = query.filter(ThreatIndicator.indicator_type == indicator_type.upper())
    if reputation and reputation.upper() != "ALL":
        query = query.filter(ThreatIndicator.reputation == reputation.upper())
    if verification_status and verification_status.upper() != "ALL":
        query = query.filter(ThreatIndicator.verification_status == verification_status.upper())
    if search:
        search_fmt = f"%{search}%"
        query = query.filter(
            or_(
                ThreatIndicator.value.ilike(search_fmt),
                ThreatIndicator.threat_actor.ilike(search_fmt),
                ThreatIndicator.description.ilike(search_fmt),
                ThreatIndicator.tags.ilike(search_fmt),
            )
        )
        
    total = query.count()
    items = query.order_by(ThreatIndicator.last_seen.desc()).offset(skip).limit(limit).all()
    formatted = [format_indicator(ti) for ti in items]
    return {"total": total, "items": formatted}

def get_threat_indicator_by_id(db: Session, indicator_id: str) -> Optional[Dict[str, Any]]:
    ti = db.query(ThreatIndicator).filter(ThreatIndicator.id == indicator_id).first()
    if not ti:
        return None
    return format_indicator(ti)

def create_threat_indicator(db: Session, indicator_in: ThreatIndicatorCreate, actor: str = "analyst.alex") -> Dict[str, Any]:
    ioc_id = indicator_in.id or f"IOC-{uuid.uuid4().hex[:8].upper()}"
    ti = ThreatIndicator(
        id=ioc_id,
        indicator_type=indicator_in.indicator_type.upper(),
        value=indicator_in.value.strip(),
        reputation=indicator_in.reputation.upper(),
        threat_actor=indicator_in.threat_actor,
        confidence=indicator_in.confidence,
        verification_status=indicator_in.verification_status.upper(),
        tags=json.dumps(indicator_in.tags),
        description=indicator_in.description,
        is_simulated=indicator_in.is_simulated,
    )
    db.add(ti)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="An indicator with this value or ID already exists.") from exc
    db.refresh(ti)

    log_action(
        db=db,
        actor=actor,
        action="IOC_CREATED",
        target_type="THREAT_INTEL",
        target_id=ti.id,
        details=f"Created IoC {ti.indicator_type}:{ti.value} [{ti.reputation}]"
    )

    return format_indicator(ti)

def update_threat_indicator(
    db: Session,
    indicator_id: str,
    update_in: ThreatIndicatorUpdate,
    actor: str = "analyst.alex"
) -> Optional[Dict[str, Any]]:
    ti = db.query(ThreatIndicator).filter(ThreatIndicator.id == indicator_id).first()
    if not ti:
        return None
    
    changes = []
    if update_in.verification_status is not None:
        changes.append(f"verification_status: {ti.verification_status} -> {update_in.verification_status}")
        ti.verification_status = update_in.verification_status.upper()
    if update_in.confidence is not None:
        changes.append(f"confidence: {ti.confidence} -> {update_in.confidence}")
        ti.confidence = update_in.confidence
    if update_in.reputation is not None:
        changes.append(f"reputation: {ti.reputation} -> {update_in.reputation}")
        ti.reputation = update_in.reputation.upper()
    
    ti.last_seen = datetime.now(timezone.utc)
    db.commit()
    db.refresh(ti)

    if changes:
        log_action(
            db=db,
            actor=actor,
            action="IOC_VERIFIED",
            target_type="THREAT_INTEL",
            target_id=ti.id,
            details=f"Threat Indicator updated ({', '.join(changes)})"
        )
        
    return format_indicator(ti)
