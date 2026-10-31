from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional
from app.database import get_db
from app.schemas.threat_intel import ThreatIndicatorCreate, ThreatIndicatorUpdate
from app.services.threat_service import (
    get_threat_indicators,
    get_threat_indicator_by_id,
    create_threat_indicator,
    update_threat_indicator,
)

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])

@router.get("")
def list_threat_indicators(
    indicator_type: Optional[str] = Query(None, description="Filter: IP, DOMAIN, MD5, SHA256, URL, CVE"),
    reputation: Optional[str] = Query(None, description="Filter: MALICIOUS, SUSPICIOUS, BENIGN, UNKNOWN"),
    verification_status: Optional[str] = Query(None, description="Filter: VERIFIED, UNVERIFIED, PENDING_REVIEW, DISPROVEN"),
    search: Optional[str] = Query(None, description="Search indicator value, actor, description, or tags"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db)
):
    return get_threat_indicators(
        db=db,
        skip=skip,
        limit=limit,
        indicator_type=indicator_type,
        reputation=reputation,
        verification_status=verification_status,
        search=search
    )

@router.get("/{indicator_id}")
def get_single_indicator(indicator_id: str, db: Session = Depends(get_db)):
    ti = get_threat_indicator_by_id(db, indicator_id)
    if not ti:
        raise HTTPException(status_code=404, detail=f"Indicator {indicator_id} not found.")
    return ti

@router.post("", status_code=201)
def add_indicator(
    indicator_in: ThreatIndicatorCreate,
    analyst: str = Query("analyst.alex", description="Analyst identifier"),
    db: Session = Depends(get_db)
):
    return create_threat_indicator(db=db, indicator_in=indicator_in, actor=analyst)

@router.patch("/{indicator_id}")
def verify_indicator(
    indicator_id: str,
    update_in: ThreatIndicatorUpdate,
    analyst: str = Query("analyst.alex", description="Analyst identifier"),
    db: Session = Depends(get_db)
):
    updated = update_threat_indicator(db=db, indicator_id=indicator_id, update_in=update_in, actor=analyst)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Indicator {indicator_id} not found.")
    return updated
