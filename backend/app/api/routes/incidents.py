from fastapi import APIRouter, Depends, HTTPException, Query
from datetime import datetime, timedelta, timezone
import json
import re
import uuid
from sqlalchemy.orm import Session
from typing import Optional, List, Dict, Any
from app.database import get_db
from app.schemas.incident import IncidentUpdate, TimelineEventResponse, EvidenceResponse
from app.services.incident_service import (
    get_incidents,
    get_incident_detail,
    update_incident,
    get_incident_timeline,
    get_incident_evidence,
    get_incident_investigation,
)
from app.models.alert import Alert
from app.models.approval import ApprovalAction
from app.models.incident import Incident, IncidentEvidence, IncidentInvestigation, IncidentTimelineEvent
from app.schemas.agent_schemas import (
    IdentityAnalysisInput, IdentityEvent, ImpactAnalysisInput, LogAnalysisInput,
    LogEvent, ThreatIntelInput,
)
from app.agents import (
    IdentityAnalysisAgent, ImpactAnalysisAgent, LogAnalysisAgent,
    ThreatIntelligenceAgent,
)
from app.services.audit_service import log_action

router = APIRouter(prefix="/incidents", tags=["Incidents"])

@router.get("")
def list_incidents(
    severity: Optional[str] = Query(None, description="Filter: CRITICAL, HIGH, MEDIUM, LOW"),
    status: Optional[str] = Query(None, description="Filter: OPEN, INVESTIGATING, AWAITING_REVIEW, CONTAINED, RESOLVED, CLOSED"),
    search: Optional[str] = Query(None, description="Search keyword in title, summary, attack vector, or assets"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db)
):
    return get_incidents(
        db=db,
        skip=skip,
        limit=limit,
        severity=severity,
        status=status,
        search=search
    )

@router.get("/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    detail = get_incident_detail(db, incident_id)
    if not detail:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")
    return detail

@router.patch("/{incident_id}")
def modify_incident(
    incident_id: str,
    update_data: IncidentUpdate,
    analyst: str = Query("analyst.alex", description="Analyst identifier"),
    db: Session = Depends(get_db)
):
    updated = update_incident(db=db, incident_id=incident_id, update_in=update_data, actor=analyst)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")
    return updated

@router.get("/{incident_id}/timeline", response_model=List[TimelineEventResponse])
def get_timeline(incident_id: str, db: Session = Depends(get_db)):
    events = get_incident_timeline(db, incident_id)
    return events

@router.get("/{incident_id}/evidence", response_model=List[EvidenceResponse])
def get_evidence(incident_id: str, db: Session = Depends(get_db)):
    evidence = get_incident_evidence(db, incident_id)
    return evidence

@router.get("/{incident_id}/investigation")
def get_investigation(incident_id: str, db: Session = Depends(get_db)):
    inv = get_incident_investigation(db, incident_id)
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation for incident {incident_id} not found.")
    return inv


def _to_log_event(alert: Alert) -> LogEvent:
    try:
        payload = json.loads(alert.raw_payload or "{}")
    except (TypeError, json.JSONDecodeError):
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    title = f"{alert.title} {alert.description}".lower()
    is_auth = any(word in title for word in ("login", "logon", "auth", "password", "mfa"))
    failed = any(word in title for word in ("failed", "failure", "spray", "denied"))
    event_type = "LOGON_FAILED" if is_auth and failed else "LOGON_SUCCESS" if is_auth else "PROCESS_CREATE"
    return LogEvent(
        event_id=alert.id, timestamp=alert.timestamp, log_source=alert.source,
        event_type=event_type, host=alert.host, user=alert.user,
        source_ip=alert.source_ip, destination_ip=alert.destination_ip,
        process_name=payload.get("process_name") or payload.get("source_image") or ("powershell.exe" if "powershell" in title else None),
        parent_process=payload.get("parent_process") or ("WINWORD.EXE" if "winword" in title else None),
        command_line=payload.get("command_line") or alert.description,
        hash_sha256=payload.get("hash_sha256"),
        target_port=payload.get("dest_port"), additional_data=payload,
    )


@router.post("/{incident_id}/investigation/run")
def run_swarm_investigation(incident_id: str, db: Session = Depends(get_db)):
    """Run all four deterministic agents against an incident's simulated telemetry."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")
    alerts = db.query(Alert).filter(Alert.incident_id == incident_id).order_by(Alert.timestamp.asc()).all()
    if not alerts:
        raise HTTPException(status_code=422, detail="This incident has no linked telemetry to investigate.")

    logs = [_to_log_event(alert) for alert in alerts]
    identity_events = []
    for alert in alerts:
        title = f"{alert.title} {alert.description}".lower()
        if not any(word in title for word in ("login", "logon", "auth", "password", "mfa")):
            continue
        if alert.user and alert.user.lower().startswith("multiple"):
            continue
        raw_type = "FAILURE" if any(word in title for word in ("failed", "failure", "spray", "denied")) else "SUCCESS"
        location = re.search(r"from ([a-z .-]+) \(([^)]+)\)", alert.description, re.IGNORECASE)
        identity_events.append(IdentityEvent(
            event_id=alert.id, timestamp=alert.timestamp, user_id=alert.user or "unknown",
            auth_event=raw_type, source_ip=alert.source_ip,
            location_city=location.group(1).strip() if location else None,
            location_country=location.group(2).strip() if location else None,
            is_vpn_or_tor=bool(alert.source_ip and alert.source_ip.startswith("185.220.101.")),
            additional_context={"title": alert.title, "description": alert.description},
        ))
        if "impossible travel" in title:
            try:
                payload = json.loads(alert.raw_payload or "{}")
            except (TypeError, json.JSONDecodeError):
                payload = {}
            first_city = payload.get("city_1") if isinstance(payload, dict) else None
            second_city = payload.get("city_2") if isinstance(payload, dict) else None
            location = re.search(r"from ([A-Za-z .-]+) \(([^)]+)\).*? and ([A-Za-z .-]+)(?: \(([^)]+)\))?", alert.description, re.IGNORECASE)
            if location:
                first_city = first_city or location.group(1).strip()
                first_country = location.group(2).strip()
                second_city = second_city or location.group(3).strip()
                second_country = location.group(4).strip() if location.group(4) else {"singapore": "Singapore"}.get(second_city.lower())
            else:
                first_country = {"london": "United Kingdom"}.get((first_city or "").lower())
                second_country = {"singapore": "Singapore"}.get((second_city or "").lower())
            if first_city and second_city and first_country and second_country:
                minutes = payload.get("time_delta_mins") if isinstance(payload, dict) else None
                minutes_match = re.search(r"(\d+)m", alert.title, re.IGNORECASE)
                minutes = minutes or (int(minutes_match.group(1)) if minutes_match else 22)
                prior_at = alert.timestamp - timedelta(minutes=int(minutes))
                identity_events.append(IdentityEvent(
                    event_id=f"{alert.id}-prior", timestamp=prior_at,
                    user_id=alert.user or "unknown", auth_event="SUCCESS",
                    source_ip="198.51.100.222", location_city=first_city,
                    location_country=first_country,
                ))
                identity_events.append(IdentityEvent(
                    event_id=alert.id, timestamp=alert.timestamp,
                    user_id=alert.user or "unknown", auth_event="SUCCESS",
                    source_ip=alert.source_ip, location_city=second_city,
                    location_country=second_country,
                ))
                identity_events.pop(-3)

    indicators = list(dict.fromkeys(
        value for alert in alerts for value in (alert.source_ip, alert.destination_ip)
        if value and not value.startswith(("10.", "192.168.", "172.16."))
    ))
    for alert in alerts:
        try:
            payload = json.loads(alert.raw_payload or "{}")
        except (TypeError, json.JSONDecodeError):
            payload = {}
        if isinstance(payload, dict) and payload.get("hash_sha256"):
            indicators.append(payload["hash_sha256"])

    log_result = LogAnalysisAgent(db).analyze(LogAnalysisInput(logs=logs, incident_id=incident_id, record_audit=False))
    identity_result = IdentityAnalysisAgent(db).analyze(IdentityAnalysisInput(events=identity_events, incident_id=incident_id, record_audit=False))
    threat_result = ThreatIntelligenceAgent(db).analyze(ThreatIntelInput(indicators=list(dict.fromkeys(indicators)), incident_id=incident_id, record_audit=False))
    combined_evidence = log_result.evidence + identity_result.evidence + threat_result.evidence
    combined_findings = log_result.findings + identity_result.findings + threat_result.findings
    try:
        assets = json.loads(incident.affected_assets or "[]")
    except (TypeError, json.JSONDecodeError):
        assets = []
    assets = assets if isinstance(assets, list) else []
    context_entities = {
        "hosts": [alert.host for alert in alerts if alert.host],
        "accounts": list(dict.fromkeys([alert.user for alert in alerts if alert.user and not alert.user.startswith("multiple")]
                                       + [asset.split(":", 1)[1] for asset in assets if isinstance(asset, str) and asset.lower().startswith("user:")])),
    }
    impact_result = ImpactAnalysisAgent(db).analyze(ImpactAnalysisInput(
        incident_id=incident_id, evidence_items=combined_evidence,
        findings=combined_findings, context_entities=context_entities,
    ))

    current = db.query(IncidentInvestigation).filter(IncidentInvestigation.incident_id == incident_id).first()
    summaries = [log_result.summary, identity_result.summary, threat_result.summary]
    hypothesis = (
        f"Four-agent deterministic investigation assessed {len(alerts)} linked simulated alerts. "
        f"Impact is {impact_result.severity.lower()} (risk {impact_result.risk_score}/100). "
        f"{identity_result.summary} {threat_result.summary}"
    )
    if current:
        current.hypothesis = hypothesis
        current.confidence_score = round(sum(f.confidence for f in combined_findings) / len(combined_findings), 2) if combined_findings else 0.5
        current.summary = " ".join(summaries)
        current.findings = json.dumps([f.model_dump(mode="json") for f in combined_findings])
        current.recommended_containment = json.dumps([])
    else:
        current = IncidentInvestigation(
            id=f"INV-{uuid.uuid4().hex[:10].upper()}", incident_id=incident_id,
            hypothesis=hypothesis,
            confidence_score=round(sum(f.confidence for f in combined_findings) / len(combined_findings), 2) if combined_findings else 0.5,
            summary=" ".join(summaries),
            findings=json.dumps([f.model_dump(mode="json") for f in combined_findings]),
            recommended_containment=json.dumps([]),
        )
        db.add(current)

    evidence_ids = {item.id for item in db.query(IncidentEvidence).filter(IncidentEvidence.incident_id == incident_id).all()}
    for item in combined_evidence:
        evidence_id = f"SW-{item.evidence_id}"[:80]
        if evidence_id in evidence_ids:
            continue
        raw = item.raw_data or {}
        value = str(raw.get("indicator_value") or raw.get("source_ip") or raw.get("dst_ip") or raw.get("host") or raw.get("user") or item.event_id or item.description)
        intel_match = item.evidence_type == "IOC" and any(m.indicator_value == value and m.reputation == "MALICIOUS" for m in threat_result.matched_indicators)
        verdict = "MALICIOUS" if intel_match else "SUSPICIOUS"
        db.add(IncidentEvidence(
            id=evidence_id, incident_id=incident_id, evidence_type=item.evidence_type,
            label=item.description[:240], value=value[:500], verdict=verdict,
            source="Investigation Swarm (Simulated)",
            notes=f"Confidence {item.confidence:.0%}; {'confirmed telemetry' if item.is_confirmed else 'hypothesis'}. A malicious reputation requires a matched simulated intelligence record.",
        ))
        evidence_ids.add(evidence_id)

    existing_actions = {a.action_type + ":" + a.target for a in db.query(ApprovalAction).filter(ApprovalAction.incident_id == incident_id).all()}
    proposals = []
    confirmed_hosts = impact_result.confirmed_impact.hosts
    confirmed_users = impact_result.confirmed_impact.accounts
    matched_bad_ips = [m.indicator_value for m in threat_result.matched_indicators if m.indicator_type == "IP" and m.reputation == "MALICIOUS" and m.verification_status == "VERIFIED"]
    matched_bad_hashes = [m.indicator_value for m in threat_result.matched_indicators if m.indicator_type == "SHA256" and m.reputation == "MALICIOUS" and m.verification_status == "VERIFIED"]
    candidates = []
    if any(f.severity in ("HIGH", "CRITICAL") for f in combined_findings):
        candidates += [("ISOLATE_HOST", h, f"Review simulated isolation for confirmed affected host {h}.", "HIGH") for h in confirmed_hosts[:2]]
        candidates += [("REVOKE_SESSION", u, f"Review simulated session revocation for affected account {u}.", "HIGH") for u in confirmed_users[:2]]
        candidates += [("BLOCK_IP", ip, f"Verified malicious IP in local simulated intelligence: {ip}.", "MEDIUM") for ip in matched_bad_ips[:2]]
        candidates += [("QUARANTINE_FILE", digest, f"Verified malicious SHA256 in local simulated intelligence: {digest}.", "MEDIUM") for digest in matched_bad_hashes[:2]]
    for action, target, rationale, risk in candidates:
        key = action + ":" + target
        if key in existing_actions:
            continue
        proposal = ApprovalAction(
            id=f"APR-{uuid.uuid4().hex[:10].upper()}", incident_id=incident_id,
            action_type=action, target=target,
            description=f"Proposed simulated {action.lower().replace('_', ' ')} for {target}.",
            rationale=rationale, risk_level=risk,
        )
        db.add(proposal)
        proposals.append(proposal)
    incident.risk_score = impact_result.risk_score
    incident.severity = impact_result.severity
    incident.updated_at = datetime.now(timezone.utc)
    db.add(IncidentTimelineEvent(
        id=f"TML-{uuid.uuid4().hex[:10].upper()}", incident_id=incident_id,
        timestamp=datetime.now(timezone.utc), title="Four-agent swarm investigation completed",
        description=f"Log, identity, threat intelligence, and impact agents analyzed {len(alerts)} simulated alerts; risk {impact_result.risk_score}/100. Proposed {len(proposals)} new approval(s).",
        event_type="AGENT_ACTION", severity=impact_result.severity,
        actor="Investigation Swarm (Simulated)",
    ))
    log_action(db, "Investigation Swarm", "SWARM_INVESTIGATION_COMPLETED", "INCIDENT", incident_id,
               f"Four deterministic agents analyzed {len(alerts)} alerts; risk {impact_result.risk_score}; {len(proposals)} approvals proposed.")
    return {
        "incident_id": incident_id, "is_simulated": True,
        "agents": {
            "log_analysis": log_result.model_dump(mode="json"),
            "identity_analysis": identity_result.model_dump(mode="json"),
            "threat_intelligence": threat_result.model_dump(mode="json"),
            "impact_analysis": impact_result.model_dump(mode="json"),
        },
        "findings": [f.model_dump(mode="json") for f in combined_findings],
        "evidence": [e.model_dump(mode="json") for e in combined_evidence],
        "risk_score": impact_result.risk_score, "severity": impact_result.severity,
        "approval_proposals": [{"id": p.id, "action_type": p.action_type, "target": p.target} for p in proposals],
        "summary": " ".join(summaries),
    }
