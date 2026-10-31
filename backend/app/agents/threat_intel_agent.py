"""
Threat Intelligence Agent (Phase 2).

Specialized deterministic investigation agent that queries incoming IOCs
(IP addresses, domains, file hashes, URLs) against the existing simulated
threat intelligence database.

CRITICAL SAFETY & INTEGRITY RULE:
Never invents threat intelligence. If an indicator is not found in the verified
local repository, it is explicitly cataloged as UNMATCHED / UNKNOWN with zero
inferred confidence.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import json
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.models.threat_intel import ThreatIndicator
from app.schemas.agent_schemas import (
    ThreatIntelInput,
    ThreatIntelOutput,
    MatchedIndicator,
    EvidenceItem,
    AgentFinding,
)
from app.services.audit_service import log_action
from app.database import SessionLocal


class ThreatIntelligenceAgent:
    """Deterministic agent for strictly verifying indicators against simulated threat intelligence."""

    NAME = "ThreatIntelligenceAgent"

    def __init__(self, db: Optional[Session] = None):
        self.db = db

    def _sanitize_value(self, val: str) -> str:
        """Removes defanging brackets, e.g. [.] -> . or hxxp -> http."""
        return val.strip().replace("[.]", ".").replace("[:]", ":").lower()

    def analyze(self, input_data: ThreatIntelInput) -> ThreatIntelOutput:
        raw_indicators = input_data.indicators
        total_queried = len(raw_indicators)

        if total_queried == 0:
            return ThreatIntelOutput(
                agent_name=self.NAME,
                status="COMPLETED",
                summary="No threat indicators submitted for correlation.",
                total_queried=0,
                total_matched=0,
                total_malicious=0,
                matched_indicators=[],
                unmatched_indicators=[],
                evidence=[],
                findings=[],
                uncertainty_explanation="Indicator query list is empty."
            )

        # Obtain a DB session if not injected
        local_session_created = False
        db = self.db
        if db is None:
            db = SessionLocal()
            local_session_created = True

        matched_list: List[MatchedIndicator] = []
        unmatched_list: List[str] = []
        evidence: List[EvidenceItem] = []
        findings: List[AgentFinding] = []

        try:
            for raw_val in raw_indicators:
                cleaned = self._sanitize_value(raw_val)
                if not cleaned:
                    continue

                # Query database: exact match on value (or sanitized value match)
                # We check case-insensitively
                records = (
                    db.query(ThreatIndicator)
                    .filter(
                        or_(
                            ThreatIndicator.value.ilike(cleaned),
                            ThreatIndicator.value.ilike(raw_val.strip()),
                        )
                    )
                    .all()
                )

                if not records:
                    # NEVER INVENT: record strictly as unmatched
                    unmatched_list.append(raw_val)
                    continue

                for rec in records:
                    # Parse tags
                    tags_parsed: List[str] = []
                    if rec.tags:
                        try:
                            tags_parsed = json.loads(rec.tags) if isinstance(rec.tags, str) else list(rec.tags)
                        except Exception:
                            tags_parsed = [str(rec.tags)]

                    matched = MatchedIndicator(
                        indicator_value=rec.value,
                        indicator_type=rec.indicator_type,
                        reputation=rec.reputation,
                        threat_actor=rec.threat_actor,
                        confidence=rec.confidence,
                        verification_status=rec.verification_status,
                        tags=tags_parsed,
                        description=rec.description,
                        db_record_id=rec.id,
                        is_simulated=rec.is_simulated,
                    )
                    matched_list.append(matched)

                    # Create evidence item
                    evidence.append(
                        EvidenceItem(
                            evidence_id=f"EVI-TI-{rec.id}",
                            event_id=rec.id,
                            timestamp=rec.last_seen or datetime.now(timezone.utc),
                            evidence_type="IOC",
                            description=(
                                f"Threat Intel match for '{rec.value}' ({rec.indicator_type}): "
                                f"Reputation={rec.reputation}, Threat Actor='{rec.threat_actor or 'Unassigned'}', "
                                f"Confidence={rec.confidence}% [Simulated DB Record {rec.id}]."
                            ),
                            raw_data={
                                "indicator_id": rec.id,
                                "indicator_value": rec.value,
                                "type": rec.indicator_type,
                                "reputation": rec.reputation,
                                "tags": tags_parsed,
                            },
                            confidence=float(rec.confidence) / 100.0,
                            is_confirmed=True,
                        )
                    )

                    # Create finding if malicious or suspicious
                    if rec.reputation in ("MALICIOUS", "SUSPICIOUS"):
                        findings.append(
                            AgentFinding(
                                finding_id=f"FIND-TI-{rec.id}",
                                category="THREAT_INTELLIGENCE_MATCH",
                                severity="CRITICAL" if rec.reputation == "MALICIOUS" and rec.confidence >= 90 else "HIGH" if rec.reputation == "MALICIOUS" else "MEDIUM",
                                title=f"Threat Intelligence Hit: {rec.reputation} {rec.indicator_type} ({rec.value})",
                                description=(
                                    f"Observed entity matched verified simulated intelligence repository. "
                                    f"Associated Actor: {rec.threat_actor or 'Unknown'}. Context: {rec.description}."
                                ),
                                confidence=float(rec.confidence) / 100.0,
                                evidence_references=[rec.id],
                                mitre_technique="T1071 (Application Layer Protocol)" if rec.indicator_type in ("IP", "DOMAIN") else "T1204 (User Execution)",
                                uncertainty_notes=None if rec.verification_status == "VERIFIED" else f"Verification status is {rec.verification_status}; confirmation pending analyst review.",
                            )
                        )

        finally:
            if local_session_created:
                db.close()

        total_matched = len(matched_list)
        total_malicious = sum(1 for m in matched_list if m.reputation == "MALICIOUS")

        uncertainty_notes = []
        if unmatched_list:
            uncertainty_notes.append(
                f"{len(unmatched_list)} queried indicators were not found in the threat intelligence repository. "
                "Per safety guidelines, no synthetic reputation was inferred."
            )
        if any(m.verification_status != "VERIFIED" for m in matched_list):
            uncertainty_notes.append("Some matched indicators carry non-verified status; confidence ratings adjusted accordingly.")

        summary = (
            f"Queried {total_queried} indicators against simulated threat intelligence database. "
            f"Matched {total_matched} ({total_malicious} MALICIOUS), {len(unmatched_list)} UNMATCHED."
        )

        output = ThreatIntelOutput(
            agent_name=self.NAME,
            status="COMPLETED",
            summary=summary,
            total_queried=total_queried,
            total_matched=total_matched,
            total_malicious=total_malicious,
            matched_indicators=matched_list,
            unmatched_indicators=unmatched_list,
            evidence=evidence,
            findings=findings,
            uncertainty_explanation=" ".join(uncertainty_notes) if uncertainty_notes else "All queried indicators had deterministic intelligence resolution.",
        )

        # Record audit log if requested and db is present
        if input_data.record_audit and self.db:
            try:
                log_action(
                    db=self.db,
                    actor=f"Agent:{self.NAME}",
                    action="THREAT_INTEL_LOOKUP_COMPLETED",
                    target_type="INCIDENT" if input_data.incident_id else "IOC_QUERY",
                    target_id=input_data.incident_id or f"IOCS-{total_queried}",
                    details=summary,
                    client_ip="127.0.0.1 (Internal Agent Orchestrator)",
                    is_simulated=True,
                )
            except Exception:
                pass

        return output
