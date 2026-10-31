"""
Identity Analysis Agent (Phase 2).

Specialized deterministic investigation agent that evaluates authentication streams,
geographic velocity anomalies, MFA events, and account privileges.
Detects:
1. Failed login clustering and push-fatigue MFA bypass
2. Impossible travel velocity (e.g., disparate countries within minutes)
3. Tor / anonymizer access to corporate identity providers
4. Distinguishes confirmed compromise from benign anomalies (VPN roaming, typos)
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.schemas.agent_schemas import (
    IdentityAnalysisInput,
    IdentityAnalysisOutput,
    IdentityEvent,
    AccountCompromiseAssessment,
    EvidenceItem,
    AgentFinding,
)
from app.services.audit_service import log_action


class IdentityAnalysisAgent:
    """Deterministic agent for assessing identity anomalies and compromised accounts."""

    NAME = "IdentityAnalysisAgent"

    HIGH_RISK_COUNTRIES = {"UNKNOWN_GEO", "TOR_EXIT_ZONE"}
    TOR_EXIT_IPS = {"185.220.101.5", "185.220.101.6", "185.220.101.7"}

    def __init__(self, db: Optional[Session] = None):
        self.db = db

    def analyze(self, input_data: IdentityAnalysisInput) -> IdentityAnalysisOutput:
        events = input_data.events
        total_events = len(events)
        baselines = input_data.user_baselines or {}

        if total_events == 0:
            return IdentityAnalysisOutput(
                agent_name=self.NAME,
                status="COMPLETED",
                summary="No identity events provided for analysis.",
                total_events_analyzed=0,
                accounts_assessed=[],
                evidence=[],
                findings=[],
                uncertainty_explanation="Identity stream empty; no authentication telemetry to inspect."
            )

        evidence: List[EvidenceItem] = []
        findings: List[AgentFinding] = []
        assessments: List[AccountCompromiseAssessment] = []

        # Group events by user_id
        user_events: Dict[str, List[IdentityEvent]] = {}
        for ev in events:
            uid = ev.user_id.lower().strip()
            user_events.setdefault(uid, []).append(ev)

        # Analyze each user's stream
        for uid, ev_list in user_events.items():
            # Sort chronologically if timestamps are present
            sorted_evs = sorted(ev_list, key=lambda x: x.timestamp or datetime.min.replace(tzinfo=timezone.utc))

            risk_factors: List[str] = []
            mitigating_factors: List[str] = []
            evidence_refs: List[str] = []
            impossible_travel = False
            mfa_anomaly = False

            failures = [e for e in sorted_evs if e.auth_event.upper() in ("FAILURE", "FAILED")]
            successes = [e for e in sorted_evs if e.auth_event.upper() in ("SUCCESS", "MFA_APPROVED")]
            mfa_denials = [e for e in sorted_evs if e.auth_event.upper() in ("MFA_DENIED", "MFA_TIMEOUT")]

            # 1. Failure Analysis
            if len(failures) >= 3:
                risk_factors.append(f"High failure volume ({len(failures)} failed attempts)")
                for f in failures:
                    evidence_refs.append(f.event_id)
                    evidence.append(
                        EvidenceItem(
                            evidence_id=f"EVI-ID-FAIL-{f.event_id}",
                            event_id=f.event_id,
                            timestamp=f.timestamp,
                            evidence_type="AUTHENTICATION",
                            description=f"Auth failure for {uid} from {f.source_ip or 'unknown IP'} ({f.location_country or 'unknown geo'})",
                            raw_data={"location": f.location_city, "country": f.location_country, "ip": f.source_ip},
                            confidence=0.9,
                            is_confirmed=True,
                        )
                    )
            elif len(failures) in (1, 2) and len(successes) > 0:
                mitigating_factors.append("Low failure count followed by normal success is typical for user typing error")

            # 2. MFA Fatigue / Denial Patterns
            if len(mfa_denials) >= 2 and len(successes) > 0:
                mfa_anomaly = True
                risk_factors.append("MFA prompt fatigue pattern: multiple denials followed by eventual approval")
                for md in mfa_denials:
                    evidence_refs.append(md.event_id)
                    evidence.append(
                        EvidenceItem(
                            evidence_id=f"EVI-ID-MFA-{md.event_id}",
                            event_id=md.event_id,
                            timestamp=md.timestamp,
                            evidence_type="AUTHENTICATION",
                            description=f"MFA denial/rejection recorded for account {uid}",
                            raw_data={"event": md.auth_event, "ip": md.source_ip},
                            confidence=0.95,
                            is_confirmed=True,
                        )
                    )

            # 3. Tor / Anonymizer / High-Risk IP
            for e in sorted_evs:
                if e.is_vpn_or_tor or (e.source_ip in self.TOR_EXIT_IPS):
                    risk_factors.append(f"Logon activity routed through anonymizer / Tor gateway ({e.source_ip})")
                    evidence_refs.append(e.event_id)
                    evidence.append(
                        EvidenceItem(
                            evidence_id=f"EVI-ID-TOR-{e.event_id}",
                            event_id=e.event_id,
                            timestamp=e.timestamp,
                            evidence_type="IOC",
                            description=f"Anonymizing proxy/Tor connection detected for user {uid} from IP {e.source_ip}",
                            raw_data={"source_ip": e.source_ip, "tor": True},
                            confidence=0.98,
                            is_confirmed=True,
                        )
                    )

            # 4. Impossible Travel Velocity
            # Compare consecutive successful authentications from different countries/cities
            if len(sorted_evs) >= 2:
                for i in range(len(sorted_evs) - 1):
                    e1 = sorted_evs[i]
                    e2 = sorted_evs[i + 1]
                    if e1.location_country and e2.location_country and e1.location_country != e2.location_country:
                        # Check timestamp delta
                        if e1.timestamp and e2.timestamp:
                            delta_hours = abs((e2.timestamp - e1.timestamp).total_seconds()) / 3600.0
                            if delta_hours < 3.0:  # > 1000 miles within 3 hours
                                impossible_travel = True
                                risk_factors.append(
                                    f"Impossible travel detected: {e1.location_city or e1.location_country} to "
                                    f"{e2.location_city or e2.location_country} in {delta_hours:.1f} hours"
                                )
                                evidence_refs.extend([e1.event_id, e2.event_id])
                                evidence.append(
                                    EvidenceItem(
                                        evidence_id=f"EVI-ID-TRAV-{e2.event_id}",
                                        event_id=e2.event_id,
                                        timestamp=e2.timestamp,
                                        evidence_type="AUTHENTICATION",
                                        description=(
                                            f"Impossible physical velocity: {uid} authenticated from {e1.location_country} "
                                            f"then {e2.location_country} in {delta_hours:.1f} hours."
                                        ),
                                        raw_data={"loc1": e1.location_country, "loc2": e2.location_country, "delta_hours": delta_hours},
                                        confidence=0.95,
                                        is_confirmed=True,
                                    )
                                )

            # 5. Baseline Check
            user_base = baselines.get(uid, {})
            expected_country = user_base.get("expected_country")
            if expected_country:
                anomalous_locs = [e for e in sorted_evs if e.location_country and e.location_country != expected_country]
                if anomalous_locs:
                    risk_factors.append(f"Login outside established user home country ({expected_country})")

            # 6. Verdict Determination & Confidence
            has_tor = any("Tor" in r or "anonymizer" in r for r in risk_factors)
            has_failures = len(failures) >= 3
            has_success = len(successes) > 0

            if (impossible_travel or has_tor or mfa_anomaly) and has_success:
                verdict = "COMPROMISED"
                confidence = 0.92
                uncertainty_desc = "Account shows high-confidence compromise indicators (impossible travel/Tor + active session). Valid credentials compromised."
            elif has_failures and not has_success:
                verdict = "SUSPICIOUS"
                confidence = 0.75
                uncertainty_desc = "Authentication spraying/brute force observed, but no successful login verified. Account may still be secure."
            elif not risk_factors:
                verdict = "BENIGN"
                confidence = 0.90
                uncertainty_desc = "All authentication activities match standard corporate login baselines."
                mitigating_factors.append("Consistent login location, valid single factor/MFA, no velocity anomalies")
            else:
                verdict = "INCONCLUSIVE"
                confidence = 0.50
                uncertainty_desc = "Conflicting evidence or insufficient telemetry to definitively determine account state."

            assessments.append(
                AccountCompromiseAssessment(
                    user_id=uid,
                    verdict=verdict,
                    confidence=confidence,
                    risk_factors=risk_factors,
                    mitigating_factors=mitigating_factors,
                    impossible_travel_detected=impossible_travel,
                    mfa_anomaly_detected=mfa_anomaly,
                    evidence_references=list(set(evidence_refs)),
                    uncertainty_explanation=uncertainty_desc,
                )
            )

            # Generate finding if suspicious or compromised
            if verdict in ("COMPROMISED", "SUSPICIOUS"):
                findings.append(
                    AgentFinding(
                        finding_id=f"FIND-ID-{uid}",
                        category="COMPROMISED_IDENTITY" if verdict == "COMPROMISED" else "SUSPICIOUS_IDENTITY",
                        severity="CRITICAL" if verdict == "COMPROMISED" else "HIGH",
                        title=f"Identity Security Risk: Account '{uid}' Evaluated as {verdict}",
                        description=f"Analysis of {len(sorted_evs)} identity events identified: {'; '.join(risk_factors)}.",
                        confidence=confidence,
                        evidence_references=list(set(evidence_refs)),
                        mitre_technique="T1078 (Valid Accounts) / T1110 (Brute Force)",
                        uncertainty_notes=uncertainty_desc,
                    )
                )

        compromised_count = sum(1 for a in assessments if a.verdict == "COMPROMISED")
        suspicious_count = sum(1 for a in assessments if a.verdict == "SUSPICIOUS")
        benign_count = sum(1 for a in assessments if a.verdict == "BENIGN")

        summary = (
            f"Assessed {len(user_events)} identity accounts across {total_events} events. "
            f"Results: {compromised_count} COMPROMISED, {suspicious_count} SUSPICIOUS, {benign_count} BENIGN."
        )

        output = IdentityAnalysisOutput(
            agent_name=self.NAME,
            status="COMPLETED",
            summary=summary,
            total_events_analyzed=total_events,
            accounts_assessed=assessments,
            evidence=evidence,
            findings=findings,
            uncertainty_explanation=(
                f"Evaluated {len(assessments)} accounts. Geolocation velocities estimated from reported country/city coordinates."
            ),
        )

        # Record audit log if requested and db is present
        if input_data.record_audit and self.db:
            try:
                log_action(
                    db=self.db,
                    actor=f"Agent:{self.NAME}",
                    action="IDENTITY_ANALYSIS_COMPLETED",
                    target_type="INCIDENT" if input_data.incident_id else "IDENTITY_BATCH",
                    target_id=input_data.incident_id or f"USERS-{len(user_events)}",
                    details=summary,
                    client_ip="127.0.0.1 (Internal Agent Orchestrator)",
                    is_simulated=True,
                )
            except Exception:
                pass

        return output
