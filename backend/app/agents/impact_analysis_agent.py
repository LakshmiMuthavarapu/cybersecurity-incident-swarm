"""
Impact Analysis Agent (Phase 2).

Specialized deterministic investigation agent that synthesizes findings and evidence
from telemetry agents to:
1. Identify affected accounts, hosts, and services
2. Calculate an explainable, deterministic risk score (0-100) and severity
3. STRICTLY separate factually confirmed evidence from investigative hypotheses
4. Detail uncertainty boundaries and unobserved telemetry blind spots
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
import re

from app.schemas.agent_schemas import (
    ImpactAnalysisInput,
    ImpactAnalysisOutput,
    ImpactScope,
    EvidenceItem,
    AgentFinding,
)
from app.services.audit_service import log_action


class ImpactAnalysisAgent:
    """Deterministic agent for impact scoping, risk calculation, and hypothesis separation."""

    NAME = "ImpactAnalysisAgent"

    # Asset tier scoring weights
    CRITICAL_ASSET_PATTERNS = ["dc", "domain", "corp-idp", "okta", "vault", "prod", "finance", "s3", "erp", "database"]

    def __init__(self, db: Optional[Session] = None):
        self.db = db

    def _is_critical_asset(self, asset: str) -> bool:
        low = asset.lower()
        return any(pat in low for pat in self.CRITICAL_ASSET_PATTERNS)

    def analyze(self, input_data: ImpactAnalysisInput) -> ImpactAnalysisOutput:
        evidence_list = input_data.evidence_items
        findings_list = input_data.findings
        context_entities = input_data.context_entities or {}

        # --------------------------------------------------------------------
        # 1. SCOPE EXTRACTION: CONFIRMED VS. HYPOTHESIZED
        # --------------------------------------------------------------------
        confirmed_accounts: set = set()
        confirmed_hosts: set = set()
        confirmed_services: set = set()
        critical_assets: set = set()

        hypo_accounts: set = set()
        hypo_hosts: set = set()
        hypo_services: set = set()

        # Add context entities if provided
        for acc in context_entities.get("accounts", []):
            confirmed_accounts.add(acc)
        for h in context_entities.get("hosts", []):
            confirmed_hosts.add(h)

        # Parse evidence items
        for evi in evidence_list:
            raw = evi.raw_data or {}
            target_set_acc = confirmed_accounts if evi.is_confirmed else hypo_accounts
            target_set_host = confirmed_hosts if evi.is_confirmed else hypo_hosts

            if "user" in raw and raw["user"]:
                target_set_acc.add(str(raw["user"]))
            if "host" in raw and raw["host"]:
                target_set_host.add(str(raw["host"]))

            # Inspect description text for accounts and hosts if not in raw
            desc = evi.description
            acc_match = re.search(r"user ['\"]?([a-zA-Z0-9._-]+)['\"]?", desc, re.IGNORECASE)
            if acc_match:
                target_set_acc.add(acc_match.group(1))

            host_match = re.search(r"host ['\"]?([a-zA-Z0-9._-]+)['\"]?", desc, re.IGNORECASE)
            if host_match:
                target_set_host.add(host_match.group(1))

        # Parse findings to separate hypotheses from confirmed
        for f in findings_list:
            # Check if finding mentions potential/hypothesized lateral targets
            if "hypothetical" in f.description.lower() or "potential" in f.description.lower():
                hypo_services.add(f.title)
            else:
                confirmed_services.add(f.category)

        # Evaluate criticality
        all_identified = list(confirmed_accounts) + list(confirmed_hosts)
        for asset in all_identified:
            if self._is_critical_asset(asset):
                critical_assets.add(asset)

        # --------------------------------------------------------------------
        # 2. DETERMINISTIC RISK SCORE CALCULATION
        # --------------------------------------------------------------------
        # Base severity derived from maximum finding severity
        severities = [f.severity.upper() for f in findings_list]
        score_breakdown: List[str] = []
        base_score = 30

        if "CRITICAL" in severities:
            base_score = 60
            score_breakdown.append("Base score: +60 (Presence of CRITICAL findings in telemetry)")
        elif "HIGH" in severities:
            base_score = 45
            score_breakdown.append("Base score: +45 (Presence of HIGH severity findings in telemetry)")
        elif "MEDIUM" in severities:
            base_score = 35
            score_breakdown.append("Base score: +35 (Presence of MEDIUM severity findings)")
        else:
            score_breakdown.append("Base score: +30 (Baseline default telemetry risk)")

        current_score = base_score

        # Critical asset impact addition (+12 per critical asset, max +24)
        crit_bonus = min(len(critical_assets) * 12, 24)
        if crit_bonus > 0:
            current_score += crit_bonus
            score_breakdown.append(
                f"Critical asset exposure bonus: +{crit_bonus} ({len(critical_assets)} high-value assets: {', '.join(critical_assets)})"
            )

        # Blast radius addition (+5 per confirmed account or host, max +15)
        blast_count = len(confirmed_accounts) + len(confirmed_hosts)
        blast_bonus = min(blast_count * 5, 15)
        if blast_bonus > 0:
            current_score += blast_bonus
            score_breakdown.append(
                f"Blast radius modifier: +{blast_bonus} ({blast_count} total confirmed compromised/affected entities)"
            )

        # Finding volume modifier (+2 per finding, max +10)
        finding_bonus = min(len(findings_list) * 2, 10)
        if finding_bonus > 0:
            current_score += finding_bonus
            score_breakdown.append(
                f"Corroborating findings factor: +{finding_bonus} ({len(findings_list)} distinct findings verified)"
            )

        # Cap score between 0 and 100
        final_risk_score = min(max(current_score, 10), 100)
        score_breakdown.append(f"Calculated Final Risk Score: {final_risk_score} / 100")

        # Map to explainable severity
        if final_risk_score >= 85:
            assessed_severity = "CRITICAL"
        elif final_risk_score >= 65:
            assessed_severity = "HIGH"
        elif final_risk_score >= 40:
            assessed_severity = "MEDIUM"
        else:
            assessed_severity = "LOW"

        score_breakdown.append(f"Assessed Incident Severity: {assessed_severity}")

        # --------------------------------------------------------------------
        # 3. UNCERTAINTY & DATA GAPS EXPLANATION
        # --------------------------------------------------------------------
        uncertainty_points: List[str] = []
        if not evidence_list:
            uncertainty_points.append("Zero direct evidence items provided; calculation relies exclusively on finding assertions.")
        if hypo_accounts or hypo_hosts:
            uncertainty_points.append(
                f"Potential lateral pivot targets ({len(hypo_accounts)} accounts, {len(hypo_hosts)} hosts) remain hypotheses pending telemetry confirmation."
            )
        if not critical_assets:
            uncertainty_points.append("No domain controller or database assets confirmed impacted; scope restricted to local endpoints.")
        else:
            uncertainty_points.append(f"Exposure confirmed on sensitive infrastructure: {', '.join(critical_assets)}.")

        confirmed_scope = ImpactScope(
            accounts=sorted(list(confirmed_accounts)),
            hosts=sorted(list(confirmed_hosts)),
            services_or_segments=sorted(list(confirmed_services)),
            critical_assets=sorted(list(critical_assets)),
        )

        hypothesized_scope = ImpactScope(
            accounts=sorted(list(hypo_accounts)),
            hosts=sorted(list(hypo_hosts)),
            services_or_segments=sorted(list(hypo_services)),
            critical_assets=[],
        )

        output = ImpactAnalysisOutput(
            agent_name=self.NAME,
            incident_id=input_data.incident_id,
            status="COMPLETED",
            risk_score=final_risk_score,
            severity=assessed_severity,
            score_breakdown=score_breakdown,
            confirmed_impact=confirmed_scope,
            hypothesized_impact=hypothesized_scope,
            evidence=evidence_list,
            findings=findings_list,
            uncertainty_explanation=" ".join(uncertainty_points),
        )

        # Record audit log if requested and db is present
        if input_data.record_audit and self.db:
            try:
                log_action(
                    db=self.db,
                    actor=f"Agent:{self.NAME}",
                    action="IMPACT_ANALYSIS_COMPLETED",
                    target_type="INCIDENT" if input_data.incident_id else "IMPACT_EVALUATION",
                    target_id=input_data.incident_id or f"RISK-{final_risk_score}",
                    details=(
                        f"Evaluated risk: {final_risk_score} ({assessed_severity}). "
                        f"Confirmed affected: {len(confirmed_accounts)} accounts, {len(confirmed_hosts)} hosts."
                    ),
                    client_ip="127.0.0.1 (Internal Agent Orchestrator)",
                    is_simulated=True,
                )
            except Exception:
                pass

        return output
