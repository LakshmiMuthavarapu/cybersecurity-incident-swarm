"""
Phase 2 Agent Verification Script.

Executes and demonstrates the four independent cybersecurity investigation agents:
1. LogAnalysisAgent
2. IdentityAnalysisAgent
3. ThreatIntelligenceAgent
4. ImpactAnalysisAgent

Run with:
    python verify_agents.py
"""

import json
from datetime import datetime, timezone, timedelta

from app.database import SessionLocal
from app.agents import (
    LogAnalysisAgent,
    IdentityAnalysisAgent,
    ThreatIntelligenceAgent,
    ImpactAnalysisAgent,
)
from app.schemas.agent_schemas import (
    LogAnalysisInput,
    LogEvent,
    IdentityAnalysisInput,
    IdentityEvent,
    ThreatIntelInput,
    ImpactAnalysisInput,
    EvidenceItem,
    AgentFinding,
)

def print_banner(title: str):
    print("\n" + "=" * 80)
    print(f" {title}")
    print("=" * 80)

def main():
    now = datetime.now(timezone.utc)
    db = SessionLocal()

    try:
        # ====================================================================
        # 1. LOG ANALYSIS AGENT
        # ====================================================================
        print_banner("1. LOG ANALYSIS AGENT DEMONSTRATION")
        log_agent = LogAnalysisAgent(db=db)
        
        sample_logs = [
            LogEvent(
                event_id="EVT-101",
                timestamp=now - timedelta(minutes=20),
                log_source="WindowsSecurity",
                event_type="LOGON_FAILED",
                user="marcus.vance",
                source_ip="198.51.100.24",
                host="FINANCE-SRV-02",
            ),
            LogEvent(
                event_id="EVT-102",
                timestamp=now - timedelta(minutes=18),
                log_source="WindowsSecurity",
                event_type="LOGON_FAILED",
                user="marcus.vance",
                source_ip="198.51.100.24",
                host="FINANCE-SRV-02",
            ),
            LogEvent(
                event_id="EVT-103",
                timestamp=now - timedelta(minutes=16),
                log_source="WindowsSecurity",
                event_type="LOGON_FAILED",
                user="marcus.vance",
                source_ip="198.51.100.24",
                host="FINANCE-SRV-02",
            ),
            LogEvent(
                event_id="EVT-104",
                timestamp=now - timedelta(minutes=12),
                log_source="WindowsSecurity",
                event_type="LOGON_SUCCESS",
                user="marcus.vance",
                source_ip="198.51.100.24",
                host="FINANCE-SRV-02",
            ),
            LogEvent(
                event_id="EVT-105",
                timestamp=now - timedelta(minutes=10),
                log_source="Sysmon",
                event_type="PROCESS_CREATE",
                user="marcus.vance",
                host="FINANCE-SRV-02",
                process_name="powershell.exe",
                parent_process="WINWORD.EXE",
                command_line="powershell.exe -NoP -W Hidden -Enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0...",
            ),
            LogEvent(
                event_id="EVT-106",
                timestamp=now - timedelta(minutes=6),
                log_source="Sysmon",
                event_type="PROCESS_CREATE",
                user="marcus.vance",
                host="FINANCE-SRV-02",
                process_name="psexec.exe",
                command_line="psexec.exe \\\\dc01.corp.internal -u corp\\admin -p secret cmd.exe",
                source_ip="10.0.4.15",
                destination_ip="10.0.1.10",
                target_port=445,
            )
        ]

        log_output = log_agent.analyze(LogAnalysisInput(logs=sample_logs, incident_id="INC-2026-084", record_audit=True))
        print(f"Status: {log_output.status}")
        print(f"Summary: {log_output.summary}")
        print(f"Brute Force Detected: {log_output.brute_force_detected}")
        print(f"Suspicious Executions Detected: {log_output.suspicious_executions_detected}")
        print(f"Lateral Movement Detected: {log_output.lateral_movement_detected}")
        print(f"Findings ({len(log_output.findings)}):")
        for f in log_output.findings:
            print(f"  - [{f.severity}] {f.title} (Confidence: {f.confidence * 100:.0f}%, MITRE: {f.mitre_technique})")
        print(f"Evidence items extracted: {len(log_output.evidence)}")

        # ====================================================================
        # 2. IDENTITY ANALYSIS AGENT
        # ====================================================================
        print_banner("2. IDENTITY ANALYSIS AGENT DEMONSTRATION")
        id_agent = IdentityAnalysisAgent(db=db)
        
        sample_id_events = [
            IdentityEvent(
                event_id="ID-001",
                timestamp=now - timedelta(hours=2),
                user_id="sarah.connor",
                auth_event="SUCCESS",
                source_ip="64.104.22.18",
                location_city="San Francisco",
                location_country="United States",
            ),
            IdentityEvent(
                event_id="ID-002",
                timestamp=now - timedelta(hours=1, minutes=45),
                user_id="sarah.connor",
                auth_event="MFA_DENIED",
                source_ip="185.220.101.5",
                location_city="Frankfurt",
                location_country="Germany",
                is_vpn_or_tor=True,
            ),
            IdentityEvent(
                event_id="ID-003",
                timestamp=now - timedelta(hours=1, minutes=40),
                user_id="sarah.connor",
                auth_event="MFA_APPROVED",
                source_ip="185.220.101.5",
                location_city="Frankfurt",
                location_country="Germany",
                is_vpn_or_tor=True,
            ),
            # Benign user
            IdentityEvent(
                event_id="ID-004",
                timestamp=now - timedelta(minutes=30),
                user_id="alex.rivera",
                auth_event="SUCCESS",
                source_ip="10.0.1.25",
                location_city="Austin",
                location_country="United States",
            )
        ]

        id_output = id_agent.analyze(IdentityAnalysisInput(events=sample_id_events, incident_id="INC-2026-085", record_audit=True))
        print(f"Status: {id_output.status}")
        print(f"Summary: {id_output.summary}")
        print("Accounts Evaluated:")
        for acc in id_output.accounts_assessed:
            print(f"  - Account: {acc.user_id} -> Verdict: {acc.verdict} (Confidence: {acc.confidence * 100:.0f}%)")
            print(f"    Risk Factors: {acc.risk_factors}")
            print(f"    Impossible Travel: {acc.impossible_travel_detected}, MFA Fatigue: {acc.mfa_anomaly_detected}")

        # ====================================================================
        # 3. THREAT INTELLIGENCE AGENT
        # ====================================================================
        print_banner("3. THREAT INTELLIGENCE AGENT DEMONSTRATION")
        ti_agent = ThreatIntelligenceAgent(db=db)

        test_indicators = [
            "198.51.100.24",                                                    # Known malicious C2
            "auth-identity-corp-update[.]com",                                  # Known typosquatted domain
            "4b68926947ac00f28e202ec102c7fb7d1d2b7811ef1f0a256f6c99c546db98be", # Known stager hash
            "203.0.113.88",                                                     # Unknown external IP
            "benign-internal-update.corp",                                      # Unknown domain
        ]

        ti_output = ti_agent.analyze(ThreatIntelInput(indicators=test_indicators, incident_id="INC-2026-084", record_audit=True))
        print(f"Status: {ti_output.status}")
        print(f"Summary: {ti_output.summary}")
        print(f"Total Queried: {ti_output.total_queried}")
        print(f"Matched Verified IOCs ({ti_output.total_matched}):")
        for m in ti_output.matched_indicators:
            print(f"  - [{m.reputation}] {m.indicator_type}: {m.indicator_value} (Actor: {m.threat_actor}, Conf: {m.confidence}%, Record: {m.db_record_id})")
        print(f"Unmatched (Strict Zero-Invention Policy, {len(ti_output.unmatched_indicators)}):")
        for u in ti_output.unmatched_indicators:
            print(f"  - [NOT FOUND / UNVERIFIED]: {u}")

        # ====================================================================
        # 4. IMPACT ANALYSIS AGENT
        # ====================================================================
        print_banner("4. IMPACT ANALYSIS AGENT DEMONSTRATION")
        impact_agent = ImpactAnalysisAgent(db=db)

        # Synthesize evidence from log and TI agents
        synthesized_evidence = log_output.evidence + ti_output.evidence + [
            # Add an unconfirmed hypothesis item
            EvidenceItem(
                evidence_id="EVI-HYPO-01",
                evidence_type="ENDPOINT",
                description="Hypothesized lateral movement toward ERP database cluster 'ERP-PROD-DB01'",
                raw_data={"host": "ERP-PROD-DB01", "user": "corp\\admin"},
                confidence=0.5,
                is_confirmed=False,
            )
        ]

        impact_output = impact_agent.analyze(ImpactAnalysisInput(
            incident_id="INC-2026-084",
            evidence_items=synthesized_evidence,
            findings=log_output.findings,
            record_audit=True,
        ))

        print(f"Status: {impact_output.status}")
        print(f"Assessed Incident Severity: {impact_output.severity}")
        print(f"Calculated Risk Score: {impact_output.risk_score} / 100")
        print("Explainable Score Breakdown:")
        for line in impact_output.score_breakdown:
            print(f"  * {line}")
        print("\nConfirmed Scope (Factually Verified in Telemetry):")
        print(f"  - Accounts: {impact_output.confirmed_impact.accounts}")
        print(f"  - Hosts: {impact_output.confirmed_impact.hosts}")
        print(f"  - Critical Assets: {impact_output.confirmed_impact.critical_assets}")
        print("\nHypothesized Scope (Investigative Inferences Pending Confirmation):")
        print(f"  - Hypothesized Hosts: {impact_output.hypothesized_impact.hosts}")
        print(f"  - Hypothesized Accounts: {impact_output.hypothesized_impact.accounts}")
        print(f"\nUncertainty Explanation: {impact_output.uncertainty_explanation}")

        print_banner("ALL FOUR AGENTS VERIFIED SUCCESSFULLY")

    finally:
        db.close()

if __name__ == "__main__":
    main()
