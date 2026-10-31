"""
Automated Unit & Integration Tests for Phase 2 Cybersecurity Investigation Agents:
1. LogAnalysisAgent
2. IdentityAnalysisAgent
3. ThreatIntelligenceAgent
4. ImpactAnalysisAgent

Tests scenarios:
- Suspicious events
- Benign events
- Missing data & empty payloads
- Conflicting evidence & ambiguous telemetry
- Non-invention of threat intelligence (strict database matching)
- Separation of confirmed evidence vs hypotheses
- Audit logging integration
"""

import pytest
from datetime import datetime, timezone, timedelta

from app.agents.log_analysis_agent import LogAnalysisAgent
from app.agents.identity_analysis_agent import IdentityAnalysisAgent
from app.agents.threat_intel_agent import ThreatIntelligenceAgent
from app.agents.impact_analysis_agent import ImpactAnalysisAgent

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
from app.models.audit_log import AuditLog


# ============================================================================
# 1. LOG ANALYSIS AGENT TESTS
# ============================================================================

def test_log_analysis_suspicious_execution_and_brute_force():
    """Verify detection of suspicious execution, obfuscated command, and brute force followed by logon."""
    now = datetime.now(timezone.utc)
    agent = LogAnalysisAgent()

    events = [
        # Brute force sequence targeting 'marcus.vance'
        LogEvent(
            event_id="EVT-01",
            timestamp=now - timedelta(minutes=15),
            log_source="WindowsSecurity",
            event_type="LOGON_FAILED",
            user="marcus.vance",
            source_ip="198.51.100.99",
            host="FINANCE-SRV-02",
        ),
        LogEvent(
            event_id="EVT-02",
            timestamp=now - timedelta(minutes=14),
            log_source="WindowsSecurity",
            event_type="LOGON_FAILED",
            user="marcus.vance",
            source_ip="198.51.100.99",
            host="FINANCE-SRV-02",
        ),
        LogEvent(
            event_id="EVT-03",
            timestamp=now - timedelta(minutes=13),
            log_source="WindowsSecurity",
            event_type="LOGON_FAILED",
            user="marcus.vance",
            source_ip="198.51.100.99",
            host="FINANCE-SRV-02",
        ),
        LogEvent(
            event_id="EVT-04",
            timestamp=now - timedelta(minutes=10),
            log_source="WindowsSecurity",
            event_type="LOGON_SUCCESS",
            user="marcus.vance",
            source_ip="198.51.100.99",
            host="FINANCE-SRV-02",
        ),
        # Abnormal parent-child execution with obfuscated payload
        LogEvent(
            event_id="EVT-05",
            timestamp=now - timedelta(minutes=8),
            log_source="Sysmon",
            event_type="PROCESS_CREATE",
            user="marcus.vance",
            host="FINANCE-SRV-02",
            process_name="powershell.exe",
            parent_process="WINWORD.EXE",
            command_line="powershell.exe -NoP -W Hidden -Enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0...",
        ),
        # LSASS handle
        LogEvent(
            event_id="EVT-06",
            timestamp=now - timedelta(minutes=5),
            log_source="Sysmon",
            event_type="PROCESS_ACCESS",
            user="marcus.vance",
            host="FINANCE-SRV-02",
            process_name="rundll32.exe",
            command_line="rundll32.exe C:\\Windows\\Temp\\loader.dll",
            additional_data={"target_image": "C:\\Windows\\System32\\lsass.exe", "granted_access": "0x1010"},
        ),
    ]

    output = agent.analyze(LogAnalysisInput(logs=events))

    assert output.status == "COMPLETED"
    assert output.brute_force_detected is True
    assert output.suspicious_executions_detected is True
    assert output.total_logs_analyzed == 6
    assert output.suspicious_event_count >= 5

    # Check evidence formatting
    assert len(output.evidence) >= 4
    for evi in output.evidence:
        assert evi.evidence_id.startswith("EVI-")
        assert evi.confidence >= 0.8
        assert evi.is_confirmed is True

    # Check findings
    bf_finding = next((f for f in output.findings if f.category == "BRUTE_FORCE"), None)
    assert bf_finding is not None
    assert bf_finding.severity == "CRITICAL"
    assert "marcus.vance" in bf_finding.title

    exec_finding = next((f for f in output.findings if f.category == "SUSPICIOUS_EXECUTION"), None)
    assert exec_finding is not None
    assert exec_finding.severity == "CRITICAL"


def test_log_analysis_benign_events():
    """Verify that routine everyday administrator activity produces no false-positive findings."""
    now = datetime.now(timezone.utc)
    agent = LogAnalysisAgent()

    events = [
        LogEvent(
            event_id="EVT-BENIGN-01",
            timestamp=now - timedelta(hours=1),
            log_source="WindowsSecurity",
            event_type="LOGON_SUCCESS",
            user="admin.workstation",
            host="WS-IT-01",
            source_ip="10.0.1.50",
        ),
        LogEvent(
            event_id="EVT-BENIGN-02",
            timestamp=now - timedelta(minutes=45),
            log_source="Sysmon",
            event_type="PROCESS_CREATE",
            user="admin.workstation",
            host="WS-IT-01",
            process_name="notepad.exe",
            parent_process="explorer.exe",
            command_line="notepad.exe C:\\Users\\admin\\notes.txt",
        ),
        LogEvent(
            event_id="EVT-BENIGN-03",
            timestamp=now - timedelta(minutes=30),
            log_source="Sysmon",
            event_type="PROCESS_CREATE",
            user="admin.workstation",
            host="WS-IT-01",
            process_name="calc.exe",
            parent_process="explorer.exe",
            command_line="calc.exe",
        ),
    ]

    output = agent.analyze(LogAnalysisInput(logs=events))

    assert output.status == "COMPLETED"
    assert output.brute_force_detected is False
    assert output.suspicious_executions_detected is False
    assert output.lateral_movement_detected is False
    assert output.suspicious_event_count == 0
    assert len(output.findings) == 0
    assert len(output.evidence) == 0
    assert "normal expected operating baselines" in (output.uncertainty_explanation or "")


def test_log_analysis_respects_aggregated_failure_count():
    event = LogEvent(
        event_id="EVT-AGGREGATE", event_type="LOGON_FAILED", user="multiple accounts",
        source_ip="198.51.100.15", additional_data={"attempt_count": 120},
    )
    result = LogAnalysisAgent().analyze(LogAnalysisInput(logs=[event]))
    assert result.brute_force_detected is True
    assert "120 reported attempts" in result.findings[0].description
    assert "individual account outcomes were not supplied" in result.findings[0].uncertainty_notes


def test_log_analysis_missing_data_and_empty():
    """Verify robust handling of empty log lists and missing attributes."""
    agent = LogAnalysisAgent()

    # Empty log list
    empty_output = agent.analyze(LogAnalysisInput(logs=[]))
    assert empty_output.status == "COMPLETED"
    assert empty_output.total_logs_analyzed == 0
    assert "No log telemetry" in empty_output.summary

    # Event missing timestamps and hostnames
    partial_event = LogEvent(
        event_id="EVT-PARTIAL",
        log_source="Unknown",
        event_type="LOGON_FAILED",
        user="test.user",
    )
    partial_output = agent.analyze(LogAnalysisInput(logs=[partial_event]))
    assert partial_output.status == "COMPLETED"
    assert partial_output.total_logs_analyzed == 1
    assert "lack timestamps" in (partial_output.uncertainty_explanation or "")


def test_log_analysis_lateral_movement_and_audit(db_session):
    """Verify lateral movement detection and audit recording."""
    agent = LogAnalysisAgent(db=db_session)

    events = [
        LogEvent(
            event_id="EVT-LAT-01",
            log_source="Sysmon",
            event_type="PROCESS_CREATE",
            host="FINANCE-SRV-02",
            user="service.backup",
            process_name="psexec.exe",
            command_line="psexec.exe \\\\dc01.corp.internal -u corp\\admin -p pass cmd.exe",
            source_ip="10.0.4.15",
            destination_ip="10.0.1.10",
            target_port=445,
        )
    ]

    initial_audit_count = db_session.query(AuditLog).count()
    output = agent.analyze(LogAnalysisInput(logs=events, incident_id="INC-TEST-01", record_audit=True))

    assert output.lateral_movement_detected is True
    assert any(f.category == "LATERAL_MOVEMENT" for f in output.findings)

    # Verify audit log entry was created
    new_audit_count = db_session.query(AuditLog).count()
    assert new_audit_count == initial_audit_count + 1
    last_log = db_session.query(AuditLog).order_by(AuditLog.timestamp.desc()).first()
    assert "LogAnalysisAgent" in last_log.actor
    assert last_log.target_id == "INC-TEST-01"



# ============================================================================
# 2. IDENTITY ANALYSIS AGENT TESTS
# ============================================================================

def test_identity_analysis_impossible_travel_and_mfa_anomaly():
    """Verify identity agent detects impossible travel velocity and MFA push fatigue."""
    now = datetime.now(timezone.utc)
    agent = IdentityAnalysisAgent()

    events = [
        # Login from New York
        IdentityEvent(
            event_id="ID-EVT-01",
            timestamp=now - timedelta(hours=1),
            user_id="sarah.connor",
            auth_event="SUCCESS",
            source_ip="64.104.22.18",
            location_city="New York",
            location_country="United States",
        ),
        # MFA Fatigue: 2 Denials followed by an Approval
        IdentityEvent(
            event_id="ID-EVT-02",
            timestamp=now - timedelta(minutes=45),
            user_id="sarah.connor",
            auth_event="MFA_DENIED",
            source_ip="185.220.101.5",
            location_city="Frankfurt",
            location_country="Germany",
            is_vpn_or_tor=True,
        ),
        IdentityEvent(
            event_id="ID-EVT-03",
            timestamp=now - timedelta(minutes=43),
            user_id="sarah.connor",
            auth_event="MFA_DENIED",
            source_ip="185.220.101.5",
            location_city="Frankfurt",
            location_country="Germany",
            is_vpn_or_tor=True,
        ),
        IdentityEvent(
            event_id="ID-EVT-04",
            timestamp=now - timedelta(minutes=40),
            user_id="sarah.connor",
            auth_event="MFA_APPROVED",
            source_ip="185.220.101.5",
            location_city="Frankfurt",
            location_country="Germany",
            is_vpn_or_tor=True,
        ),
    ]

    output = agent.analyze(IdentityAnalysisInput(events=events))

    assert output.status == "COMPLETED"
    assert len(output.accounts_assessed) == 1
    assessment = output.accounts_assessed[0]
    assert assessment.user_id == "sarah.connor"
    assert assessment.verdict == "COMPROMISED"
    assert assessment.impossible_travel_detected is True
    assert assessment.mfa_anomaly_detected is True
    assert assessment.confidence >= 0.90
    assert any("Tor gateway" in r for r in assessment.risk_factors)

    # Check findings
    assert len(output.findings) >= 1
    assert output.findings[0].severity == "CRITICAL"


def test_identity_analysis_benign_single_typo():
    """Verify single login failure followed by routine success is marked BENIGN."""
    now = datetime.now(timezone.utc)
    agent = IdentityAnalysisAgent()

    events = [
        IdentityEvent(
            event_id="ID-BENIGN-01",
            timestamp=now - timedelta(minutes=20),
            user_id="jordan.chen",
            auth_event="FAILURE",
            source_ip="10.0.1.25",
            location_city="Seattle",
            location_country="United States",
        ),
        IdentityEvent(
            event_id="ID-BENIGN-02",
            timestamp=now - timedelta(minutes=19),
            user_id="jordan.chen",
            auth_event="SUCCESS",
            source_ip="10.0.1.25",
            location_city="Seattle",
            location_country="United States",
        ),
    ]

    output = agent.analyze(IdentityAnalysisInput(events=events))

    assert len(output.accounts_assessed) == 1
    assessment = output.accounts_assessed[0]
    assert assessment.verdict == "BENIGN"
    assert assessment.confidence >= 0.85
    assert len(assessment.mitigating_factors) > 0
    assert len(output.findings) == 0


def test_identity_analysis_conflicting_evidence_and_missing_data():
    """Verify handling of accounts with failed spraying but no successful sessions (SUSPICIOUS, not COMPROMISED)."""
    now = datetime.now(timezone.utc)
    agent = IdentityAnalysisAgent()

    events = [
        IdentityEvent(
            event_id="ID-SPRAY-01",
            timestamp=now - timedelta(minutes=30),
            user_id="dev.ops-svc",
            auth_event="FAILURE",
            source_ip="185.220.101.5",
        ),
        IdentityEvent(
            event_id="ID-SPRAY-02",
            timestamp=now - timedelta(minutes=29),
            user_id="dev.ops-svc",
            auth_event="FAILURE",
            source_ip="185.220.101.5",
        ),
        IdentityEvent(
            event_id="ID-SPRAY-03",
            timestamp=now - timedelta(minutes=28),
            user_id="dev.ops-svc",
            auth_event="FAILURE",
            source_ip="185.220.101.5",
        ),
    ]

    output = agent.analyze(IdentityAnalysisInput(events=events))

    assessment = output.accounts_assessed[0]
    assert assessment.verdict == "SUSPICIOUS"  # Not yet compromised because no success
    assert "no successful login verified" in assessment.uncertainty_explanation.lower()


# ============================================================================
# 3. THREAT INTELLIGENCE AGENT TESTS
# ============================================================================

def test_threat_intel_exact_match_against_database(db_session):
    """Verify strict query against simulated threat indicators in the database."""
    agent = ThreatIntelligenceAgent(db=db_session)

    # Values known to be present in seed_data:
    # 198.51.100.24 (IP - MALICIOUS)
    # 4b68926947ac00f28e202ec102c7fb7d1d2b7811ef1f0a256f6c99c546db98be (SHA256 - MALICIOUS)
    # auth-identity-corp-update[.]com (defanged domain)
    queried = [
        "198.51.100.24",
        "4b68926947ac00f28e202ec102c7fb7d1d2b7811ef1f0a256f6c99c546db98be",
        "auth-identity-corp-update[.]com",
    ]

    output = agent.analyze(ThreatIntelInput(indicators=queried))

    assert output.status == "COMPLETED"
    assert output.total_queried == 3
    assert output.total_matched == 3
    assert output.total_malicious == 3
    assert len(output.unmatched_indicators) == 0

    # Ensure details match the seed database
    ip_match = next((m for m in output.matched_indicators if m.indicator_value == "198.51.100.24"), None)
    assert ip_match is not None
    assert ip_match.reputation == "MALICIOUS"
    assert ip_match.confidence == 96
    assert ip_match.verification_status == "VERIFIED"
    assert "Cobalt Strike" in (ip_match.threat_actor or "")


def test_threat_intel_never_invents_results(db_session):
    """CRITICAL SAFETY TEST: Unknown indicator must strictly return as UNMATCHED with no fabricated data."""
    agent = ThreatIntelligenceAgent(db=db_session)

    non_existent = [
        "203.0.113.99",
        "random-unregistered-adversary-domain.org",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ]

    output = agent.analyze(ThreatIntelInput(indicators=non_existent))

    assert output.total_queried == 3
    assert output.total_matched == 0
    assert output.total_malicious == 0
    assert len(output.matched_indicators) == 0
    assert output.unmatched_indicators == non_existent
    assert len(output.findings) == 0
    assert "no synthetic reputation was inferred" in output.uncertainty_explanation


def test_threat_intel_mixed_and_audit(db_session):
    """Verify mixed batch of known, unknown, and audit logging."""
    agent = ThreatIntelligenceAgent(db=db_session)

    initial_audit_count = db_session.query(AuditLog).count()
    mixed = ["198.51.100.24", "192.168.1.1"]

    output = agent.analyze(ThreatIntelInput(indicators=mixed, incident_id="INC-TEST-IOC", record_audit=True))

    assert output.total_queried == 2
    assert output.total_matched == 1
    assert len(output.unmatched_indicators) == 1
    assert output.unmatched_indicators[0] == "192.168.1.1"

    # Audit check
    new_audit_count = db_session.query(AuditLog).count()
    assert new_audit_count == initial_audit_count + 1



# ============================================================================
# 4. IMPACT ANALYSIS AGENT TESTS
# ============================================================================

def test_impact_analysis_risk_score_and_separation_of_hypotheses():
    """Verify explainable deterministic risk scoring and strict separation of confirmed vs hypothesized scope."""
    agent = ImpactAnalysisAgent()

    now = datetime.now(timezone.utc)

    # Confirmed evidence
    evidence = [
        EvidenceItem(
            evidence_id="EVI-01",
            evidence_type="ENDPOINT",
            description="Active process execution verified on host 'FINANCE-SRV-02'",
            raw_data={"host": "FINANCE-SRV-02", "user": "marcus.vance"},
            is_confirmed=True,
        ),
        EvidenceItem(
            evidence_id="EVI-02",
            evidence_type="AUTHENTICATION",
            description="Compromised domain controller credentials verified for user 'marcus.vance'",
            raw_data={"host": "dc01.corp.internal", "user": "marcus.vance"},
            is_confirmed=True,
        ),
        # Hypothesized evidence
        EvidenceItem(
            evidence_id="EVI-03",
            evidence_type="ENDPOINT",
            description="Hypothetical lateral pivot to host 'HR-DB-01' suspected via Kerberoasting",
            raw_data={"host": "HR-DB-01", "user": "finance.service"},
            is_confirmed=False,
        ),
    ]

    findings = [
        AgentFinding(
            finding_id="F-01",
            category="CREDENTIAL_THEFT",
            severity="CRITICAL",
            title="Domain Controller Credential Dumping",
            description="Confirmed LSASS memory extraction targeting domain credentials.",
            confidence=0.95,
        ),
        AgentFinding(
            finding_id="F-02",
            category="LATERAL_MOVEMENT",
            severity="HIGH",
            title="Suspected Lateral Pivoting",
            description="Potential lateral pivoting towards ERP database clusters.",
            confidence=0.60,
        ),
    ]

    output = agent.analyze(ImpactAnalysisInput(
        incident_id="INC-2026-084",
        evidence_items=evidence,
        findings=findings,
    ))

    assert output.status == "COMPLETED"
    assert output.severity == "CRITICAL"
    assert output.risk_score >= 85

    # Check step-by-step mathematical breakdown
    assert len(output.score_breakdown) >= 4
    assert any("Base score: +60" in line for line in output.score_breakdown)
    assert any("Critical asset exposure" in line for line in output.score_breakdown)

    # Check strict separation of confirmed vs hypothesized scope
    assert "FINANCE-SRV-02" in output.confirmed_impact.hosts
    assert "dc01.corp.internal" in output.confirmed_impact.hosts
    assert "marcus.vance" in output.confirmed_impact.accounts
    assert "HR-DB-01" not in output.confirmed_impact.hosts

    # Hypothesized impact must contain the unconfirmed item
    assert "HR-DB-01" in output.hypothesized_impact.hosts
    assert "finance.service" in output.hypothesized_impact.accounts

    # Critical assets identified
    assert any("dc" in a.lower() or "finance" in a.lower() for a in output.confirmed_impact.critical_assets)


def test_impact_analysis_benign_or_low_severity():
    """Verify low risk score when only informational/low telemetry is provided."""
    agent = ImpactAnalysisAgent()

    findings = [
        AgentFinding(
            finding_id="F-LOW",
            category="ROUTINE_ADMIN",
            severity="LOW",
            title="Scheduled Task Maintenance Execution",
            description="Routine scheduled maintenance triggered on workstation.",
            confidence=0.99,
        )
    ]

    output = agent.analyze(ImpactAnalysisInput(
        incident_id="INC-LOW-01",
        evidence_items=[],
        findings=findings,
        context_entities={"hosts": ["WS-ENG-05"], "accounts": ["dev.user"]},
    ))

    assert output.status == "COMPLETED"
    assert output.severity in ("LOW", "MEDIUM")
    assert output.risk_score < 65
    assert "WS-ENG-05" in output.confirmed_impact.hosts
    assert len(output.confirmed_impact.critical_assets) == 0
