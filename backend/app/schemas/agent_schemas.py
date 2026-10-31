"""
Pydantic schemas for Phase 2 Independent Cybersecurity Investigation Agents.

Provides strongly typed schemas for:
- Shared evidence, findings, and confidence ratings
- Log Analysis Agent inputs and outputs
- Identity Analysis Agent inputs and outputs
- Threat Intelligence Agent inputs and outputs
- Impact Analysis Agent inputs and outputs
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field


# ============================================================================
# SHARED EVIDENCE & FINDING SCHEMAS
# ============================================================================

class EvidenceItem(BaseModel):
    evidence_id: str = Field(description="Unique identifier for this evidence item")
    event_id: Optional[str] = Field(default=None, description="Original telemetry source event ID")
    timestamp: Optional[datetime] = Field(default=None, description="Timestamp of the observed event")
    evidence_type: str = Field(description="Type of evidence: AUTHENTICATION, PROCESS_EXECUTION, NETWORK, IOC, ACCOUNT, ENDPOINT")
    description: str = Field(description="Human-readable description of what was observed")
    raw_data: Optional[Dict[str, Any]] = Field(default=None, description="Raw telemetry attributes")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence in the validity of this evidence (0.0 - 1.0)")
    is_confirmed: bool = Field(default=True, description="True if factually verified in telemetry, False if inferred/hypothesized")


class AgentFinding(BaseModel):
    finding_id: str = Field(description="Unique identifier for the finding")
    category: str = Field(description="Finding category (e.g., BRUTE_FORCE, SUSPICIOUS_EXECUTION, LATERAL_MOVEMENT, COMPROMISED_IDENTITY)")
    severity: str = Field(description="CRITICAL, HIGH, MEDIUM, LOW, or INFORMATIONAL")
    title: str = Field(description="Summary headline of the finding")
    description: str = Field(description="Detailed finding narrative")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score for this finding")
    evidence_references: List[str] = Field(default_factory=list, description="List of evidence_ids or event_ids supporting this finding")
    mitre_technique: Optional[str] = Field(default=None, description="MITRE ATT&CK technique ID and name if applicable")
    uncertainty_notes: Optional[str] = Field(default=None, description="Explanation of uncertainty, data gaps, or alternative explanations")


# ============================================================================
# 1. LOG ANALYSIS AGENT SCHEMAS
# ============================================================================

class LogEvent(BaseModel):
    event_id: str = Field(description="Unique event ID (e.g. EVT-1001, Sysmon ID)")
    timestamp: Optional[datetime] = Field(default=None, description="Event timestamp")
    log_source: str = Field(default="Sysmon", description="Source of log: Sysmon, WindowsSecurity, LinuxAuth, Suricata, Okta, etc.")
    event_type: str = Field(description="Type: LOGON_SUCCESS, LOGON_FAILED, PROCESS_CREATE, NETWORK_CONNECT, etc.")
    host: Optional[str] = Field(default=None, description="Target or source hostname")
    user: Optional[str] = Field(default=None, description="Username or account")
    source_ip: Optional[str] = Field(default=None, description="Source IP address")
    destination_ip: Optional[str] = Field(default=None, description="Destination IP address")
    process_name: Optional[str] = Field(default=None, description="Name of executed process")
    parent_process: Optional[str] = Field(default=None, description="Parent process name")
    command_line: Optional[str] = Field(default=None, description="Full command line invocation")
    hash_sha256: Optional[str] = Field(default=None, description="SHA256 hash of binary")
    target_port: Optional[int] = Field(default=None, description="Network port")
    additional_data: Optional[Dict[str, Any]] = Field(default=None, description="Any supplemental log fields")


class LogAnalysisInput(BaseModel):
    logs: List[LogEvent] = Field(description="List of log events to analyze")
    incident_id: Optional[str] = Field(default=None, description="Incident context ID if applicable")
    record_audit: bool = Field(default=False, description="Whether to record this run in the audit log")


class LogAnalysisOutput(BaseModel):
    agent_name: str = "LogAnalysisAgent"
    status: str = Field(default="COMPLETED", description="COMPLETED, PARTIAL, or FAILED")
    summary: str = Field(description="Executive summary of log telemetry analysis")
    brute_force_detected: bool = Field(default=False)
    suspicious_executions_detected: bool = Field(default=False)
    lateral_movement_detected: bool = Field(default=False)
    total_logs_analyzed: int = 0
    suspicious_event_count: int = 0
    evidence: List[EvidenceItem] = Field(default_factory=list)
    findings: List[AgentFinding] = Field(default_factory=list)
    uncertainty_explanation: Optional[str] = Field(default=None, description="Notes on telemetry gaps or ambiguity")


# ============================================================================
# 2. IDENTITY ANALYSIS AGENT SCHEMAS
# ============================================================================

class IdentityEvent(BaseModel):
    event_id: str = Field(description="Event identifier")
    timestamp: Optional[datetime] = Field(default=None)
    user_id: str = Field(description="Target user account identifier (e.g. marcus.vance)")
    auth_event: str = Field(description="SUCCESS, FAILURE, MFA_CHALLENGE, MFA_DENIED, MFA_APPROVED, PASSWORD_CHANGE, PRIVILEGE_ASSIGN")
    source_ip: Optional[str] = Field(default=None)
    location_city: Optional[str] = Field(default=None)
    location_country: Optional[str] = Field(default=None)
    user_agent: Optional[str] = Field(default=None)
    device_id: Optional[str] = Field(default=None)
    is_vpn_or_tor: bool = Field(default=False)
    additional_context: Optional[Dict[str, Any]] = Field(default=None)


class AccountCompromiseAssessment(BaseModel):
    user_id: str
    verdict: str = Field(description="COMPROMISED, SUSPICIOUS, BENIGN, or INCONCLUSIVE")
    confidence: float = Field(ge=0.0, le=1.0)
    risk_factors: List[str] = Field(default_factory=list)
    mitigating_factors: List[str] = Field(default_factory=list)
    impossible_travel_detected: bool = False
    mfa_anomaly_detected: bool = False
    evidence_references: List[str] = Field(default_factory=list)
    uncertainty_explanation: str = Field(description="Why confidence is bounded and what remains uncertain")


class IdentityAnalysisInput(BaseModel):
    events: List[IdentityEvent] = Field(description="Authentication & identity activity events")
    user_baselines: Optional[Dict[str, Dict[str, Any]]] = Field(
        default=None,
        description="Optional baseline profiles (e.g. typical login country, typical devices)"
    )
    incident_id: Optional[str] = Field(default=None)
    record_audit: bool = Field(default=False)


class IdentityAnalysisOutput(BaseModel):
    agent_name: str = "IdentityAnalysisAgent"
    status: str = Field(default="COMPLETED")
    summary: str = Field(description="Summary of identity risk evaluation")
    total_events_analyzed: int = 0
    accounts_assessed: List[AccountCompromiseAssessment] = Field(default_factory=list)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    findings: List[AgentFinding] = Field(default_factory=list)
    uncertainty_explanation: Optional[str] = None


# ============================================================================
# 3. THREAT INTELLIGENCE AGENT SCHEMAS
# ============================================================================

class MatchedIndicator(BaseModel):
    indicator_value: str
    indicator_type: str = Field(description="IP, DOMAIN, SHA256, MD5, URL, CVE")
    reputation: str = Field(description="MALICIOUS, SUSPICIOUS, BENIGN, UNKNOWN")
    threat_actor: Optional[str] = None
    confidence: int = Field(ge=0, le=100)
    verification_status: str = Field(description="VERIFIED, UNVERIFIED, PENDING_REVIEW, DISPROVEN")
    tags: List[str] = Field(default_factory=list)
    description: str
    db_record_id: str = Field(description="Primary key from simulated ThreatIndicator table")
    is_simulated: bool = True


class ThreatIntelInput(BaseModel):
    indicators: List[str] = Field(description="List of raw indicator values to check (IP, domain, hash)")
    incident_id: Optional[str] = Field(default=None)
    record_audit: bool = Field(default=False)


class ThreatIntelOutput(BaseModel):
    agent_name: str = "ThreatIntelligenceAgent"
    status: str = Field(default="COMPLETED")
    summary: str
    total_queried: int = 0
    total_matched: int = 0
    total_malicious: int = 0
    matched_indicators: List[MatchedIndicator] = Field(default_factory=list)
    unmatched_indicators: List[str] = Field(default_factory=list, description="Indicators not found in database; NEVER invented")
    evidence: List[EvidenceItem] = Field(default_factory=list)
    findings: List[AgentFinding] = Field(default_factory=list)
    uncertainty_explanation: Optional[str] = None


# ============================================================================
# 4. IMPACT ANALYSIS AGENT SCHEMAS
# ============================================================================

class ImpactScope(BaseModel):
    accounts: List[str] = Field(default_factory=list)
    hosts: List[str] = Field(default_factory=list)
    services_or_segments: List[str] = Field(default_factory=list)
    critical_assets: List[str] = Field(default_factory=list)


class ImpactAnalysisInput(BaseModel):
    incident_id: Optional[str] = None
    evidence_items: List[EvidenceItem] = Field(default_factory=list)
    findings: List[AgentFinding] = Field(default_factory=list)
    context_entities: Optional[Dict[str, List[str]]] = Field(
        default=None,
        description="Optional explicitly identified entities {'accounts': [...], 'hosts': [...]}"
    )
    record_audit: bool = Field(default=False)


class ImpactAnalysisOutput(BaseModel):
    agent_name: str = "ImpactAnalysisAgent"
    incident_id: Optional[str] = None
    status: str = Field(default="COMPLETED")
    risk_score: int = Field(ge=0, le=100, description="Explainable deterministic risk score (0-100)")
    severity: str = Field(description="CRITICAL, HIGH, MEDIUM, or LOW")
    score_breakdown: List[str] = Field(default_factory=list, description="Step-by-step mathematical explanation")
    confirmed_impact: ImpactScope = Field(description="Impact factually confirmed by evidence")
    hypothesized_impact: ImpactScope = Field(description="Potential impact based on hypothesis/active investigation")
    evidence: List[EvidenceItem] = Field(default_factory=list)
    findings: List[AgentFinding] = Field(default_factory=list)
    uncertainty_explanation: str = Field(description="Explicit explanation of unknown impact dimensions")
