"""Evaluate the deterministic swarm against one simulated attack and one benign event."""

from datetime import datetime, timezone

from app.agents import IdentityAnalysisAgent, ImpactAnalysisAgent, LogAnalysisAgent, ThreatIntelligenceAgent
from app.schemas.agent_schemas import (
    IdentityAnalysisInput, IdentityEvent, ImpactAnalysisInput, LogAnalysisInput,
    LogEvent, ThreatIntelInput,
)


def evaluate(name, log_events, identity_events, indicators, expected_detection):
    logs = LogAnalysisAgent().analyze(LogAnalysisInput(logs=log_events))
    identity = IdentityAnalysisAgent().analyze(IdentityAnalysisInput(events=identity_events))
    intel = ThreatIntelligenceAgent().analyze(ThreatIntelInput(indicators=indicators))
    findings = logs.findings + identity.findings + intel.findings
    impact = ImpactAnalysisAgent().analyze(ImpactAnalysisInput(
        findings=findings,
        evidence_items=logs.evidence + identity.evidence + intel.evidence,
    ))
    detected = bool(findings)
    passed = detected == expected_detection
    print(f"{'PASS' if passed else 'FAIL'} {name}: expected_detection={expected_detection}, detected={detected}, risk={impact.risk_score}, findings={len(findings)}")
    return passed


def main():
    now = datetime.now(timezone.utc)
    attack_logs = [
        LogEvent(event_id=f"ATTACK-{i}", timestamp=now, event_type="LOGON_FAILED", user="analyst.test", source_ip="203.0.113.77", host="WS-SIM-01")
        for i in range(3)
    ] + [LogEvent(event_id="ATTACK-EXEC", timestamp=now, event_type="PROCESS_CREATE", user="analyst.test", host="WS-SIM-01", process_name="powershell.exe", parent_process="WINWORD.EXE", command_line="powershell.exe -NoP -W Hidden -Enc AAAAAAAAAAAAAAAA")]
    benign_logs = [LogEvent(event_id="BENIGN-01", timestamp=now, event_type="LOGON_SUCCESS", user="analyst.test", source_ip="10.0.0.8", host="WS-ENG-01", process_name="notepad.exe", parent_process="explorer.exe", command_line="notepad.exe notes.txt")]
    ok = evaluate("simulated attack", attack_logs, [
        IdentityEvent(event_id="ATTACK-ID", timestamp=now, user_id="analyst.test", auth_event="SUCCESS", source_ip="203.0.113.77", is_vpn_or_tor=True),
    ], ["unlisted-simulated-indicator.invalid"], True)
    ok = evaluate("benign routine activity", benign_logs, [
        IdentityEvent(event_id="BENIGN-ID", timestamp=now, user_id="analyst.test", auth_event="SUCCESS", source_ip="10.0.0.8", location_city="Seattle", location_country="United States"),
    ], [], False) and ok
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
