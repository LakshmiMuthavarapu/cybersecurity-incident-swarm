"""
Log Analysis Agent (Phase 2).

Specialized deterministic investigation agent that analyzes simulated authentication
and endpoint execution telemetry. Detects:
1. Brute-force & credential spraying attempts
2. Suspicious process executions and obfuscated scripting patterns
3. Lateral movement indicators (remote services, PsExec, WinRM, internal pivoting)

Produces structured Pydantic output containing timestamps, source event IDs,
confidence ratings, and uncertainty explanations.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
import re

from app.schemas.agent_schemas import (
    LogAnalysisInput,
    LogAnalysisOutput,
    LogEvent,
    EvidenceItem,
    AgentFinding,
)
from app.services.audit_service import log_action


class LogAnalysisAgent:
    """Deterministic rule-based agent for analyzing simulated endpoint & auth logs."""

    NAME = "LogAnalysisAgent"

    # Suspicious execution signatures
    SUSPICIOUS_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrobat.exe"}
    SUSPICIOUS_CHILDREN = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe"}
    OBFUSCATION_PATTERNS = [
        re.compile(r"-nop\s+-w\s+hidden", re.IGNORECASE),
        re.compile(r"-enc(odedcommand)?\s+[a-zA-Z0-9+/=]{10,}", re.IGNORECASE),
        re.compile(r"iex\s*\(", re.IGNORECASE),
        re.compile(r"downloadstring", re.IGNORECASE),
        re.compile(r"bypass\s+-c", re.IGNORECASE),
        re.compile(r"invoke-expression", re.IGNORECASE),
    ]
    CREDENTIAL_ACCESS_TARGETS = ["lsass.exe", "sam", "security", "ntds.dit"]
    LATERAL_BINARIES = {"psexec.exe", "psexesvc.exe", "wmic.exe", "winrm.cmd", "net.exe"}

    def __init__(self, db: Optional[Session] = None):
        self.db = db

    def analyze(self, input_data: LogAnalysisInput) -> LogAnalysisOutput:
        """Executes deterministic log analysis across provided events."""
        logs = input_data.logs
        total_logs = len(logs)

        evidence: List[EvidenceItem] = []
        findings: List[AgentFinding] = []
        suspicious_event_ids: set = set()

        if total_logs == 0:
            return LogAnalysisOutput(
                agent_name=self.NAME,
                status="COMPLETED",
                summary="No log telemetry provided for analysis.",
                total_logs_analyzed=0,
                suspicious_event_count=0,
                uncertainty_explanation="Empty log batch. Telemetry source may be disabled or unconfigured."
            )

        # --------------------------------------------------------------------
        # 1. BRUTE-FORCE & AUTHENTICATION ANALYSIS
        # --------------------------------------------------------------------
        user_failures: Dict[str, List[LogEvent]] = {}
        ip_failures: Dict[str, List[LogEvent]] = {}
        successful_logins: Dict[str, List[LogEvent]] = {}

        for log in logs:
            if not log.event_type:
                continue

            event_type = log.event_type.upper()
            if event_type in ("LOGON_FAILED", "AUTH_FAILURE", "4625"):
                key_user = log.user.lower() if log.user else "UNKNOWN_USER"
                user_failures.setdefault(key_user, []).append(log)

                key_ip = log.source_ip if log.source_ip else "UNKNOWN_IP"
                ip_failures.setdefault(key_ip, []).append(log)

            elif event_type in ("LOGON_SUCCESS", "AUTH_SUCCESS", "4624"):
                key_user = log.user.lower() if log.user else "UNKNOWN_USER"
                successful_logins.setdefault(key_user, []).append(log)

        # Evaluate brute force by user
        for user_key, fail_events in user_failures.items():
            fail_count = sum(
                max(1, int((event.additional_data or {}).get("attempt_count", 1)))
                if str((event.additional_data or {}).get("attempt_count", 1)).isdigit() else 1
                for event in fail_events
            )
            if fail_count >= 3:
                # Corroborate whether a success followed
                has_subsequent_success = user_key in successful_logins
                confidence = 0.95 if has_subsequent_success else 0.85
                severity = "CRITICAL" if has_subsequent_success else "HIGH"

                ref_event_ids = [e.event_id for e in fail_events]
                if has_subsequent_success:
                    ref_event_ids.extend([e.event_id for e in successful_logins[user_key]])

                suspicious_event_ids.update(ref_event_ids)

                # Create evidence items
                for fe in fail_events:
                    evidence.append(
                        EvidenceItem(
                            evidence_id=f"EVI-AUTH-{fe.event_id}",
                            event_id=fe.event_id,
                            timestamp=fe.timestamp,
                            evidence_type="AUTHENTICATION",
                            description=f"Authentication failure recorded for user '{user_key}' from {fe.source_ip or 'unknown IP'}.",
                            raw_data=fe.additional_data or {"user": user_key, "source_ip": fe.source_ip},
                            confidence=0.9,
                            is_confirmed=True,
                        )
                    )

                title = f"Credential Attack Detected Against '{user_key}' ({fail_count} failures)"
                if has_subsequent_success:
                    title += " [SUCCEEDED - COMPROMISE LIKELY]"

                findings.append(
                    AgentFinding(
                        finding_id=f"FIND-BF-{user_key}",
                        category="BRUTE_FORCE",
                        severity=severity,
                        title=title,
                        description=(
                            f"Detected repeated authentication failures ({fail_count} reported attempts) targeting '{user_key}'. "
                            + ("A successful logon followed the failures, indicating a potential password crack or spray success."
                               if has_subsequent_success else
                               "No successful logon followed within this telemetry window.")
                        ),
                        confidence=confidence,
                        evidence_references=ref_event_ids,
                        mitre_technique="T1110 (Brute Force)",
                        uncertainty_notes=(
                            None if has_subsequent_success else
                            "This count may represent an aggregated sensor report; individual account outcomes were not supplied."
                        ),
                    )
                )

        # --------------------------------------------------------------------
        # 2. SUSPICIOUS EXECUTION PATTERNS & OBFUSCATION
        # --------------------------------------------------------------------
        for log in logs:
            p_name = (log.process_name or "").lower()
            parent = (log.parent_process or "").lower()
            cmd = log.command_line or ""

            # Check abnormal process hierarchy (Office spawning scripting engines)
            has_abnormal_parent = any(sp in parent for sp in self.SUSPICIOUS_PARENTS) and any(sc in p_name for sc in self.SUSPICIOUS_CHILDREN)

            # Check obfuscation / script execution
            has_obfuscation = any(pat.search(cmd) for pat in self.OBFUSCATION_PATTERNS)

            # Check credential dumping access (e.g. Sysmon Event 10 LSASS handle)
            has_lsass_dump = any(target in cmd.lower() for target in self.CREDENTIAL_ACCESS_TARGETS) or (
                log.additional_data and any(target in str(log.additional_data).lower() for target in self.CREDENTIAL_ACCESS_TARGETS)
            )

            # Check temp folder execution
            is_temp_path = "appdata\\local\\temp" in cmd.lower() or "\\windows\\temp" in cmd.lower()

            if has_abnormal_parent or has_obfuscation or has_lsass_dump:
                suspicious_event_ids.add(log.event_id)
                confidence = 0.95 if (has_abnormal_parent and has_obfuscation) else 0.88

                evi_desc = f"Suspicious execution on host {log.host or 'unknown'}: Process '{log.process_name}'"
                if parent:
                    evi_desc += f" spawned by parent '{log.parent_process}'"
                if has_obfuscation:
                    evi_desc += " with obfuscated/encoded parameters"

                evidence.append(
                    EvidenceItem(
                        evidence_id=f"EVI-EXEC-{log.event_id}",
                        event_id=log.event_id,
                        timestamp=log.timestamp,
                        evidence_type="PROCESS_EXECUTION",
                        description=evi_desc,
                        raw_data={"process": log.process_name, "parent": log.parent_process, "cmd": cmd},
                        confidence=confidence,
                        is_confirmed=True,
                    )
                )

                finding_title = f"Suspicious Execution Pattern: {log.process_name or 'Script'}"
                if has_lsass_dump:
                    finding_title = f"Credential Access Attempt: {log.process_name or 'Process'} accessing LSASS"

                findings.append(
                    AgentFinding(
                        finding_id=f"FIND-EXEC-{log.event_id}",
                        category="SUSPICIOUS_EXECUTION",
                        severity="CRITICAL" if (has_lsass_dump or (has_abnormal_parent and has_obfuscation)) else "HIGH",
                        title=finding_title,
                        description=(
                            f"Process '{log.process_name}' (PID parent '{log.parent_process}') executed on host '{log.host}'. "
                            f"Command line: '{cmd}'. Obfuscation: {has_obfuscation}, LSASS target: {has_lsass_dump}."
                        ),
                        confidence=confidence,
                        evidence_references=[log.event_id],
                        mitre_technique="T1059.001 (PowerShell)" if "powershell" in p_name else "T1003.001 (LSASS Memory)" if has_lsass_dump else "T1204 (User Execution)",
                        uncertainty_notes=(
                            "Administrative deployment scripts can sometimes utilize encoded commands; "
                            "verified against baseline admin tools." if has_obfuscation and not has_abnormal_parent else None
                        ),
                    )
                )

        # --------------------------------------------------------------------
        # 3. LATERAL MOVEMENT INDICATORS
        # --------------------------------------------------------------------
        for log in logs:
            p_name = (log.process_name or "").lower()
            cmd = (log.command_line or "").lower()
            src_ip = log.source_ip or ""
            dst_ip = log.destination_ip or ""

            is_lateral_tool = any(lat in p_name for lat in self.LATERAL_BINARIES)
            is_remote_share = "net use" in cmd or "\\\\" in cmd or "admin$" in cmd or "ipc$" in cmd
            is_internal_pivot = src_ip.startswith("10.") and dst_ip.startswith("10.") and src_ip != dst_ip and log.target_port in (445, 135, 3389, 5985, 5986)

            if is_lateral_tool or is_remote_share or is_internal_pivot:
                suspicious_event_ids.add(log.event_id)
                evidence.append(
                    EvidenceItem(
                        evidence_id=f"EVI-LAT-{log.event_id}",
                        event_id=log.event_id,
                        timestamp=log.timestamp,
                        evidence_type="NETWORK" if is_internal_pivot else "PROCESS_EXECUTION",
                        description=f"Lateral movement indicator observed from {src_ip or log.host} to {dst_ip or 'internal target'}.",
                        raw_data={"cmd": cmd, "src_ip": src_ip, "dst_ip": dst_ip, "port": log.target_port},
                        confidence=0.88,
                        is_confirmed=True,
                    )
                )
                findings.append(
                    AgentFinding(
                        finding_id=f"FIND-LAT-{log.event_id}",
                        category="LATERAL_MOVEMENT",
                        severity="HIGH",
                        title=f"Lateral Movement Activity ({log.process_name or 'Internal Network Pivot'})",
                        description=f"Evidence of internal host pivoting or remote service execution: '{cmd or log.process_name}'.",
                        confidence=0.88,
                        evidence_references=[log.event_id],
                        mitre_technique="T1021 (Remote Services) / T1570 (Lateral Tool Transfer)",
                        uncertainty_notes="Confirm whether source machine is an authorized IT management jumpbox.",
                    )
                )

        # --------------------------------------------------------------------
        # 4. BENIGN EVALUATION & UNCERTAINTY SYNTHESIS
        # --------------------------------------------------------------------
        brute_force_detected = any(f.category == "BRUTE_FORCE" for f in findings)
        suspicious_executions_detected = any(f.category == "SUSPICIOUS_EXECUTION" for f in findings)
        lateral_movement_detected = any(f.category == "LATERAL_MOVEMENT" for f in findings)
        suspicious_count = len(suspicious_event_ids)

        # Check for missing telemetry fields across batch
        missing_timestamps = sum(1 for l in logs if l.timestamp is None)
        missing_hosts = sum(1 for l in logs if not l.host)
        gaps: List[str] = []
        if missing_timestamps > 0:
            gaps.append(f"{missing_timestamps} events lack timestamps")
        if missing_hosts > 0:
            gaps.append(f"{missing_hosts} events lack target hostname")

        uncertainty_exp = None
        if gaps:
            uncertainty_exp = f"Telemetry gaps observed: {', '.join(gaps)}. Telemetry correlation may be incomplete."
        elif suspicious_count == 0:
            uncertainty_exp = "All analyzed log events conform to normal expected operating baselines; no threat signatures triggered."

        summary = (
            f"Analyzed {total_logs} log events. Detected {suspicious_count} suspicious events: "
            f"Brute-Force={brute_force_detected}, Suspicious Executions={suspicious_executions_detected}, "
            f"Lateral Movement={lateral_movement_detected}."
        )

        output = LogAnalysisOutput(
            agent_name=self.NAME,
            status="COMPLETED",
            summary=summary,
            brute_force_detected=brute_force_detected,
            suspicious_executions_detected=suspicious_executions_detected,
            lateral_movement_detected=lateral_movement_detected,
            total_logs_analyzed=total_logs,
            suspicious_event_count=suspicious_count,
            evidence=evidence,
            findings=findings,
            uncertainty_explanation=uncertainty_exp,
        )

        # Record audit log if requested and db session is provided
        if input_data.record_audit and self.db:
            try:
                log_action(
                    db=self.db,
                    actor=f"Agent:{self.NAME}",
                    action="LOG_ANALYSIS_COMPLETED",
                    target_type="INCIDENT" if input_data.incident_id else "LOG_BATCH",
                    target_id=input_data.incident_id or f"BATCH-{total_logs}-EVENTS",
                    details=summary,
                    client_ip="127.0.0.1 (Internal Agent Orchestrator)",
                    is_simulated=True,
                )
            except Exception:
                pass

        return output
