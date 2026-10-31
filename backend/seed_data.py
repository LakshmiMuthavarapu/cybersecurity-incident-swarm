"""
Database Seeder for Cybersecurity Incident Investigation Swarm.
Populates realistic, high-fidelity SIMULATED security operations data.
All records are explicitly labeled with is_simulated=True.
"""

import json
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from app.database import SessionLocal, Base, engine
from app.models.alert import Alert
from app.models.incident import (
    Incident,
    IncidentTimelineEvent,
    IncidentEvidence,
    IncidentInvestigation,
)
from app.models.threat_intel import ThreatIndicator
from app.models.approval import ApprovalAction
from app.models.audit_log import AuditLog

def seed_database():
    Base.metadata.create_all(bind=engine)
    db: Session = SessionLocal()

    try:
        # Check if already seeded
        if db.query(Incident).count() > 0:
            print("Database already contains records. Skipping seed.")
            return

        now = datetime.now(timezone.utc)
        print("Seeding database with simulated cybersecurity incident data...")

        # ---------------------------------------------------------
        # INCIDENTS
        # ---------------------------------------------------------
        inc1 = Incident(
            id="INC-2026-084",
            title="Multi-Stage Ransomware Precursor & Cobalt Strike Beaconing on FINANCE-SRV-02",
            severity="CRITICAL",
            status="AWAITING_REVIEW",
            lead_analyst="SecOps Swarm / Analyst Alex Rivera",
            created_at=now - timedelta(hours=3, minutes=45),
            updated_at=now - timedelta(minutes=15),
            summary=(
                "[SIMULATED SCENARIO] High-confidence intrusion sequence detected on corporate finance host. "
                "Initial execution spawned through an obfuscated Word macro document, leading to in-memory "
                "PowerShell injection, LSASS credential harvesting, and persistent HTTPS beaconing to an external C2 server."
            ),
            affected_assets=json.dumps(["FINANCE-SRV-02", "dc01.corp.internal", "user:marcus.vance"]),
            attack_vector="Spearphishing Attachment -> Encoded PowerShell -> LSASS Memory Injection -> Lateral C2",
            mitre_tactics=json.dumps([
                "TA0001 Initial Access (T1566.001 - Spearphishing Attachment)",
                "TA0002 Execution (T1059.001 - PowerShell)",
                "TA0006 Credential Access (T1003.001 - LSASS Memory Dumping)",
                "TA0011 Command & Control (T1071.001 - Web Protocols)",
            ]),
            risk_score=94,
            is_simulated=True,
        )

        inc2 = Incident(
            id="INC-2026-085",
            title="Distributed Password Spraying & Impossible Travel Anomaly on Cloud IdP",
            severity="HIGH",
            status="OPEN",
            lead_analyst="SecOps Swarm / Analyst Jordan Chen",
            created_at=now - timedelta(hours=6, minutes=20),
            updated_at=now - timedelta(hours=1, minutes=10),
            summary=(
                "[SIMULATED SCENARIO] Okta Identity event correlation detected an ongoing distributed credential "
                "spraying campaign originating from Tor exit gateways, followed by an impossible travel velocity "
                "anomaly for account sarah.connor."
            ),
            affected_assets=json.dumps(["Okta IdP Tenant", "user:sarah.connor", "user:dev.ops-svc"]),
            attack_vector="Tor Exit Node Spray -> Password Spraying -> Push Fatigue MFA Exploit",
            mitre_tactics=json.dumps([
                "TA0006 Credential Access (T1110.003 - Password Spraying)",
                "TA0001 Initial Access (T1078.004 - Cloud Accounts)",
                "TA0005 Defense Evasion (T1562.001 - Disable Security Tools)",
            ]),
            risk_score=78,
            is_simulated=True,
        )

        inc3 = Incident(
            id="INC-2026-086",
            title="Unauthorized AWS S3 Bucket Configuration Modification & Data Egress Prep",
            severity="MEDIUM",
            status="CONTAINED",
            lead_analyst="SecOps Swarm / Analyst Elena Rostova",
            created_at=now - timedelta(days=1, hours=4),
            updated_at=now - timedelta(hours=5),
            summary=(
                "[SIMULATED SCENARIO] CloudTrail alert triggered on unexpected S3 PutBucketPublicAccessBlock "
                "modification using an anomalous service role credential. Containment policy successfully executed."
            ),
            affected_assets=json.dumps(["aws:s3:corp-analytics-archive", "role:data-pipeline-worker"]),
            attack_vector="Leaked IAM Service Credential -> S3 Policy Alteration",
            mitre_tactics=json.dumps([
                "TA0001 Initial Access (T1078.004 - Cloud Accounts)",
                "TA0009 Collection (T1530 - Data from Cloud Storage)",
            ]),
            risk_score=52,
            is_simulated=True,
        )

        inc4 = Incident(
            id="INC-2026-087",
            title="Anomalous DNS Tunneling Queries Detected on Engineering Workstation",
            severity="LOW",
            status="INVESTIGATING",
            lead_analyst="SecOps Swarm / Analyst Rivera",
            created_at=now - timedelta(hours=12),
            updated_at=now - timedelta(hours=2),
            summary=(
                "[SIMULATED SCENARIO] High entropy base64 encoded TXT record requests to unknown apex domain "
                "ex-data-sync[.]org observed from host WS-ENG-12."
            ),
            affected_assets=json.dumps(["WS-ENG-12", "dns01.corp.internal"]),
            attack_vector="DNS Tunneling Protocol Abuse",
            mitre_tactics=json.dumps([
                "TA0011 Command and Control (T1071.004 - DNS)",
                "TA0010 Exfiltration (T1048.003 - Exfiltration Over Alternative Protocol)",
            ]),
            risk_score=38,
            is_simulated=True,
        )

        db.add_all([inc1, inc2, inc3, inc4])
        db.commit()

        # ---------------------------------------------------------
        # ALERTS
        # ---------------------------------------------------------
        alerts = [
            # Correlated with INC-2026-084
            Alert(
                id="ALT-2026-101",
                timestamp=now - timedelta(hours=3, minutes=45),
                title="Suspicious Encoded PowerShell Spawned by WINWORD.EXE",
                source="CrowdStrike Falcon EDR",
                severity="CRITICAL",
                status="ESCALATED",
                category="Execution",
                source_ip="10.0.4.15",
                destination_ip="198.51.100.24",
                user="marcus.vance",
                host="FINANCE-SRV-02",
                description="WINWORD.EXE spawned powershell.exe with base64 encoded payload: -NoP -NonI -W Hidden -Enc SQBFAFgA...",
                raw_payload=json.dumps({
                    "process_name": "powershell.exe",
                    "parent_process": "WINWORD.EXE",
                    "command_line": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0...",
                    "hash_sha256": "4b68926947ac00f28e202ec102c7fb7d1d2b7811ef1f0a256f6c99c546db98be",
                    "simulated": True
                }),
                incident_id="INC-2026-084",
                is_simulated=True,
            ),
            Alert(
                id="ALT-2026-102",
                timestamp=now - timedelta(hours=3, minutes=20),
                title="Suspected LSASS Memory Credential Access Attempt",
                source="Sysmon EDR",
                severity="CRITICAL",
                status="ESCALATED",
                category="Credential Access",
                source_ip="10.0.4.15",
                destination_ip=None,
                user="marcus.vance",
                host="FINANCE-SRV-02",
                description="Process created a handle with PROCESS_VM_READ access to C:\\Windows\\System32\\lsass.exe.",
                raw_payload=json.dumps({
                    "target_image": "C:\\Windows\\System32\\lsass.exe",
                    "granted_access": "0x1010",
                    "source_image": "C:\\Windows\\Temp\\rundll32_host.exe",
                    "simulated": True
                }),
                incident_id="INC-2026-084",
                is_simulated=True,
            ),
            Alert(
                id="ALT-2026-103",
                timestamp=now - timedelta(hours=2, minutes=50),
                title="Repetitive HTTPS Beaconing to Uncategorized External IP",
                source="Suricata NIDS",
                severity="HIGH",
                status="INVESTIGATING",
                category="Command and Control",
                source_ip="10.0.4.15",
                destination_ip="198.51.100.24",
                user="marcus.vance",
                host="FINANCE-SRV-02",
                description="Jittered periodic HTTPS POST requests matching Cobalt Strike malleable C2 profile signatures.",
                raw_payload=json.dumps({
                    "dest_port": 443,
                    "packet_count": 842,
                    "interval_seconds": 60,
                    "jitter_percent": 15,
                    "ja3_fingerprint": "a0e9f5d64349fb13191bc781f81f42e1",
                    "simulated": True
                }),
                incident_id="INC-2026-084",
                is_simulated=True,
            ),
            Alert(
                id="ALT-2026-104",
                timestamp=now - timedelta(hours=2, minutes=10),
                title="Anomalous Active Directory Kerberoasting Query Spike",
                source="Zeek AD Sensor",
                severity="HIGH",
                status="ESCALATED",
                category="Credential Access",
                source_ip="10.0.4.15",
                destination_ip="10.0.0.1",
                user="marcus.vance",
                host="FINANCE-SRV-02",
                description="Host issued 48 Kerberos TGS-REQ requests requesting RC4-HMAC cipher tickets for SPNs in 90 seconds.",
                raw_payload=json.dumps({
                    "dc_host": "dc01.corp.internal",
                    "cipher": "0x17 (RC4-HMAC)",
                    "requested_spns": ["MSSQLSvc/db01.corp.internal", "HTTP/sharepoint.corp.internal"],
                    "simulated": True
                }),
                incident_id="INC-2026-084",
                is_simulated=True,
            ),

            # Correlated with INC-2026-085
            Alert(
                id="ALT-2026-105",
                timestamp=now - timedelta(hours=6, minutes=20),
                title="Distributed Password Spraying Targetting Enterprise Cloud IdP",
                source="Okta Identity Cloud",
                severity="HIGH",
                status="ESCALATED",
                category="Initial Access",
                source_ip="185.220.101.5",
                destination_ip="10.200.0.5",
                user="multiple (120 accounts)",
                host="okta-corp.identity.com",
                description="120 failed authentication attempts using common enterprise seasonal passwords across multiple Tor exit nodes.",
                raw_payload=json.dumps({"attempt_count": 120, "unique_source_ips": 18, "simulated": True}),
                incident_id="INC-2026-085",
                is_simulated=True,
            ),
            Alert(
                id="ALT-2026-106",
                timestamp=now - timedelta(hours=5, minutes=15),
                title="Impossible Travel Velocity Anomaly: London to Singapore in 22m",
                source="Okta ThreatInsight",
                severity="HIGH",
                status="INVESTIGATING",
                category="Initial Access",
                source_ip="203.0.113.88",
                destination_ip="10.200.0.5",
                user="sarah.connor",
                host="okta-corp.identity.com",
                description="User authenticated from London (UK) at 04:12 UTC and Singapore at 04:34 UTC (speed > 18,000 km/h).",
                raw_payload=json.dumps({"city_1": "London", "city_2": "Singapore", "time_delta_mins": 22, "simulated": True}),
                incident_id="INC-2026-085",
                is_simulated=True,
            ),

            # Standalone / Uncorrelated Alerts
            Alert(
                id="ALT-2026-107",
                timestamp=now - timedelta(hours=1, minutes=5),
                title="Multiple SSH Failed Login Attempts from Unregistered IP",
                source="AuthLog Monitor",
                severity="MEDIUM",
                status="NEW",
                category="Credential Access",
                source_ip="192.0.2.144",
                destination_ip="10.0.8.22",
                user="root",
                host="BASTION-01",
                description="14 consecutive failed SSH attempts for root user over port 22 within 3 minutes.",
                raw_payload=json.dumps({"failed_count": 14, "service": "sshd", "simulated": True}),
                incident_id=None,
                is_simulated=True,
            ),
            Alert(
                id="ALT-2026-108",
                timestamp=now - timedelta(minutes=40),
                title="Endpoint USB Removable Storage Device Connected",
                source="Defender for Endpoint",
                severity="LOW",
                status="NEW",
                category="Exfiltration",
                source_ip=None,
                destination_ip=None,
                user="j.smith",
                host="WS-HR-04",
                description="SanDisk Ultra USB 3.0 mounted on HR workstation. Hardware ID: USB\\VID_0781&PID_5581.",
                raw_payload=json.dumps({"serial": "4C530001090124115162", "mount_point": "E:\\", "simulated": True}),
                incident_id=None,
                is_simulated=True,
            ),
            Alert(
                id="ALT-2026-109",
                timestamp=now - timedelta(minutes=18),
                title="Port Scan Sweep Detected Across Management Subnet",
                source="Snort NIDS",
                severity="INFORMATIONAL",
                status="NEW",
                category="Reconnaissance",
                source_ip="10.0.12.99",
                destination_ip="10.0.1.0/24",
                user="svc_qualys_scanner",
                host="VULN-SCANNER-01",
                description="SYN sweep across TCP ports 22, 80, 443, 3389 originating from authorized security scanner host.",
                raw_payload=json.dumps({"scanned_ports": [22, 80, 443, 3389], "authorized": True, "simulated": True}),
                incident_id=None,
                is_simulated=True,
            ),
        ]

        db.add_all(alerts)
        db.commit()

        # ---------------------------------------------------------
        # TIMELINE EVENTS FOR INC-2026-084
        # ---------------------------------------------------------
        timeline_events = [
            IncidentTimelineEvent(
                id="EVT-084-01",
                incident_id="INC-2026-084",
                timestamp=now - timedelta(hours=3, minutes=50),
                title="Phishing Email Delivered to Marcus Vance",
                description="Message delivered with subject 'URGENT: Q3 Executive Compensation Review' containing weaponized Word attachment.",
                event_type="OBSERVATION",
                severity="HIGH",
                actor="Proofpoint Email Security",
                mitre_technique="T1566.001 - Spearphishing Attachment",
            ),
            IncidentTimelineEvent(
                id="EVT-084-02",
                incident_id="INC-2026-084",
                timestamp=now - timedelta(hours=3, minutes=45),
                title="Document Macro Executes Encoded PowerShell",
                description="User Marcus Vance opened attachment. Word macro spawned hidden powershell.exe with base64 payload.",
                event_type="ALERT",
                severity="CRITICAL",
                actor="CrowdStrike Falcon",
                mitre_technique="T1059.001 - PowerShell",
            ),
            IncidentTimelineEvent(
                id="EVT-084-03",
                incident_id="INC-2026-084",
                timestamp=now - timedelta(hours=3, minutes=20),
                title="Credential Dumping Targetting LSASS Memory",
                description="Injected process issued OpenProcess API call against lsass.exe to dump NTLM password hashes.",
                event_type="ALERT",
                severity="CRITICAL",
                actor="Sysmon EDR",
                mitre_technique="T1003.001 - LSASS Memory",
            ),
            IncidentTimelineEvent(
                id="EVT-084-04",
                incident_id="INC-2026-084",
                timestamp=now - timedelta(hours=2, minutes=50),
                title="C2 Channel Established with 198.51.100.24",
                description="Outbound encrypted HTTPS beaconing established at 60s intervals matching Cobalt Strike malleable profile.",
                event_type="ALERT",
                severity="HIGH",
                actor="Suricata NIDS",
                mitre_technique="T1071.001 - Web Protocols",
            ),
            IncidentTimelineEvent(
                id="EVT-084-05",
                incident_id="INC-2026-084",
                timestamp=now - timedelta(hours=2, minutes=10),
                title="Active Directory Kerberoasting Query Cluster",
                description="Attacker queried domain controller dc01.corp.internal for Kerberos tickets of service accounts.",
                event_type="ALERT",
                severity="HIGH",
                actor="Zeek AD Sensor",
                mitre_technique="T1558.003 - Kerberoasting",
            ),
            IncidentTimelineEvent(
                id="EVT-084-06",
                incident_id="INC-2026-084",
                timestamp=now - timedelta(hours=1, minutes=15),
                title="Swarm Containment Actions Formulated",
                description="Automated swarm correlation formulated 3 high-priority containment action proposals awaiting analyst decision.",
                event_type="AGENT_ACTION",
                severity="INFO",
                actor="Containment Agent (Simulated)",
                mitre_technique=None,
            ),
        ]
        db.add_all(timeline_events)

        # ---------------------------------------------------------
        # EVIDENCE ITEMS FOR INC-2026-084
        # ---------------------------------------------------------
        evidence_items = [
            IncidentEvidence(
                id="EVI-084-01",
                incident_id="INC-2026-084",
                evidence_type="FILE_HASH",
                label="Weaponized Phishing Attachment (invoice_q3_final.docm)",
                value="4b68926947ac00f28e202ec102c7fb7d1d2b7811ef1f0a256f6c99c546db98be",
                verdict="MALICIOUS",
                source="CrowdStrike EDR",
                notes="VBA macro decodes XOR encrypted shellcode in memory.",
                created_at=now - timedelta(hours=3, minutes=45),
            ),
            IncidentEvidence(
                id="EVI-084-02",
                incident_id="INC-2026-084",
                evidence_type="IP_ADDRESS",
                label="External C2 Command & Control Destination",
                value="198.51.100.24",
                verdict="MALICIOUS",
                source="Suricata NIDS",
                notes="Associated with known simulated adversary infrastructure (APT29 simulation).",
                created_at=now - timedelta(hours=2, minutes=50),
            ),
            IncidentEvidence(
                id="EVI-084-03",
                incident_id="INC-2026-084",
                evidence_type="COMMAND_LINE",
                label="Stager Execution Command String",
                value="powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0...",
                verdict="MALICIOUS",
                source="Sysmon Event ID 1",
                notes="De-obfuscated script initiates IEX web download cradle from 198.51.100.24:8443.",
                created_at=now - timedelta(hours=3, minutes=45),
            ),
            IncidentEvidence(
                id="EVI-084-04",
                incident_id="INC-2026-084",
                evidence_type="USER_ACCOUNT",
                label="Compromised Domain Identity",
                value="marcus.vance (Marcus Vance - Finance VP)",
                verdict="SUSPICIOUS",
                source="Active Directory / Okta",
                notes="User has administrative rights on FINANCE-SRV-02 and read access to shared ERP volumes.",
                created_at=now - timedelta(hours=3, minutes=45),
            ),
            IncidentEvidence(
                id="EVI-084-05",
                incident_id="INC-2026-084",
                evidence_type="REGISTRY_KEY",
                label="Persistence Run Key Value",
                value="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemDiagnosticsAgent",
                verdict="SUSPICIOUS",
                source="Registry Telemetry",
                notes="Points to C:\\Users\\marcus.vance\\AppData\\Local\\Temp\\diagsvc.exe",
                created_at=now - timedelta(hours=2, minutes=30),
            ),
        ]
        db.add_all(evidence_items)

        # ---------------------------------------------------------
        # INVESTIGATION FINDINGS FOR INC-2026-084
        # ---------------------------------------------------------
        inv1 = IncidentInvestigation(
            id="INV-084",
            incident_id="INC-2026-084",
            hypothesis=(
                "[DETERMINISTIC CORRELATION HYPOTHESIS] The attacker achieved initial access via spearphishing "
                "attachment invoice_q3_final.docm opened by Marcus Vance. Macro spawned an in-memory PowerShell stager "
                "which downloaded Cobalt Strike beacon payload from 198.51.100.24. The adversary then performed "
                "LSASS credential dumping to acquire local administrator credentials and executed Kerberoasting against "
                "corporate domain controllers to escalate privileges across financial ERP systems."
            ),
            confidence_score=0.94,
            summary=(
                "Full cyber kill-chain progression observed within 90 minutes. Telemetry links initial execution to "
                "active C2 communications. Critical financial database access is at risk if lateral movement is not halted."
            ),
            findings=json.dumps([
                {
                    "finding_id": "FIND-01",
                    "title": "Initial Access Vector Verified",
                    "description": "Macro weaponization confirmed via Sysmon Event ID 1 parent-child process relationship (WINWORD.EXE -> powershell.exe).",
                    "severity": "CRITICAL",
                    "status": "CONFIRMED"
                },
                {
                    "finding_id": "FIND-02",
                    "title": "Credential Harvest Scope",
                    "description": "LSASS memory handle injection detected. At least 2 cached domain service account credentials potentially compromised.",
                    "severity": "CRITICAL",
                    "status": "CONFIRMED"
                },
                {
                    "finding_id": "FIND-03",
                    "title": "Exfiltration Analysis",
                    "description": "C2 beacon observed transmitting heartbeat telemetry (~1.2 KB/min). No large outbound bulk data egress detected to date.",
                    "severity": "MEDIUM",
                    "status": "MONITORING"
                }
            ]),
            recommended_containment=json.dumps([
                {
                    "action": "Host Isolation",
                    "target": "FINANCE-SRV-02 (10.0.4.15)",
                    "priority": "P0 - IMMEDIATE",
                    "detail": "Disconnect network adapter via EDR host isolation to stop lateral traversal."
                },
                {
                    "action": "Session Revocation & TGT Reset",
                    "target": "user:marcus.vance",
                    "priority": "P0 - IMMEDIATE",
                    "detail": "Invalidate active Kerberos tickets and force immediate password reset."
                },
                {
                    "action": "Perimeter IP Block",
                    "target": "198.51.100.24",
                    "priority": "P1 - HIGH",
                    "detail": "Inject egress DROP rule in border Palo Alto / Fortinet firewalls."
                }
            ]),
            updated_at=now - timedelta(minutes=15),
        )
        db.add(inv1)

        # ---------------------------------------------------------
        # PROPOSED APPROVAL ACTIONS
        # ---------------------------------------------------------
        approvals = [
            ApprovalAction(
                id="APP-2026-001",
                incident_id="INC-2026-084",
                action_type="ISOLATE_HOST",
                target="Host FINANCE-SRV-02 (10.0.4.15)",
                description="Sever network connectivity for FINANCE-SRV-02 while maintaining EDR telemetry channel.",
                rationale="Active Cobalt Strike beaconing and memory injection detected. Isolation prevents domain controller lateral pivot.",
                risk_level="HIGH",
                proposed_by="Containment Agent (Deterministic Swarm)",
                status="PENDING",
                created_at=now - timedelta(hours=1, minutes=15),
            ),
            ApprovalAction(
                id="APP-2026-002",
                incident_id="INC-2026-084",
                action_type="REVOKE_SESSION",
                target="User marcus.vance (Marcus Vance)",
                description="Invalidate all active Okta SAML assertions, Microsoft Entra tokens, and Kerberos TGT sessions.",
                rationale="Credential theft suspected via LSASS dumping. Prevents adversary using stolen hash for pass-the-hash attacks.",
                risk_level="MEDIUM",
                proposed_by="Containment Agent (Deterministic Swarm)",
                status="PENDING",
                created_at=now - timedelta(hours=1, minutes=10),
            ),
            ApprovalAction(
                id="APP-2026-003",
                incident_id="INC-2026-084",
                action_type="BLOCK_IP",
                target="IP 198.51.100.24 at Border Gateways",
                description="Deploy firewall egress blacklist rule for 198.51.100.24 on perimeter firewall cluster.",
                rationale="External C2 server verified actively receiving telemetry beacons from infected finance server.",
                risk_level="LOW",
                proposed_by="Containment Agent (Deterministic Swarm)",
                status="PENDING",
                created_at=now - timedelta(hours=1, minutes=5),
            ),
            ApprovalAction(
                id="APP-2026-004",
                incident_id="INC-2026-085",
                action_type="RESET_CREDENTIALS",
                target="Account sarah.connor",
                description="Initiate emergency credential rotation and unbind registered MFA hardware keys.",
                rationale="Password spray attack succeeded against account; impossible travel alert indicates hijacked credential.",
                risk_level="MEDIUM",
                proposed_by="Containment Agent (Deterministic Swarm)",
                status="PENDING",
                created_at=now - timedelta(hours=4),
            ),
            ApprovalAction(
                id="APP-2026-005",
                incident_id="INC-2026-086",
                action_type="REVOKE_SESSION",
                target="IAM Access Key AKIAEXAMPLE00492",
                description="Deactivate AWS IAM Access Key and apply explicit deny policy on corp-analytics-archive S3 bucket.",
                rationale="Unauthorized bucket policy tampering detected.",
                risk_level="MEDIUM",
                proposed_by="Containment Agent (Deterministic Swarm)",
                status="APPROVED",
                created_at=now - timedelta(days=1, hours=3),
                decided_at=now - timedelta(hours=5),
                decided_by="Analyst Elena Rostova",
                decision_reason="Confirmed anomalous role usage. Cloud containment approved and executed in simulation.",
                simulation_execution_notes="[SIMULATION ONLY] IAM policy deactivated successfully. CloudTrail synthetic event confirmed.",
            ),
        ]
        db.add_all(approvals)

        # ---------------------------------------------------------
        # THREAT INDICATORS (THREAT INTELLIGENCE)
        # ---------------------------------------------------------
        indicators = [
            ThreatIndicator(
                id="IOC-2026-001",
                indicator_type="IP",
                value="198.51.100.24",
                reputation="MALICIOUS",
                threat_actor="Simulated Cobalt Strike C2 (APT29 Profile)",
                confidence=96,
                verification_status="VERIFIED",
                first_seen=now - timedelta(days=5),
                last_seen=now - timedelta(hours=2),
                tags=json.dumps(["Cobalt-Strike", "C2-Server", "Bulletproof-Host"]),
                description="External IP hosting simulated HTTPS Cobalt Strike command and control listener with custom SSL certificates.",
                is_simulated=True,
            ),
            ThreatIndicator(
                id="IOC-2026-002",
                indicator_type="SHA256",
                value="4b68926947ac00f28e202ec102c7fb7d1d2b7811ef1f0a256f6c99c546db98be",
                reputation="MALICIOUS",
                threat_actor="Financially Motivated Phishing Actor",
                confidence=92,
                verification_status="VERIFIED",
                first_seen=now - timedelta(days=3),
                last_seen=now - timedelta(hours=3),
                tags=json.dumps(["Malicious-Doc", "VBA-Macro", "Stager"]),
                description="Weaponized Microsoft Word invoice macro loader containing Base64 encoded PowerShell cradle.",
                is_simulated=True,
            ),
            ThreatIndicator(
                id="IOC-2026-003",
                indicator_type="DOMAIN",
                value="auth-identity-corp-update[.]com",
                reputation="MALICIOUS",
                threat_actor="Typosquatting Credential Harvester",
                confidence=88,
                verification_status="VERIFIED",
                first_seen=now - timedelta(days=8),
                last_seen=now - timedelta(hours=14),
                tags=json.dumps(["Typosquat", "Phishing-Kit", "Evilginx"]),
                description="Lookalike domain masquerading as corporate Okta single-sign-on portal with reverse proxy MFA interceptor.",
                is_simulated=True,
            ),
            ThreatIndicator(
                id="IOC-2026-004",
                indicator_type="IP",
                value="185.220.101.5",
                reputation="SUSPICIOUS",
                threat_actor="Tor Exit Node Network",
                confidence=75,
                verification_status="PENDING_REVIEW",
                first_seen=now - timedelta(days=12),
                last_seen=now - timedelta(hours=6),
                tags=json.dumps(["Tor-Exit", "Anonymizer", "Password-Spray"]),
                description="Public Tor exit gateway repeatedly observed in distributed credential stuffing and password spraying attempts.",
                is_simulated=True,
            ),
            ThreatIndicator(
                id="IOC-2026-005",
                indicator_type="CVE",
                value="CVE-2026-2189",
                reputation="MALICIOUS",
                threat_actor="Simulated Remote Code Execution PoC",
                confidence=95,
                verification_status="VERIFIED",
                first_seen=now - timedelta(days=20),
                last_seen=now - timedelta(days=1),
                tags=json.dumps(["RCE", "Privilege-Escalation", "Windows-Kernel"]),
                description="Critical zero-day elevation of privilege vulnerability in legacy graphics driver subsystem.",
                is_simulated=True,
            ),
            ThreatIndicator(
                id="IOC-2026-006",
                indicator_type="DOMAIN",
                value="ex-data-sync[.]org",
                reputation="SUSPICIOUS",
                threat_actor="Unknown DNS Exfiltration Group",
                confidence=64,
                verification_status="PENDING_REVIEW",
                first_seen=now - timedelta(days=1),
                last_seen=now - timedelta(hours=2),
                tags=json.dumps(["DNS-Tunneling", "High-Entropy"]),
                description="Apex domain receiving anomalous high-frequency Base64 encoded sub-domain queries.",
                is_simulated=True,
            ),
            ThreatIndicator(
                id="IOC-2026-007",
                indicator_type="IP",
                value="8.8.8.8",
                reputation="BENIGN",
                threat_actor="Google Public DNS",
                confidence=99,
                verification_status="VERIFIED",
                first_seen=now - timedelta(days=365),
                last_seen=now,
                tags=json.dumps(["Public-DNS", "Legitimate-Infra"]),
                description="Legitimate public recursive DNS resolver service.",
                is_simulated=True,
            ),
        ]
        db.add_all(indicators)

        # ---------------------------------------------------------
        # AUDIT LOGS
        # ---------------------------------------------------------
        audit_logs = [
            AuditLog(
                id="AUD-2026-0001",
                timestamp=now - timedelta(hours=3, minutes=44),
                actor="System Ingestion Engine",
                action="ALERT_INGESTED",
                target_type="ALERT",
                target_id="ALT-2026-101",
                details="Ingested CRITICAL alert 'Suspicious Encoded PowerShell Spawned by WINWORD.EXE' from CrowdStrike EDR.",
                client_ip="127.0.0.1 (Local Collector)",
                is_simulated=True,
            ),
            AuditLog(
                id="AUD-2026-0002",
                timestamp=now - timedelta(hours=3, minutes=40),
                actor="TriageAgent (Rule Engine)",
                action="INCIDENT_CREATED",
                target_type="INCIDENT",
                target_id="INC-2026-084",
                details="Escalated correlated cluster on FINANCE-SRV-02 to CRITICAL Incident INC-2026-084.",
                client_ip="127.0.0.1 (Local Analyst Session)",
                is_simulated=True,
            ),
            AuditLog(
                id="AUD-2026-0003",
                timestamp=now - timedelta(hours=2, minutes=50),
                actor="CorrelationAgent (Swarm)",
                action="IOC_CORRELATED",
                target_type="THREAT_INTEL",
                target_id="IOC-2026-001",
                details="Correlated external C2 IP 198.51.100.24 with Incident INC-2026-084 evidence record.",
                client_ip="127.0.0.1 (Local Analyst Session)",
                is_simulated=True,
            ),
            AuditLog(
                id="AUD-2026-0004",
                timestamp=now - timedelta(hours=1, minutes=15),
                actor="ContainmentAgent (Swarm)",
                action="APPROVAL_PROPOSED",
                target_type="APPROVAL",
                target_id="APP-2026-001",
                details="Formulated containment action ISOLATE_HOST for FINANCE-SRV-02 (Risk: HIGH). Submitted to SOC queue.",
                client_ip="127.0.0.1 (Local Analyst Session)",
                is_simulated=True,
            ),
            AuditLog(
                id="AUD-2026-0005",
                timestamp=now - timedelta(hours=5),
                actor="Analyst Elena Rostova",
                action="APPROVAL_APPROVED",
                target_type="APPROVAL",
                target_id="APP-2026-005",
                details="Analyst approved simulation containment for AWS IAM Access Key AKIAEXAMPLE00492. Simulated revocation executed.",
                client_ip="127.0.0.1 (Local Analyst Session)",
                is_simulated=True,
            ),
        ]
        db.add_all(audit_logs)

        db.commit()
        print("Database successfully seeded with realistic simulated security data!")

    except Exception as e:
        db.rollback()
        print(f"Error seeding database: {e}")
        raise e
    finally:
        db.close()

if __name__ == "__main__":
    seed_database()
