# Cybersecurity Incident Investigation Swarm

A full-stack, multi-agent cybersecurity operations platform that triages simulated security telemetry, correlates multi-stage attack chains mapped to the MITRE ATT&CK framework, and coordinates human-in-the-loop analyst decisions for containment actions in a controlled sandbox environment.

Implements four independent Python investigation agents with deterministic rule-based analysis, strict zero-invention threat intelligence, explainable risk scoring, and evidence linking without requiring external LLM API keys.

---

## 🛡️ Safety & Reliability Principles

1. **Simulation-Only Environment**: All telemetry, endpoints, identities, and threat indicators are synthetic.
2. **No Real Containment Execution**: Containment decisions trigger mock responses in the local sandbox and never alter real operating systems, cloud tenants, or firewall devices.
3. **Audit Trail**: Investigation steps, indicator verification, and analyst decisions are recorded in the SQLite audit ledger.
4. **Strict Zero-Invention Threat Intel**: Indicators not verified in the local intelligence repository are strictly marked as unverified/not found; no reputations or threat actor attributions are ever fabricated.
5. **No Secrets Exposed**: API keys and external credentials are strictly separated from client code via `.env.example`.

This is a local training/demo application. It uses synthetic records and mock containment, and it does not provide production authentication, authorization, or live security integrations.

---

## 🏗️ Architecture & Technology Stack

```
cybersecurity-incident-swarm/
├── backend/                        # FastAPI Python Backend
│   ├── app/
│   │   ├── main.py                 # Application factory & CORS configuration
│   │   ├── config.py               # Pydantic Settings & simulation guardrails
│   │   ├── database.py             # SQLite engine & session management
│   │   ├── models/                 # SQLAlchemy ORM models
│   │   │   ├── alert.py            # Security Alert model
│   │   │   ├── incident.py         # Incident, Timeline, Evidence, Investigation
│   │   │   ├── threat_intel.py     # Threat Indicator model
│   │   │   ├── approval.py         # Containment Approval Action model
│   │   │   └── audit_log.py        # SOC Audit Log model
│   │   ├── schemas/                # Pydantic validation schemas
│   │   │   ├── alert.py            # Alert schemas
│   │   │   ├── incident.py         # Incident schemas
│   │   │   ├── threat_intel.py     # Threat Intel schemas
│   │   │   ├── approval.py         # Approval schemas
│   │   │   └── agent_schemas.py    # Phase 2 Agent inputs, outputs, evidence & findings
│   │   ├── services/               # Business logic & correlation services
│   │   │   ├── alert_service.py    # Alert querying & filtering
│   │   │   ├── incident_service.py # Incident management & timeline/evidence
│   │   │   ├── threat_service.py   # IoC querying & verification
│   │   │   ├── approval_service.py # Human-in-the-loop decisions & simulation
│   │   │   ├── audit_service.py    # Audit logging service
│   │   │   └── investigation_rules.py # Deterministic correlation heuristics
│   │   ├── agents/                 # Cybersecurity Investigation Agents
│   │   │   ├── log_analysis_agent.py      # Log Analysis Agent
│   │   │   ├── identity_analysis_agent.py # Identity Analysis Agent
│   │   │   ├── threat_intel_agent.py      # Threat Intelligence Agent
│   │   │   ├── impact_analysis_agent.py   # Impact Analysis Agent
│   │   │   ├── state.py            # Shared investigation state
│   │   │   ├── base.py             # BaseSecurityAgent abstract class
│   │   │   ├── prompts.py          # Prompt templates
│   │   │   ├── triage_agent.py     # Phase 1 Alert triage agent
│   │   │   ├── correlation_agent.py# Phase 1 Attack chain correlation agent
│   │   │   ├── containment_agent.py# Phase 1 Containment recommendation agent
│   │   │   └── workflow.py         # Phase 1 triage/correlation workflow
│   │   └── api/                    # Modular API routing
│   │       └── routes/             # health, dashboard, alerts, incidents, threat_intel, approvals, audit_logs
│   ├── tests/                      # API and agent unit/integration tests
│   │   ├── test_agents.py          # Unit tests for all 4 Phase 2 investigation agents
│   │   └── ...                     # Existing API & component tests
│   ├── verify_agents.py            # CLI verification script for all 4 agents
│   ├── seed_data.py                # High-fidelity simulated scenario seed data
│   ├── init_db.py                  # Database initialization & re-seeding CLI
│   ├── requirements.txt            # Python dependencies
│   └── .env.example                # Configuration template without real secrets
├── frontend/                       # React (Vite) Frontend
│   ├── src/
│   │   ├── api/client.js           # API client with Vite proxy integration
│   │   ├── components/             # Reusable UI components
│   │   ├── pages/                  # 7 Core Operations Views
│   │   ├── App.jsx                 # Main application controller
│   │   └── index.css               # Security Light Theme design system
│   ├── package.json
│   └── vite.config.js              # Vite server & API proxy config
└── README.md
```


---

## 🚀 Setup & Execution Instructions

### Prerequisites
- Python 3.10+
- Node.js 18+ and npm

---

### Step 1: Backend Setup & Database Initialization (Terminal 1)

1. Open a Windows PowerShell terminal and navigate to `backend/`:
   ```powershell
   cd backend
   ```

2. (Optional) Create and activate a Python virtual environment:
   ```powershell
   python -m venv venv
   # In PowerShell (run with ExecutionPolicy if restricted):
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\venv\Scripts\Activate.ps1
   ```

3. Install backend dependencies:
   ```powershell
   python -m pip install -r requirements.txt
   ```

4. Create local configuration file from template:
   ```powershell
   Copy-Item .env.example .env
   ```

5. Initialize and seed the SQLite database with realistic simulated security data:
   ```powershell
   python init_db.py --reset
   ```

6. Run the backend tests to verify all endpoints and investigation agents:
   ```powershell
   python -m pytest -v
   ```
   *(Runs the backend API and agent unit/integration suite.)*

7. Execute the independent investigation agents verification script:
   ```powershell
   python verify_agents.py
   ```
   *(Demonstrates all 4 agents analyzing simulated attack chains, compromised identities, IoC correlation, and explainable risk scoring)*

8. Evaluate suspicious and benign scenarios:
   ```powershell
   python evaluate_scenarios.py
   ```
   *(Both cases should print PASS: attack telemetry triggers findings while routine activity does not.)*

9. Start the FastAPI backend server:
   ```powershell
   python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
   ```
   - API Root: `http://127.0.0.1:8000/`
   - Interactive OpenAPI Documentation: `http://127.0.0.1:8000/docs`
   - Health Check: `http://127.0.0.1:8000/api/health`

---

### Step 2: Frontend Setup & Dev Server (Terminal 2)

1. Open a second Windows PowerShell terminal and navigate to `frontend/`:
   ```powershell
   cd frontend
   ```

2. Install dependencies:
   ```powershell
   npm install
   ```

3. Start the Vite development server:
   ```powershell
   npm run dev -- --host 127.0.0.1 --port 5173
   ```

4. Open your browser and navigate to:
   ```
   http://127.0.0.1:5173/
   ```

---

### Running Both Services Simultaneously on Windows

To run both services side-by-side on Windows, keep **Terminal 1** (`uvicorn app.main:app`) and **Terminal 2** (`npm run dev`) active at the same time. The Vite dev server proxies API calls (`/api/*`) directly to `http://127.0.0.1:8000/`, with CORS pre-configured to allow local development.

---

## 🖥️ Operations Dashboard Walkthrough

### 1. Operations Dashboard
- **Key Metrics**: Real-time counters for Total Alerts, Open Incidents, Critical Incidents, Incidents Awaiting Review, and Pending Containment Approvals.
- **Telemetry Breakdown**: Visual charts categorizing alerts by severity (Critical, High, Medium, Low) and MITRE ATT&CK categories.
- **Priority Incidents & Telemetry Feed**: Instant drill-down to investigate correlated clusters or inspect incoming sensor events.

### 2. Security Alerts
- Search across alert titles, description text, source/destination IPs, users, and hostnames.
- Filter by Severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), Status (`NEW`, `INVESTIGATING`, `ESCALATED`, `RESOLVED`), and Sensor Source (`CrowdStrike EDR`, `Sysmon`, `Suricata NIDS`, `Okta IdP`, `Zeek`).
- One-click raw JSON payload inspector modal.

### 3. Correlated Incidents
- Incident cards featuring risk scores (0–100), affected assets tags, attack vector summary, and MITRE tactics.
- "Investigate Swarm Graph" button to jump directly into the full forensic console.

### 4. Incident Investigation Console
- **Swarm Findings & Hypothesis**: Rule-based correlation hypothesis with confidence scores, observable findings, and recommended containment actions.
- **Event Timeline**: Chronological attack sequence with actor attribution and MITRE technique tags.
- **Correlated Evidence**: Forensic artifacts (file hashes, C2 IP addresses, obfuscated PowerShell command lines, registry keys) with one-click copy.
- **Related Alerts**: Ingested sensor telemetry tied to the active incident.

### 5. Threat Intelligence
- Searchable IoC vault with reputation indicators (`MALICIOUS`, `SUSPICIOUS`, `BENIGN`), confidence percentages, and threat actor tags.
- "Verify Indicator" button allowing analysts to promote indicators to verified status.
- "Add Simulated IoC" dialog for testing custom indicators.

### 6. Approvals Queue (Containment Actions)
- Human-in-the-loop decision queue for proposed actions (Host Isolation, Session Revocation, IP Blocking).
- "Simulate & Authorize" and "Reject" workflows with mandatory analyst justification.
- Sandbox execution feedback displaying simulated host isolation and firewall rule notes.

### 7. SOC Audit Logs
- Immutable chronological ledger recording all telemetry ingestions, correlation events, indicator verifications, and containment approval decisions.
- Filterable by actor, action type, and target category.

### 8. Four-Agent Swarm Investigation
- Open an incident with linked simulated alerts and select **Run four-agent investigation**.
- Log analysis, identity analysis, and threat intelligence analyze the same telemetry. Impact analysis combines their results into an explainable risk score.
- The run is saved to the incident investigation, timeline, and evidence list.
- Evidence-backed simulated host isolation, session revocation, verified malicious IP block, and verified malicious file hash quarantine proposals enter the analyst approvals queue. Approval records only a simulated result.
- Re-running refreshes the report without duplicating evidence or approval proposals. Incidents without linked alerts return a clear `422` response.

Threat intelligence results only reflect matches in the local simulated repository. Unknown indicators remain unmatched.

---

---

## 🧠 Independent Investigation Agents

Four independent deterministic Python investigation agents are housed in [`backend/app/agents/`](backend/app/agents/). Each agent operates using strongly typed Pydantic models from [`agent_schemas.py`](backend/app/schemas/agent_schemas.py) and does not require an external LLM API key.

### 1. Log Analysis Agent ([`log_analysis_agent.py`](backend/app/agents/log_analysis_agent.py))
- **Responsibilities**: Ingests authentication and endpoint telemetry (Sysmon, Windows Security, Linux auth, Suricata).
- **Detection Capabilities**:
  - Brute force and password spraying clustering (correlated with subsequent successful logons).
  - Suspicious execution hierarchies (Office / browsers spawning PowerShell, cmd, mshta, wscript).
  - Parameter obfuscation (`-NoP -W Hidden -Enc`, IEX download cradles).
  - Credential access targets (`lsass.exe` handle inspection with `PROCESS_VM_READ`).
  - Lateral movement tools (`psexec.exe`, `wmic.exe`, internal `10.x.x.x` pivoting on SMB/RPC ports 445/135).
- **Outputs**: Granular evidence items with source `event_id`, timestamps, confidence ratings (0.0–1.0), and MITRE technique tags (`T1110`, `T1059.001`, `T1021`).

### 2. Identity Analysis Agent ([`identity_analysis_agent.py`](backend/app/agents/identity_analysis_agent.py))
- **Responsibilities**: Evaluates authentication streams, geographic velocity, and multi-factor authentication events.
- **Detection Capabilities**:
  - Push fatigue MFA abuse (multiple denials followed by an approval).
  - Impossible travel physical velocity anomalies (disparate geographic regions traversed within minutes).
  - Anonymizing Tor exit node / proxy routing.
  - Distinguishes confirmed compromise from benign anomalies (user typing mistakes, established VPN baselines).
- **Outputs**: Account assessments labeled `COMPROMISED`, `SUSPICIOUS`, or `BENIGN` with confidence, risk factors, and mitigating factors.

### 3. Threat Intelligence Agent ([`threat_intel_agent.py`](backend/app/agents/threat_intel_agent.py))
- **Responsibilities**: Queries IP addresses, domains, and SHA-256 hashes against the simulated threat-intelligence database (`ThreatIndicator` table).
- **Safety Guarantee**: **Never invents threat intelligence results**. Any unindexed indicator is cataloged strictly as `UNMATCHED` / `UNVERIFIED` with zero inferred confidence.
- **Outputs**: Matched intelligence records with verification status, confidence score, threat actor attribution, and raw provenance tags.

### 4. Impact Analysis Agent ([`impact_analysis_agent.py`](backend/app/agents/impact_analysis_agent.py))
- **Responsibilities**: Scopes affected infrastructure, calculates explainable deterministic risk scores, and strictly separates fact from hypothesis.
- **Separation of Evidence**:
  - `confirmed_impact`: Factually verified compromised accounts and hosts from telemetry (`is_confirmed=True`).
  - `hypothesized_impact`: Speculative lateral pivot targets and potential exposure pending telemetry verification.
- **Explainable Risk Scoring**: Mathematical breakdown combining finding severities, critical asset bonuses (Domain Controllers, IdP tenants, ERP servers), and blast radius modifiers.

---

## Evaluation scope

`backend/evaluate_scenarios.py` provides a small local smoke evaluation for one suspicious and one benign scenario. It helps catch basic regressions, but it is not a labeled production detection benchmark. The current workflow uses deterministic local agents and does not require LangGraph, an LLM provider, or API credentials.

