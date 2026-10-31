def test_list_approvals(client):
    response = client.get("/api/approvals")
    assert response.status_code == 200
    approvals = response.json()
    assert len(approvals) >= 4

def test_filter_pending_approvals(client):
    response = client.get("/api/approvals?status=PENDING")
    assert response.status_code == 200
    approvals = response.json()
    assert all(a["status"] == "PENDING" for a in approvals)

def test_approve_containment_action(client):
    # Approve APP-2026-003 (IP Block)
    response = client.post(
        "/api/approvals/APP-2026-003/decision",
        json={
            "decision": "APPROVED",
            "analyst_name": "Analyst Alex Rivera",
            "reason": "Authorized IP block simulation at perimeter firewall."
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "APPROVED"
    assert data["decided_by"] == "Analyst Alex Rivera"
    assert "SIMULATION ONLY" in data["simulation_execution_notes"]
    assert "Perimeter IP block simulation recorded" in data["simulation_execution_notes"]
    incident = client.get("/api/incidents/INC-2026-084").json()
    assert incident["status"] == "AWAITING_REVIEW"
    repeated = client.post(
        "/api/approvals/APP-2026-003/decision",
        json={"decision": "REJECTED", "reason": "Reconsidered after review."},
    )
    assert repeated.status_code == 409

def test_reject_containment_action(client):
    response = client.post(
        "/api/approvals/APP-2026-004/decision",
        json={
            "decision": "REJECTED",
            "analyst_name": "Analyst Jordan Chen",
            "reason": "False positive travel alert, user confirmed remote work VPN."
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "REJECTED"
    assert data["decided_by"] == "Analyst Jordan Chen"

def test_decision_requires_supported_action_and_nonblank_reason(client):
    missing_reason = client.post(
        "/api/approvals/APP-2026-001/decision",
        json={"decision": "APPROVED", "reason": "   "},
    )
    assert missing_reason.status_code == 422
    unsupported = client.post(
        "/api/approvals/APP-2026-001/decision",
        json={"decision": "EXECUTED", "reason": "Not an allowed decision."},
    )
    assert unsupported.status_code == 422
