def test_list_incidents(client):
    response = client.get("/api/incidents")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "items" in data
    assert data["total"] >= 4

def test_get_incident_detail(client):
    response = client.get("/api/incidents/INC-2026-084")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "INC-2026-084"
    assert data["severity"] == "CRITICAL"
    assert isinstance(data["affected_assets"], list)
    assert len(data["affected_assets"]) > 0
    assert "timeline_events" in data
    assert len(data["timeline_events"]) >= 5
    assert "evidence_items" in data
    assert len(data["evidence_items"]) >= 4
    assert data["investigation"] is not None
    assert "hypothesis" in data["investigation"]

def test_get_incident_timeline(client):
    response = client.get("/api/incidents/INC-2026-084/timeline")
    assert response.status_code == 200
    events = response.json()
    assert len(events) >= 5
    assert any("Phishing" in e["title"] for e in events)

def test_get_incident_evidence(client):
    response = client.get("/api/incidents/INC-2026-084/evidence")
    assert response.status_code == 200
    evidence = response.json()
    assert len(evidence) >= 4
    assert any(e["evidence_type"] == "IP_ADDRESS" for e in evidence)

def test_update_incident_status(client):
    response = client.patch(
        "/api/incidents/INC-2026-087?analyst=analyst.tester",
        json={"status": "RESOLVED", "risk_score": 15}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "RESOLVED"
    assert data["risk_score"] == 15

def test_incident_rejects_out_of_range_risk(client):
    response = client.patch("/api/incidents/INC-2026-087", json={"risk_score": 140})
    assert response.status_code == 422

def test_run_swarm_investigation_and_rerun(client):
    first = client.post("/api/incidents/INC-2026-084/investigation/run")
    assert first.status_code == 200
    result = first.json()
    assert result["is_simulated"] is True
    assert set(result["agents"]) == {"log_analysis", "identity_analysis", "threat_intelligence", "impact_analysis"}
    assert result["agents"]["threat_intelligence"]["total_malicious"] >= 1
    proposals = {(item["action_type"], item["target"]) for item in result["approval_proposals"]}
    assert ("BLOCK_IP", "198.51.100.24") in proposals
    assert ("QUARANTINE_FILE", "4b68926947ac00f28e202ec102c7fb7d1d2b7811ef1f0a256f6c99c546db98be") in proposals
    assert not any(action == "BLOCK_IP" and len(target) == 64 for action, target in proposals)
    assert result["agents"]["identity_analysis"]["accounts_assessed"] == []
    assert result["evidence"]
    assert client.get("/api/incidents/INC-2026-084/evidence").json()
    assert client.get("/api/incidents/INC-2026-084/timeline").json()[-1]["title"] == "Four-agent swarm investigation completed"

    second = client.post("/api/incidents/INC-2026-084/investigation/run")
    assert second.status_code == 200
    assert second.json()["approval_proposals"] == []

def test_run_swarm_reports_incidents_without_alerts(client):
    response = client.post("/api/incidents/INC-2026-086/investigation/run")
    assert response.status_code == 422
    assert "no linked telemetry" in response.json()["detail"]

def test_swarm_uses_aggregated_identity_and_travel_telemetry(client):
    result = client.post("/api/incidents/INC-2026-085/investigation/run")
    assert result.status_code == 200
    agents = result.json()["agents"]
    assert agents["log_analysis"]["brute_force_detected"] is True
    assessments = agents["identity_analysis"]["accounts_assessed"]
    assert all("multiple" not in account["user_id"] for account in assessments)
    sarah = next(account for account in assessments if account["user_id"] == "sarah.connor")
    assert sarah["impossible_travel_detected"] is True
