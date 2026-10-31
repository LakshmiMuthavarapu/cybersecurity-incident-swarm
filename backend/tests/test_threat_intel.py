def test_list_threat_indicators(client):
    response = client.get("/api/threat-intel")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "items" in data
    assert data["total"] >= 5

def test_create_and_verify_threat_indicator(client):
    new_ioc = {
        "indicator_type": "DOMAIN",
        "value": "simulated-malware-test-drop[.]net",
        "reputation": "SUSPICIOUS",
        "threat_actor": "Test Simulation Unit",
        "confidence": 70,
        "verification_status": "PENDING_REVIEW",
        "tags": ["Simulation", "Test-Drop"],
        "description": "Simulated drop domain for test execution.",
        "is_simulated": True
    }
    create_res = client.post("/api/threat-intel?analyst=analyst.tester", json=new_ioc)
    assert create_res.status_code == 201
    ioc = create_res.json()
    assert ioc["value"] == "simulated-malware-test-drop[.]net"

    # Verify indicator
    update_res = client.patch(
        f"/api/threat-intel/{ioc['id']}?analyst=analyst.tester",
        json={"verification_status": "VERIFIED", "confidence": 95}
    )
    assert update_res.status_code == 200
    updated_ioc = update_res.json()
    assert updated_ioc["verification_status"] == "VERIFIED"
    assert updated_ioc["confidence"] == 95

def test_threat_indicator_rejects_invalid_values_and_duplicates(client):
    invalid = client.post("/api/threat-intel", json={
        "indicator_type": "DOMAIN", "value": "bad.example", "reputation": "FAKE",
        "confidence": 140, "description": "Invalid simulated indicator.",
    })
    assert invalid.status_code == 422

    duplicate = client.post("/api/threat-intel", json={
        "indicator_type": "IP", "value": "198.51.100.24", "reputation": "MALICIOUS",
        "confidence": 90, "description": "Duplicate simulated indicator.",
    })
    assert duplicate.status_code == 409
