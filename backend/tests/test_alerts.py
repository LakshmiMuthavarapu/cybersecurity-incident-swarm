def test_list_alerts(client):
    response = client.get("/api/alerts")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "items" in data
    assert data["total"] > 0
    assert len(data["items"]) > 0

def test_filter_alerts_by_severity(client):
    response = client.get("/api/alerts?severity=CRITICAL")
    assert response.status_code == 200
    data = response.json()
    for item in data["items"]:
        assert item["severity"] == "CRITICAL"

def test_search_alerts(client):
    response = client.get("/api/alerts?search=PowerShell")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    assert any("PowerShell" in item["title"] or "PowerShell" in item["description"] for item in data["items"])

def test_get_single_alert(client):
    response = client.get("/api/alerts/ALT-2026-101")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "ALT-2026-101"
    assert data["source"] == "CrowdStrike Falcon EDR"

def test_modify_alert(client):
    response = client.patch(
        "/api/alerts/ALT-2026-107?analyst=analyst.tester",
        json={"status": "INVESTIGATING"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "INVESTIGATING"

def test_alert_rejects_unknown_status(client):
    response = client.patch("/api/alerts/ALT-2026-107", json={"status": "CONTAINED"})
    assert response.status_code == 422
