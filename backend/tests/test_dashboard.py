def test_dashboard_stats(client):
    response = client.get("/api/dashboard/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_alerts" in data
    assert "open_incidents" in data
    assert "critical_incidents" in data
    assert "incidents_awaiting_review" in data
    assert "pending_approvals" in data
    assert "alerts_by_severity" in data
    assert "alerts_by_category" in data
    assert "recent_incidents" in data
    assert data["total_alerts"] >= 8
    assert data["critical_incidents"] >= 1
