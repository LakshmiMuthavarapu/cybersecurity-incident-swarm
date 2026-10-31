def test_list_audit_logs(client):
    response = client.get("/api/audit-logs")
    assert response.status_code == 200
    logs = response.json()
    assert isinstance(logs, list)
    assert len(logs) >= 4
    for log in logs:
        assert "actor" in log
        assert "action" in log
        assert "target_type" in log

def test_filter_audit_logs_by_target(client):
    response = client.get("/api/audit-logs?target_type=INCIDENT")
    assert response.status_code == 200
    logs = response.json()
    assert all(l["target_type"] == "INCIDENT" for l in logs)
