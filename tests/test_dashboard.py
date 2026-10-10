import pytest
from fastapi.testclient import TestClient
from dashboard_backend.main import app

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}

def test_soc_dashboard():
    response = client.get("/api/dashboard/soc")
    assert response.status_code == 200
    data = response.json()
    assert "compromised_hosts" in data
    assert "active_alerts" in data
    assert "critical_nodes" in data
    assert len(data["compromised_hosts"]) == 2

def test_engineer_dashboard():
    response = client.get("/api/dashboard/engineer")
    assert response.status_code == 200
    data = response.json()
    assert "risk_scores" in data
    assert "monitored_services" in data
    assert "WS-01" in data["risk_scores"]

def test_hunter_dashboard():
    response = client.get("/api/dashboard/hunter")
    assert response.status_code == 200
    data = response.json()
    assert "highest_exposure_nodes" in data
    assert "blast_radius_default" in data

def test_ir_dashboard():
    response = client.get("/api/dashboard/ir")
    assert response.status_code == 200
    data = response.json()
    assert "isolated_hosts" in data
    assert "incident_response_logs" in data
    assert "WS-01" in data["isolated_hosts"]

def test_ciso_dashboard():
    response = client.get("/api/dashboard/ciso")
    assert response.status_code == 200
    data = response.json()
    assert "enterprise_risk_score" in data
    assert "financial_loss_estimate" in data
    assert data["enterprise_risk_score"] > 0.0

def test_executive_dashboard():
    response = client.get("/api/dashboard/executive")
    assert response.status_code == 200
    data = response.json()
    assert "business_impact" in data
    assert "financial_summary" in data
    assert "markdown_executive_summary" in data
