from __future__ import annotations

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "healthy"


def test_scan_endpoint():
    response = client.post("/api/scan", json={"url": "https://example.com"})
    assert response.status_code == 200
    payload = response.json()
    assert "verdict" in payload
    assert payload["method"] == "ml"
    assert "class_probabilities" in payload
