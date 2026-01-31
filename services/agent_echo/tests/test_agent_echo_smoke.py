from __future__ import annotations

from fastapi.testclient import TestClient

from services.agent_echo.app import app


def test_health_ok():
    c = TestClient(app)
    r = c.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True


def test_invoke_echo():
    c = TestClient(app)
    r = c.post("/invoke", json={"event_type": "trace.ingested", "payload": {"x": 1}})
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["events"][0]["event_type"] == "echo"
