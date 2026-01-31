import os
from fastapi.testclient import TestClient


def _make_client():
    # Ensure dashboard DB points to a local temp file for tests.
    # Note: init_db() is called at import time in app in this repo pattern.
    os.environ.setdefault("DASHBOARD_JWT_SECRET", "test-secret")
    os.environ.setdefault("DASHBOARD_DB_URL", "sqlite:////tmp/kakveda_dashboard_test.db")
    from services.dashboard.app import app  # noqa

    return TestClient(app)


def test_login_page_loads():
    client = _make_client()
    r = client.get("/auth/login")
    assert r.status_code == 200
    assert "Login" in r.text


def test_requires_login_redirects():
    client = _make_client()
    r = client.get("/runs", allow_redirects=False)
    assert r.status_code in (302, 307)
    assert r.headers.get("location", "").startswith("/auth/login")


def test_static_css_served():
    client = _make_client()
    r = client.get("/static/style.css")
    assert r.status_code == 200
    assert "Option A" in r.text


def test_ingest_requires_api_key():
    client = _make_client()
    r = client.post("/api/ingest/run", json={"app_id": "a", "agent_id": "b", "input": {"prompt": "hi"}, "output": {"response": "yo"}})
    assert r.status_code == 200
    assert r.json().get("ok") is False


def test_runs_page_accepts_advanced_query_syntax():
    client = _make_client()
    # Not logged in, but should still redirect cleanly (parsing shouldn't blow up).
    r = client.get("/runs?q=provider:ollama%20latency_ms%3E100%20has:error", allow_redirects=False)
    assert r.status_code in (302, 307)
