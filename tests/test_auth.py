"""API auth-gate tests (item #5).

Exercises the real FastAPI app: /api/export, /ask, and the WebSocket must
reject requests without a valid key when API_KEY is set, accept them with the
key, and run open when API_KEY is unset. Read endpoints stay open.

Requires a reachable Redis (compose network); skipped otherwise.
"""
import os

import pytest

redis_sync = pytest.importorskip("redis")
pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

_REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")


def _redis_reachable() -> bool:
    try:
        c = redis_sync.from_url(_REDIS_URL, socket_connect_timeout=2)
        c.ping()
        c.close()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _redis_reachable(),
                                reason="Redis not reachable at REDIS_URL")

_KEY = "test-secret-key"


@pytest.fixture(autouse=True)
def _fresh_async_redis(monkeypatch):
    # TestClient runs each request in a fresh event loop; a module-global
    # redis.asyncio client would bind to the first loop and then fail with
    # "attached to a different loop". A fresh client per test binds cleanly to
    # that request's loop. (Production uvicorn uses one persistent loop, so this
    # is purely a test-harness concern.)
    import redis.asyncio as aioredis
    from api import server
    monkeypatch.setattr(server, "R", aioredis.from_url(_REDIS_URL))
    yield


@pytest.fixture
def client():
    from api.server import app
    return TestClient(app)


# ── HTTP endpoints ──────────────────────────────────────────────────────────

def test_export_rejected_without_key(client, monkeypatch):
    monkeypatch.setenv("API_KEY", _KEY)
    assert client.post("/api/export").status_code == 401


def test_export_allowed_with_header_key(client, monkeypatch):
    monkeypatch.setenv("API_KEY", _KEY)
    r = client.post("/api/export", headers={"X-API-Key": _KEY})
    assert r.status_code == 200
    assert r.json()["status"] == "exported"


def test_export_allowed_with_bearer_token(client, monkeypatch):
    monkeypatch.setenv("API_KEY", _KEY)
    r = client.post("/api/export", headers={"Authorization": f"Bearer {_KEY}"})
    assert r.status_code == 200


def test_export_rejected_with_wrong_key(client, monkeypatch):
    monkeypatch.setenv("API_KEY", _KEY)
    assert client.post("/api/export", headers={"X-API-Key": "nope"}).status_code == 401


def test_ask_requires_key(client, monkeypatch):
    monkeypatch.setenv("API_KEY", _KEY)
    body = {"question": "why?"}
    assert client.post("/api/incidents/INC-DOESNOTEXIST/ask", json=body).status_code == 401
    ok = client.post("/api/incidents/INC-DOESNOTEXIST/ask", json=body,
                     headers={"X-API-Key": _KEY})
    assert ok.status_code == 200   # authorized; body handled by the assistant


def test_read_endpoints_stay_open(client, monkeypatch):
    # Only the sensitive surface is gated — dashboards still read incidents/metrics.
    monkeypatch.setenv("API_KEY", _KEY)
    assert client.get("/api/metrics").status_code == 200


def test_open_when_no_key_configured(client, monkeypatch):
    monkeypatch.delenv("API_KEY", raising=False)
    assert client.post("/api/export").status_code == 200   # auth disabled


# ── WebSocket ───────────────────────────────────────────────────────────────

def test_ws_rejected_without_token(client, monkeypatch):
    monkeypatch.setenv("API_KEY", _KEY)
    with pytest.raises(Exception):        # handshake closed before accept
        with client.websocket_connect("/api/ws/incidents"):
            pass


def test_ws_allowed_with_token(client, monkeypatch):
    monkeypatch.setenv("API_KEY", _KEY)
    with client.websocket_connect(f"/api/ws/incidents?token={_KEY}"):
        pass   # connects (accepted) without raising


def test_ws_open_when_no_key(client, monkeypatch):
    monkeypatch.delenv("API_KEY", raising=False)
    with client.websocket_connect("/api/ws/incidents"):
        pass
