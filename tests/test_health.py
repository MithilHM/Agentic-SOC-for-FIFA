"""/api/health worker-liveness tests (item #6).

Health must report real worker liveness from the heartbeat, not just that the
API process is up: fresh heartbeat -> ok/200; stale or missing -> degraded/503.

Uses a test-specific heartbeat key so it doesn't race the live worker (which
continuously rewrites the real key). Requires a reachable Redis; skipped otherwise.
"""
import json
import os
import time

import pytest

redis_sync = pytest.importorskip("redis")
pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

_REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
_TEST_HB_KEY = "test:soc:worker:heartbeat"


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


@pytest.fixture
def rc():
    c = redis_sync.from_url(_REDIS_URL)
    yield c
    c.delete(_TEST_HB_KEY)
    c.close()


@pytest.fixture
def client(monkeypatch):
    import redis.asyncio as aioredis
    from api import server
    # Fresh async client (TestClient event-loop isolation) + isolated hb key.
    monkeypatch.setattr(server, "R", aioredis.from_url(_REDIS_URL))
    monkeypatch.setattr(server, "_HEARTBEAT_KEY", _TEST_HB_KEY)
    return TestClient(server.app)


def _write_hb(rc, *, beat_age=0.0, processed_age=1.0, count=42):
    now = time.time()
    rc.set(_TEST_HB_KEY, json.dumps({
        "worker_id": "worker-test",
        "beat_ts": now - beat_age,
        "processed_ts": now - processed_age,
        "processed_count": count,
        "last_alert_id": "ALT-000042",
        "last_incident_id": "INC-000007",
    }))


def test_health_ok_with_fresh_heartbeat(client, rc):
    _write_hb(rc, beat_age=1.0)
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["worker"]["alive"] is True
    assert body["worker"]["processed_count"] == 42
    assert body["worker"]["last_processed_alert"] == "ALT-000042"
    assert body["redis"]["reachable"] is True


def test_health_degraded_with_stale_heartbeat(client, rc):
    _write_hb(rc, beat_age=999.0)      # far beyond WORKER_STALE_SEC
    r = client.get("/api/health")
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "degraded"
    assert body["worker"]["alive"] is False


def test_health_degraded_when_no_heartbeat(client, rc):
    rc.delete(_TEST_HB_KEY)
    r = client.get("/api/health")
    assert r.status_code == 503
    body = r.json()
    assert body["worker"]["heartbeat_seen"] is False
    assert body["worker"]["alive"] is False
