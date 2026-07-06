"""Tests for distributed, atomic alert/incident ID generation (Subtasks 2.1 / 2.2).

IDs used to come from an in-process ``itertools.count`` / ``count(1)``, which
restarts at 1 in every process — two ingestor or worker containers would then
mint the *same* ID and clobber each other's Redis keys.  The fix delegates ID
generation to Redis ``INCR`` (atomic and process-global).  These tests assert:

  • the formatted output is sequential (``ALT-000001`` / ``INC-000001``), and
  • concurrent callers never collide — the property that actually matters for
    the multi-worker deployment the refactor targets.

Requires a reachable Redis (present on the compose network); skipped otherwise.
"""
import os
import threading

import pytest

redis_sync = pytest.importorskip("redis")

from ingestion.parsers.base import next_alert_id  # noqa: E402
from pipeline.correlation import _next_incident_id  # noqa: E402

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


@pytest.fixture()
def client():
    c = redis_sync.from_url(_REDIS_URL, decode_responses=True)
    yield c
    c.close()


def test_alert_id_is_sequential_and_formatted(client):
    client.delete("soc:sequence:alert")
    assert next_alert_id() == "ALT-000001"
    assert next_alert_id() == "ALT-000002"
    assert next_alert_id() == "ALT-000003"


def test_incident_id_is_sequential_and_formatted(client):
    client.delete("soc:sequence:incident")
    assert _next_incident_id() == "INC-000001"
    assert _next_incident_id() == "INC-000002"


def test_alert_ids_are_unique_under_concurrency(client):
    """8 threads × 50 IDs each — atomic INCR must yield 400 distinct IDs.

    This is the property the old itertools.count broke across processes; threads
    exercise the same race in-process (the module-level Redis client is shared).
    """
    client.delete("soc:sequence:alert")

    ids: list[str] = []
    lock = threading.Lock()

    def worker():
        local = [next_alert_id() for _ in range(50)]
        with lock:
            ids.extend(local)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(ids) == 400
    assert len(set(ids)) == 400, "duplicate alert IDs generated under concurrency"
    assert all(i.startswith("ALT-") for i in ids)


def test_incident_ids_are_unique_under_concurrency(client):
    client.delete("soc:sequence:incident")

    ids: list[str] = []
    lock = threading.Lock()

    def worker():
        local = [_next_incident_id() for _ in range(50)]
        with lock:
            ids.extend(local)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(set(ids)) == len(ids) == 300, "duplicate incident IDs under concurrency"
