"""Tests for the O(1) reverse-index correlation engine (Component 3) and the
pre-aggregated metrics hash (Subtask 1.3).

The old ``_find_open_incident`` scanned every ``incident:*`` key (O(N) per
alert).  The refactor maintains four reverse indexes (ioc / asset / user / ip)
mapping each value to its active incident_id, so lookups are O(1) MGETs with a
TTL equal to the correlation window.  These tests verify:

  • alerts sharing any one dimension land in the SAME incident,
  • fully-disjoint alerts land in DIFFERENT incidents,
  • index keys carry a TTL bounded by CORRELATION_WINDOW_SEC,
  • the open_incidents sorted set and soc:metrics hash are maintained, and
  • the ``p1`` counter increments exactly once per incident that crosses into
    P1 — the bug the accompanying fix addressed (it used to be reset to 0 and
    never re-populated).

Requires a reachable Redis; skipped otherwise.
"""
import os

import pytest

redis_sync = pytest.importorskip("redis")
pytest.importorskip("pydantic")

from schema.ocsf import OCSFAlert  # noqa: E402
from pipeline.correlation import correlate, WINDOW_SEC  # noqa: E402

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


def _flush(client):
    """Remove only the keys this engine touches — leaves any unrelated data."""
    for pattern in ("incident:*", "alert:*", "soc:idx:*", "soc:sequence:*"):
        keys = list(client.scan_iter(pattern))
        if keys:
            client.delete(*keys)
    client.delete("soc:open_incidents", "soc:metrics")


@pytest.fixture()
def client():
    c = redis_sync.from_url(_REDIS_URL, decode_responses=True)
    _flush(c)
    yield c
    _flush(c)
    c.close()


def _mk(alert_id, **kw) -> OCSFAlert:
    fields = dict(alert_id=alert_id, event_source="IDS")
    fields.update(kw)
    return OCSFAlert(**fields)


def test_shared_ioc_groups_into_same_incident(client):
    a1 = _mk("A1", ioc_value="evil.example", asset="Portal", risk_score=50)
    # Different asset/user, only the IOC is shared -> must still correlate.
    a2 = _mk("A2", ioc_value="evil.example", asset="OtherAsset", user="bob", risk_score=50)

    inc1, new1 = correlate(a1)
    inc2, new2 = correlate(a2)

    assert new1 is True
    assert new2 is False
    assert inc1 == inc2


def test_shared_source_ip_groups_across_event_types(client):
    # Kill-chain progression: same source IP, different event types / assets.
    c1 = _mk("C1", source_ip="203.0.113.5", event_type="Recon", asset="AssetX")
    c2 = _mk("C2", source_ip="203.0.113.5", event_type="Malware", asset="AssetY", user="z")

    inc1, _ = correlate(c1)
    inc2, new2 = correlate(c2)

    assert new2 is False
    assert inc1 == inc2


def test_disjoint_alerts_create_separate_incidents(client):
    b1 = _mk("B1", ioc_value="one.example", asset="AssetOne", user="u1", source_ip="10.0.0.1")
    b2 = _mk("B2", ioc_value="two.example", asset="AssetTwo", user="u2", source_ip="10.0.0.2")

    inc1, _ = correlate(b1)
    inc2, new2 = correlate(b2)

    assert new2 is True
    assert inc1 != inc2


def test_index_ttl_is_bounded_by_window(client):
    correlate(_mk("D1", ioc_value="ttl.example"))
    ttl = client.ttl("soc:idx:ioc:ttl.example")
    assert 0 < ttl <= WINDOW_SEC


def test_open_set_and_metrics_hash_maintained(client):
    correlate(_mk("E1", ioc_value="m1.example", severity="High", event_type="Malware"))

    assert client.zcard("soc:open_incidents") == 1
    assert int(client.hget("soc:metrics", "open_incidents")) == 1
    assert int(client.hget("soc:metrics", "sev:High")) == 1
    assert int(client.hget("soc:metrics", "type:Malware")) == 1


def test_p1_counter_increments_once_per_incident(client):
    # New incident, immediately P1 (score = risk 95 >= 90).
    correlate(_mk("P1a", ioc_value="p1.example", risk_score=95))
    assert int(client.hget("soc:metrics", "p1")) == 1

    # Another alert into the SAME incident, still P1 -> must NOT double-count.
    correlate(_mk("P1b", ioc_value="p1.example", risk_score=99, user="x"))
    assert int(client.hget("soc:metrics", "p1")) == 1

    # A distinct new P1 incident -> counter advances to 2.
    correlate(_mk("P1c", ioc_value="p1c.example", risk_score=95))
    assert int(client.hget("soc:metrics", "p1")) == 2


def test_p1_counter_counts_escalation_into_p1(client):
    # Start below P1 (risk 30 -> score 30 -> P4).
    correlate(_mk("Ea", ioc_value="esc.example", risk_score=30))
    p1_before = int(client.hget("soc:metrics", "p1") or 0)

    # Same incident escalates into P1 as risk climbs -> counter goes up by one.
    correlate(_mk("Eb", ioc_value="esc.example", risk_score=95, user="y"))
    assert int(client.hget("soc:metrics", "p1")) == p1_before + 1
