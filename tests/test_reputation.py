"""IP-reputation caching / TTL tests.

The reputation module downloads multi-MB public blocklists at most once per
refresh window and answers lookups from an in-memory index. These tests pin
that behaviour without any network access by stubbing the download.
"""
import logging

import pytest

from intel import reputation


@pytest.fixture(autouse=True)
def _reset_reputation_state(monkeypatch):
    """Isolate the module-global cache/state between tests."""
    monkeypatch.setattr(reputation, "_state",
                        {"networks": [], "flat_ips": set(), "loaded_at": 0.0})
    # Never touch the network or disk in tests.
    monkeypatch.setattr(reputation, "_save_disk_cache", lambda data: None)
    monkeypatch.setattr(reputation, "_load_disk_cache", lambda: None)
    monkeypatch.setenv("ENABLE_LIVE_INTEL", "1")
    yield


def _stub_download(monkeypatch, payload):
    calls = {"n": 0}

    def fake_download():
        calls["n"] += 1
        return payload

    monkeypatch.setattr(reputation, "_download_all", fake_download)
    return calls


_PAYLOAD = {
    "cidrs": {"spamhaus_drop": ["185.174.0.0/16"], "firehol_level1": ["45.155.205.0/24"]},
    "ips":   {"tor_exit": ["1.1.1.1"]},
    "fetched_at": 1000.0,
}


def test_lookup_matches_cidr_source_and_weight(monkeypatch):
    _stub_download(monkeypatch, _PAYLOAD)
    r = reputation.ip_reputation("185.174.21.14")
    assert r["is_listed"] is True
    assert r["sources"] == ["spamhaus_drop"]
    assert r["reputation_score"] == 90       # _SOURCE_WEIGHT["spamhaus_drop"]


def test_lookup_matches_flat_ip_source(monkeypatch):
    _stub_download(monkeypatch, _PAYLOAD)
    r = reputation.ip_reputation("1.1.1.1")
    assert r["is_listed"] is True
    assert r["sources"] == ["tor_exit"]
    assert r["reputation_score"] == 55


def test_clean_ip_when_data_loaded_scores_low_not_none(monkeypatch):
    _stub_download(monkeypatch, _PAYLOAD)
    r = reputation.ip_reputation("8.8.8.8")
    assert r["is_listed"] is False
    assert r["reputation_score"] == 10       # loaded, but not listed


def test_empty_ip_returns_none_score():
    r = reputation.ip_reputation("")
    assert r["reputation_score"] is None


def test_offline_no_data_returns_none_score(monkeypatch):
    # Live intel disabled and no disk cache -> nothing loaded.
    monkeypatch.setenv("ENABLE_LIVE_INTEL", "0")
    monkeypatch.setattr(reputation, "_download_all", lambda: {})
    r = reputation.ip_reputation("8.8.8.8")
    assert r["reputation_score"] is None


def test_download_cached_within_ttl(monkeypatch):
    calls = _stub_download(monkeypatch, _PAYLOAD)
    monkeypatch.setenv("ENABLE_LIVE_INTEL", "1")
    # Three lookups in quick succession must hit the network only once.
    reputation.ip_reputation("1.1.1.1")
    reputation.ip_reputation("8.8.8.8")
    reputation.ip_reputation("185.174.21.14")
    assert calls["n"] == 1


def test_download_refreshes_after_ttl_expiry(monkeypatch):
    calls = _stub_download(monkeypatch, _PAYLOAD)
    monkeypatch.setenv("ENABLE_LIVE_INTEL", "1")
    reputation.ip_reputation("1.1.1.1")
    assert calls["n"] == 1
    # Force the cache to look stale (older than the refresh window).
    reputation._state["loaded_at"] = reputation._state["loaded_at"] - reputation._REFRESH_SEC - 10
    reputation.ip_reputation("1.1.1.1")
    assert calls["n"] == 2


# ── startup warm-up / explicit failure path (#2) ────────────────────────────

def test_warm_blocklists_disabled(monkeypatch):
    monkeypatch.setenv("ENABLE_LIVE_INTEL", "0")
    assert reputation.warm_blocklists() == {"enabled": False, "sources_loaded": 0, "sources": []}


def test_warm_blocklists_loads_sources(monkeypatch):
    monkeypatch.setenv("ENABLE_LIVE_INTEL", "1")
    _stub_download(monkeypatch, _PAYLOAD)
    status = reputation.warm_blocklists()
    assert status["enabled"] is True
    assert status["sources_loaded"] == 3
    assert set(status["sources"]) == {"spamhaus_drop", "firehol_level1", "tor_exit"}


def test_warm_blocklists_total_failure_warns(monkeypatch, caplog):
    monkeypatch.setenv("ENABLE_LIVE_INTEL", "1")
    monkeypatch.setattr(reputation, "_download_all", lambda: {})   # every feed failed
    # autouse fixture already makes _load_disk_cache() return None
    with caplog.at_level(logging.WARNING):
        status = reputation.warm_blocklists()
    assert status["sources_loaded"] == 0
    assert any("no IP-reputation feeds available" in r.message for r in caplog.records)
