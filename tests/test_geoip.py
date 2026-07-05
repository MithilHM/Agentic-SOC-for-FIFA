"""Geolocation retry/backoff + fallback-provider tests (intel/geoip.py)."""
import pytest

from intel import geoip


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    geoip._cache.clear()
    # Never actually sleep during backoff.
    sleeps = []
    monkeypatch.setattr(geoip.time, "sleep", lambda s: sleeps.append(s))
    geoip._sleeps = sleeps
    yield
    geoip._cache.clear()


def _providers(monkeypatch, primary, fallback):
    monkeypatch.setattr(geoip, "_PROVIDERS", [("ipapi.co", primary), ("ipwho.is", fallback)])


def test_empty_ip_returns_unknown_without_calls():
    assert geoip.geolocate("")["source"] == "unavailable"


def test_retries_on_rate_limit_then_succeeds(monkeypatch):
    calls = {"n": 0}

    def flaky(ip):
        calls["n"] += 1
        if calls["n"] <= 2:                     # 429 on first two attempts
            raise geoip._RateLimited("429")
        return {"country": "Russia", "org": "AS-X", "source": "ipapi.co"}

    _providers(monkeypatch, flaky, lambda ip: {"country": "X", "org": None, "source": "ipwho.is"})
    res = geoip.geolocate("185.174.21.14")
    assert res["country"] == "Russia"
    assert res["source"] == "ipapi.co"
    assert calls["n"] == 3                       # retried twice, succeeded on 3rd
    assert len(geoip._sleeps) == 2               # backed off between attempts


def test_falls_back_to_secondary_when_primary_exhausted(monkeypatch):
    def always_429(ip):
        raise geoip._RateLimited("429")

    def fallback(ip):
        return {"country": "Netherlands", "org": "AS-SERVERS", "source": "ipwho.is"}

    _providers(monkeypatch, always_429, fallback)
    res = geoip.geolocate("45.155.205.99")
    assert res["source"] == "ipwho.is"
    assert res["country"] == "Netherlands"


def test_all_providers_fail_returns_unknown(monkeypatch):
    def boom(ip):
        raise RuntimeError("network down")

    _providers(monkeypatch, boom, boom)
    res = geoip.geolocate("1.2.3.4")
    assert res == {"country": "Unknown", "org": None, "source": "unavailable"}


def test_result_is_cached(monkeypatch):
    calls = {"n": 0}

    def once(ip):
        calls["n"] += 1
        return {"country": "Belarus", "org": None, "source": "ipapi.co"}

    _providers(monkeypatch, once, once)
    geoip.geolocate("193.169.255.10")
    geoip.geolocate("193.169.255.10")            # served from cache
    assert calls["n"] == 1


# ── provider-level 429 detection ────────────────────────────────────────────

class _FakeResp:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


def test_ipapi_co_detects_http_429(monkeypatch):
    monkeypatch.setattr(geoip.httpx, "get", lambda *a, **k: _FakeResp(status=429))
    with pytest.raises(geoip._RateLimited):
        geoip._ipapi_co("1.2.3.4")


def test_ipapi_co_detects_body_rate_limit(monkeypatch):
    monkeypatch.setattr(geoip.httpx, "get",
                        lambda *a, **k: _FakeResp(payload={"error": True, "reason": "RateLimited"}))
    with pytest.raises(geoip._RateLimited):
        geoip._ipapi_co("1.2.3.4")


def test_ipapi_co_parses_success(monkeypatch):
    monkeypatch.setattr(geoip.httpx, "get",
                        lambda *a, **k: _FakeResp(payload={"country_name": "France", "org": "AS-FR"}))
    res = geoip._ipapi_co("1.2.3.4")
    assert res == {"country": "France", "org": "AS-FR", "source": "ipapi.co"}
