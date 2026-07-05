"""
intel/geoip.py — IP geolocation with retry/backoff and a fallback provider.

Primary source is ipapi.co (rich data, but the free tier aggressively rate
limits with HTTP 429). Instead of immediately falling back to "Unknown" on the
first 429 — which is what the pipeline used to do, losing geo on the very first
burst of traffic — we retry with exponential backoff. If ipapi.co is still
unavailable, we fall back to a second free, no-key, HTTPS provider (ipwho.is).

Results are cached in-memory per IP (long TTL for hits, short TTL for misses so
a transient outage self-heals) so repeat IPs never re-hit the network. Callers
must still gate live lookups behind ENABLE_LIVE_INTEL=1.
"""
from __future__ import annotations

import logging
import os
import time

import httpx

logger = logging.getLogger(__name__)

_MAX_RETRIES = int(os.getenv("GEO_MAX_RETRIES", "2"))       # per provider
_BASE_DELAY  = float(os.getenv("GEO_BACKOFF_BASE_SEC", "0.5"))
_TIMEOUT     = float(os.getenv("GEO_TIMEOUT_SEC", "3"))

_POS_TTL  = 24 * 3600   # cache successful lookups for a day
_NEG_TTL  = 300         # re-attempt failed lookups after 5 minutes
_CACHE_MAX = 4096

_UNKNOWN = {"country": "Unknown", "org": None, "source": "unavailable"}

_cache: dict[str, tuple[float, dict]] = {}


class _RateLimited(Exception):
    """Raised by a provider when it signals rate limiting (HTTP 429 / body flag)."""


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def _cache_get(ip: str) -> dict | None:
    hit = _cache.get(ip)
    if not hit:
        return None
    expires_at, value = hit
    if time.time() > expires_at:
        _cache.pop(ip, None)
        return None
    return value


def _cache_put(ip: str, value: dict, ttl: int) -> None:
    if len(_cache) >= _CACHE_MAX:
        _cache.clear()   # crude but bounded; demo-scale IP cardinality
    _cache[ip] = (time.time() + ttl, value)


def _backoff(attempt: int) -> None:
    time.sleep(_BASE_DELAY * (2 ** attempt))


# ---------------------------------------------------------------------------
# Providers — each returns a normalized dict or raises (_RateLimited / Exception)
# ---------------------------------------------------------------------------

def _ipapi_co(ip: str) -> dict:
    resp = httpx.get(f"https://ipapi.co/{ip}/json/", timeout=_TIMEOUT)
    if resp.status_code == 429:
        raise _RateLimited("ipapi.co HTTP 429")
    resp.raise_for_status()
    data = resp.json()
    # ipapi.co also signals rate limiting inside a 200 body.
    if data.get("error"):
        reason = str(data.get("reason", "")).lower()
        if "rate" in reason or "limit" in reason:
            raise _RateLimited(f"ipapi.co body error: {data.get('reason')}")
        raise RuntimeError(f"ipapi.co error: {data.get('reason')}")
    return {"country": data.get("country_name") or "Unknown",
            "org": data.get("org"), "source": "ipapi.co"}


def _ipwho_is(ip: str) -> dict:
    resp = httpx.get(f"https://ipwho.is/{ip}", timeout=_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    if data.get("success") is False:
        msg = str(data.get("message", "")).lower()
        if "rate" in msg or "limit" in msg:
            raise _RateLimited(f"ipwho.is: {data.get('message')}")
        raise RuntimeError(f"ipwho.is error: {data.get('message')}")
    conn = data.get("connection") or {}
    return {"country": data.get("country") or "Unknown",
            "org": conn.get("org") or conn.get("isp"), "source": "ipwho.is"}


_PROVIDERS = [("ipapi.co", _ipapi_co), ("ipwho.is", _ipwho_is)]


def _try_provider(name: str, fn, ip: str, retries: int) -> dict | None:
    """Call one provider, retrying with backoff on rate-limit / transient error."""
    for attempt in range(retries + 1):
        try:
            return fn(ip)
        except _RateLimited as e:
            if attempt < retries:
                logger.info("%s rate-limited for %s (attempt %d/%d) — backing off",
                            name, ip, attempt + 1, retries + 1)
                _backoff(attempt)
                continue
            logger.warning("%s still rate-limited for %s after %d attempts",
                           name, ip, retries + 1)
            return None
        except Exception as e:
            if attempt < retries:
                _backoff(attempt)
                continue
            logger.debug("%s geolocation failed for %s: %s", name, ip, e)
            return None
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def geolocate(ip: str) -> dict:
    """
    Resolve an IP to {"country", "org", "source"}. Tries providers in order,
    each with retry/backoff, and caches the result. Returns an "unavailable"
    Unknown result (never raises) if every provider fails.
    """
    if not ip:
        return dict(_UNKNOWN)

    cached = _cache_get(ip)
    if cached is not None:
        return cached

    for i, (name, fn) in enumerate(_PROVIDERS):
        result = _try_provider(name, fn, ip, _MAX_RETRIES)
        if result is not None:
            _cache_put(ip, result, _POS_TTL)
            return result
        # Only log the "trying fallback" line if there IS a next provider.
        if i + 1 < len(_PROVIDERS):
            logger.warning("Primary geolocation (%s) unavailable for %s — trying fallback %s",
                           name, ip, _PROVIDERS[i + 1][0])

    logger.warning("All geolocation providers failed for %s — country=Unknown", ip)
    _cache_put(ip, dict(_UNKNOWN), _NEG_TTL)
    return dict(_UNKNOWN)
