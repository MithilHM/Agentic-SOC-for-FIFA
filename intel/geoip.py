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
import json
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

# L1 in-process cache (avoids Redis roundtrip for hot IPs within one process)
_cache: dict[str, tuple[float, dict]] = {}

# L2 Redis cache (shared across all worker processes)
_REDIS_CACHE_PREFIX = "soc:cache:geoip:"
_r_geo = None   # lazily initialised


def _geo_redis():
    """Return a shared Redis client for the GeoIP cache (lazy init)."""
    global _r_geo
    if _r_geo is None:
        import redis
        try:
            _r_geo = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"),
                                    socket_connect_timeout=1)
        except Exception:
            pass   # silently degrade to L1-only
    return _r_geo



class _RateLimited(Exception):
    """Raised by a provider when it signals rate limiting (HTTP 429 / body flag)."""


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def _cache_get(ip: str) -> dict | None:
    """L1 (in-process) cache read."""
    hit = _cache.get(ip)
    if not hit:
        return None
    expires_at, value = hit
    if time.time() > expires_at:
        _cache.pop(ip, None)
        return None
    return value


def _cache_put(ip: str, value: dict, ttl: int) -> None:
    """Write to both L1 (in-process dict) and L2 (Redis) caches."""
    if len(_cache) >= _CACHE_MAX:
        _cache.clear()   # crude but bounded; demo-scale IP cardinality
    _cache[ip] = (time.time() + ttl, value)
    # L2: persist to Redis so other worker instances benefit
    r = _geo_redis()
    if r is not None:
        try:
            r.setex(f"{_REDIS_CACHE_PREFIX}{ip}", ttl, json.dumps(value))
        except Exception:
            pass   # degrade gracefully if Redis is unavailable


def _redis_cache_get(ip: str) -> dict | None:
    """L2 (Redis) cache read — called when L1 misses."""
    r = _geo_redis()
    if r is None:
        return None
    try:
        raw = r.get(f"{_REDIS_CACHE_PREFIX}{ip}")
        return json.loads(raw) if raw else None
    except Exception:
        return None


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

    Cache hierarchy:
      L1 — in-process dict (zero latency for hot IPs within one worker)
      L2 — Redis (shared across all worker containers, avoids redundant lookups)
    """
    if not ip:
        return dict(_UNKNOWN)

    # L1 lookup
    cached = _cache_get(ip)
    if cached is not None:
        return cached

    # L2 lookup (Redis shared cache)
    cached = _redis_cache_get(ip)
    if cached is not None:
        # Backfill L1 so the next call from this process is free
        _cache[ip] = (time.time() + _POS_TTL, cached)
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
