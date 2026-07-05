"""
intel/reputation.py — Free, no-signup IP reputation via public blocklists.

Sources (all free, no API key required):
  - Spamhaus DROP     https://www.spamhaus.org/drop/drop.txt        (hijacked/botnet netblocks)
  - Tor bulk exit list https://check.torproject.org/torbulkexitlist (active Tor exit nodes)
  - FireHOL level1    firehol_level1.netset                         (curated aggressive blocklist)

Guarded by ENABLE_LIVE_INTEL=1 (these are outbound network calls). Lists are
downloaded once, cached in-memory + on disk, and refreshed on a TTL so the
pipeline doesn't re-fetch multi-MB lists on every alert.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import threading
import time

import httpx

logger = logging.getLogger(__name__)

_DATA_DIR   = os.path.join(os.path.dirname(__file__), "data")
_CACHE_FILE = os.path.join(_DATA_DIR, "blocklist_cache.json")

_SOURCES = {
    "spamhaus_drop": ("https://www.spamhaus.org/drop/drop.txt", "cidr"),
    "tor_exit":       ("https://check.torproject.org/torbulkexitlist", "ip"),
    "firehol_level1": ("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "cidr"),
}

# Weight applied when an IP matches a given source (higher = more severe)
_SOURCE_WEIGHT = {
    "spamhaus_drop":  90,
    "firehol_level1": 80,
    "tor_exit":       55,
}

_REFRESH_SEC = int(os.getenv("BLOCKLIST_REFRESH_HOURS", "6")) * 3600

_lock  = threading.Lock()
_state = {"networks": [], "flat_ips": set(), "loaded_at": 0.0}


def _parse_cidr_list(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        line = line.split(";", 1)[0].split("#", 1)[0].strip()
        if not line:
            continue
        try:
            ipaddress.ip_network(line, strict=False)
            out.append(line)
        except ValueError:
            continue
    return out


def _parse_ip_list(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            ipaddress.ip_address(line)
            out.append(line)
        except ValueError:
            continue
    return out


def _download_all() -> dict:
    """Fetch all blocklists. Returns a serializable dict, or {} on total failure."""
    cidrs: dict[str, list[str]] = {}
    ips: dict[str, list[str]] = {}

    for name, (url, kind) in _SOURCES.items():
        try:
            resp = httpx.get(url, timeout=15, follow_redirects=True)
            resp.raise_for_status()
            if kind == "cidr":
                cidrs[name] = _parse_cidr_list(resp.text)
            else:
                ips[name] = _parse_ip_list(resp.text)
            logger.info("Fetched blocklist '%s': %d entries", name,
                        len(cidrs.get(name, ips.get(name, []))))
        except Exception as e:
            logger.warning("Failed to fetch blocklist '%s': %s", name, e)

    if not cidrs and not ips:
        # Explicit, visible failure path: every feed failed to download.
        logger.warning(
            "All %d IP-reputation feeds failed to download (%s). "
            "Falling back to on-disk cache / offline heuristics.",
            len(_SOURCES), ", ".join(_SOURCES),
        )
        return {}
    return {"cidrs": cidrs, "ips": ips, "fetched_at": time.time()}


def _load_disk_cache() -> dict | None:
    try:
        with open(_CACHE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _save_disk_cache(data: dict) -> None:
    try:
        os.makedirs(_DATA_DIR, exist_ok=True)
        with open(_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception as e:
        logger.warning("Could not persist blocklist cache (will re-download next refresh): %s", e)


def _build_indexes(data: dict) -> tuple[list, set]:
    networks = []
    for source, cidr_list in data.get("cidrs", {}).items():
        for cidr in cidr_list:
            try:
                networks.append((ipaddress.ip_network(cidr, strict=False), source))
            except ValueError:
                continue
    flat_ips = set()
    for source, ip_list in data.get("ips", {}).items():
        for ip in ip_list:
            flat_ips.add((ip, source))
    return networks, flat_ips


def _refresh_if_stale() -> None:
    with _lock:
        if time.time() - _state["loaded_at"] < _REFRESH_SEC:
            return

        data = _download_all() if os.getenv("ENABLE_LIVE_INTEL") == "1" else {}
        if data:
            _save_disk_cache(data)
        else:
            data = _load_disk_cache() or {}

        if data:
            networks, flat_ips = _build_indexes(data)
            _state["networks"]  = networks
            _state["flat_ips"]  = flat_ips
            _state["loaded_at"] = time.time()
        else:
            # Nothing available yet (offline demo mode) — avoid re-hammering every call.
            _state["loaded_at"] = time.time()


def warm_blocklists(force: bool = True) -> dict:
    """
    Eagerly load the reputation feeds at process startup and log a clear summary
    of what was (or wasn't) loaded, so a total feed outage is visible in logs
    rather than only surfacing as silently-degraded scoring later.

    Returns a small status dict for observability/health checks.
    """
    if os.getenv("ENABLE_LIVE_INTEL") != "1":
        logger.info("IP-reputation feeds disabled (ENABLE_LIVE_INTEL != 1) — using offline heuristics.")
        return {"enabled": False, "sources_loaded": 0, "sources": []}

    if force:
        with _lock:
            _state["loaded_at"] = 0.0   # force a re-fetch on the next refresh
    _refresh_if_stale()

    sources = ({s for _, s in _state["networks"]}
               | {s for _, s in _state["flat_ips"]})
    n = len(sources)
    if n == 0:
        logger.warning(
            "Startup: no IP-reputation feeds available (all downloads failed and "
            "no on-disk cache). IP reputation degraded to offline heuristics.")
    else:
        logger.info("Startup: loaded IP-reputation feeds from %d source(s): %s",
                    n, ", ".join(sorted(sources)))
    return {"enabled": True, "sources_loaded": n, "sources": sorted(sources)}


def ip_reputation(ip: str) -> dict:
    """
    Check an IP against free public blocklists.
    Returns {"is_listed": bool, "sources": [...], "reputation_score": int|None}.
    reputation_score is None when no blocklist data is loaded (offline/disabled).
    """
    if not ip:
        return {"is_listed": False, "sources": [], "reputation_score": None}

    _refresh_if_stale()

    if not _state["networks"] and not _state["flat_ips"]:
        return {"is_listed": False, "sources": [], "reputation_score": None}

    matched_sources = set()
    try:
        addr = ipaddress.ip_address(ip)
        for net, source in _state["networks"]:
            if addr in net:
                matched_sources.add(source)
    except ValueError:
        pass

    for entry_ip, source in _state["flat_ips"]:
        if entry_ip == ip:
            matched_sources.add(source)

    if not matched_sources:
        return {"is_listed": False, "sources": [], "reputation_score": 10}

    score = min(100, max(_SOURCE_WEIGHT.get(s, 50) for s in matched_sources))
    return {"is_listed": True, "sources": sorted(matched_sources), "reputation_score": score}
