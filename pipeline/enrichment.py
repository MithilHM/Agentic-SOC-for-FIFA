"""
pipeline/enrichment.py — Threat-Intel Enrichment layer.

Decorates an OCSFAlert with:
  - GeoIP country + reputation score (offline lookup, optional live via ipapi.co)
  - WHOIS domain age estimate (suspicious if < 30 days, keyword-based for demo)
  - Primary IOC selection (Domain > URL > IP > User) for correlation key
  - MITRE ATT&CK tactic/technique mapping (ML event_type → MITRE, with source fallback)

External calls are guarded by ENABLE_LIVE_INTEL=1 so the demo runs fully offline.
"""
import logging
import os

import httpx

from intel.mitre import map_to_attack
from schema.ocsf import OCSFAlert

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Offline intel tables
# ---------------------------------------------------------------------------

_KNOWN_BAD_IPS = {
    "185.174.21.14":  ("Russia",      95),
    "45.155.205.99":  ("Netherlands", 88),
    "193.169.255.10": ("Belarus",     82),
    "91.108.4.0":     ("Russia",      78),
    "198.54.117.200": ("United States", 65),
}

# Source-based MITRE fallback when ML classifies as "Other"
_SOURCE_MITRE_FALLBACK = {
    "WAF":       ("Initial Access",   "T1190"),
    "Auth":      ("Credential Access","T1110"),
    "Firewall":  ("Reconnaissance",   "T1595"),
    "DNS":       ("Execution",        "T1204"),
    "Email":     ("Initial Access",   "T1566"),
    "SIEM":      ("Initial Access",   "T1566"),
    "Cloud":     ("Exfiltration",     "T1052"),
    "IDS":       ("Reconnaissance",   "T1595"),
    "EDR":       ("Execution",        "T1204"),
    "Ticketing": ("Exfiltration",     "T1052"),
    "Streaming": ("Impact",           "T1498"),
}

# Suspicious domain keywords for WHOIS estimate
_SUSPICIOUS_KEYWORDS = [
    "secure2026", "ticket2026", "fifalogin", "wc2026",
    "fifa-login", "fifa-ticket", "fifapass",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _geo_and_rep(ip: str) -> tuple[str, int]:
    """Return (country, reputation_score) for an IP address."""
    if ip in _KNOWN_BAD_IPS:
        return _KNOWN_BAD_IPS[ip]
    if os.getenv("ENABLE_LIVE_INTEL") == "1" and ip:
        try:
            g = httpx.get(f"https://ipapi.co/{ip}/json/", timeout=3).json()
            return g.get("country_name", "Unknown"), 20
        except Exception as e:
            logger.debug("Live IP lookup failed: %s", e)
    return "Unknown", 10


def _estimate_whois_age(domain: str) -> int:
    """Estimate WHOIS age in days. Newly registered suspicious domains → 2 days."""
    if any(kw in domain.lower() for kw in _SUSPICIOUS_KEYWORDS):
        return 2
    return 400   # established domain assumption


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def enrich(a: OCSFAlert) -> OCSFAlert:
    """
    Enrich an OCSFAlert in-place with threat intelligence.
    Safe to call even when all optional fields are None.
    """
    # ── GeoIP + reputation ────────────────────────────────────────────────
    if a.source_ip:
        country, rep = _geo_and_rep(a.source_ip)
        a.country           = a.country or country
        a.threat_intel_score = max(a.threat_intel_score or 0, rep)

    # ── WHOIS age ─────────────────────────────────────────────────────────
    if a.domain and a.whois_age_days is None:
        a.whois_age_days = _estimate_whois_age(a.domain)

    # ── SSL / visual similarity (stub values for demo) ────────────────────
    if a.domain and any(kw in a.domain.lower() for kw in _SUSPICIOUS_KEYWORDS):
        a.visual_similarity_score = a.visual_similarity_score or 92
        a.ssl_valid               = True   # phishing sites do get certs

    # ── Primary IOC for correlation ───────────────────────────────────────
    if not a.ioc_value:
        if a.domain:
            a.ioc_type, a.ioc_value = "Domain", a.domain
        elif a.url:
            a.ioc_type, a.ioc_value = "URL",    a.url
        elif a.source_ip:
            a.ioc_type, a.ioc_value = "IP",     a.source_ip
        elif a.user:
            a.ioc_type, a.ioc_value = "User",   a.user

    # ── MITRE ATT&CK mapping ──────────────────────────────────────────────
    tactic, technique = map_to_attack(a.event_type)
    if tactic:
        a.mitre_tactic, a.mitre_technique = tactic, technique
    else:
        # ML classified as "Other" — use source-based fallback
        fallback = _SOURCE_MITRE_FALLBACK.get(a.event_source)
        if fallback:
            a.mitre_tactic, a.mitre_technique = fallback

    return a
