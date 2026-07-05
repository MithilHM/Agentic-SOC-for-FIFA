"""
pipeline/enrichment.py — Threat-Intel Enrichment layer.

Decorates an OCSFAlert with:
  - GeoIP country + IP reputation (curated offline list, else live geo + public
    blocklist reputation when ENABLE_LIVE_INTEL=1)
  - WHOIS domain age (real lookup when ENABLE_LIVE_INTEL=1, else keyword heuristic)
  - Visual/brand-impersonation similarity score (domain-similarity algorithm)
  - Primary IOC selection (Domain > URL > IP > User) for correlation key
  - MITRE ATT&CK tactic/technique mapping (ML event_type → MITRE, with source fallback)

External calls are guarded by ENABLE_LIVE_INTEL=1 so the demo runs fully offline.
"""
import difflib
import logging
import os

import httpx

from intel.mitre import map_to_attack
from intel.reputation import ip_reputation
from intel.whois_lookup import lookup_domain_age
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

# Legitimate FIFA brand domains — reference set for impersonation scoring
_LEGIT_BRAND_DOMAINS = ["fifa.com", "fifaplus.com", "fifa.org"]
_BRAND_TOKEN = "fifa"
_SUSPICIOUS_TLDS = (".xyz", ".top", ".ru", ".tk", ".click", ".info")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _geo_and_rep(ip: str) -> tuple[str, int]:
    """Return (country, reputation_score) for an IP address."""
    if ip in _KNOWN_BAD_IPS:
        return _KNOWN_BAD_IPS[ip]

    country = "Unknown"
    rep     = 10

    if os.getenv("ENABLE_LIVE_INTEL") == "1" and ip:
        try:
            g = httpx.get(f"https://ipapi.co/{ip}/json/", timeout=3).json()
            country = g.get("country_name", "Unknown")
        except Exception as e:
            logger.debug("Live IP lookup failed: %s", e)

        blocklist = ip_reputation(ip)
        if blocklist["reputation_score"] is not None:
            rep = blocklist["reputation_score"]

    return country, rep


def _domain_similarity_score(domain: str) -> int:
    """
    Score (0-100) how much a domain resembles/impersonates a known FIFA brand
    domain — real string-similarity + typosquat heuristics, not a fixed value.
    """
    domain_l = domain.lower()
    if domain_l in _LEGIT_BRAND_DOMAINS:
        return 0

    base = domain_l.split(".")[0]
    best_ratio = max(
        difflib.SequenceMatcher(None, base, legit.split(".")[0]).ratio()
        for legit in _LEGIT_BRAND_DOMAINS
    )

    score = best_ratio * 60
    if _BRAND_TOKEN in domain_l:
        score += 30   # contains the brand name but isn't the real domain
    if domain_l.endswith(_SUSPICIOUS_TLDS):
        score += 10

    return min(100, round(score))


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
        whois_info = lookup_domain_age(a.domain)
        a.whois_age_days = whois_info["age_days"]

    # ── Brand-impersonation / visual similarity ──────────────────────────
    if a.domain:
        sim = _domain_similarity_score(a.domain)
        if sim > 0:
            a.visual_similarity_score = a.visual_similarity_score or sim
            a.ssl_valid               = True   # phishing sites do get certs too

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
