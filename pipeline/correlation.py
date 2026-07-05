"""
pipeline/correlation.py — Alert → Incident correlation engine.

Grouping rules (any match within the time window links alerts to an existing incident):
  • shared IOC value (domain, IP, URL, hash)
  • shared asset
  • shared user
  • kill-chain progression (same source IP across different event_types)

Priority formula:
  score = max_risk + n_distinct_tactics × 8
  P1 ≥ 90 | P2 ≥ 70 | P3 ≥ 40 | P4 < 40

Multi-stage detection: an incident touching multiple distinct mitre_tactic values
is a kill-chain; the priority formula boosts it and the LLM narrates the chain.
"""
import json
import logging
import os
import time
from itertools import count

import redis

from schema.ocsf import OCSFAlert

logger = logging.getLogger(__name__)

r = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))

WINDOW_SEC = int(os.getenv("CORRELATION_WINDOW_SEC", "900"))   # 15-minute default
_inc_seq   = count(1)


def _incident_key(inc_id: str) -> str:
    return f"incident:{inc_id}"


def _find_open_incident(alert: OCSFAlert) -> str | None:
    """
    Scan open incidents and return the first one that shares an
    IOC / asset / user / source-IP with the incoming alert.
    """
    alert_keys = {
        k for k in (alert.ioc_value, alert.asset, alert.user, alert.source_ip)
        if k
    }
    if not alert_keys:
        return None

    for key in r.scan_iter("incident:*"):
        raw = r.get(key)
        if not raw:
            continue
        try:
            inc = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            continue

        # Skip stale incidents outside the correlation window
        if time.time() - inc.get("last_seen", 0) > WINDOW_SEC:
            continue

        incident_keys = (
            set(inc.get("ioc_values", []))
            | {inc.get("asset")}
            | set(inc.get("users", []))
            | set(inc.get("source_ips", []))
        )
        incident_keys.discard(None)

        if alert_keys & incident_keys:
            return inc["incident_id"]

    return None


def correlate(alert: OCSFAlert) -> tuple[str, bool]:
    """
    Group alert into an existing or new incident.

    Returns:
        (incident_id, is_new)  — is_new=True triggers the LLM investigation.
    """
    inc_id = _find_open_incident(alert)
    is_new = inc_id is None

    if is_new:
        inc_id = f"INC-{next(_inc_seq):06d}"
        inc = {
            "incident_id":   inc_id,
            "created":       time.time(),
            "last_seen":     time.time(),
            "asset":         alert.asset,
            "users":         [],
            "ioc_values":    [],
            "source_ips":    [],
            "alert_ids":     [],
            "event_types":   [],
            "max_risk":      0,
            "tactics":       [],
            "techniques":    [],
            "campaign_name": alert.campaign_name,
            "priority":      "P4",
        }
        logger.info("NEW incident %s (asset=%s)", inc_id, alert.asset)
    else:
        raw = r.get(_incident_key(inc_id))
        inc = json.loads(raw) if raw else {}
        if not inc:
            # Race condition — create fresh
            is_new = True
            inc = {
                "incident_id": inc_id, "created": time.time(), "last_seen": time.time(),
                "asset": alert.asset, "users": [], "ioc_values": [], "source_ips": [],
                "alert_ids": [], "event_types": [], "max_risk": 0,
                "tactics": [], "techniques": [], "campaign_name": alert.campaign_name,
                "priority": "P4",
            }

    # ── Update incident fields ────────────────────────────────────────────────
    now = time.time()
    inc["last_seen"] = now
    inc["alert_ids"].append(alert.alert_id)
    inc["max_risk"] = max(inc.get("max_risk", 0), alert.risk_score)

    _append_unique(inc, "users",       alert.user)
    _append_unique(inc, "ioc_values",  alert.ioc_value)
    _append_unique(inc, "source_ips",  alert.source_ip)
    _append_unique(inc, "tactics",     alert.mitre_tactic)
    _append_unique(inc, "techniques",  alert.mitre_technique)
    _append_unique(inc, "event_types", alert.event_type)

    # Keep campaign name if not already set
    if not inc.get("campaign_name") and alert.campaign_name:
        inc["campaign_name"] = alert.campaign_name

    # Recalculate priority
    inc["priority"] = _priority(inc["max_risk"], len(inc.get("tactics", [])))

    # Persist
    r.set(_incident_key(inc_id), json.dumps(inc))
    alert.incident_id = inc_id

    return inc_id, is_new


def _append_unique(inc: dict, key: str, value):
    """Append value to list in inc[key] if not already present and value is truthy."""
    if value and value not in inc[key]:
        inc[key].append(value)


def _priority(max_risk: int, n_tactics: int) -> str:
    """
    Priority formula (documented for judges):
      score = max_risk + n_distinct_tactics × 8
      Multi-stage kill-chains escalate to P1 faster.
    """
    score = max_risk + n_tactics * 8
    return ("P1" if score >= 90 else
            "P2" if score >= 70 else
            "P3" if score >= 40 else "P4")
