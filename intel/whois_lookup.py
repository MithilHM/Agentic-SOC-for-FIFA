"""
intel/whois_lookup.py — Domain age lookup, shared by enrichment.py and llm_assistant.py.

Attempts a real WHOIS query (guarded by ENABLE_LIVE_INTEL=1, since it makes an
outbound network call). Falls back to a keyword heuristic when the live lookup
fails or is disabled — this keeps the demo deterministic offline and keeps
working for the simulator's fake domains, which don't have real WHOIS records.
"""
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_SUSPICIOUS_KEYWORDS = [
    "secure2026", "ticket2026", "fifalogin", "wc2026",
    "fifa-login", "fifa-ticket", "fifapass",
]

_WHOIS_TIMEOUT_SEC = 5


def _live_whois_age_days(domain: str) -> int | None:
    """Query real WHOIS for a domain's creation date. Returns age in days or None on failure.

    The python-whois library has no per-call socket timeout parameter; it uses
    the global socket default.  The OLD approach called socket.setdefaulttimeout()
    in the main thread, which is a process-wide mutation that races with concurrent
    Redis/HTTP calls running in other threads.

    Fix: run the blocking whois() call in an isolated thread and join() with a
    timeout.  The worker thread inherits the (unmodified) default timeout so
    global state is never mutated in the main thread.
    """
    try:
        import whois  # python-whois
    except ImportError:
        logger.debug("python-whois not installed — skipping live WHOIS lookup")
        return None

    import threading

    result_box: list[int | None] = [None]
    error_box:  list[Exception | None] = [None]

    def _query():
        try:
            record = whois.whois(domain)
            created = record.creation_date
            if isinstance(created, list):
                created = created[0] if created else None
            if not created:
                return
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - created).days
            result_box[0] = max(age_days, 0)
        except Exception as e:
            error_box[0] = e

    t = threading.Thread(target=_query, daemon=True, name="whois-lookup")
    t.start()
    t.join(timeout=_WHOIS_TIMEOUT_SEC)

    if t.is_alive():
        # Thread still blocked on the socket — treat as timeout.
        logger.debug("WHOIS lookup timed out for %s after %ss", domain, _WHOIS_TIMEOUT_SEC)
        return None
    if error_box[0] is not None:
        logger.debug("Live WHOIS lookup failed for %s: %s", domain, error_box[0])
        return None
    return result_box[0]


def lookup_domain_age(domain: str) -> dict:
    """
    Return {"age_days": int, "is_suspicious": bool, "source": str}.
    Tries a real WHOIS lookup first (if ENABLE_LIVE_INTEL=1), then falls back
    to a keyword-based heuristic used by the alert simulator's fake domains.
    """
    if not domain:
        return {"age_days": 400, "is_suspicious": False, "source": "default"}

    if os.getenv("ENABLE_LIVE_INTEL") == "1":
        age = _live_whois_age_days(domain)
        if age is not None:
            return {"age_days": age, "is_suspicious": age < 30, "source": "whois-live"}

    is_suspicious = any(kw in domain.lower() for kw in _SUSPICIOUS_KEYWORDS)
    return {
        "age_days": 2 if is_suspicious else 400,
        "is_suspicious": is_suspicious,
        "source": "heuristic",
    }
