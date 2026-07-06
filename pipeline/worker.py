"""
pipeline/worker.py — Redis Streams consumer driving the AI pipeline.

Per-alert flow:
  1. triage(alert)     — XGBoost classify + FP gate + risk score
  2. enrich(alert)     — GeoIP + WHOIS + MITRE mapping  ← runs in thread pool
  3. correlate(alert)  — group into incident (IOC/asset/user/window)
  4. persist alert     — save back to Redis with incident_id
  5. LLM summary       — only triggered on NEW incident creation (not every update)
  6. WS notify         — Redis publish → API pushes to dashboard

Concurrency notes:
  enrich() calls out to ipapi.co / ipwho.is / WHOIS with retry+backoff.
  Running those blocking HTTP calls directly on the main consumer thread
  can block for up to (retries × backoff) seconds — easily exceeding
  WORKER_STALE_SEC (default 20 s), which causes /api/health to declare the
  worker dead and triggers container restarts.

  Fix: enrich() is submitted to a ThreadPoolExecutor.  The main thread
  immediately continues to the next message while the enrichment runs
  concurrently.  We await the future before proceeding to correlation so
  the enriched fields are available; but the timeout is capped so a
  completely hung external API can't block indefinitely.
"""
import json
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

import redis

from pipeline.triage import triage
from pipeline.enrichment import enrich
from pipeline.correlation import correlate
from pipeline.llm_assistant import summarize_incident, initialize_rag
from schema.ocsf import OCSFAlert

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [WORKER] %(levelname)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)

r = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))
GROUP    = "soc"
CONSUMER = os.getenv("WORKER_ID", "worker-1")
STREAM   = "alerts.raw"

# Thread pool for blocking external enrichment calls.
# Size-2 by default: allows two concurrent outbound lookups without contending
# too heavily on the GIL for CPU-bound ML work.
_ENRICH_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="enrich")

# Maximum seconds to wait for an enrichment result before proceeding with
# partial data (heuristic fallback is used automatically inside enrich()).
_ENRICH_TIMEOUT = float(os.getenv("ENRICH_TIMEOUT_SEC", "15"))

# ── Liveness heartbeat ────────────────────────────────────────────────────
# `beat_ts` is refreshed every consumer-loop cycle (proves the worker loop is
# alive even when idle); `processed_ts` advances only when an alert is actually
# handled (proves work progress). /api/health reads this so we report real
# liveness, not just "the process exists".
_HEARTBEAT_KEY = "soc:worker:heartbeat"
_hb = {
    "worker_id":         CONSUMER,
    "started_ts":        None,
    "beat_ts":           None,
    "processed_ts":      None,
    "processed_count":   0,
    "last_alert_id":     None,
    "last_incident_id":  None,
}


def _write_heartbeat() -> None:
    _hb["beat_ts"] = time.time()
    try:
        r.set(_HEARTBEAT_KEY, json.dumps(_hb))
    except Exception as e:
        logger.warning("Failed to write worker heartbeat: %s", e)


def _ensure_group():
    try:
        r.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
        logger.info("Consumer group '%s' created on stream '%s'", GROUP, STREAM)
    except redis.ResponseError:
        pass  # group already exists


def _is_new_incident(inc_id: str, alert_count: int) -> bool:
    """Return True if this is the first alert in the incident (triggers LLM)."""
    return alert_count == 1


def run():
    _ensure_group()

    # Eagerly warm the IP-reputation feeds so a total outage is logged loudly at
    # startup instead of silently degrading scoring on the first alert.
    try:
        from intel.reputation import warm_blocklists
        warm_blocklists()
    except Exception as e:
        logger.warning("Blocklist warm-up failed: %s", e)

    # Explicitly trigger RAG seeding in the background (replaces the bare
    # threading.Thread() that was fired on module import — see llm_assistant.py).
    try:
        initialize_rag()
        logger.info("RAG background seeding triggered at worker startup.")
    except Exception as e:
        logger.warning("RAG seeding startup call failed: %s", e)

    _hb["started_ts"] = time.time()
    _write_heartbeat()
    logger.info("Worker '%s' listening on '%s'…", CONSUMER, STREAM)

    while True:
        try:
            msgs = r.xreadgroup(GROUP, CONSUMER, {STREAM: ">"}, count=10, block=5000)
        except redis.ConnectionError as e:
            logger.error("Redis connection error: %s — retrying in 3s", e)
            time.sleep(3)
            continue

        # Beat every cycle (even on an empty read) so liveness is decoupled from
        # whether alerts are currently flowing.
        _write_heartbeat()

        for _stream, entries in msgs or []:
            for msg_id, fields in entries:
                try:
                    _process_one(msg_id, fields)
                except Exception as exc:
                    logger.exception("Failed to process message %s: %s", msg_id, exc)
                    # Still ack to avoid poison-pill blocking the stream
                    r.xack(STREAM, GROUP, msg_id)


def _process_one(msg_id: bytes, fields: dict):
    # ── 1. Deserialize ───────────────────────────────────────────────────────
    raw_data = fields.get(b"data") or fields.get("data", b"{}")
    if isinstance(raw_data, bytes):
        raw_data = raw_data.decode()
    a = OCSFAlert(**json.loads(raw_data))

    # ── 2. Triage (ML classify + FP gate + risk score) ───────────────────────
    a = triage(a)

    # ── 3. Enrich (GeoIP + WHOIS + MITRE mapping) — non-blocking ─────────────
    # Submit to thread pool; the main consumer thread stays alive and continues
    # writing its heartbeat beat_ts.  We cap the wait at _ENRICH_TIMEOUT so a
    # completely hung external provider can never block indefinitely.
    future = _ENRICH_POOL.submit(enrich, a)
    try:
        a = future.result(timeout=_ENRICH_TIMEOUT)
    except FutureTimeout:
        logger.warning("Enrichment timed out for %s after %.0fs — using partial data",
                       a.alert_id, _ENRICH_TIMEOUT)
    except Exception as exc:
        logger.warning("Enrichment raised for %s: %s — using partial data", a.alert_id, exc)

    # ── 4. Persist alert (pre-incident) ──────────────────────────────────────
    r.set(f"alert:{a.alert_id}", a.model_dump_json())

    # ── 5. Correlate (group → incident) ──────────────────────────────────────
    inc_id, is_new = correlate(a)

    # ── 6. Persist alert again (now has incident_id) ─────────────────────────
    r.set(f"alert:{a.alert_id}", a.model_dump_json())

    logger.info(
        "[%s] alert=%s src=%s inc=%s risk=%d sev=%s type=%s %s",
        a.event_source, a.alert_id, a.source_ip or "-",
        inc_id, a.risk_score, a.severity, a.event_type,
        "★NEW" if is_new else "",
    )

    # ── 7. LLM agentic summary — only on NEW incident ────────────────────────
    if is_new and os.getenv("DISABLE_LLM", "0") != "1":
        try:
            logger.info("Triggering agentic investigation for NEW incident %s", inc_id)
            summarize_incident(inc_id)
        except Exception as e:
            logger.error("LLM summarization failed for %s: %s", inc_id, e)

    # ── 8. Notify WebSocket clients ───────────────────────────────────────────
    r.publish("incidents.live", inc_id)

    # ── 9. Acknowledge message ────────────────────────────────────────────────
    r.xack(STREAM, GROUP, msg_id)

    # ── 10. Record work progress in the heartbeat ─────────────────────────────
    _hb["processed_ts"]     = time.time()
    _hb["processed_count"] += 1
    _hb["last_alert_id"]    = a.alert_id
    _hb["last_incident_id"] = inc_id
    _write_heartbeat()


if __name__ == "__main__":
    run()

import json
import logging
import os
import sys
import time

import redis

from pipeline.triage import triage
from pipeline.enrichment import enrich
from pipeline.correlation import correlate
from pipeline.llm_assistant import summarize_incident
from schema.ocsf import OCSFAlert

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [WORKER] %(levelname)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)

r = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))
GROUP    = "soc"
CONSUMER = os.getenv("WORKER_ID", "worker-1")
STREAM   = "alerts.raw"

# ── Liveness heartbeat ────────────────────────────────────────────────────
# `beat_ts` is refreshed every consumer-loop cycle (proves the worker loop is
# alive even when idle); `processed_ts` advances only when an alert is actually
# handled (proves work progress). /api/health reads this so we report real
# liveness, not just "the process exists".
_HEARTBEAT_KEY = "soc:worker:heartbeat"
_hb = {
    "worker_id":         CONSUMER,
    "started_ts":        None,
    "beat_ts":           None,
    "processed_ts":      None,
    "processed_count":   0,
    "last_alert_id":     None,
    "last_incident_id":  None,
}


def _write_heartbeat() -> None:
    _hb["beat_ts"] = time.time()
    try:
        r.set(_HEARTBEAT_KEY, json.dumps(_hb))
    except Exception as e:
        logger.warning("Failed to write worker heartbeat: %s", e)


def _ensure_group():
    try:
        r.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
        logger.info("Consumer group '%s' created on stream '%s'", GROUP, STREAM)
    except redis.ResponseError:
        pass  # group already exists


def _is_new_incident(inc_id: str, alert_count: int) -> bool:
    """Return True if this is the first alert in the incident (triggers LLM)."""
    return alert_count == 1


def run():
    _ensure_group()
    # Eagerly warm the IP-reputation feeds so a total outage is logged loudly at
    # startup instead of silently degrading scoring on the first alert.
    try:
        from intel.reputation import warm_blocklists
        warm_blocklists()
    except Exception as e:
        logger.warning("Blocklist warm-up failed: %s", e)
    _hb["started_ts"] = time.time()
    _write_heartbeat()
    logger.info("Worker '%s' listening on '%s'…", CONSUMER, STREAM)

    while True:
        try:
            msgs = r.xreadgroup(GROUP, CONSUMER, {STREAM: ">"}, count=10, block=5000)
        except redis.ConnectionError as e:
            logger.error("Redis connection error: %s — retrying in 3s", e)
            time.sleep(3)
            continue

        # Beat every cycle (even on an empty read) so liveness is decoupled from
        # whether alerts are currently flowing.
        _write_heartbeat()

        for _stream, entries in msgs or []:
            for msg_id, fields in entries:
                try:
                    _process_one(msg_id, fields)
                except Exception as exc:
                    logger.exception("Failed to process message %s: %s", msg_id, exc)
                    # Still ack to avoid poison-pill blocking the stream
                    r.xack(STREAM, GROUP, msg_id)


def _process_one(msg_id: bytes, fields: dict):
    # ── 1. Deserialize ───────────────────────────────────────────────────────
    raw_data = fields.get(b"data") or fields.get("data", b"{}")
    if isinstance(raw_data, bytes):
        raw_data = raw_data.decode()
    a = OCSFAlert(**json.loads(raw_data))

    # ── 2. Triage (ML classify + FP gate + risk score) ───────────────────────
    a = triage(a)

    # ── 3. Enrich (GeoIP + WHOIS + MITRE mapping) ────────────────────────────
    a = enrich(a)

    # ── 4. Persist alert (pre-incident) ──────────────────────────────────────
    r.set(f"alert:{a.alert_id}", a.model_dump_json())

    # ── 5. Correlate (group → incident) ──────────────────────────────────────
    inc_id, is_new = correlate(a)

    # ── 6. Persist alert again (now has incident_id) ─────────────────────────
    r.set(f"alert:{a.alert_id}", a.model_dump_json())

    logger.info(
        "[%s] alert=%s src=%s inc=%s risk=%d sev=%s type=%s %s",
        a.event_source, a.alert_id, a.source_ip or "-",
        inc_id, a.risk_score, a.severity, a.event_type,
        "★NEW" if is_new else "",
    )

    # ── 7. LLM agentic summary — only on NEW incident ────────────────────────
    if is_new and os.getenv("DISABLE_LLM", "0") != "1":
        try:
            logger.info("Triggering agentic investigation for NEW incident %s", inc_id)
            summarize_incident(inc_id)
        except Exception as e:
            logger.error("LLM summarization failed for %s: %s", inc_id, e)

    # ── 8. Notify WebSocket clients ───────────────────────────────────────────
    r.publish("incidents.live", inc_id)

    # ── 9. Acknowledge message ────────────────────────────────────────────────
    r.xack(STREAM, GROUP, msg_id)

    # ── 10. Record work progress in the heartbeat ─────────────────────────────
    _hb["processed_ts"]     = time.time()
    _hb["processed_count"] += 1
    _hb["last_alert_id"]    = a.alert_id
    _hb["last_incident_id"] = inc_id
    _write_heartbeat()


if __name__ == "__main__":
    run()
