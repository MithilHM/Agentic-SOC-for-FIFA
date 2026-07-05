"""
pipeline/worker.py — Redis Streams consumer driving the AI pipeline.

Per-alert flow:
  1. triage(alert)     — XGBoost classify + FP gate + risk score
  2. enrich(alert)     — GeoIP + WHOIS + MITRE mapping
  3. correlate(alert)  — group into incident (IOC/asset/user/window)
  4. persist alert     — save back to Redis with incident_id
  5. LLM summary       — only triggered on NEW incident creation (not every update)
  6. WS notify         — Redis publish → API pushes to dashboard
"""
import json
import logging
import os
import sys

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
    logger.info("Worker '%s' listening on '%s'…", CONSUMER, STREAM)

    while True:
        try:
            msgs = r.xreadgroup(GROUP, CONSUMER, {STREAM: ">"}, count=10, block=5000)
        except redis.ConnectionError as e:
            logger.error("Redis connection error: %s — retrying in 3s", e)
            import time; import time as t; t.sleep(3)
            continue

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


if __name__ == "__main__":
    run()
