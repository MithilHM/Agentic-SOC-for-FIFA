# Alert Lifecycle

This traces one alert from generation to the dashboard, naming the exact
functions involved. The authoritative source is `pipeline/worker.py::_process_one`.

## Sequence

```
generator/scenario
      │  native record (dict)
      ▼
normalize(source, raw)            ingestion/normalizer.py
      │  OCSFAlert  (alert_id via next_alert_id())
      ▼
publish(alert)                    ingestion/publisher.py → XADD alerts.raw
      │
      ▼
XREADGROUP "soc" ">"              pipeline/worker.py::run  (block=5000ms, count=10)
      │
      ▼  _process_one(msg_id, fields)
 1. OCSFAlert(**json)             deserialize the stream payload
 2. triage(a)                     pipeline/triage.py  — classify, FP gate, risk, severity
 3. enrich(a)                     submitted to ThreadPoolExecutor (max_workers=2),
                                  awaited with timeout=ENRICH_TIMEOUT_SEC
 4. SET alert:{id}               persist enriched alert (pre-incident)
 5. correlate(a)                  pipeline/correlation.py → (incident_id, is_new)
 6. SET alert:{id}               persist again (now carries incident_id)
 7. if is_new: summarize_incident(inc_id)   LangGraph agent (unless DISABLE_LLM=1)
 8. PUBLISH incidents.live inc_id            API pushes to dashboards
 9. XACK alerts.raw soc msg_id               acknowledge
10. update heartbeat             processed_ts / processed_count / last_*_id
```

## Stage detail

**1. Deserialize.** The stream stores the alert JSON under the `data` field.
The worker decodes it back into an `OCSFAlert` pydantic model.

**2. Triage.** [`triage()`](../components/triage.md) loads the XGBoost model
lazily, classifies the `event_type`, sets `confidence_score`, applies the
false-positive gate (low-confidence, non-known-bad alerts are downgraded to
`event_type="Other"` with a reduced risk), then computes `risk_score` and
`severity`.

**3. Enrich — the concurrency-critical step.** `enrich()` makes potentially slow
outbound calls (GeoIP, WHOIS) when `ENABLE_LIVE_INTEL=1`. Running those inline
could block the consumer loop past `WORKER_STALE_SEC` and make `/api/health`
declare the worker dead. So the worker submits `enrich()` to a
`ThreadPoolExecutor` and waits on the future with `timeout=ENRICH_TIMEOUT_SEC`
(default 15s); on timeout it proceeds with partial (heuristic) data. See
[Scaling & concurrency](../operations/scaling-and-concurrency.md#4-non-blocking-enrichment).

**4 & 6. Persist twice.** The alert is written once after enrichment (so it's
visible even if correlation fails) and again after correlation attaches the
`incident_id`.

**5. Correlate.** [`correlate()`](../components/correlation.md) looks for an open
incident sharing this alert's IOC, asset, user, or source IP via O(1) reverse
indexes. If found, the alert joins it; otherwise a new incident is minted with a
distributed ID. Correlation also maintains the `soc:open_incidents` sorted set
and the `soc:metrics` hash.

**7. Investigate (new incidents only).** The worker calls `summarize_incident()`
only when `is_new` is true — investigation is expensive, so it runs once per
incident, not once per alert. With a Gemini key, a LangGraph ReAct agent runs;
without one, a deterministic heuristic summary is produced. Skipped entirely
when `DISABLE_LLM=1`. See [LLM assistant](../components/llm-assistant.md).

**8. Notify.** The worker publishes the incident ID on `incidents.live`. The API
WebSocket handler (`api/server.py::ws`) receives it, re-reads `incident:{id}`,
and pushes the full payload to every connected dashboard.

**9. Acknowledge.** `XACK` marks the message processed. Note: if `_process_one`
raises, the worker logs the exception and **still acks** the message — this is a
deliberate poison-pill guard so one malformed record can't wedge the stream.

**10. Heartbeat.** `processed_ts`, `processed_count`, `last_alert_id`, and
`last_incident_id` are written to `soc:worker:heartbeat`. A lighter beat
(`beat_ts` only) also fires every loop cycle — even on an idle read — so
liveness is decoupled from whether alerts are currently flowing. See
[Health & observability](../operations/health-and-observability.md).

## Where IDs come from

- **Alert IDs** (`ALT-000123`) — `ingestion/parsers/base.py::next_alert_id`,
  backed by a Redis `INCR` on `soc:sequence:alert`.
- **Incident IDs** (`INC-000045`) — `pipeline/correlation.py::_next_incident_id`,
  backed by `INCR` on `soc:sequence:incident`.

Both are globally coordinated so multiple worker/ingestor processes never
collide. See [Correlation](../components/correlation.md#distributed-id-generation).
