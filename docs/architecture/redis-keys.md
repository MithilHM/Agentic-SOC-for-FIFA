# Redis Key Schema

Redis is the message bus, notification channel, and datastore. This is the
complete inventory of what lives where. All keys use the `soc:` prefix except the
per-entity `alert:` / `incident:` records and the raw stream.

## Streams

| Key | Type | Producer | Consumer | Notes |
|---|---|---|---|---|
| `alerts.raw` | Stream | `ingestion/publisher.py` (`XADD`) | `pipeline/worker.py` (`XREADGROUP` group `soc`, consumer `WORKER_ID`) | Payload is a single `data` field holding the alert JSON. Delivery is at-least-once; the worker `XACK`s every message (including poison pills). |

Multiple workers can join the `soc` consumer group; the stream distributes
messages across them, which is the basis for horizontal scale.

## Pub/Sub

| Channel | Publisher | Subscriber | Payload |
|---|---|---|---|
| `incidents.live` | `pipeline/worker.py` after each processed alert | `api/server.py::ws` (one subscription per WebSocket client) | The incident ID (string). The API re-reads `incident:{id}` and pushes the full payload. |

## Entity records (key/value)

| Key pattern | Written by | Read by | Value |
|---|---|---|---|
| `alert:{alert_id}` | worker (twice per alert) | `/api/incidents/{id}` (bulk `MGET`) | Full `OCSFAlert` JSON. |
| `incident:{incident_id}` | `correlation.py`, `llm_assistant.py`, `store/incidents.py` | API endpoints, worker, agent tools | Full incident JSON (see below). |

An incident record contains: `incident_id`, `created`, `last_seen`, `asset`,
`users[]`, `ioc_values[]`, `source_ips[]`, `alert_ids[]`, `event_types[]`,
`max_risk`, `tactics[]`, `techniques[]`, `campaign_name`, `priority`, and — once
investigated — `summary`, `attack_narrative`, `recommended_action`, `confidence`,
`steps_taken`, `tool_calls`.

## Sequence counters

| Key | Command | Purpose |
|---|---|---|
| `soc:sequence:alert` | `INCR` | Global monotonic alert number → `ALT-%06d`. |
| `soc:sequence:incident` | `INCR` | Global monotonic incident number → `INC-%06d`. |

Atomic `INCR` guarantees uniqueness across concurrent processes. If Redis is
unreachable, callers fall back to a UUID-suffixed ID (`ALT-<hex>`). See
[Correlation](../components/correlation.md#distributed-id-generation).

## Serving indexes (maintained by the worker, read by the API)

| Key | Type | Score / fields | Purpose |
|---|---|---|---|
| `soc:open_incidents` | Sorted set | score = `last_seen` (UNIX ts) | `GET /api/incidents` uses `ZREVRANGE` to list newest-first, then one pipeline `MGET` — no keyspace scan. |
| `soc:metrics` | Hash | see below | `GET /api/metrics` reads this directly — O(1) instead of scanning all alerts/incidents. |

`soc:metrics` fields:

| Field | Maintained via | Meaning |
|---|---|---|
| `open_incidents` | `HINCRBY +1` on each new incident | Count of incidents created. |
| `p1` | `HINCRBY +1` when an incident **crosses into** P1 | Count of P1 incidents. Priority is monotonic here, so each incident increments this at most once. |
| `sev:{severity}` | `HINCRBY +1` per alert | Alerts by severity (`sev:High`, `sev:Medium`, …). |
| `type:{event_type}` | `HINCRBY +1` per alert | Alerts by attack type (`type:Phishing`, …). |

> Both `/api/incidents` and `/api/metrics` fall back to a legacy `SCAN` if these
> structures are missing (first boot before the worker has written them).

## Correlation reverse indexes

Created on every incident create/update; each maps one correlation dimension to
its active incident ID with a TTL equal to `CORRELATION_WINDOW_SEC`.

| Key pattern | Example | TTL |
|---|---|---|
| `soc:idx:ioc:{value}` | `soc:idx:ioc:fifa-ticket-secure2026.com` | `CORRELATION_WINDOW_SEC` |
| `soc:idx:asset:{value}` | `soc:idx:asset:official ticket portal` | `CORRELATION_WINDOW_SEC` |
| `soc:idx:user:{value}` | `soc:idx:user:ticket_ops` | `CORRELATION_WINDOW_SEC` |
| `soc:idx:ip:{value}` | `soc:idx:ip:185.174.21.14` | `CORRELATION_WINDOW_SEC` |

Values are normalized (lower-cased, trimmed) before keying. `_find_open_incident`
checks up to four of these in a single pipeline and returns the first live match.
The TTL means stale incidents automatically fall out of matching once the window
passes.

## Operational keys

| Key | Type | Written by | Read by | Notes |
|---|---|---|---|---|
| `soc:worker:heartbeat` | String (JSON) | worker every loop cycle | `/api/health` | `{worker_id, started_ts, beat_ts, processed_ts, processed_count, last_alert_id, last_incident_id}`. |
| `soc:cache:geoip:{ip}` | String (JSON) | `intel/geoip.py` | `intel/geoip.py` | L2 shared GeoIP cache. TTL 24h for hits, 5min for misses. Shared across worker instances. |

## Quick inspection

```bash
# All SOC keys
redis-cli --scan --pattern 'soc:*'

# Open incidents, newest first
redis-cli ZREVRANGE soc:open_incidents 0 -1 WITHSCORES

# Live metrics hash
redis-cli HGETALL soc:metrics

# Worker heartbeat
redis-cli GET soc:worker:heartbeat

# Current sequence highs
redis-cli MGET soc:sequence:alert soc:sequence:incident
```
