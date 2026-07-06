# Architecture Overview

The platform is organized into five layers. Redis sits at the center as the
message bus (Streams), notification channel (pub/sub), and datastore (key/value,
sorted sets, hashes).

```
┌─────────────────────────────────────────────────────────────────────┐
│ 1 · SOURCES        simulator/generator.py · simulator/scenarios.py    │
│                    11 native log formats @ SIM_RATE alerts/sec        │
└───────────────────────────────┬─────────────────────────────────────┘
                                 │ native records (dicts)
┌───────────────────────────────▼─────────────────────────────────────┐
│ 2 · INGESTION      ingestion/parsers/*  → OCSF (schema/ocsf.py)       │
│                    normalizer.py → publisher.py (XADD alerts.raw)     │
└───────────────────────────────┬─────────────────────────────────────┘
                                 │ XADD alerts.raw
┌───────────────────────────────▼─────────────────────────────────────┐
│  REDIS   Streams (alerts.raw) · pub/sub (incidents.live) · KV/ZSET/HASH│
└───────┬───────────────────────────────────────────────┬─────────────┘
        │ XREADGROUP "soc"                               │ publish
┌───────▼───────────────────────────┐                    │
│ 3 · PIPELINE   pipeline/worker.py  │                    │
│   1 triage   (pipeline/triage.py)  │  XGBoost + FP gate │
│   2 enrich   (pipeline/enrichment) │  intel/* (threaded)│
│   3 correlate(pipeline/correlation)│  reverse indexes   │
│   4 LLM      (pipeline/llm_assist.) │  LangGraph + RAG   │
│   ↳ heartbeat → soc:worker:heartbeat│                   │
└───────┬───────────────────────────┘                    │
        │ incident:* / alert:* (KV)                       │
┌───────▼───────────────────────────┐   REST + WS  ┌──────▼───────────┐
│ 4 · SERVING   api/server.py        │◀────────────▶│ 5 · DASHBOARD    │
│   FastAPI + WebSocket + auth       │              │ dashboard/ (React)│
│   store/incidents.py (Redis/SQLite)│              │ Vite + nginx     │
└────────────────────────────────────┘              └──────────────────┘
```

## The five layers

### 1 · Sources
`simulator/generator.py` continuously emits synthetic events across 11 FIFA log
sources at `SIM_RATE` alerts/sec; `simulator/scenarios.py` plays a scripted
multi-stage "Fake FIFA Ticket Campaign" kill-chain for demos. Both produce
**source-native** records — the same shapes real firewalls, WAFs, EDR agents,
etc. would emit.

### 2 · Ingestion
Each source has a dedicated parser under `ingestion/parsers/` that maps its
native record onto the canonical **OCSF alert** ([schema reference](../reference/ocsf-schema.md)).
`ingestion/normalizer.py` routes a record to the right parser via a registry;
`ingestion/publisher.py` serializes the alert and `XADD`s it to the `alerts.raw`
Redis Stream. See [Ingestion](../components/ingestion.md).

### 3 · Pipeline
`pipeline/worker.py` is a Redis Streams consumer (group `soc`) that runs each
alert through four stages:

| Stage | Module | What it does |
|---|---|---|
| Triage | `pipeline/triage.py` | XGBoost multi-class classification, false-positive gate, risk & severity scoring. |
| Enrich | `pipeline/enrichment.py` | GeoIP, WHOIS domain age, IP reputation, brand-impersonation scoring, MITRE mapping. Runs in a thread pool so slow upstreams can't stall the loop. |
| Correlate | `pipeline/correlation.py` | Groups the alert into a new or existing incident via O(1) reverse-index lookups. |
| Investigate | `pipeline/llm_assistant.py` | On a **new** incident, a LangGraph ReAct agent (Gemini + Pinecone RAG) produces a summary, attack narrative, and recommended action. Falls back to a heuristic without a key. |

See [Alert lifecycle](alert-lifecycle.md) for the exact ordering and the
concurrency model.

### 4 · Serving
`api/server.py` (FastAPI) exposes REST endpoints and a WebSocket. It reads from
pre-maintained Redis structures (a sorted set of open incidents, a metrics hash)
so it never scans the keyspace on the hot path. `store/incidents.py` provides a
Redis wrapper plus a SQLite export for offline forensics. See [API](../components/api.md).

### 5 · Dashboard
A React (Vite) single-page app served by nginx, with three views — Pipeline
Monitor, Incident Investigation, FIFA Operations. It loads data over REST and
streams live incident updates over the WebSocket. See [Dashboard](../components/dashboard.md).

## Why Redis for everything

- **Streams** give durable, consumer-group delivery — multiple workers can share
  the `soc` group and each message is processed once, enabling horizontal scale.
- **Pub/sub** (`incidents.live`) fans incident updates out to every connected
  dashboard with no polling.
- **Sorted sets / hashes / reverse-index keys** let the API and correlation
  engine answer "what's open?" and "does this alert belong to an existing
  incident?" in O(1) instead of scanning. See [Redis key schema](redis-keys.md)
  and [Scaling & concurrency](../operations/scaling-and-concurrency.md).
