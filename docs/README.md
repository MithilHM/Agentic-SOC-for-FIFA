# FIFA AI-SIEM — Documentation

An AI-powered Security Operations Center (SOC) that ingests, normalizes, triages,
correlates, and investigates security alerts across FIFA's digital infrastructure
(ticketing, payments, media portals, mobile apps, streaming, admin consoles).

This directory is the **deep reference**. For a quick project overview and a
one-command launch, see the top-level [`../README.md`](../README.md).

## Map

### Architecture
- [Overview](architecture/overview.md) — the five layers and how data flows between them.
- [Alert lifecycle](architecture/alert-lifecycle.md) — the journey of a single alert, step by step.
- [Redis key schema](architecture/redis-keys.md) — every key, stream, channel, and index the system uses.

### Getting started
- [Installation & running](getting-started/installation.md) — Docker Compose and local dev.
- [Configuration](getting-started/configuration.md) — the complete environment-variable reference.

### Components
- [Ingestion](components/ingestion.md) — source parsers, OCSF normalization, the stream publisher.
- [Triage](components/triage.md) — XGBoost classification, the false-positive gate, risk/severity scoring.
- [Enrichment](components/enrichment.md) — GeoIP, WHOIS, IP reputation, brand-impersonation scoring, MITRE mapping.
- [Correlation engine](components/correlation.md) — reverse-index grouping, distributed ID generation, pre-aggregated metrics.
- [LLM assistant](components/llm-assistant.md) — the LangGraph ReAct agent and Pinecone RAG.
- [API](components/api.md) — REST + WebSocket endpoint reference.
- [Dashboard](components/dashboard.md) — the React SOC console.

### Operations
- [Scaling & concurrency](operations/scaling-and-concurrency.md) — the multi-worker refactor and the guarantees it provides.
- [Health & observability](operations/health-and-observability.md) — the `/api/health` probe and the worker heartbeat.
- [Testing](operations/testing.md) — running the suite, what each test covers, the regression pins.

### Reference
- [OCSF alert schema](reference/ocsf-schema.md) — every field on the canonical alert object.

## The 30-second mental model

```
simulator ──native records──▶ ingestion (parse → OCSF → XADD)
                                         │
                                   Redis Streams  (alerts.raw, group "soc")
                                         │
                    ┌────────────────────▼────────────────────┐
                    │  worker:  triage → enrich → correlate    │
                    │           → LLM (on new incident)        │
                    └────────────────────┬────────────────────┘
              incident:* / alert:* (KV)  │  publish incidents.live
                                         ▼
                    api (FastAPI + WS) ──▶ dashboard (React)
```

Everything runs offline with **zero API keys** (heuristic triage/summaries,
local enrichment). Keys and flags progressively light up live features — see
[Configuration](getting-started/configuration.md).
