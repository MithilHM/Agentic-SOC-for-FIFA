# Configuration Reference

All configuration is via environment variables, loaded from `.env` (copy
`.env.example`). The system is designed so that **every key is optional** — with
none set it runs a fully offline, deterministic demo.

## Full variable reference

| Variable | Required? | Default | Purpose |
|---|---|---|---|
| `REDIS_URL` | **Required** | `redis://redis:6379` (compose) / `redis://localhost:6379` (code) | Redis connection for streams, pub/sub, and storage. |
| `GEMINI_API_KEY` | Optional | _none_ | Enables the LangGraph LLM analyst **and** RAG embeddings. Without it, incidents get a rule-based heuristic summary. |
| `GEMINI_MODEL` | Optional | `gemini-2.5-flash` | Chat model for the analyst agent. |
| `PINECONE_API_KEY` | Optional | _none_ | Enables Pinecone RAG (similar-incident + ATT&CK grounding). No-ops gracefully if unset. |
| `PINECONE_INDEX` | Optional | `fifa-soc-incidents` | Pinecone index name. |
| `PINECONE_CLOUD` | Optional | `aws` | Serverless cloud for index creation. |
| `PINECONE_REGION` | Optional | `us-east-1` | Serverless region for index creation. |
| `ENABLE_LIVE_INTEL` | Optional | `0` | `1` = real outbound intel: GeoIP (ipapi.co + ipwho.is fallback), public IP blocklists (Spamhaus DROP / Tor / FireHOL), live WHOIS. `0` = fully offline heuristics. |
| `BLOCKLIST_REFRESH_HOURS` | Optional | `6` | TTL before reputation blocklists are re-downloaded. |
| `API_KEY` | Optional | _empty_ (auth **disabled**) | Set to require a key on `/api/export`, `/api/incidents/{id}/ask`, and the WebSocket. Sent as `X-API-Key` / `Authorization: Bearer` (HTTP) or `?token=` (WS). |
| `VITE_API_KEY` | Optional | _empty_ | Must match `API_KEY`. **Baked into the dashboard bundle at build time** so the UI can authenticate. |
| `VITE_API` | Optional | `http://localhost:8080` | API base URL the dashboard talks to (build-time). |
| `SIM_RATE` | Optional | `2.0` (compose) | Simulator alert emission rate (alerts/sec). |
| `WORKER_ID` | Optional | `worker-1` | Consumer name within the `soc` Redis consumer group. Must be **unique per worker** when scaling out. |
| `CORRELATION_WINDOW_SEC` | Optional | `900` | Time window for grouping alerts into one incident; also the TTL on the correlation reverse indexes. |
| `DISABLE_LLM` | Optional | `0` | `1` = skip LLM summarization on new incidents (fast/offline demos). |
| `WORKER_STALE_SEC` | Optional | `20` | `/api/health` marks the worker not-live if its heartbeat is older than this. |
| `ENRICH_TIMEOUT_SEC` | Optional | `15` | Max seconds the worker waits for threaded GeoIP/WHOIS enrichment before proceeding with partial data. |
| `GEO_MAX_RETRIES` | Optional | `2` | Retry attempts per geolocation provider on 429/transient errors. |
| `GEO_BACKOFF_BASE_SEC` | Optional | `0.5` | Base delay for geolocation exponential backoff. |
| `GEO_TIMEOUT_SEC` | Optional | `3` | Per-request geolocation HTTP timeout. |

## Feature matrix — what unlocks what

```
              no keys           +GEMINI_API_KEY       +PINECONE_API_KEY     +ENABLE_LIVE_INTEL=1
triage        XGBoost (offline) same                  same                  same
enrichment    heuristics        same                  same                  live GeoIP/WHOIS/blocklists
summaries     heuristic         LangGraph agent       agent + RAG grounding same
analyst Q&A   heuristic reply   Gemini-powered        + RAG context         same
```

## Operational notes

- **Scaling workers:** run additional `worker` replicas, each with a distinct
  `WORKER_ID`. They all join the `soc` consumer group and share the `alerts.raw`
  stream. The reverse-index correlation and Redis `INCR` IDs are built for this —
  see [Scaling & concurrency](../operations/scaling-and-concurrency.md).
- **Correlation window:** raising `CORRELATION_WINDOW_SEC` keeps incidents "open"
  (and matchable) longer; it directly sets the TTL on `soc:idx:*` keys.
- **Auth is off by default** and logs a warning at API startup so the open state
  is never silent. See [API](../components/api.md#authentication).
- **Free-tier Gemini quota:** `gemini-2.5-flash` allows roughly ~20
  `generate_content`/day and embeddings ~100/min, which caps full agent
  investigations to a handful per day and spreads MITRE RAG seeding across runs.
  A paid key removes these limits.
