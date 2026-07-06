# API

`api/server.py` — a FastAPI app exposing REST endpoints and a WebSocket. It's
designed to read from pre-maintained Redis structures so it never scans the
keyspace on the hot path, and to keep the event loop free of blocking work.

Base URL (default): `http://localhost:8080`. Uses `redis.asyncio` throughout.

## Endpoints

### `GET /api/health`
Liveness/readiness probe. Reports Redis reachability **and real worker liveness**
(from `soc:worker:heartbeat`), not just that the API process is up.

- Returns **200** with `status: "ok"` when Redis is reachable and the worker's
  heartbeat is younger than `WORKER_STALE_SEC`.
- Returns **503** with `status: "degraded"` otherwise — usable directly as a
  container/orchestrator probe.

Body includes `redis.reachable`, and a `worker` block with `alive`, `worker_id`,
`seconds_since_heartbeat`, `seconds_since_last_alert`, `last_processed_alert`,
`last_incident`, `processed_count`. See
[Health & observability](../operations/health-and-observability.md).

### `GET /api/incidents`
All incidents, newest first. Reads IDs from the `soc:open_incidents` sorted set
via `ZREVRANGE`, then bulk-fetches payloads in a single pipeline `MGET`. Falls
back to a legacy `SCAN` only if the sorted set is missing (first boot).

### `GET /api/incidents/{inc_id}`
A single incident with its full alert payloads. The incident's `alert_ids` are
fetched in one pipeline pass. **404** if the incident doesn't exist.

### `GET /api/metrics`
Pre-computed counters read directly from the `soc:metrics` hash (O(1)):

```json
{ "open_incidents": 7, "by_severity": {"High": 3, ...},
  "by_type": {"Phishing": 5, ...}, "p1": 1 }
```

Falls back to a legacy scan of all alerts/incidents if the hash is missing.

### `POST /api/incidents/{inc_id}/ask`  🔒
Ad-hoc analyst Q&A about an incident. Body: `{"question": "..."}`. Returns
`{"answer": "..."}`.

The underlying `answer_query()` is synchronous blocking I/O (the Gemini call), so
the handler offloads it with `await asyncio.to_thread(...)` — the event loop stays
free for WebSocket pushes and other requests.

### `POST /api/export`  🔒
Exports all incidents to a SQLite file (`data/incidents_export_<ts>.db`) for
offline forensics. The SQLite write runs via `asyncio.to_thread`. Returns the
path and count.

### `WS /api/ws/incidents`  🔒
Live incident feed. The handler authorizes **before** accepting the handshake,
subscribes to the `incidents.live` pub/sub channel, and pushes the full
`incident:{id}` JSON on every published update.

> **Connection-pool hygiene:** on disconnect the handler calls `_close_pubsub()`,
> which `unsubscribe()`s **and** `aclose()`s the pubsub. `unsubscribe()` alone
> leaves the dedicated pool connection checked out forever — the leak that used
> to exhaust the pool (default 100) after ~100 reconnects and 500 the whole API.
> Pinned by `tests/test_regression_ws_leak.py`.

## Authentication

Auth is handled in `api/auth.py` and guards `/api/export`,
`/api/incidents/{id}/ask`, and the WebSocket (marked 🔒 above).

- **Disabled by default.** If `API_KEY` is unset, auth is open and a warning is
  logged at import (never silent).
- **HTTP:** send `X-API-Key: <key>` or `Authorization: Bearer <key>`.
- **WebSocket:** browsers can't set custom headers on a WS handshake, so the key
  is accepted as `?token=<key>` (or the header). Rejected handshakes close with
  policy-violation **before** accept.
- Key comparison uses `hmac.compare_digest` (constant-time).
- **JWT-ready:** every protected route depends on `require_auth` / `authorize_ws`,
  never the raw key — swap the body of `_verify_token()` for JWT validation and
  everything keeps working.

The dashboard authenticates with `VITE_API_KEY`, which must match `API_KEY` and
is compiled into the bundle at build time. Covered by `tests/test_auth.py`.

## Startup

The FastAPI `lifespan` handler schedules `initialize_rag()` in an executor at
startup — replacing the old import-time background thread. See
[LLM assistant](llm-assistant.md#explicit-initialization-no-import-side-effects).
