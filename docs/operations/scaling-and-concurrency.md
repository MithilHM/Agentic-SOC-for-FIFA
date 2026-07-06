# Scaling & Concurrency

This is the design writeup for the refactor that makes the system safe to run
with multiple workers under high throughput. Each item lists the failure mode it
removes and where it lives.

## Why it was needed

The original build assumed a single process: in-memory ID counters, O(N)
keyspace scans on every alert and API call, blocking I/O on the worker loop and
the API event loop, and import-time side effects. Running two workers, or a burst
of traffic, would produce duplicate IDs, stalled loops, health-probe flaps, and
exhausted connection pools.

## 1. Distributed, atomic ID generation

**Was:** `itertools.count(1)` / `count(1)` per process → two processes both mint
`ALT-000001` / `INC-000001` and clobber each other's Redis keys.

**Now:** Redis `INCR` on `soc:sequence:alert` and `soc:sequence:incident` — atomic
and process-global — with a UUID fallback when Redis is unreachable.
`ingestion/parsers/base.py::next_alert_id`, `pipeline/correlation.py::_next_incident_id`.

**Trade-off:** IDs are globally coordinated, so a single process no longer starts
at `000001`; they remain unique and sequential across the fleet.

Tests: `tests/test_id_generation.py`.

## 2. O(1) correlation via reverse indexes

**Was:** `_find_open_incident()` scanned every `incident:*` key per alert — O(N),
degrading as incidents accumulate.

**Now:** four reverse-index keys (`soc:idx:{ioc,asset,user,ip}:{value}`) map each
correlation dimension to its incident ID, checked in a single pipeline. TTL =
`CORRELATION_WINDOW_SEC` so stale incidents self-evict.
`pipeline/correlation.py`. See [Correlation](../components/correlation.md).

Tests: `tests/test_correlation_index.py`.

## 3. Keyspace-scan-free API

**Was:** `/api/incidents` and `/api/metrics` scanned all `incident:*` / `alert:*`
keys on every request.

**Now:** the worker maintains a `soc:open_incidents` sorted set (list via
`ZREVRANGE` + pipelined `MGET`) and a `soc:metrics` hash (read directly). Both
retain a legacy-scan fallback for first boot. `api/server.py`,
`pipeline/correlation.py::_update_metrics`.

The `p1` field of `soc:metrics` was a live bug — it reset to `0` and was never
re-populated. It now `HINCRBY`s once on the monotonic crossing into P1. See
[Correlation → Serving structures](../components/correlation.md#serving-structures-maintained-here).

## 4. Non-blocking enrichment

**Was:** GeoIP/WHOIS ran inline on the consumer loop. With retries/backoff they
could block for many seconds — past `WORKER_STALE_SEC` — making `/api/health`
declare the worker dead and triggering restarts.

**Now:** `enrich()` is submitted to a `ThreadPoolExecutor` (`max_workers=2`) and
awaited with `timeout=ENRICH_TIMEOUT_SEC` (default 15s); on timeout the worker
proceeds with partial/heuristic data. The lighter heartbeat beat fires every loop
cycle regardless, decoupling liveness from enrichment latency.
`pipeline/worker.py`.

Supporting fixes:
- **Shared GeoIP cache:** moved from a process-local dict to L1 dict **+ L2 Redis**
  (`soc:cache:geoip:{ip}`, 24h TTL) so all worker instances share lookups.
  `intel/geoip.py`.
- **No global socket mutation:** WHOIS no longer calls
  `socket.setdefaulttimeout()` (a process-wide change racing other threads); it
  runs the blocking query in an isolated daemon thread with `join(timeout)`.
  `intel/whois_lookup.py`.

## 5. Non-blocking API event loop

**Was:** `POST /api/incidents/{id}/ask` ran the blocking LLM call directly inside
an `async def`, freezing the event loop for seconds.

**Now:** `await asyncio.to_thread(answer_query, ...)`. The SQLite export is
offloaded the same way. `api/server.py`.

## 6. No import-time side effects

**Was:** importing `pipeline/llm_assistant.py` spawned a background RAG-seeding
thread (hitting Pinecone/Gemini) — surprising in tests and unwanted at import.

**Now:** an explicit, idempotent `initialize_rag()` called deliberately from
`pipeline/worker.py::run` and the API `lifespan` handler.
`pipeline/llm_assistant.py`.

## 7. Frontend resource-leak guards

- `startPolling()` returns a `clearInterval` cleanup that `App.jsx`'s `useEffect`
  returns — no stacked intervals on remount/hot-reload.
- `connect()` guards on `connecting` as well as `connected` — no duplicate
  WebSocket channels. `dashboard/src/store.js`, `dashboard/src/App.jsx`.
- **WebSocket pool leak:** the API's WS handler `aclose()`s the pubsub on
  disconnect (not just `unsubscribe()`), returning the pooled connection.
  `api/server.py::_close_pubsub`, pinned by `tests/test_regression_ws_leak.py`.

## Running multiple workers

Scale the `worker` service horizontally; give each replica a unique `WORKER_ID`.
All replicas join the `soc` consumer group and share the `alerts.raw` stream, so
each message is processed once. The reverse-index correlation, atomic IDs, and
shared caches make concurrent processing safe. See
[Configuration → Operational notes](../getting-started/configuration.md#operational-notes).
