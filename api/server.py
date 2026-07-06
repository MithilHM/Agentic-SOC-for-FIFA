import os, json, time, asyncio, logging, redis.asyncio as aioredis
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.auth import authorize_ws, require_auth
from store.incidents import IncidentStore

logger = logging.getLogger("api.server")

# ── Lifespan: explicit RAG initialisation instead of import-time side-effect ──
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Run startup tasks before serving requests.

    Moving RAG seeding here (instead of a bare module-level threading.Thread
    call in llm_assistant.py) means importing the module during unit tests no
    longer silently spawns a background thread that hits Pinecone/Gemini.
    """
    try:
        from pipeline.llm_assistant import initialize_rag
        asyncio.get_event_loop().run_in_executor(None, initialize_rag)
        logger.info("RAG background seeding scheduled via lifespan startup.")
    except Exception as e:
        logger.warning("RAG initialisation skipped: %s", e)
    yield
    # Shutdown: nothing extra required — daemon threads die with the process.


app = FastAPI(title="FIFA AI-SIEM API", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
R = aioredis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))

# A worker whose heartbeat is older than this is considered not-live. The worker
# beats every consumer-loop cycle (xreadgroup blocks ≤5s), so 20s = a few missed
# cycles.
_WORKER_STALE_SEC = int(os.getenv("WORKER_STALE_SEC", "20"))
_HEARTBEAT_KEY = "soc:worker:heartbeat"   # written by pipeline.worker

# ── Redis index keys ──────────────────────────────────────────────────────────
_OPEN_INCIDENTS_KEY = "soc:open_incidents"   # sorted set  score=last_seen
_METRICS_KEY        = "soc:metrics"          # hash: field=counter name


@app.get("/api/health")
async def health():
    """Liveness/readiness: reports Redis reachability and real worker liveness
    (from the worker heartbeat), not just that this API process is up. Returns
    HTTP 503 when degraded so container/orchestrator probes can act on it."""
    now = time.time()

    redis_ok = True
    try:
        await R.ping()
    except Exception as e:
        redis_ok = False
        logger.warning("Health check: Redis unreachable: %s", e)

    hb = None
    if redis_ok:
        try:
            raw = await R.get(_HEARTBEAT_KEY)
            hb = json.loads(raw) if raw else None
        except Exception as e:
            logger.warning("Health check: could not read worker heartbeat: %s", e)

    beat_age = round(now - hb["beat_ts"], 1) if hb and hb.get("beat_ts") else None
    proc_age = round(now - hb["processed_ts"], 1) if hb and hb.get("processed_ts") else None
    worker_alive = beat_age is not None and beat_age < _WORKER_STALE_SEC

    status = "ok" if (redis_ok and worker_alive) else "degraded"
    body = {
        "status": status,
        "time": now,
        "redis": {"reachable": redis_ok},
        "worker": {
            "alive": worker_alive,
            "worker_id": hb.get("worker_id") if hb else None,
            "seconds_since_heartbeat": beat_age,
            "seconds_since_last_alert": proc_age,
            "last_processed_alert": hb.get("last_alert_id") if hb else None,
            "last_incident": hb.get("last_incident_id") if hb else None,
            "processed_count": hb.get("processed_count") if hb else None,
            "heartbeat_seen": hb is not None,
        },
    }
    return JSONResponse(body, status_code=200 if status == "ok" else 503)


@app.get("/api/incidents")
async def incidents():
    """Return all incidents ordered by last_seen desc.

    Uses the `soc:open_incidents` sorted set (maintained by the worker) so we
    avoid an O(N) SCAN over the whole key-space.  ZRANGE ... REV gives IDs
    already sorted newest-first; a single pipeline then bulk-fetches payloads.
    Falls back to the legacy SCAN when the sorted set is missing (first boot or
    old worker version).
    """
    ids = await R.zrange(_OPEN_INCIDENTS_KEY, 0, -1, rev=True)
    if ids:
        pipe = R.pipeline()
        for inc_id in ids:
            pipe.get(f"incident:{inc_id.decode() if isinstance(inc_id, bytes) else inc_id}")
        raws = await pipe.execute()
        return [json.loads(r) for r in raws if r]

    # Fallback: legacy scan (first boot before the sorted set exists)
    out = []
    async for key in R.scan_iter("incident:*"):
        raw = await R.get(key)
        if raw:
            out.append(json.loads(raw))
    return sorted(out, key=lambda i: i["last_seen"], reverse=True)


@app.get("/api/incidents/{inc_id}")
async def incident(inc_id: str):
    """Fetch a single incident with its full alert payloads.

    Alert keys are fetched in a single pipeline instead of N sequential GETs.
    """
    raw = await R.get(f"incident:{inc_id}")
    if not raw:
        return JSONResponse({"detail": "Incident not found"}, status_code=404)
    inc = json.loads(raw)

    # Bulk-fetch all alert payloads in one pipeline pass
    alert_ids = inc.get("alert_ids", [])
    if alert_ids:
        pipe = R.pipeline()
        for a_id in alert_ids:
            pipe.get(f"alert:{a_id}")
        alert_raws = await pipe.execute()
        inc["alerts"] = [json.loads(r) for r in alert_raws if r]
    else:
        inc["alerts"] = []
    return inc


@app.get("/api/metrics")
async def metrics():
    """Return pre-computed metrics maintained atomically by the pipeline worker.

    Reads from a Redis Hash (`soc:metrics`) that the worker increments via
    HINCRBY on every processed alert — O(1) instead of a full SCAN + parse.
    Falls back to legacy scan when the hash is missing.
    """
    stored = await R.hgetall(_METRICS_KEY)
    if stored:
        def _int(v):
            try:
                return int(v)
            except (TypeError, ValueError):
                return 0

        sev   = {}
        types = {}
        for k, v in stored.items():
            key = k.decode() if isinstance(k, bytes) else k
            val = _int(v)
            if key.startswith("sev:"):
                sev[key[4:]] = val
            elif key.startswith("type:"):
                types[key[5:]] = val

        open_incs = _int(stored.get(b"open_incidents", stored.get("open_incidents", 0)))
        p1        = _int(stored.get(b"p1",             stored.get("p1", 0)))
        return {"open_incidents": open_incs, "by_severity": sev,
                "by_type": types, "p1": p1}

    # Fallback: legacy scan for first-boot compatibility
    incs, sev, types = [], {}, {}
    async for key in R.scan_iter("incident:*"):
        raw = await R.get(key)
        if raw:
            incs.append(json.loads(raw))
    async for key in R.scan_iter("alert:*"):
        raw = await R.get(key)
        if not raw:
            continue
        a = json.loads(raw)
        sev[a["severity"]]   = sev.get(a["severity"], 0) + 1
        types[a["event_type"]] = types.get(a["event_type"], 0) + 1
    return {"open_incidents": len(incs), "by_severity": sev, "by_type": types,
            "p1": sum(1 for i in incs if i.get("priority") == "P1")}


@app.post("/api/incidents/{inc_id}/ask")
async def ask(inc_id: str, body: dict, _principal: dict = Depends(require_auth)):
    """Answer an ad-hoc analyst question about an incident.

    answer_query() is synchronous (it calls the Gemini API via LangChain which
    is blocking I/O).  Running it directly inside an `async def` handler would
    block the entire event loop for multiple seconds.  asyncio.to_thread()
    offloads it to a worker thread in FastAPI's default thread-pool executor so
    the event loop stays free for WebSocket pushes and other requests.
    """
    from pipeline.llm_assistant import answer_query
    answer = await asyncio.to_thread(answer_query, inc_id, body.get("question", ""))
    return {"answer": answer}


@app.post("/api/export")
async def export_incidents(_principal: dict = Depends(require_auth)):
    """Export all incidents to a SQLite file for offline/forensic analysis."""
    incs = [json.loads(await R.get(key)) async for key in R.scan_iter("incident:*")]
    db_path = os.path.join("data", f"incidents_export_{int(time.time())}.db")
    await asyncio.to_thread(IncidentStore.export_sqlite_data, incs, db_path)
    return {"status": "exported", "path": db_path, "count": len(incs)}


async def _close_pubsub(pub, channel: str = "incidents.live") -> None:
    """Fully release a pubsub's dedicated pool connection.

    unsubscribe() alone leaves the pubsub's dedicated connection checked out of
    the pool forever — aclose() is what actually returns it. Without this, every
    WS disconnect/reconnect leaked one connection until the pool (default 100)
    was exhausted and the whole API 500'd. Kept as a named helper so the leak
    regression test can exercise this exact cleanup sequence.
    """
    try:
        await pub.unsubscribe(channel)
    finally:
        await pub.aclose()


@app.websocket("/api/ws/incidents")
async def ws(sock: WebSocket):
    # Authorize BEFORE accepting: rejects the handshake if the key is missing.
    if not await authorize_ws(sock):
        return
    await sock.accept()
    pub = R.pubsub()
    await pub.subscribe("incidents.live")
    try:
        async for m in pub.listen():
            if m["type"] == "message":
                inc_id = m["data"].decode()
                await sock.send_text(await R.get(f"incident:{inc_id}"))
    except Exception as e:
        # Was a silent `pass` — exactly the kind of swallow that hides bugs. A
        # client disconnect is normal (info); anything else is worth seeing.
        logger.info("WebSocket closed: %s: %s", type(e).__name__, e)
    finally:
        await _close_pubsub(pub)
