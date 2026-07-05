import os, json, time, asyncio, logging, redis.asyncio as aioredis
from fastapi import Depends, FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.auth import authorize_ws, require_auth
from store.incidents import IncidentStore

logger = logging.getLogger("api.server")

app = FastAPI(title="FIFA AI-SIEM API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
R = aioredis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))

# A worker whose heartbeat is older than this is considered not-live. The worker
# beats every consumer-loop cycle (xreadgroup blocks ≤5s), so 20s = a few missed
# cycles.
_WORKER_STALE_SEC = int(os.getenv("WORKER_STALE_SEC", "20"))
_HEARTBEAT_KEY = "soc:worker:heartbeat"   # written by pipeline.worker

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
    out = []
    async for key in R.scan_iter("incident:*"):
        out.append(json.loads(await R.get(key)))
    return sorted(out, key=lambda i: i["last_seen"], reverse=True)

@app.get("/api/incidents/{inc_id}")
async def incident(inc_id: str):
    raw = await R.get(f"incident:{inc_id}")
    inc = json.loads(raw)
    inc["alerts"] = [json.loads(await R.get(f"alert:{a}"))
                     for a in inc["alert_ids"] if await R.exists(f"alert:{a}")]
    return inc

@app.get("/api/metrics")
async def metrics():
    incs, sev, types = [], {}, {}
    async for key in R.scan_iter("incident:*"):
        incs.append(json.loads(await R.get(key)))
    async for key in R.scan_iter("alert:*"):
        a = json.loads(await R.get(key))
        sev[a["severity"]] = sev.get(a["severity"], 0) + 1
        types[a["event_type"]] = types.get(a["event_type"], 0) + 1
    return {"open_incidents": len(incs), "by_severity": sev, "by_type": types,
            "p1": sum(1 for i in incs if i.get("priority") == "P1")}

@app.post("/api/incidents/{inc_id}/ask")
async def ask(inc_id: str, body: dict, _principal: dict = Depends(require_auth)):
    from pipeline.llm_assistant import answer_query
    return {"answer": answer_query(inc_id, body.get("question", ""))}

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
