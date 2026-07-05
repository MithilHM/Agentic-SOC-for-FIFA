import os, json, asyncio, redis.asyncio as aioredis
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="FIFA AI-SIEM API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
R = aioredis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))

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
async def ask(inc_id: str, body: dict):
    from pipeline.llm_assistant import answer_query
    return {"answer": answer_query(inc_id, body.get("question", ""))}

@app.websocket("/api/ws/incidents")
async def ws(sock: WebSocket):
    await sock.accept()
    pub = R.pubsub()
    await pub.subscribe("incidents.live")
    try:
        async for m in pub.listen():
            if m["type"] == "message":
                inc_id = m["data"].decode()
                await sock.send_text(await R.get(f"incident:{inc_id}"))
    except Exception:
        pass
    finally:
        await pub.unsubscribe("incidents.live")
