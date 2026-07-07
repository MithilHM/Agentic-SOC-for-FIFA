from fastapi import FastAPI, Request, HTTPException
import logging
from typing import Set
import redis
import json
import os

r = redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379"))

def pub_log(level: str, msg: str):
    r.publish("sandbox.logs", json.dumps({
        "source": "sandbox",
        "level": level,
        "message": msg
    }))

# Set up vivid logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - [SANDBOX] - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="FIFA Ticketing Sandbox")

blocked_ips: Set[str] = set()

from fastapi.responses import JSONResponse

@app.middleware("http")
async def block_ip_middleware(request: Request, call_next):
    # Always allow admin endpoints to bypass the firewall
    if request.url.path.startswith("/admin/"):
        return await call_next(request)

    client_ip = request.client.host
    if client_ip in blocked_ips or "ALL" in blocked_ips:
        msg = f"Connection dropped for BLOCKED IP: {client_ip}"
        logger.warning(msg)
        pub_log("warning", msg)
        return JSONResponse(status_code=403, content={"detail": "Forbidden - IP Blocked by Agentic Firewall"})
    return await call_next(request)

@app.get("/checkout")
async def checkout(request: Request, item_id: str = "1"):
    client_ip = request.client.host
    # Check for simple SQLi pattern
    if "'" in item_id or "OR" in item_id.upper():
        msg = f"SQL Injection attack detected on /checkout from IP {client_ip}. Payload: {item_id}"
        logger.error(msg)
        pub_log("error", msg)
    else:
        msg = f"Legitimate checkout request from {client_ip}"
        logger.info(msg)
        pub_log("info", msg)
    return {"status": "processing", "item_id": item_id}

@app.post("/admin/block")
async def block_ip(target_ip: str = "ALL"):
    msg = f"🛡️ AGENTIC ACTION RECEIVED: Blocking IP {target_ip} at network level 🛡️"
    logger.critical(msg)
    pub_log("critical", msg)
    blocked_ips.add(target_ip)
    return {"status": "success", "message": f"IP {target_ip} blocked successfully."}

@app.post("/admin/reset")
async def reset_sandbox():
    blocked_ips.clear()
    msg = "🔄 Sandbox Environment Reset. Firewall rules cleared."
    logger.info(msg)
    pub_log("info", msg)
    return {"status": "success", "message": "Sandbox reset."}
