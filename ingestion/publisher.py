import json, os, redis
r = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))
STREAM = "alerts.raw"

def publish(alert) -> str:
    return r.xadd(STREAM, {"data": alert.model_dump_json()}).decode()
