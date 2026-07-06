# Health & Observability

## `/api/health` — real liveness, not "is the process up"

`GET /api/health` reports two independent facts:

1. **Redis reachability** — an actual `PING`.
2. **Worker liveness** — read from the worker's heartbeat in Redis, so the probe
   reflects whether the *pipeline* is alive, not just whether the API is.

Status logic:

```
status = "ok"  iff  redis_ok AND worker_alive
worker_alive   iff  seconds_since_heartbeat < WORKER_STALE_SEC   (default 20)
```

- **200 / `ok`** when both hold.
- **503 / `degraded`** when Redis is down, or the heartbeat is stale/missing —
  so orchestrators (Docker/K8s) can act on it directly.

Example healthy body:

```json
{
  "status": "ok",
  "redis": { "reachable": true },
  "worker": {
    "alive": true,
    "worker_id": "worker-1",
    "seconds_since_heartbeat": 0.4,
    "seconds_since_last_alert": 0.4,
    "last_processed_alert": "ALT-000029",
    "last_incident": "INC-000007",
    "processed_count": 29,
    "heartbeat_seen": true
  }
}
```

Covered by `tests/test_health.py` (fresh / stale / missing heartbeat).

## The worker heartbeat

Written to `soc:worker:heartbeat` (JSON) by `pipeline/worker.py`:

| Field | Cadence | Meaning |
|---|---|---|
| `beat_ts` | **every loop cycle**, even on an idle read | Proves the consumer loop is alive regardless of traffic. |
| `processed_ts` | on each processed alert | Proves work is progressing. |
| `processed_count` | on each processed alert | Total alerts handled. |
| `last_alert_id` / `last_incident_id` | on each processed alert | Last work items. |
| `worker_id` / `started_ts` | at startup | Identity. |

Splitting `beat_ts` (liveness) from `processed_ts` (progress) is deliberate: an
idle worker with no alerts flowing is still healthy. The `XREADGROUP` block is
≤5s, so `WORKER_STALE_SEC=20` tolerates a few missed cycles before flagging.

## Logging conventions

- Pipeline exception handlers log at **info/warning**, not debug, so silent
  failures surface — e.g. RAG checkpoint durability, blocklist-cache download
  failures (`warm_blocklists` logs loudly on total outage at startup).
- The WebSocket handler logs disconnects at **info** (a client disconnect is
  normal) rather than swallowing them.
- `api/auth.py` logs a **warning** at import when `API_KEY` is unset, so running
  open is never silent.

## Quick checks

```bash
curl -s localhost:8080/api/health | jq .status        # ok | degraded
curl -s localhost:8080/api/metrics | jq                # live counters
docker compose logs -f worker                          # pipeline activity
redis-cli GET soc:worker:heartbeat                     # raw heartbeat
```

## Agent evaluation

`make eval` (`python -m evals.run_agent_eval`) runs the LangGraph analyst against
a labeled incident set (`evals/agent_eval_cases.json`) and reports PASS/FAIL per
case (verdict direction, priority, confidence, action content). Cases where the
agent couldn't run (no key / quota exhausted) are **SKIP**, so only genuine
judgment regressions fail — see the free-tier quota note in
[Configuration](../getting-started/configuration.md#operational-notes).
