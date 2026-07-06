# Installation & Running

## Prerequisites

- **Docker + Docker Compose** (the recommended path — no local Python/Node needed).
- For local (non-Docker) dev: **Python 3.12+**, **Node.js 20+**, and a running **Redis**.

> The application code uses `X | None` type annotations, so it requires
> **Python 3.10+**. The Docker image uses Python 3.12.

## Option A — Docker Compose (recommended)

```bash
# 1. Configure. Works unedited (offline demo). Add keys to enable live features.
cp .env.example .env

# 2. Build & start everything: redis, worker, simulator, api, dashboard.
#    The image trains the XGBoost model at build time.
docker compose up --build -d

# 3. Open the dashboard
open http://localhost:5173          # API at http://localhost:8080

# 4. (optional) run the scripted kill-chain demo
make demo
```

Services and ports:

| Service | Container | Host port | Purpose |
|---|---|---|---|
| `dashboard` | nginx + built React bundle | **5173** | The SOC console. |
| `api` | uvicorn `api.server:app` | **8080** | REST + WebSocket. |
| `redis` | `redis:7-alpine` | 6379 | Bus + datastore. |
| `worker` | `python -m pipeline.worker` | — | The processing pipeline. |
| `simulator` | `python -m simulator.generator` | — | Continuous synthetic alert feed. |

Verify it's healthy:

```bash
curl -s http://localhost:8080/api/health      # {"status":"ok", "worker":{"alive":true,...}}
curl -s http://localhost:8080/api/metrics     # live counters
docker compose logs -f worker simulator       # watch alerts flow
```

### Makefile shortcuts

| Target | Effect |
|---|---|
| `make up` | Start redis + worker + api only. |
| `make seed` | Start the continuous simulator. |
| `make dash` | Start the dashboard. |
| `make demo` | Run the scripted kill-chain (`simulator/scenarios.py`) once. |
| `make test` | Run the pytest suite in a throwaway container (needs redis up). |
| `make eval` | Run the LangGraph agent eval harness against labeled incidents. |
| `make train` | Retrain the XGBoost model locally. |
| `make down` | Tear down containers **and volumes**. |

Stop everything: `docker compose down` (add `-v` to also drop volumes).

## Option B — Local processes

```bash
# 1. Config + deps
cp .env.example .env
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 2. Redis
docker run -d -p 6379:6379 redis:7-alpine

# 3. Train the model (writes ml/model/xgboost_model.json)
python -m ml.train_model

# 4. Start the pieces (separate terminals). Point them at local Redis:
export REDIS_URL=redis://localhost:6379
python -m pipeline.worker
python -m simulator.generator
uvicorn api.server:app --port 8080 --reload

# 5. Dashboard
cd dashboard && npm install && npm run dev     # http://localhost:5173
```

> When running locally, set `REDIS_URL=redis://localhost:6379`. The compose
> default is `redis://redis:6379` (the service name on the compose network).

## Enabling live features

Everything runs with **zero keys**. To progressively enable more:

| Want | Set |
|---|---|
| Real AI incident summaries + analyst Q&A | `GEMINI_API_KEY` |
| RAG grounding (similar incidents + ATT&CK) | `PINECONE_API_KEY` |
| Live GeoIP / IP blocklists / WHOIS | `ENABLE_LIVE_INTEL=1` |
| API authentication | `API_KEY` **and** matching `VITE_API_KEY` |

See the full [Configuration reference](configuration.md).

> **Auth + dashboard:** `VITE_API_KEY` is compiled into the dashboard bundle at
> build time. If you enable auth, set both keys **before** `docker compose up
> --build`, or rebuild the dashboard afterward.
