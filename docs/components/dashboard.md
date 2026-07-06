# Dashboard

`dashboard/` is a React (Vite) single-page app served by nginx in production.
It's the SOC console — live incident ledger, timelines, charts, MITRE matrix, and
an analyst chat.

- **Dev:** `cd dashboard && npm install && npm run dev` → http://localhost:5173
- **Prod (compose):** built to a static bundle and served by nginx on port 5173.
- Talks to the API at `VITE_API` (default `http://localhost:8080`), authenticating
  with `VITE_API_KEY` if set. Both are **build-time** values baked into the bundle.

## State — `dashboard/src/store.js`

A single Zustand store (`useNexus`) is the source of truth for all three views.
Key state: `view`, `incidents`, `metrics`, `health`, `selected`, `connected`,
`connecting`. Notable actions:

| Action | What it does |
|---|---|
| `load()` | Fetches `/api/incidents`, `/api/metrics`, `/api/health` in parallel; auto-selects the first incident. |
| `select(id)` | Loads a single incident's full alert detail and merges it in. |
| `startPolling(ms)` | Kicks an immediate `load()` then `setInterval`. **Returns a cleanup function** that clears the interval. |
| `connect()` | Opens the WebSocket to `/api/ws/incidents`, prepends live incidents, and keeps `metrics.open_incidents` in sync. Auto-reconnects on close. |
| `ask(id, q)` | `POST`s to `/api/incidents/{id}/ask`. |

### Resource-leak guards

- **Polling cleanup:** `startPolling()` returns `() => clearInterval(id)`, and
  `App.jsx`'s `useEffect` returns it — so React tears the interval down on unmount
  and doesn't stack duplicate intervals across hot-reloads/remounts.
- **Single WebSocket:** `connect()` early-returns if already `connected` **or**
  `connecting`, preventing duplicate channels while a connection attempt is in
  flight.

## Views — `dashboard/src/dashboards/`

Three tabs, switched via the top nav in `dashboard/src/App.jsx`:

| Tab | Component | Focus |
|---|---|---|
| **Pipeline Monitor** | `PipelineMonitor.jsx` | Live throughput and the alert→incident pipeline as events stream in. |
| **Incident Investigation** | `IncidentInvestigation.jsx` | The incident ledger, per-incident detail, attack timeline, MITRE tactics, and the analyst chat. Its nav badge shows the live P1 count. |
| **FIFA Operations** | `FIFAOperations.jsx` | Operational/asset-oriented view across FIFA's digital estate. |

The P1 badge reads `metrics.p1` (server-computed) and falls back to counting P1
incidents client-side — so the [`p1` metric fix](correlation.md#serving-structures-maintained-here)
makes the badge accurate without relying on the fallback.

## Data flow

```
REST  load()  ───▶  incidents / metrics / health   (poll every ~10s)
WS    connect() ─▶  incidents.live push  ───▶  prepend live incident, bump metrics
```

Live updates arrive over the WebSocket; the periodic poll is a backstop that also
refreshes metrics and health.
