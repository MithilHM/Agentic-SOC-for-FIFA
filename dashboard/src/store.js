import { create } from "zustand";

const API     = import.meta.env.VITE_API     || "http://localhost:8080";
const API_KEY = import.meta.env.VITE_API_KEY || "";

const authHeader = () => API_KEY ? { "X-API-Key": API_KEY } : {};

/* ─────────────────────────────────────────────────────────────────
   NEXUS Store — single source of truth for all three dashboards
───────────────────────────────────────────────────────────────── */
export const useNexus = create((set, get) => ({

  /* ── UI state ── */
  view:      "pipeline",   // "pipeline" | "investigation" | "operations"
  setView:   (v) => set({ view: v }),

  /* ── Data ── */
  incidents: [],
  actions:   [],
  sandboxLogs: [],
  metrics:   {},
  health:    null,
  selected:  null,        // selected incident_id
  connected: false,
  connecting: false,

  /* ── Select incident (also loads full alert detail) ── */
  select: async (id) => {
    if (id === get().selected) return;
    set({ selected: id });
    try {
      const detail = await fetch(`${API}/api/incidents/${id}`, {
        headers: authHeader(),
      }).then(r => r.json());
      set(state => ({
        incidents: state.incidents.map(i =>
          i.incident_id === id ? { ...i, ...detail } : i
        ),
      }));
    } catch (e) {
      console.warn("Could not load incident detail:", e.message);
    }
  },

  /* ── Load all data ── */
  async load() {
    try {
      const [incidents, metrics, health, actions] = await Promise.all([
        fetch(`${API}/api/incidents`, { headers: authHeader() }).then(r => r.json()),
        fetch(`${API}/api/metrics`,   { headers: authHeader() }).then(r => r.json()),
        fetch(`${API}/api/health`,    { headers: authHeader() }).then(r => r.json()).catch(() => null),
        fetch(`${API}/api/actions`,   { headers: authHeader() }).then(r => r.json()).catch(() => []),
      ]);
      set({ incidents, metrics, health, actions });
      // Auto-select first incident if none selected
      if (!get().selected && incidents.length > 0) {
        get().select(incidents[0].incident_id);
      }
    } catch (e) {
      console.warn("API load failed:", e.message);
    }
  },

  /* ── WebSocket live feed ── */
  connect() {
    if (get().connected || get().connecting) return;
    set({ connecting: true });

    const wsBase = API.replace(/^http/, "ws");
    const token  = API_KEY ? `?token=${encodeURIComponent(API_KEY)}` : "";

    let ws, wsActions, wsSandbox;
    const open = () => {
      ws = new WebSocket(`${wsBase}/api/ws/incidents${token}`);
      ws.onopen    = () => set({ connected: true, connecting: false });
      ws.onmessage = (e) => {
        try {
          const inc  = JSON.parse(e.data);
          const rest = get().incidents.filter(x => x.incident_id !== inc.incident_id);
          set({ incidents: [inc, ...rest] });
          // keep metrics.open_incidents in sync
          set(s => ({ metrics: { ...s.metrics, open_incidents: rest.length + 1 } }));
        } catch (_) {}
      };
      ws.onclose = () => {
        set({ connected: false, connecting: false });
        setTimeout(open, 4000);
      };
      ws.onerror = () => ws.close();

      // Actions WebSocket
      wsActions = new WebSocket(`${wsBase}/api/ws/actions${token}`);
      wsActions.onmessage = (e) => {
        try {
          const act = JSON.parse(e.data);
          const rest = get().actions.filter(x => x.action_id !== act.action_id);
          set({ actions: [act, ...rest] });
        } catch (_) {}
      };
      wsActions.onerror = () => wsActions.close();

      // Sandbox WebSocket
      wsSandbox = new WebSocket(`${wsBase}/api/ws/sandbox${token}`);
      wsSandbox.onmessage = (e) => {
        try {
          const log = JSON.parse(e.data);
          set(state => ({
            sandboxLogs: [...state.sandboxLogs, { ...log, timestamp: Date.now() }].slice(-100) // keep last 100
          }));
        } catch (_) {}
      };
      wsSandbox.onerror = () => wsSandbox.close();
    };
    open();
  },

  /* ── Polling ── */
  startPolling(ms = 12000) {
    const load = get().load.bind(get());
    load();
    const id = setInterval(load, ms);
    return () => clearInterval(id);
  },

  /* ── Ask Gemini ── */
  async ask(incidentId, question) {
    const res = await fetch(`${API}/api/incidents/${incidentId}/ask`, {
      method:  "POST",
      headers: { "Content-Type": "application/json", ...authHeader() },
      body:    JSON.stringify({ question }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    return data.answer;
  },

  /* ── Action Approval/Rejection ── */
  async approveAction(actionId) {
    const res = await fetch(`${API}/api/actions/${actionId}/approve`, {
      method: "POST", headers: authHeader(),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
  },

  async rejectAction(actionId) {
    const res = await fetch(`${API}/api/actions/${actionId}/reject`, {
      method: "POST", headers: authHeader(),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
  },
}));
