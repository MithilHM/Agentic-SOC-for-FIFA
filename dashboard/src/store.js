import { create } from "zustand";

const API = import.meta.env.VITE_API || "http://localhost:8080";
// Optional API key — sent on the WS handshake as ?token= (browsers can't set
// WS headers). Empty when the backend runs with auth disabled.
const API_KEY = import.meta.env.VITE_API_KEY || "";

export const useSoc = create((set, get) => ({
  incidents: [],
  metrics: {},
  alerts: [],
  trends: [],       // [{time, Phishing, BruteForce, …}]
  selected: null,
  connected: false,

  // ── Load all data from API ─────────────────────────────────────────────
  async load() {
    try {
      const [incidents, metrics] = await Promise.all([
        fetch(`${API}/api/incidents`).then(r => r.json()),
        fetch(`${API}/api/metrics`).then(r => r.json()),
      ]);
      set({ incidents, metrics });
    } catch (e) {
      console.warn("API load failed — is the backend running?", e.message);
    }
  },

  // ── WebSocket live feed ────────────────────────────────────────────────
  connect() {
    if (get().connected) return;
    const wsUrl = API.replace(/^http/, "ws");
    let ws;

    const tokenQS = API_KEY ? `?token=${encodeURIComponent(API_KEY)}` : "";
    const open = () => {
      ws = new WebSocket(`${wsUrl}/api/ws/incidents${tokenQS}`);
      ws.onopen    = () => { set({ connected: true }); };
      ws.onmessage = (e) => {
        try {
          const inc  = JSON.parse(e.data);
          const rest = get().incidents.filter(x => x.incident_id !== inc.incident_id);
          set({ incidents: [inc, ...rest] });
          // keep metrics.open_incidents in sync
          set(state => ({
            metrics: { ...state.metrics, open_incidents: rest.length + 1 }
          }));
        } catch (_) {}
      };
      ws.onclose = () => {
        set({ connected: false });
        setTimeout(open, 3000);   // auto-reconnect
      };
      ws.onerror = () => ws.close();
    };
    open();
  },

  // ── Select incident ───────────────────────────────────────────────────
  select(id) { set({ selected: id }); },

  // ── Periodic refresh ─────────────────────────────────────────────────
  startPolling(intervalMs = 15000) {
    const load = get().load.bind(get());
    load();
    setInterval(load, intervalMs);
  },
}));
