import { useEffect } from "react";
import { useSoc } from "./store";
import MetricsRow      from "./components/MetricsRow";
import IncidentLedger  from "./components/IncidentLedger";
import IncidentDetail  from "./components/IncidentDetail";
import AttackTimeline  from "./components/AttackTimeline";
import SeverityDonut   from "./components/SeverityDonut";
import AttackTrends    from "./components/AttackTrends";
import MitreMatrix     from "./components/MitreMatrix";
import AssetMap        from "./components/AssetMap";
import AnalystChat     from "./components/AnalystChat";

export default function App() {
  const { startPolling, connect, connected } = useSoc();

  useEffect(() => {
    startPolling(10000);   // initial load + refresh every 10s
    connect();             // WebSocket live feed
  }, []);                  // intentionally no deps — run once

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-4 flex flex-col gap-5">

      {/* ── Top bar ─────────────────────────────────────────────────────── */}
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-black tracking-tight
                         bg-gradient-to-r from-blue-400 via-violet-400 to-emerald-400
                         bg-clip-text text-transparent">
            FIFA AI-SIEM
          </h1>
          <p className="text-xs text-slate-500 mt-0.5 uppercase tracking-widest">
            AI-Powered Security Operations Center · Code Cup 2026 · PS-8
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className={`text-xs font-semibold px-2 py-1 rounded-full
            ${connected
              ? "bg-emerald-900/50 text-emerald-400 border border-emerald-700"
              : "bg-slate-800 text-slate-500 border border-slate-700"}`}>
            {connected ? "● LIVE" : "○ OFFLINE"}
          </span>
        </div>
      </header>

      {/* ── Metrics row ─────────────────────────────────────────────────── */}
      <MetricsRow />

      {/* ── Main grid ───────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5 flex-1">

        {/* Left column — Incident Ledger + MITRE Matrix */}
        <div className="xl:col-span-2 flex flex-col gap-5">
          <IncidentLedger />
          <MitreMatrix />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <AttackTrends />
            <SeverityDonut />
          </div>
        </div>

        {/* Right column — Detail + Timeline + Chat + Asset Map */}
        <div className="xl:col-span-1 flex flex-col gap-5">
          <IncidentDetail />
          <AttackTimeline />
          <AnalystChat />
          <AssetMap />
        </div>

      </div>
    </div>
  );
}
