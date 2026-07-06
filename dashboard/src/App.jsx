import { useEffect } from "react";
import { useNexus } from "./store";
import PipelineMonitor       from "./dashboards/PipelineMonitor";
import IncidentInvestigation from "./dashboards/IncidentInvestigation";
import FIFAOperations        from "./dashboards/FIFAOperations";

/* ── FIFA AI-SIEM Logo mark ── */
function FifaLogo() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
      <path d="M12 2L3 6.5V12c0 5 3.8 9.7 9 11 5.2-1.3 9-6 9-11V6.5L12 2z"
            fill="white" fillOpacity="0.95" />
      <path d="M9 12l2 2 4-4" stroke="#1e3a8a" strokeWidth="2.2"
            strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

const TABS = [
  { id: "pipeline",      label: "Pipeline Monitor" },
  { id: "investigation", label: "Incident Investigation" },
  { id: "operations",    label: "FIFA Operations" },
];

export default function App() {
  const { view, setView, startPolling, connect, connected, incidents, metrics } = useNexus();

  useEffect(() => {
    const stop = startPolling(10000);
    connect();
    return stop;
  }, []); // eslint-disable-line

  const p1 = metrics?.p1 || incidents.filter(i => i.priority === "P1").length;

  return (
    <div style={{ height: "100vh", display: "flex", flexDirection: "column", overflow: "hidden", background: "var(--color-bg)" }}>

      {/* ══════════════════ TOP NAV BAR ══════════════════ */}
      <header style={{
        height: 52,
        background: "var(--color-surface)",
        borderBottom: "1px solid var(--color-border)",
        display: "flex",
        alignItems: "center",
        padding: "0 24px",
        gap: 0,
        flexShrink: 0,
        zIndex: 20,
      }}>
        {/* Brand */}
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginRight: 32 }}>
          <div style={{
            width: 30, height: 30,
            borderRadius: 7,
            background: "linear-gradient(135deg, #1e3a8a, #3b82f6)",
            display: "flex", alignItems: "center", justifyContent: "center",
            flexShrink: 0,
          }}>
            <FifaLogo />
          </div>
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, color: "var(--color-text)", lineHeight: 1.2 }}>
              FIFA AI-SIEM
            </div>
            <div style={{ fontSize: 10, color: "var(--color-text-4)" }}>
              Security Operations Center
            </div>
          </div>
        </div>

        {/* Divider */}
        <div style={{ width: 1, height: 24, background: "var(--color-border)", marginRight: 20 }} />

        {/* Dashboard tabs */}
        <nav style={{ display: "flex", gap: 2 }}>
          {TABS.map(tab => (
            <button
              key={tab.id}
              onClick={() => setView(tab.id)}
              style={{
                padding: "6px 16px",
                borderRadius: 6,
                border: "none",
                background: view === tab.id ? "var(--color-blue-light)" : "transparent",
                color: view === tab.id ? "var(--color-blue-dark)" : "var(--color-text-3)",
                fontFamily: "var(--font-sans)",
                fontSize: 13,
                fontWeight: view === tab.id ? 600 : 500,
                cursor: "pointer",
                transition: "all 0.12s",
                display: "flex",
                alignItems: "center",
                gap: 6,
                position: "relative",
              }}
            >
              {tab.label}
              {tab.id === "investigation" && p1 > 0 && (
                <span style={{
                  background: "var(--color-red)", color: "#fff",
                  borderRadius: "50%", width: 17, height: 17,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontSize: 10, fontWeight: 700,
                  animation: "blink-dot 0.9s ease-in-out infinite",
                }}>
                  {p1}
                </span>
              )}
            </button>
          ))}
        </nav>
      </header>

      {/* ══════════════════ PAGE CONTENT ══════════════════ */}
      <main style={{ flex: 1, overflowY: "auto", overflowX: "hidden" }}>
        {view === "pipeline"      && <PipelineMonitor />}
        {view === "investigation" && <IncidentInvestigation />}
        {view === "operations"    && <FIFAOperations />}
      </main>
    </div>
  );
}

