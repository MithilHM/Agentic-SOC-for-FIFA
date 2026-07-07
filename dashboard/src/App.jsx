import { useEffect } from "react";
import { useNexus } from "./store";
import PipelineMonitor       from "./dashboards/PipelineMonitor";
import IncidentInvestigation from "./dashboards/IncidentInvestigation";
import FIFAOperations        from "./dashboards/FIFAOperations";
import ThreatAnalytics       from "./dashboards/ThreatAnalytics";
import AgenticCenter         from "./dashboards/AgenticCenter";

/* ── FIFA AI-SIEM Shield mark ── */
function FifaLogo() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
      <path d="M12 2L3 6.5V12c0 5 3.8 9.7 9 11 5.2-1.3 9-6 9-11V6.5L12 2z"
            fill="#09090b" />
      <path d="M9 12l2 2 4-4" stroke="#fafafa" strokeWidth="2.2"
            strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

const TABS = [
  { id: "pipeline",      label: "Pipeline Monitor" },
  { id: "investigation", label: "Incident Investigation" },
  { id: "operations",    label: "FIFA Operations" },
  { id: "analytics",     label: "Threat Analytics" },
  { id: "agentic",       label: "Agent Response Center" },
];

export default function App() {
  const { view, setView, startPolling, connect, connected, incidents, metrics } = useNexus();

  useEffect(() => {
    const stop = startPolling(10000);
    connect();
    return () => {
      stop();
    };
  }, []);

  const p1 = metrics?.p1 ?? incidents.filter(i => i.priority === "P1").length;

  return (
    <div className="app-shell">
      {/* Sidebar navigation */}
      <aside className="sidebar">
        <div className="sidebar-logo">
          <div className="logo-icon">
            <FifaLogo />
          </div>
          <div>
            <div className="sidebar-brand-name">FIFA AI-SIEM</div>
            <div className="sidebar-brand-sub">Security Operations Center</div>
          </div>
        </div>

        <nav className="sidebar-nav">
          <div className="nav-section-label">Dashboards</div>
          {TABS.map(tab => (
            <button
              key={tab.id}
              className={`nav-item ${view === tab.id ? "active" : ""}`}
              onClick={() => setView(tab.id)}
              aria-current={view === tab.id ? "page" : undefined}
            >
              {/* Clean solid SVGs for navigation tabs instead of emojis */}
              <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                {tab.id === "pipeline" && (
                  <>
                    <line x1="22" y1="12" x2="2" y2="12" />
                    <path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z" />
                  </>
                )}
                {tab.id === "investigation" && (
                  <>
                    <circle cx="11" cy="11" r="8" />
                    <line x1="21" y1="21" x2="16.65" y2="16.65" />
                  </>
                )}
                {tab.id === "operations" && (
                  <>
                    <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
                    <line x1="8" y1="21" x2="16" y2="21" />
                    <line x1="12" y1="17" x2="12" y2="21" />
                  </>
                )}
                {tab.id === "analytics" && (
                  <>
                    <line x1="18" y1="20" x2="18" y2="10" />
                    <line x1="12" y1="20" x2="12" y2="4" />
                    <line x1="6" y1="20" x2="6" y2="14" />
                  </>
                )}
                {tab.id === "agentic" && (
                  <>
                    <polygon points="12 2 2 7 12 12 22 7 12 2" />
                    <polyline points="2 17 12 22 22 17" />
                    <polyline points="2 12 12 17 22 12" />
                  </>
                )}
              </svg>
              {tab.label}
              {tab.id === "investigation" && p1 > 0 && (
                <span className="top-nav-badge" style={{ marginLeft: "auto" }}>
                  {p1}
                </span>
              )}
            </button>
          ))}
        </nav>

        {/* Sidebar footer — connection status */}
        <div className="sidebar-footer">
          <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
            <span className={`status-dot ${connected ? "live" : "offline"}`} />
            <span style={{ fontSize: 11, color: connected ? "#6ee7b7" : "var(--color-sidebar-text)", fontWeight: 500 }}>
              {connected ? "Connected" : "Offline"}
            </span>
          </div>
        </div>
      </aside>

      {/* ══════════════════ MAIN CONTENT ══════════════════ */}
      <div className="main-area">

        {/* Top header — breadcrumb + actions */}
        <header className="top-header">
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: 12, color: "var(--color-text-4)" }}>SOC</span>
            <span style={{ fontSize: 12, color: "var(--color-text-4)" }}>/</span>
            <span style={{ fontSize: 12, fontWeight: 600, color: "var(--color-text)" }}>
              {TABS.find(t => t.id === view)?.label}
            </span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "4px 12px", borderRadius: 20,
              background: "var(--color-surface-2)", border: "1px solid var(--color-border)",
              fontSize: 11, color: "var(--color-text-3)", fontWeight: 500 }}>
              <span className="status-dot live" style={{ width: 6, height: 6, display: "inline-block" }} />
              FIFA 2026 — Active Tournament
            </div>
          </div>
        </header>

        {/* Page content */}
        <main style={{ flex: 1, overflowY: "auto", overflowX: "hidden" }}>
          {view === "pipeline"      && <PipelineMonitor />}
          {view === "investigation" && <IncidentInvestigation />}
          {view === "operations"    && <FIFAOperations />}
          {view === "analytics"     && <ThreatAnalytics />}
          {view === "agentic"       && <AgenticCenter />}
        </main>
      </div>
    </div>
  );
}
