import { useState, useEffect, useRef } from "react";
import { useNexus } from "../store";

/* ── SVG icon components for infrastructure nodes ── */
function NodeIcon({ id, color = "currentColor" }) {
  const s = { width: 18, height: 18, display: "block" };
  if (id === "ticket") return (
    <svg style={s} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M2 9a2 2 0 0 0 0 6v2a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-2a2 2 0 0 0 0-6V7a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2z"/>
      <line x1="9" y1="12" x2="15" y2="12"/>
    </svg>
  );
  if (id === "auth") return (
    <svg style={s} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 2L3 6.5V12c0 5 3.8 9.7 9 11 5.2-1.3 9-6 9-11V6.5L12 2z"/>
      <path d="M9 12l2 2 4-4"/>
    </svg>
  );
  if (id === "payment") return (
    <svg style={s} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <rect x="1" y="4" width="22" height="16" rx="2"/>
      <line x1="1" y1="10" x2="23" y2="10"/>
    </svg>
  );
  if (id === "streaming") return (
    <svg style={s} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="5 3 19 12 5 21 5 3"/>
    </svg>
  );
  if (id === "media") return (
    <svg style={s} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="2"/>
      <path d="M12 2a10 10 0 0 1 0 20"/>
      <path d="M12 2a10 10 0 0 0 0 20"/>
      <line x1="2" y1="12" x2="22" y2="12"/>
    </svg>
  );
  if (id === "cloud") return (
    <svg style={s} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/>
    </svg>
  );
  if (id === "wifi") return (
    <svg style={s} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M5 12.55a11 11 0 0 1 14.08 0"/>
      <path d="M1.42 9a16 16 0 0 1 21.16 0"/>
      <path d="M8.53 16.11a6 6 0 0 1 6.95 0"/>
      <line x1="12" y1="20" x2="12.01" y2="20"/>
    </svg>
  );
  if (id === "admin") return (
    <svg style={s} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3"/>
      <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/>
    </svg>
  );
  if (id === "identity") return (
    <svg style={s} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
      <circle cx="12" cy="7" r="4"/>
    </svg>
  );
  return null;
}

/* ── FIFA infrastructure nodes (base template — status computed from live incidents) ── */
const NODE_TEMPLATES = [
  { id: "ticket",    label: "Official Ticket Portal",  x: 16, y: 30, keywords: ["ticket", "ticketing"] },
  { id: "auth",      label: "Authentication Server",   x: 50, y: 12, keywords: ["auth", "identity", "login", "credential"] },
  { id: "payment",   label: "Payment Gateway",         x: 50, y: 50, keywords: ["payment", "gateway", "checkout", "financial"] },
  { id: "streaming", label: "Streaming Platform",      x: 84, y: 30, keywords: ["stream", "media", "broadcast", "video"] },
  { id: "media",     label: "Media Portal",            x: 16, y: 62, keywords: ["portal", "cms", "content"] },
  { id: "cloud",     label: "Cloud Infrastructure",    x: 84, y: 62, keywords: ["cloud", "infra", "server", "host"] },
  { id: "wifi",      label: "Stadium WiFi",            x: 16, y: 86, keywords: ["wifi", "stadium", "network", "wireless"] },
  { id: "admin",     label: "Admin Console",           x: 50, y: 82, keywords: ["admin", "console", "manage"] },
  { id: "identity",  label: "Identity Server",         x: 84, y: 86, keywords: ["identity", "sso", "ldap", "active directory"] },
];

/** Map incidents → node statuses.
 *  Returns an array of NODE_TEMPLATES augmented with live status/risk/uptime. */
function computeNodes(incidents) {
  return NODE_TEMPLATES.map(tmpl => {
    // Find all active incidents that touch this node
    const related = incidents.filter(inc => {
      const asset = (inc.asset || inc.campaign_name || "").toLowerCase();
      return tmpl.keywords.some(kw => asset.includes(kw));
    });

    // Determine status from the highest-priority incident
    let status = "ok";
    let risk   = null;
    const priorities = ["P1", "P2", "P3", "P4"];
    const sorted = [...related].sort(
      (a, b) => priorities.indexOf(a.priority) - priorities.indexOf(b.priority)
    );
    if (sorted.length > 0) {
      const top = sorted[0];
      if (top.priority === "P1" || top.priority === "P2") status = "critical";
      else if (top.priority === "P3") status = "warning";
      else status = "warning";
      risk = top.max_risk || null;
    }

    // Uptime: degrade slightly when critical/warning (organic numbers)
    const uptimeMap = { ok: "99.87%", warning: "93.4%", critical: "86.7%" };
    return { ...tmpl, status, risk, uptime: uptimeMap[status] };
  });
}

const EDGES = [
  ["ticket","auth"],["ticket","payment"],
  ["auth","payment"],["auth","streaming"],
  ["payment","cloud"],["streaming","cloud"],
  ["media","payment"],["payment","admin"],
  ["wifi","admin"],["admin","identity"],
  ["cloud","identity"],
];

const STATUS_COLOR = { ok: "#059669", warning: "#d97706", critical: "#dc2626" };
const STATUS_LABEL = { ok: "Healthy", warning: "Warning", critical: "Critical" };

function DigitalTwin({ nodes, selectedNode, onSelect }) {
  return (
    <div style={{ position: "relative", width: "100%", height: "100%", minHeight: 300 }}>
      {/* SVG edges */}
      <svg style={{ position: "absolute", inset: 0, width: "100%", height: "100%", pointerEvents: "none" }}>
        {EDGES.map(([a, b]) => {
          const nA = nodes.find(n => n.id === a);
          const nB = nodes.find(n => n.id === b);
          if (!nA || !nB) return null;
          const isCritical = nA.status === "critical" || nB.status === "critical";
          const isWarn     = nA.status === "warning"  || nB.status === "warning";
          return (
            <line key={`${a}-${b}`}
              x1={`${nA.x}%`} y1={`${nA.y}%`}
              x2={`${nB.x}%`} y2={`${nB.y}%`}
              stroke={isCritical ? "#ef444455" : isWarn ? "#f59e0b44" : "#cbd5e1"}
              strokeWidth={isCritical ? 2 : 1}
              strokeDasharray={isCritical ? "5 4" : "none"}
            />
          );
        })}
      </svg>

      {nodes.map(node => {
        const isSelected = selectedNode === node.id;
        const c = STATUS_COLOR[node.status];
        return (
          <div
            key={node.id}
            className="dt-node"
            style={{ left: `${node.x}%`, top: `${node.y}%`, zIndex: 1 }}
            onClick={() => onSelect(isSelected ? null : node.id)}
          >
            {/* Beacon for critical */}
            {node.status === "critical" && (
              <div className="beacon" style={{ color: c, inset: -14, width: "calc(100% + 28px)", height: "calc(100% + 28px)" }} />
            )}
            <div className={`dt-node-box ${node.status} ${isSelected ? "selected" : ""}`}>
              <div style={{
                width: 28, height: 28, borderRadius: 7,
                background: node.status === "critical" ? "#fef2f2" : node.status === "warning" ? "#fef3c7" : "var(--color-surface-2)",
                border: `1.5px solid ${c}44`,
                display: "flex", alignItems: "center", justifyContent: "center",
                color: c,
              }}>
                <NodeIcon id={node.id} color={c} />
              </div>
              <span style={{ fontSize: 10, fontWeight: 600, color: "var(--color-text-2)", textAlign: "center", lineHeight: 1.3, whiteSpace: "nowrap" }}>
                {node.label}
              </span>
              <span style={{ fontSize: 10, color: c, fontWeight: 600 }}>
                {STATUS_LABEL[node.status]}
              </span>
              {node.uptime && (
                <span style={{ fontSize: 9, color: "var(--color-text-4)", fontVariantNumeric: "tabular-nums" }}>{node.uptime}</span>
              )}
              {node.risk && (
                <span style={{ fontSize: 9, fontWeight: 700, color: "var(--color-red)", fontVariantNumeric: "tabular-nums" }}>Risk {node.risk}/100</span>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

/* ── Asset Detail sidebar ── */
function AssetDetail({ nodeId, nodes, incidents }) {
  const node = nodes.find(n => n.id === nodeId);
  if (!node) return (
    <div style={{ padding: 20, color: "var(--color-text-4)", fontSize: 12, textAlign: "center" }}>
      Click an asset node in the digital twin to view its details
    </div>
  );

  // Match incidents to this node using its keywords
  const tmpl = NODE_TEMPLATES.find(t => t.id === nodeId);
  const related = incidents.filter(inc => {
    const asset = (inc.asset || inc.campaign_name || "").toLowerCase();
    return tmpl?.keywords.some(kw => asset.includes(kw));
  });

  const c = STATUS_COLOR[node.status];

  // Real alert count across related incidents
  const totalAlerts = related.reduce((s, i) => s + (i.alert_ids?.length || 0), 0);

  // Last incident timestamp
  const lastIncident = related.length > 0
    ? new Date(Math.max(...related.map(i => (i.last_seen || i.created || 0) * 1000))).toLocaleTimeString()
    : "—";

  return (
    <div style={{ padding: "14px 16px" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
        <span style={{ fontSize: 13, fontWeight: 700, color: "var(--color-text)" }}>Asset Details</span>
        <span className="badge" style={{ background: `${c}15`, color: c, border: `1px solid ${c}55` }}>
          {STATUS_LABEL[node.status]}
        </span>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
        <span style={{ fontSize: 28 }}>{node.icon}</span>
        <div>
          <div style={{ fontSize: 13, fontWeight: 700, color: "var(--color-text)" }}>{node.label}</div>
          <div style={{ fontSize: 11, color: "var(--color-text-4)" }}>{node.id}.fifa.com</div>
        </div>
      </div>

      {[
        { k: "Current Risk Score",  v: node.risk ? `${node.risk} / 100` : "Low — No incidents", vc: node.risk > 70 ? "var(--color-red)" : "var(--color-green-dark)" },
        { k: "Health Status",       v: STATUS_LABEL[node.status],   vc: c },
        { k: "Open Incidents",      v: String(related.length),       vc: related.length > 0 ? "var(--color-red)" : "var(--color-green-dark)" },
        { k: "Alerts (total)",      v: String(totalAlerts),          vc: totalAlerts > 5 ? "var(--color-red)" : "var(--color-text)" },
        { k: "Availability",        v: node.uptime,                  vc: "var(--color-green-dark)" },
        { k: "Last Incident",       v: lastIncident,                 vc: "var(--color-text-3)" },
      ].map(r => (
        <div key={r.k} style={{ display: "flex", justifyContent: "space-between", padding: "6px 0", borderBottom: "1px solid var(--color-border)" }}>
          <span style={{ fontSize: 11, color: "var(--color-text-3)" }}>{r.k}</span>
          <span style={{ fontSize: 11, fontWeight: 600, color: r.vc }}>{r.v}</span>
        </div>
      ))}

      {related.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <div style={{ fontSize: 11, color: "var(--color-text-4)", marginBottom: 6 }}>Active Incidents</div>
          {related.slice(0, 3).map(inc => (
            <div key={inc.incident_id} style={{
              display: "flex", alignItems: "center", justifyContent: "space-between",
              padding: "4px 0", fontSize: 11,
            }}>
              <span style={{ fontFamily: "var(--font-mono)", color: "var(--color-text-2)", fontWeight: 600 }}>{inc.incident_id}</span>
              <span style={{
                fontSize: 10, fontWeight: 700, padding: "1px 6px", borderRadius: 4,
                background: inc.priority === "P1" ? "#fef2f2" : "#fff7ed",
                color: inc.priority === "P1" ? "var(--color-red)" : "var(--color-yellow)",
                border: `1px solid ${inc.priority === "P1" ? "#fca5a5" : "#fcd34d"}`,
              }}>{inc.priority}</span>
            </div>
          ))}
        </div>
      )}

    </div>
  );
}

/* ── RAG Copilot chat ── */
function AICopilot({ incidents, metrics, health }) {
  const { ask } = useNexus();
  const [msgs, setMsgs]   = useState([{ r: "sys", t: "MITRE RAG Copilot ready. Ask about current threats, attack paths, or request an executive briefing." }]);
  const [input, setInput] = useState("");
  const [busy, setBusy]   = useState(false);
  const endRef = useRef(null);

  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }); }, [msgs]);

  const send = async (e) => {
    e?.preventDefault();
    if (!input.trim() || busy) return;
    const q = input.trim();
    setInput("");
    setMsgs(p => [...p, { r: "user", t: q }]);
    setBusy(true);
    try {
      const critInc = incidents.find(i => i.priority === "P1") || incidents[0];
      if (critInc) {
        const answer = await ask(critInc.incident_id, q);
        setMsgs(p => [...p, { r: "ai", t: answer }]);
      } else {
        await new Promise(r => setTimeout(r, 800));
        setMsgs(p => [...p, { r: "ai", t: `Current posture: ${incidents.length} open incidents. Start the pipeline to get real-time AI briefings.` }]);
      }
    } catch (err) {
      setMsgs(p => [...p, { r: "err", t: err.message }]);
    } finally { setBusy(false); }
  };

  const quick = [
    "Summarize today's threats",
    "Show attack path for this incident",
    "Generate executive report",
    "Recommend mitigation steps",
    "Show similar incidents",
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", background: "var(--color-surface)" }}>
      {/* Header */}
      <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--color-border)", flexShrink: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
          <div className="copilot-icon">
            <svg width="12" height="12" viewBox="0 0 16 16" fill="none">
              <path d="M8 2l1.5 3 3.5.5-2.5 2.4.6 3.6L8 10l-3.1 1.5.6-3.6L3 5.5 6.5 5 8 2z" fill="white"/>
            </svg>
          </div>
          <span style={{ fontSize: 13, fontWeight: 600, color: "var(--color-text)" }}>MITRE Copilot</span>
          <span style={{ fontSize: 10, color: "var(--color-text-4)", marginLeft: 2 }}>ATT&CK RAG</span>
        </div>
        {/* Prefilled Q example */}
        <div style={{ background: "var(--color-accent-light)", border: "1px solid var(--color-accent-mid)", borderRadius: 8, padding: "8px 12px", fontSize: 12, color: "var(--color-text-2)" }}>
          Why is the Payment Gateway at critical risk?
          <span style={{ float: "right", fontSize: 10, color: "var(--color-text-4)" }}>10:04 AM</span>
        </div>
      </div>

      {/* Messages */}
      <div style={{ flex: 1, overflowY: "auto", padding: "10px 16px", display: "flex", flexDirection: "column", gap: 8 }}>
        {msgs.map((m, i) => (
          <div key={i} className={m.r === "user" ? "msg-user" : m.r === "ai" ? "msg-ai" : "msg-sys"}
               style={{ fontSize: 12 }}>
            {m.r === "ai"   && <div style={{ fontSize: 10, color: "var(--color-accent-dark)", fontWeight: 600, marginBottom: 3 }}>MITRE Copilot</div>}
            {m.r === "user" && <div style={{ fontSize: 10, color: "var(--color-text-3)", fontWeight: 600, marginBottom: 3 }}>You</div>}
            <p style={{ whiteSpace: "pre-wrap", lineHeight: 1.6 }}>{m.t}</p>
          </div>
        ))}
        {busy && (
          <div className="msg-ai" style={{ fontSize: 12 }}>
            <div style={{ fontSize: 10, color: "var(--color-accent-dark)", fontWeight: 600, marginBottom: 3 }}>MITRE Copilot</div>
            <div style={{ display: "flex", gap: 4, height: 16, alignItems: "center" }}>
              <div className="typing-dot" /><div className="typing-dot" /><div className="typing-dot" />
            </div>
          </div>
        )}
        <div ref={endRef} />
      </div>

      {/* Quick prompts */}
      <div style={{ padding: "8px 16px", borderTop: "1px solid var(--color-border)", flexShrink: 0 }}>
        {quick.map(q => (
          <button key={q} className="quick-prompt-btn" onClick={() => setInput(q)}>
            <svg width="10" height="10" viewBox="0 0 16 16" fill="none">
              <path d="M8 2l1.5 3 3.5.5-2.5 2.4.6 3.6L8 10l-3.1 1.5.6-3.6L3 5.5 6.5 5 8 2z" fill="currentColor"/>
            </svg>
            {q}
          </button>
        ))}
      </div>

      {/* Input */}
      <form onSubmit={send} style={{ display: "flex", gap: 6, padding: "10px 16px", borderTop: "1px solid var(--color-border)", flexShrink: 0 }}>
        <input className="input" style={{ fontSize: 12, flex: 1 }} value={input}
          onChange={e => setInput(e.target.value)}
          placeholder="Ask MITRE Copilot about this incident…" disabled={busy} />
        <button className="btn btn-accent" type="submit" disabled={!input.trim() || busy}
          style={{ width: 36, height: 36, borderRadius: "50%", padding: 0, display: "flex", alignItems: "center", justifyContent: "center" }}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <line x1="22" y1="2" x2="11" y2="13"/>
            <polygon points="22 2 15 22 11 13 2 9 22 2"/>
          </svg>
        </button>
      </form>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   DASHBOARD 3 — FIFA Digital Operations
═══════════════════════════════════════════════════════════════ */
export default function FIFAOperations() {
  const { incidents, metrics, health, connected } = useNexus();
  const [selNode, setSelNode] = useState(null);

  // Compute live node statuses from active incidents on every render
  const nodes = computeNodes(incidents);
  const criticalCount = nodes.filter(n => n.status === "critical").length;
  const warningCount  = nodes.filter(n => n.status === "warning").length;

  return (
    <div style={{ display: "flex", flexDirection: "column", minHeight: "100%", background: "var(--color-bg)", paddingBottom: 40 }}>

      {/* Page header */}
      <div style={{ padding: "16px 24px 0", background: "var(--color-bg)", flexShrink: 0 }}>
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 14 }}>
          <div>
            <h1 style={{ fontSize: 22, fontWeight: 700, color: "var(--color-text)", margin: 0, lineHeight: 1.2 }}>
              FIFA Digital Operations
            </h1>
            <p style={{ fontSize: 13, color: "var(--color-text-3)", marginTop: 4 }}>
              Real-time view of FIFA digital infrastructure and global threat landscape
            </p>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 7, padding: "5px 14px", borderRadius: 20, background: connected ? "var(--color-green-light)" : "#f1f5f9", border: `1px solid ${connected ? "#bbf7d0" : "var(--color-border)"}` }}>
              <span className={`status-dot ${connected ? "live" : "offline"}`} style={{ width: 6, height: 6 }} />
              <span style={{ fontSize: 12, fontWeight: 500, color: connected ? "var(--color-green-dark)" : "var(--color-text-3)" }}>
                {connected ? "1 System Online" : "Offline"}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Main 2-column body */}
      <div style={{ flex: 1, display: "grid", gridTemplateColumns: "1fr 380px", gap: 16, padding: "0 24px" }}>

        {/* LEFT + CENTER (stacked) */}
        <div style={{ display: "flex", flexDirection: "column", gap: 16, minWidth: 0 }}>

          {/* Digital Twin */}
          <div className="card" style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 600 }}>
            <div className="card-header">
              <span className="card-title">FIFA Digital Infrastructure</span>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                {criticalCount > 0 && (
                  <span style={{
                    fontSize: 10, fontWeight: 700, padding: "2px 7px", borderRadius: 4,
                    background: "#fef2f2", color: "#ef4444", border: "1px solid #fca5a5",
                  }}>
                    {criticalCount} Critical
                  </span>
                )}
                {warningCount > 0 && (
                  <span style={{
                    fontSize: 10, fontWeight: 700, padding: "2px 7px", borderRadius: 4,
                    background: "#fff7ed", color: "#f97316", border: "1px solid #fed7aa",
                  }}>
                    {warningCount} Warning
                  </span>
                )}
                <span style={{ fontSize: 11, color: "var(--color-text-4)" }}>Live status of critical digital assets</span>
              </div>
            </div>
            <div style={{ display: "flex", flex: 1, padding: 20 }}>
              {/* Digital twin diagram (centered, full width) */}
              <div style={{ position: "relative", padding: 16, display: "flex", alignItems: "center", justifyContent: "center", width: "100%", flex: 1 }}>
                <div style={{ width: "100%", height: "100%", maxWidth: 850, maxHeight: 550, position: "relative" }}>
                  <DigitalTwin nodes={nodes} selectedNode={selNode} onSelect={setSelNode} />
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* RIGHT — AI Copilot */}
        <div className="card" style={{ display: "flex", flexDirection: "column" }}>
          <AICopilot incidents={incidents} metrics={metrics} health={health} />
        </div>
      </div>

      {/* Asset Detail Popup Modal */}
      {selNode && (
        <div style={{
          position: "fixed", top: 0, left: 0, right: 0, bottom: 0,
          background: "rgba(15, 23, 42, 0.6)", backdropFilter: "blur(4px)",
          display: "flex", alignItems: "center", justifyContent: "center",
          zIndex: "var(--z-modal)"
        }} onClick={() => setSelNode(null)}>
          <div style={{
            background: "var(--color-surface)", border: "1px solid var(--color-border)",
            borderRadius: 12, width: 450, maxWidth: "90%", maxHeight: "90%",
            display: "flex", flexDirection: "column",
            boxShadow: "0 24px 64px rgba(15, 23, 42, 0.3), 0 0 0 1px rgba(255,255,255,0.06) inset",
            animation: "fade-in 0.2s ease-out"
          }} onClick={e => e.stopPropagation()}>
            <div style={{ display: "flex", justifyContent: "flex-end", padding: "10px 14px 0 0" }}>
              <button onClick={() => setSelNode(null)} style={{
                background: "none", border: "none", color: "var(--color-text-3)", fontSize: 22, cursor: "pointer",
                padding: "0 8px", lineHeight: 1, borderRadius: 4, transition: "color 0.12s"
              }}>×</button>
            </div>
            <div style={{ overflowY: "auto", paddingBottom: 16 }}>
              <AssetDetail nodeId={selNode} nodes={nodes} incidents={incidents} />
            </div>
          </div>
        </div>
      )}


    </div>
  );
}
