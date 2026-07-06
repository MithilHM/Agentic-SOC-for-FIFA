import { useState, useEffect, useRef } from "react";
import { useNexus } from "../store";

/* ── FIFA infrastructure nodes ── */
const NODES = [
  { id: "ticket",    label: "Official Ticket Portal",  icon: "🎫", x: 16, y: 30, status: "ok",       uptime: "99.2%" },
  { id: "auth",      label: "Authentication Server",   icon: "🔐", x: 50, y: 12, status: "ok",       uptime: "99.5%" },
  { id: "payment",   label: "Payment Gateway",         icon: "💳", x: 50, y: 50, status: "critical", uptime: "97.1%", risk: 92 },
  { id: "streaming", label: "Streaming Platform",      icon: "▶️",  x: 84, y: 30, status: "ok",       uptime: "99.7%" },
  { id: "media",     label: "Media Portal",            icon: "📡", x: 16, y: 62, status: "ok",       uptime: "98.2%" },
  { id: "cloud",     label: "Cloud Infrastructure",    icon: "☁️",  x: 84, y: 62, status: "warning",  uptime: "95.3%", risk: 43 },
  { id: "wifi",      label: "Stadium WiFi",            icon: "📶", x: 16, y: 86, status: "ok",       uptime: "98.9%" },
  { id: "admin",     label: "Admin Console",           icon: "⚙️",  x: 50, y: 82, status: "warning",  uptime: "91.0%", risk: 48 },
  { id: "identity",  label: "Identity Server",         icon: "🔑", x: 84, y: 86, status: "ok",       uptime: "99.6%" },
];

const EDGES = [
  ["ticket","auth"],["ticket","payment"],
  ["auth","payment"],["auth","streaming"],
  ["payment","cloud"],["streaming","cloud"],
  ["media","payment"],["payment","admin"],
  ["wifi","admin"],["admin","identity"],
  ["cloud","identity"],
];

const STATUS_COLOR = { ok: "#22c55e", warning: "#f59e0b", critical: "#ef4444" };
const STATUS_LABEL = { ok: "Healthy", warning: "Warning", critical: "Critical" };

function DigitalTwin({ selectedNode, onSelect }) {
  return (
    <div style={{ position: "relative", width: "100%", height: "100%", minHeight: 300 }}>
      {/* SVG edges */}
      <svg style={{ position: "absolute", inset: 0, width: "100%", height: "100%", pointerEvents: "none" }}>
        {EDGES.map(([a, b]) => {
          const nA = NODES.find(n => n.id === a);
          const nB = NODES.find(n => n.id === b);
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

      {/* Nodes */}
      {NODES.map(node => {
        const isSelected = selectedNode === node.id;
        const c = STATUS_COLOR[node.status];
        return (
          <div
            key={node.id}
            className="dt-node"
            style={{ left: `${node.x}%`, top: `${node.y}%` }}
            onClick={() => onSelect(isSelected ? null : node.id)}
          >
            {/* Beacon for critical */}
            {node.status === "critical" && (
              <div className="beacon" style={{ color: c, inset: -14, width: "calc(100% + 28px)", height: "calc(100% + 28px)" }} />
            )}
            <div className={`dt-node-box ${node.status} ${isSelected ? "selected" : ""}`}>
              <span style={{ fontSize: 18 }}>{node.icon}</span>
              <span style={{ fontSize: 10, fontWeight: 600, color: "var(--color-text-2)", textAlign: "center", lineHeight: 1.3, whiteSpace: "nowrap" }}>
                {node.label}
              </span>
              <span style={{ fontSize: 10, color: STATUS_COLOR[node.status], fontWeight: 500 }}>
                {STATUS_LABEL[node.status]}
              </span>
              {node.uptime && (
                <span style={{ fontSize: 9, color: "var(--color-text-4)" }}>{node.uptime}</span>
              )}
              {node.risk && (
                <span style={{ fontSize: 9, fontWeight: 700, color: "var(--color-red)" }}>Risk {node.risk}/100</span>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

/* ── Asset Detail sidebar ── */
function AssetDetail({ nodeId, incidents }) {
  const node = NODES.find(n => n.id === nodeId);
  if (!node) return (
    <div style={{ padding: 20, color: "var(--color-text-4)", fontSize: 12, textAlign: "center" }}>
      Click an asset node in the digital twin to view its details
    </div>
  );

  const related = incidents.filter(inc => inc.asset?.toLowerCase().includes(node.label.split(" ")[0].toLowerCase()));
  const c = STATUS_COLOR[node.status];

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
        { k: "Current Risk Score",  v: node.risk ? `${node.risk} / 100` : "12 / 100",   vc: node.risk > 70 ? "var(--color-red)" : "var(--color-green-dark)" },
        { k: "Health Status",       v: STATUS_LABEL[node.status],                         vc: c },
        { k: "Open Incidents",      v: String(related.length || 0),                       vc: "var(--color-text)" },
        { k: "Users Impacted",      v: node.status === "critical" ? "41,258" : "1,204",  vc: "var(--color-text)" },
        { k: "Requests / sec",      v: node.status === "critical" ? "2,842" : "1,120",   vc: "var(--color-text)" },
        { k: "Availability",        v: node.uptime,                                       vc: "var(--color-green-dark)" },
        { k: "Last Incident",       v: new Date().toLocaleTimeString(),                   vc: "var(--color-text-3)" },
      ].map(r => (
        <div key={r.k} style={{ display: "flex", justifyContent: "space-between", padding: "6px 0", borderBottom: "1px solid var(--color-border)" }}>
          <span style={{ fontSize: 11, color: "var(--color-text-3)" }}>{r.k}</span>
          <span style={{ fontSize: 11, fontWeight: 600, color: r.vc }}>{r.v}</span>
        </div>
      ))}

      <div style={{ marginTop: 12 }}>
        <div style={{ fontSize: 11, color: "var(--color-text-4)", marginBottom: 6 }}>Related Threats</div>
        <div style={{ display: "flex", gap: 4 }}>
          {["🔴","🟠","🟡"].map((e, i) => (
            <span key={i} style={{ fontSize: 16 }}>{e}</span>
          ))}
          <span style={{ fontSize: 11, color: "var(--color-text-4)", marginLeft: 4 }}>+3</span>
        </div>
      </div>

      <button className="btn btn-secondary" style={{ marginTop: 12, width: "100%", justifyContent: "center", fontSize: 12 }}>
        View Full Details →
      </button>
    </div>
  );
}

/* ── RAG Copilot chat ── */
function AICopilot({ incidents, metrics, health }) {
  const { ask } = useNexus();
  const [msgs, setMsgs]   = useState([{ r: "sys", t: "NEXUS MITRE RAG Copilot online. Ask about FIFA security posture or request an executive briefing." }]);
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
          <div style={{ width: 22, height: 22, borderRadius: 6, background: "linear-gradient(135deg, #8b5cf6, #3b82f6)", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <span style={{ fontSize: 11, color: "#fff" }}>✦</span>
          </div>
          <span style={{ fontSize: 13, fontWeight: 600, color: "var(--color-text)" }}>RAG Copilot</span>
          <span style={{ fontSize: 10, color: "var(--color-text-4)", marginLeft: 2 }}>Powered by MITRE RAG</span>
        </div>
        {/* Prefilled Q example */}
        <div style={{ background: "var(--color-blue-light)", border: "1px solid var(--color-blue-mid)", borderRadius: 8, padding: "8px 12px", fontSize: 12, color: "var(--color-text-2)" }}>
          Why is the Payment Gateway at critical risk?
          <span style={{ float: "right", fontSize: 10, color: "var(--color-text-4)" }}>10:04 AM ✓</span>
        </div>
      </div>

      {/* Messages */}
      <div style={{ flex: 1, overflowY: "auto", padding: "10px 16px", display: "flex", flexDirection: "column", gap: 8 }}>
        {msgs.map((m, i) => (
          <div key={i} className={m.r === "user" ? "msg-user" : m.r === "ai" ? "msg-ai" : "msg-sys"}
               style={{ fontSize: 12 }}>
            {m.r === "ai"   && <div style={{ fontSize: 10, color: "var(--color-purple)", fontWeight: 600, marginBottom: 3 }}>AI Copilot</div>}
            {m.r === "user" && <div style={{ fontSize: 10, color: "var(--color-blue-dark)", fontWeight: 600, marginBottom: 3 }}>You</div>}
            <p style={{ whiteSpace: "pre-wrap", lineHeight: 1.6 }}>{m.t}</p>
          </div>
        ))}
        {busy && (
          <div className="msg-ai" style={{ fontSize: 12 }}>
            <div style={{ fontSize: 10, color: "var(--color-purple)", fontWeight: 600, marginBottom: 3 }}>AI Copilot</div>
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
          <button key={q} onClick={() => setInput(q)}
            style={{
              display: "flex", alignItems: "center", gap: 8,
              width: "100%", padding: "6px 10px", background: "var(--color-surface-2)",
              border: "1px solid var(--color-border)", borderRadius: 6, marginBottom: 4,
              fontSize: 12, color: "var(--color-blue-dark)", cursor: "pointer",
              textAlign: "left", fontFamily: "var(--font-sans)",
            }}>
            <span style={{ color: "var(--color-blue)" }}>✦</span> {q}
          </button>
        ))}
      </div>

      {/* Input */}
      <form onSubmit={send} style={{ display: "flex", gap: 6, padding: "10px 16px", borderTop: "1px solid var(--color-border)", flexShrink: 0 }}>
        <input className="input" style={{ fontSize: 12, flex: 1 }} value={input}
          onChange={e => setInput(e.target.value)}
          placeholder="Ask the AI Copilot…" disabled={busy} />
        <button className="btn btn-primary" type="submit" disabled={!input.trim() || busy}
          style={{ width: 36, height: 36, borderRadius: "50%", padding: 0, display: "flex", alignItems: "center", justifyContent: "center" }}>
          →
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
  const [selNode, setSelNode] = useState("payment");

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
                <span style={{ fontSize: 11, color: "var(--color-text-4)" }}>Live status of critical digital assets</span>
                <button className="btn btn-secondary" style={{ fontSize: 10, padding: "3px 10px" }}>View All Assets →</button>
              </div>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 320px", flex: 1 }}>
              {/* Digital twin diagram (centered) */}
              <div style={{ position: "relative", padding: 16, display: "flex", alignItems: "center", justifyContent: "center", borderRight: "1px solid var(--color-border)" }}>
                <div style={{ width: "100%", height: "100%", maxWidth: 650, maxHeight: 450, position: "relative" }}>
                  <DigitalTwin selectedNode={selNode} onSelect={setSelNode} />
                </div>
              </div>
              {/* Asset detail */}
              <div style={{ overflowY: "auto" }}>
                <AssetDetail nodeId={selNode} incidents={incidents} />
              </div>
            </div>
          </div>
        </div>

        {/* RIGHT — AI Copilot */}
        <div className="card" style={{ display: "flex", flexDirection: "column" }}>
          <AICopilot incidents={incidents} metrics={metrics} health={health} />
        </div>
      </div>
    </div>
  );
}
