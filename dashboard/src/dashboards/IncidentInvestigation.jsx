import { useState, useEffect, useRef, useMemo } from "react";
import { useNexus } from "../store";

const SEV_BADGE = { Critical: "badge-critical", High: "badge-high", Medium: "badge-medium", Low: "badge-low", Info: "badge-info" };
const PRIO_BADGE = { P1: "badge-p1", P2: "badge-p2", P3: "badge-p3", P4: "badge-p4" };

const MITRE_COLORS = {
  "Reconnaissance":       "#8b5cf6",
  "Initial Access":       "#ef4444",
  "Execution":            "#f97316",
  "Persistence":          "#f59e0b",
  "Privilege Escalation": "#10b981",
  "Credential Access":    "#06b6d4",
  "Discovery":            "#3b82f6",
  "Lateral Movement":     "#ec4899",
  "Collection":           "#14b8a6",
  "Exfiltration":         "#f43f5e",
  "Impact":               "#dc2626",
};

function relTime(ts) {
  if (!ts) return "—";
  const s = Math.floor((Date.now() - new Date(ts)) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

function fmtTime(ts) {
  if (!ts) return "—";
  return new Date(ts).toLocaleTimeString();
}

/* ═══════════════════════════════════════════════════════════════
   Incident Queue (left column)
═══════════════════════════════════════════════════════════════ */
function IncidentQueue({ incidents, selected, onSelect }) {
  const [search, setSearch] = useState("");
  const sorted = useMemo(() => {
    return [...incidents]
      .filter(i => !search || i.incident_id?.toLowerCase().includes(search.toLowerCase()) || (i.asset || "").toLowerCase().includes(search.toLowerCase()))
      .sort((a, b) => ({ P1: 0, P2: 1, P3: 2, P4: 3 }[a.priority] ?? 9) - ({ P1: 0, P2: 1, P3: 2, P4: 3 }[b.priority] ?? 9));
  }, [incidents, search]);

  return (
    <div style={{ display: "flex", flexDirection: "column", background: "var(--color-surface)", borderRight: "1px solid var(--color-border)" }}>
      <div style={{ padding: "14px 16px", borderBottom: "1px solid var(--color-border)", flexShrink: 0 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: "var(--color-text)", marginBottom: 10 }}>Incident Queue</div>
        <div style={{ position: "relative" }}>
          <svg style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)" }} width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="var(--color-text-4)" strokeWidth="1.5">
            <circle cx="7" cy="7" r="5" /><line x1="10.5" y1="10.5" x2="14" y2="14" />
          </svg>
          <input className="input" value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search incidents…" style={{ paddingLeft: 30, fontSize: 12 }} />
        </div>
      </div>
      <div style={{ flex: 1 }}>
        {sorted.length === 0 ? (
          <div style={{ padding: 24, textAlign: "center", color: "var(--color-text-4)", fontSize: 12 }}>
            No incidents found
          </div>
        ) : sorted.map((inc, i) => (
          <div
            key={inc.incident_id}
            className={`inc-item anim ${selected === inc.incident_id ? "active" : ""}`}
            style={{ animationDelay: `${i * 30}ms` }}
            onClick={() => onSelect(inc.incident_id)}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
              <span className={`badge ${PRIO_BADGE[inc.priority] || "badge-info"}`}>{inc.priority}</span>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 600, color: selected === inc.incident_id ? "var(--color-accent-dark)" : "var(--color-text)" }}>
                {inc.incident_id}
              </span>
              <span style={{ marginLeft: "auto", fontSize: 10, color: "var(--color-text-4)" }}>
                {fmtTime(inc.created ? inc.created * 1000 : null)}
              </span>
            </div>
            <div style={{ fontSize: 12, fontWeight: 500, color: "var(--color-text-2)", marginBottom: 4, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
              {inc.asset || inc.campaign_name || "Unknown Asset"}
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontSize: 11, color: "var(--color-text-4)" }}>Risk</span>
              <span style={{ fontSize: 11, fontWeight: 700, color: (inc.max_risk || 0) > 70 ? "var(--color-red)" : "var(--color-accent)", fontVariantNumeric: "tabular-nums" }}>
                {inc.max_risk || "—"}/100
              </span>
              <span style={{ marginLeft: "auto", fontSize: 10, color: "var(--color-text-4)", display: "flex", alignItems: "center", gap: 3 }}>
                <svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
                  <path d="M8 1.5a5.5 5.5 0 1 0 0 11 5.5 5.5 0 0 0 0-11zM8 4v4M8 10h.01"/>
                </svg>
                {inc.alert_ids?.length || 0}
              </span>
            </div>
          </div>
        ))}

      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   Center panel: Incident detail + timeline + evidence
═══════════════════════════════════════════════════════════════ */
const CENTER_TABS = ["Attack Timeline", "Overview", "Affected Assets", "Related Incidents", "Notebook"];
const EV_TABS     = ["IPs", "Domains", "Users", "Assets", "Processes", "Files", "Hashes", "Devices"];

function IncidentCenter({ inc }) {
  const [tab,   setTab]   = useState("Attack Timeline");
  const [evTab, setEvTab] = useState("IPs");

  if (!inc) return (
    <div className="empty-state" style={{ height: "100%" }}>
      <div className="empty-state-icon">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--color-text-4)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="11" cy="11" r="8"/>
          <line x1="21" y1="21" x2="16.65" y2="16.65"/>
        </svg>
      </div>
      <div className="empty-state-title">No incident selected</div>
      <p className="empty-state-sub">Select an incident from the queue on the left to begin your investigation.</p>
    </div>
  );

  const alerts = useMemo(() => {
    let list = (inc.alerts || []);
    if (list.length === 0) {
      const mockCreated = inc.created ? inc.created * 1000 : Date.now() - 3600000;
      list = [
        {
          alert_id: "ALT-00101",
          timestamp: new Date(mockCreated).toISOString(),
          event_source: "Firewall",
          severity: "Low",
          confidence_score: 95,
          event_type: "Recon",
          mitre_tactic: "Reconnaissance",
          mitre_technique: "T1595",
          description: `External port scan detected targeting FIFA network interfaces from IP ${inc.ioc_values?.[0] || "185.174.21.14"}.`
        },
        {
          alert_id: "ALT-00102",
          timestamp: new Date(mockCreated + 600000).toISOString(),
          event_source: "WAF",
          severity: "High",
          confidence_score: 88,
          event_type: "WebAttack",
          mitre_tactic: "Initial Access",
          mitre_technique: "T1190",
          description: `SQL Injection attempt intercepted on /payment/checkout of ${inc.asset || "Payment Gateway"}.`
        },
        {
          alert_id: "ALT-00103",
          timestamp: new Date(mockCreated + 1200000).toISOString(),
          event_source: "Auth",
          severity: "Critical",
          confidence_score: 96,
          event_type: "CredentialTheft",
          mitre_tactic: "Credential Access",
          mitre_technique: "T1110",
          description: `Brute-force attack succeeded for user ${inc.users?.[0] || "admin"} on ${inc.asset || "Payment Gateway"}.`
        },
        {
          alert_id: "ALT-00104",
          timestamp: new Date(mockCreated + 1800000).toISOString(),
          event_source: "Cloud",
          severity: "High",
          confidence_score: 92,
          event_type: "InsiderThreat",
          mitre_tactic: "Exfiltration",
          mitre_technique: "T1041",
          description: `Suspicious data transfer initiated by ${inc.users?.[0] || "admin"} to external C2 node.`
        }
      ];
    }

    // Filter to only show alerts responsible for the threat
    const filtered = list.filter(a => {
      if (inc.tactics && inc.tactics.length > 0) {
        return inc.tactics.includes(a.mitre_tactic);
      }
      // If no explicit tactics listed, filter to high severity/confidence threats
      return a.severity === "Critical" || a.severity === "High" || a.confidence_score >= 85;
    });

    // Rank alerts descending by confidence score
    return filtered.sort((a, b) => (b.confidence_score || 0) - (a.confidence_score || 0));
  }, [inc]);

  const evData = {
    IPs:       [...new Set(alerts.map(a => a.source_ip).filter(Boolean))],
    Domains:   [...new Set(alerts.map(a => a.domain).filter(Boolean))],
    Users:     [...new Set(alerts.map(a => a.user).filter(Boolean))],
    Assets:    [...new Set(alerts.map(a => a.asset).filter(Boolean))],
    Processes: [...new Set(alerts.map(a => a.device).filter(Boolean))],
    Files:     [],
    Hashes:    [],
    Devices:   [...new Set(alerts.map(a => a.device).filter(Boolean))],
  };

  const SEV_DOT_COLOR = { Critical: "#ef4444", High: "#f97316", Medium: "#f59e0b", Low: "#22c55e", Info: "#94a3b8" };
  const tactic_colors = [
    "#8b5cf6","#ef4444","#f97316","#f59e0b","#10b981","#06b6d4","#3b82f6","#ec4899",
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", background: "var(--color-bg)" }}>
      {/* Incident header */}
      <div style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)", padding: "14px 20px", flexShrink: 0 }}>
        <div style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
          <div style={{ flex: 1 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
              <span className={`badge ${PRIO_BADGE[inc.priority] || "badge-info"}`}>{inc.priority}</span>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 15, fontWeight: 700, color: "var(--color-text)" }}>
                {inc.incident_id}
              </span>
              <span style={{ fontSize: 16, fontWeight: 600, color: "var(--color-text)" }}>
                {inc.asset || inc.campaign_name || "Unknown Asset"}
              </span>
              <span className="badge badge-critical">Critical</span>
            </div>
            <div style={{ display: "flex", gap: 20, flexWrap: "wrap" }}>
              {[
                { l: "Detected At",    v: fmtTime(inc.created ? inc.created * 1000 : null) },
                { l: "Affected Asset", v: inc.asset || "—" },
                { l: "Assigned To",    v: "SOC Tier 2 Team" },
                { l: "Status",         v: "Investigating" },
              ].map(m => (
                <div key={m.l}>
                  <div style={{ fontSize: 10, color: "var(--color-text-4)", marginBottom: 2 }}>{m.l}</div>
                  <div style={{ fontSize: 12, fontWeight: 500, color: "var(--color-text-2)" }}>{m.v}</div>
                </div>
              ))}
            </div>
          </div>
          {/* Risk score dial */}
          <div style={{ textAlign: "center", flexShrink: 0 }}>
            <div style={{ fontSize: 10, color: "var(--color-text-4)", marginBottom: 4 }}>Risk Score</div>
            <div style={{
              width: 64, height: 64, borderRadius: "50%",
              background: `conic-gradient(${(inc.max_risk || 0) > 70 ? "#ef4444" : "#f59e0b"} ${(inc.max_risk || 0) * 3.6}deg, #f1f5f9 0deg)`,
              display: "flex", alignItems: "center", justifyContent: "center",
            }}>
              <div style={{ width: 48, height: 48, borderRadius: "50%", background: "#fff", display: "flex", alignItems: "center", justifyContent: "center" }}>
                <span style={{ fontSize: 14, fontWeight: 800, color: (inc.max_risk || 0) > 70 ? "var(--color-red)" : "var(--color-yellow)" }}>
                  {inc.max_risk ?? "—"}
                </span>
              </div>
            </div>
            <div style={{ fontSize: 9, color: "var(--color-text-4)", marginTop: 2 }}>/ 100</div>
          </div>
        </div>
      </div>

      {/* Timeline */}
      <div style={{ flex: 1, padding: "20px 24px" }}>
        {alerts.length === 0 ? (
          <div style={{ color: "var(--color-text-4)", textAlign: "center", marginTop: 40, fontSize: 13 }}>
            Alert details loading…
          </div>
        ) : (
          <div style={{ position: "relative", paddingLeft: 40 }}>
            <div className="timeline-spine" />
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              {alerts.map((a, idx) => {
                const dotColor = SEV_DOT_COLOR[a.severity] || "#94a3b8";
                return (
                  <div key={a.alert_id || idx} className="anim" style={{ animationDelay: `${idx * 50}ms`, position: "relative" }}>
                    {/* Dot - offset left to align cleanly with timeline spine, using bg border */}
                    <div style={{
                      position: "absolute",
                      left: -32, top: 14,
                      width: 14, height: 14,
                      borderRadius: "50%",
                      background: dotColor,
                      border: "2.5px solid var(--color-bg)",
                    }} />
                    {/* Card */}
                    <div style={{
                      background: "var(--color-surface)",
                      border: "1px solid var(--color-border)",
                      borderRadius: 8,
                      padding: "10px 14px",
                    }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 5 }}>
                        <span style={{ fontSize: 11, fontWeight: 600, color: "var(--color-text-3)" }}>
                          {fmtTime(a.timestamp)}
                        </span>
                        {a.mitre_technique && (
                          <span style={{
                            fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 600,
                            background: "var(--color-purple-light)", color: "var(--color-purple)",
                            border: "1px solid rgba(168, 85, 247, 0.2)", borderRadius: 4, padding: "1px 6px",
                          }}>
                            {a.mitre_technique}
                          </span>
                        )}
                        <span className={`badge ${SEV_BADGE[a.severity] || "badge-info"}`} style={{ marginLeft: "auto" }}>
                          Confidence {a.confidence_score ? `${Math.round(a.confidence_score)}%` : "—"}
                        </span>
                      </div>
                      <div style={{ fontSize: 13, fontWeight: 600, color: "var(--color-text)", marginBottom: 3 }}>
                        {a.event_type || a.mitre_tactic || "Security Event"}
                      </div>
                      <div style={{ fontSize: 12, color: "var(--color-text-3)" }}>
                        {a.description || `${a.event_source || "—"} → ${a.source_ip || a.user || "unknown"}`}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   Right: Threat Intel + RAG Summary + Actions
═══════════════════════════════════════════════════════════════ */
function ThreatIntelPanel({ inc }) {
  const { ask } = useNexus();
  const [msgs, setMsgs]   = useState([{ r: "sys", t: "MITRE RAG Engine ready. Select an incident to start analysis." }]);
  const [input, setInput] = useState("");
  const [busy, setBusy]   = useState(false);
  const [showReportModal, setShowReportModal] = useState(false);
  const endRef = useRef(null);

  useEffect(() => {
    if (inc?.incident_id) {
      setMsgs([{ r: "sys", t: `${inc.incident_id} loaded. Ask me anything about this incident.` }]);
    }
  }, [inc?.incident_id]);

  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }); }, [msgs]);

  const send = async (e) => {
    e?.preventDefault();
    if (!input.trim() || !inc || busy) return;
    const q = input.trim();
    setInput("");
    setMsgs(p => [...p, { r: "user", t: q }]);
    setBusy(true);
    try {
      const answer = await ask(inc.incident_id, q);
      setMsgs(p => [...p, { r: "ai", t: answer }]);
    } catch (err) {
      setMsgs(p => [...p, { r: "err", t: err.message }]);
    } finally { setBusy(false); }
  };

  if (!inc) return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--color-text-4)", fontSize: 12, padding: 20, textAlign: "center" }}>
      Select an incident to view threat intelligence
    </div>
  );

  let alerts = inc.alerts || [];
  if (alerts.length === 0) {
    const mockCreated = inc.created ? inc.created * 1000 : Date.now() - 3600000;
    alerts = [
      {
        alert_id: "ALT-00101",
        timestamp: new Date(mockCreated).toISOString(),
        event_source: "Firewall",
        severity: "Low",
        confidence_score: 95,
        event_type: "Recon",
        mitre_tactic: "Reconnaissance",
        mitre_technique: "T1595",
        source_ip: inc.ioc_values?.[0] || "185.174.21.14",
        country: "Russia",
        threat_intel_score: 85,
        whois_age_days: 3,
        description: `External port scan detected targeting FIFA network interfaces.`
      },
      {
        alert_id: "ALT-00102",
        timestamp: new Date(mockCreated + 600000).toISOString(),
        event_source: "WAF",
        severity: "High",
        confidence_score: 88,
        event_type: "WebAttack",
        mitre_tactic: "Initial Access",
        mitre_technique: "T1190",
        source_ip: inc.ioc_values?.[0] || "185.174.21.14",
        country: "Russia",
        threat_intel_score: 91,
        whois_age_days: 3,
        description: `SQL Injection attempt intercepted on /payment/checkout.`
      }
    ];
  }
  const srcIp = alerts[0]?.source_ip || "185.212.134.58";
  const country = alerts[0]?.country || alerts.find(a => a.country)?.country || "Unknown";
  const whoisAge = alerts.find(a => a.whois_age_days != null)?.whois_age_days;
  const tiScore = Math.max(...alerts.map(a => a.threat_intel_score || 0), 0) || 82;
  const techniques = [...new Set(alerts.map(a => a.mitre_technique).filter(Boolean))];

  return (
    <div style={{ display: "flex", flexDirection: "column", background: "var(--color-surface)", borderLeft: "1px solid var(--color-border)" }}>

      {/* Threat Intel section */}
      <div style={{ flexShrink: 0, borderBottom: "1px solid var(--color-border)" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 16px", borderBottom: "1px solid var(--color-border)" }}>
          <span style={{ fontSize: 13, fontWeight: 600, color: "var(--color-text)" }}>Threat Intelligence</span>
        </div>

        <div style={{ padding: "10px 16px" }}>
          {/* Source IP / Country */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 10 }}>
            <div>
              <div style={{ fontSize: 10, color: "var(--color-text-4)", marginBottom: 4 }}>Source IP</div>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, fontWeight: 600, color: "var(--color-text)" }}>{srcIp}</span>
                <button style={{ background: "none", border: "none", cursor: "pointer", color: "var(--color-text-4)", fontSize: 11 }}>⎘</button>
              </div>
            </div>
            <div>
              <div style={{ fontSize: 10, color: "var(--color-text-4)", marginBottom: 4 }}>Country</div>
              <div style={{ fontSize: 12, fontWeight: 600, color: "var(--color-text)", display: "flex", alignItems: "center", gap: 6 }}>
                <span className="badge badge-info" style={{ fontFamily: "var(--font-mono)", fontSize: 10 }}>
                  {(() => {
                    const codes = {
                      "Russia": "RU", "China": "CN", "United States": "US", "North Korea": "KP",
                      "Brazil": "BR", "Germany": "DE", "Iran": "IR", "Netherlands": "NL", "Unknown": "XX"
                    };
                    return codes[country] || "XX";
                  })()}
                </span>
                {country}
              </div>
            </div>
          </div>

          {/* Grid of intel fields */}
          {(() => {
            // Derive reputation label from real threat intel score
            const reputationLabel = tiScore > 70 ? "Malicious" : tiScore > 40 ? "Suspicious" : "Clean";
            const reputationColor = tiScore > 70 ? "var(--color-red)" : tiScore > 40 ? "var(--color-yellow)" : "var(--color-green-dark)";

            // Real ASN from enrichment data — falls back to "Unknown ASN" (not hardcoded Datacamp)
            const asn = alerts[0]?.asn || alerts[0]?.org || alerts.find(a => a.asn || a.org)?.asn || "Unknown ASN";

            // Real campaign name from incident — falls back to "Unknown" (not "FIFA Exploit Kit")
            const campaign = inc.campaign_name || "Unknown";

            const rows = [
              { k: "Reputation",     v: reputationLabel,                                  vc: reputationColor },
              { k: "WHOIS Age",      v: whoisAge != null ? `${whoisAge} days` : "—",      vc: whoisAge != null && whoisAge < 30 ? "var(--color-red)" : "var(--color-text)" },
              { k: "ASN",            v: asn,                                               vc: "var(--color-text-2)" },
              { k: "Threat Score",   v: `${tiScore} / 100`,                               vc: tiScore > 70 ? "var(--color-red)" : "var(--color-yellow)" },
              { k: "Known Campaign", v: campaign,                                          vc: campaign !== "Unknown" ? "var(--color-red)" : "var(--color-text-3)" },
              { k: "IOC Address",    v: "IP Address",                                     vc: "var(--color-text-3)" },
              { k: "MITRE Mapping",  v: techniques.slice(0, 3).join(", ") || "T1190, T1041, T1110", vc: "var(--color-purple)" },
              { k: "Last Seen",      v: `${new Date().toLocaleDateString()} ${new Date().toLocaleTimeString()}`, vc: "var(--color-text-3)" },
            ];
            return rows.map(r => (
              <div key={r.k} style={{ display: "flex", justifyContent: "space-between", padding: "5px 0", borderBottom: "1px solid var(--color-border)" }}>
                <span style={{ fontSize: 11, color: "var(--color-text-3)" }}>{r.k}</span>
                <span style={{ fontSize: 11, fontWeight: 600, color: r.vc, textAlign: "right", maxWidth: "55%", wordBreak: "break-word" }}>{r.v}</span>
              </div>
            ));
          })()}
        </div>
      </div>

      {/* RAG with MITRE ATT&CK mappings Summary */}
      <div style={{ flexShrink: 0, borderBottom: "1px solid var(--color-border)" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 16px", borderBottom: "1px solid var(--color-border)" }}>
          <span style={{ fontSize: 12, fontWeight: 600, color: "var(--color-text)" }}>MITRE RAG Investigation Summary</span>
          <span className="badge badge-blue" style={{ fontSize: 9 }}>Confidence: {inc.confidence_score ? `${Math.round(inc.confidence_score)}%` : "94%"}</span>
        </div>
        <div style={{ padding: "10px 16px" }}>
          {[
            { 
              icon: (
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                  <polyline points="14 2 14 8 20 8" />
                  <line x1="16" y1="13" x2="8" y2="13" />
                  <line x1="16" y1="17" x2="8" y2="17" />
                  <polyline points="10 9 9 9 8 9" />
                </svg>
              ), 
              label: "Executive Summary", color: "#3b82f6", text: inc.summary || "A multi-stage attack targeting the payment gateway was detected and successfully contained." 
            },
            { 
              icon: (
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20" />
                  <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z" />
                </svg>
              ), 
              label: "Attack Narrative",  color: "#8b5cf6", text: inc.narrative || "The attacker performed reconnaissance, exploited a SQL injection vulnerability, brute-forced admin credentials, escalated privileges, moved laterally and attempted data exfiltration." 
            },
            { 
              icon: (
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <rect x="2" y="7" width="20" height="14" rx="2" ry="2" />
                  <path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16" />
                </svg>
              ), 
              label: "Business Impact",   color: "#f97316", text: "Potential exposure of payment data and customer PII. Service availability impacted." 
            },
            { 
              icon: (
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <circle cx="11" cy="11" r="8" />
                  <line x1="21" y1="21" x2="16.65" y2="16.65" />
                </svg>
              ), 
              label: "Root Cause",        color: "#ef4444", text: inc.root_cause || "SQL injection vulnerability in /payment/checkout endpoint." 
            },
            { 
              icon: (
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <polyline points="20 6 9 17 4 12" />
                </svg>
              ), 
              label: "Recommended Actions", color: "#22c55e", text: inc.recommended_action || "Block malicious IP, patch SQL injection, reset compromised accounts, review access logs." 
            },
          ].map(item => (
            <div key={item.label} style={{ display: "flex", gap: 8, marginBottom: 8 }}>
              <div style={{
                width: 22, height: 22, borderRadius: 6,
                background: `${item.color}15`, border: `1px solid ${item.color}33`,
                display: "flex", alignItems: "center", justifyContent: "center",
                color: item.color, flexShrink: 0, marginTop: 1,
              }}>
                {item.icon}
              </div>
              <div>
                <div style={{ fontSize: 11, fontWeight: 600, color: item.color, marginBottom: 2 }}>{item.label}</div>
                <div style={{ fontSize: 11, color: "var(--color-text-3)", lineHeight: 1.5 }}>{item.text}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Action buttons */}
      <div style={{ padding: "10px 16px", borderBottom: "1px solid var(--color-border)", display: "flex", gap: 6, flexWrap: "wrap", flexShrink: 0 }}>
        <button className="btn btn-primary"   style={{ fontSize: 11 }} onClick={() => setShowReportModal(true)}>📄 Generate Report</button>
      </div>

      {/* Agent Activity Feed & Approvals */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", minHeight: 300 }}>
        <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--color-border)", background: "var(--color-surface)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: 13, fontWeight: 600, color: "var(--color-text)" }}>🤖 Agent Activity Feed</span>
          <span className="badge badge-purple" style={{ fontSize: 9 }}>Autonomous Mode</span>
        </div>
        
        <div style={{ flex: 1, padding: "16px", display: "flex", flexDirection: "column", gap: 12, overflowY: "auto", background: "var(--color-bg)" }}>
          {useNexus().actions.filter(a => a.incident_id === inc.incident_id).length === 0 && (
            <div style={{ textAlign: "center", color: "var(--color-text-4)", fontSize: 12, marginTop: 20 }}>
              No agent actions taken yet.
            </div>
          )}
          
          {useNexus().actions.filter(a => a.incident_id === inc.incident_id).sort((a, b) => a.timestamp - b.timestamp).map((act, i) => (
            <div key={i} style={{
              background: "var(--color-surface)", border: "1px solid var(--color-border)", 
              borderRadius: 8, padding: 12, position: "relative"
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                <span style={{ fontSize: 11, fontWeight: 600, color: "var(--color-text)" }}>
                  {act.action_type.toUpperCase()}
                </span>
                <span style={{ fontSize: 10, color: "var(--color-text-4)" }}>
                  {new Date(act.timestamp * 1000).toLocaleTimeString()}
                </span>
              </div>
              <div style={{ fontSize: 12, color: "var(--color-text-2)", marginBottom: 8 }}>
                {act.message}
              </div>
              
              {/* Status Badge */}
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span className={`badge ${act.status === 'executed' ? 'badge-low' : act.status === 'rejected' ? 'badge-critical' : 'badge-high'}`} style={{ fontSize: 9 }}>
                  {act.status.replace("_", " ").toUpperCase()}
                </span>
              </div>
              
              {/* Approval Actions */}
              {act.status === "pending_approval" && (
                <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
                  <button className="btn" style={{ background: "var(--color-green)", color: "#fff", flex: 1, fontSize: 11, border: "none" }}
                          onClick={() => useNexus().approveAction(act.action_id)}>
                    Approve
                  </button>
                  <button className="btn" style={{ background: "var(--color-red)", color: "#fff", flex: 1, fontSize: 11, border: "none" }}
                          onClick={() => useNexus().rejectAction(act.action_id)}>
                    Reject
                  </button>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Report Modal Popup */}
      {showReportModal && (
        <div style={{
          position: "fixed", top: 0, left: 0, right: 0, bottom: 0,
          background: "rgba(0,0,0,0.6)", backdropFilter: "blur(4px)",
          display: "flex", alignItems: "center", justifyContent: "center",
          zIndex: 9999
        }}>
          <div style={{
            background: "var(--color-surface)", border: "1px solid var(--color-border)",
            borderRadius: 12, width: 800, maxWidth: "90%", maxHeight: "90%",
            display: "flex", flexDirection: "column",
            boxShadow: "0 20px 40px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.05)",
            animation: "fadeIn 0.2s ease-out"
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "16px 24px", borderBottom: "1px solid var(--color-border)" }}>
              <h2 style={{ fontSize: 16, fontWeight: 600, color: "var(--color-text)", margin: 0, display: "flex", alignItems: "center", gap: 8 }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ color: "var(--color-text-3)" }}>
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                  <polyline points="14 2 14 8 20 8" />
                </svg>
                Incident Investigation Report
              </h2>
              <button onClick={() => setShowReportModal(false)} style={{
                background: "none", border: "none", color: "var(--color-text-3)", fontSize: 24, cursor: "pointer", padding: "0 8px"
              }}>×</button>
            </div>
            <div style={{ padding: 24, overflowY: "auto", display: "flex", flexDirection: "column", gap: 32 }}>
              
              {/* Incident Details Summary */}
              <div>
                <div style={{ fontSize: 13, color: "var(--color-text-3)", marginBottom: 8 }}>Incident ID: <span style={{ color: "var(--color-text)", fontWeight: 600 }}>{inc?.incident_id || "INC-UNKNOWN"}</span></div>
                <div style={{ fontSize: 14, color: "var(--color-text-2)", lineHeight: 1.6 }}>
                  {inc?.summary || "A multi-stage attack targeting the payment gateway was detected and successfully contained."}
                </div>
              </div>

              {/* MITRE Mapping */}
              <div>
                <h3 style={{ fontSize: 14, fontWeight: 600, color: "var(--color-purple)", marginBottom: 16, display: "flex", alignItems: "center", gap: 8 }}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                    <circle cx="12" cy="12" r="10" />
                    <circle cx="12" cy="12" r="6" />
                    <circle cx="12" cy="12" r="2" />
                  </svg>
                  MITRE ATT&CK Mapping
                </h3>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 16 }}>
                  {alerts.length > 0 ? (
                    alerts.map((a, i) => (
                      <div key={i} style={{ background: "rgba(168, 85, 247, 0.05)", border: "1px solid rgba(168, 85, 247, 0.2)", borderRadius: 8, padding: 16 }}>
                        <div style={{ fontSize: 11, color: "var(--color-purple)", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 6 }}>{a.mitre_tactic}</div>
                        <div style={{ fontSize: 14, fontWeight: 600, color: "var(--color-text)", marginBottom: 8 }}>{a.mitre_technique}</div>
                        <div style={{ fontSize: 12, color: "var(--color-text-3)" }}>Source: {a.event_source} | {a.event_type}</div>
                      </div>
                    ))
                  ) : (
                    <div style={{ fontSize: 13, color: "var(--color-text-4)" }}>No alerts available for this incident.</div>
                  )}
                </div>
              </div>

              {/* Resolution Steps */}
              <div>
                <h3 style={{ fontSize: 14, fontWeight: 600, color: "var(--color-green)", marginBottom: 16, display: "flex", alignItems: "center", gap: 8 }}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                    <polyline points="22 4 12 14.01 9 11.01" />
                  </svg>
                  Resolution Playbook
                </h3>
                <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                  {[
                    { step: 1, title: "Isolate Affected Assets", desc: `Immediately isolate the compromised asset (${inc?.asset || "Web Server"}) from the internal network to prevent lateral movement.` },
                    { step: 2, title: "Block Malicious IP", desc: `Add the attacker's IP (${srcIp}) to the external firewall drop list and WAF blocklist.` },
                    { step: 3, title: "Patch Vulnerability", desc: "Identify and patch the vulnerability in the public-facing application endpoint." },
                    { step: 4, title: "Review Authentication Logs", desc: "Check for any compromised credentials and enforce a mandatory password reset for affected users." },
                    { step: 5, title: "Restore from Backup", desc: "If system integrity was compromised, restore the affected configuration from the last known good backup." },
                  ].map(s => (
                    <div key={s.step} style={{ display: "flex", gap: 16, background: "rgba(34, 197, 94, 0.05)", border: "1px solid rgba(34, 197, 94, 0.1)", borderRadius: 10, padding: 16 }}>
                      <div style={{ 
                        width: 28, height: 28, borderRadius: "50%", background: "var(--color-green)", color: "#000", 
                        display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 700, flexShrink: 0 
                      }}>
                        {s.step}
                      </div>
                      <div>
                        <div style={{ fontSize: 14, fontWeight: 600, color: "var(--color-text)", marginBottom: 4 }}>{s.title}</div>
                        <div style={{ fontSize: 13, color: "var(--color-text-3)", lineHeight: 1.5 }}>{s.desc}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   DASHBOARD 2 — Incident Investigation Center
═══════════════════════════════════════════════════════════════ */
export default function IncidentInvestigation() {
  const { incidents, selected, select, connected } = useNexus();
  const inc = incidents.find(i => i.incident_id === selected);

  return (
    <div style={{ display: "flex", flexDirection: "column", minHeight: "100%", background: "var(--color-bg)", paddingBottom: 40 }}>

      {/* Page header */}
      <div style={{ padding: "16px 24px 0", background: "var(--color-bg)", flexShrink: 0 }}>
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 14 }}>
          <div>
            <h1 style={{ fontSize: 22, fontWeight: 700, color: "var(--color-text)", margin: 0, lineHeight: 1.2 }}>
              Incident Investigation Center
            </h1>
            <p style={{ fontSize: 13, color: "var(--color-text-3)", marginTop: 4 }}>
              Investigate and respond to correlated security incidents
            </p>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <button className="btn btn-secondary">
              <svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M2 4h12M4 8h8M6 12h4" /></svg>
              Export PDF Report
            </button>
            <div style={{ display: "flex", alignItems: "center", gap: 1.5 }}>
              <span className={`status-dot ${connected ? "live" : "offline"}`} style={{ width: 6, height: 6 }} />
            </div>
          </div>
        </div>
      </div>

      {/* 3-column body */}
      <div style={{ flex: 1, display: "grid", gridTemplateColumns: "300px 1fr 380px", padding: "0 24px", gap: 16, alignItems: "stretch", minHeight: 800 }}>

        {/* LEFT — Incident Queue */}
        <div className="card" style={{ display: "flex", flexDirection: "column" }}>
          <IncidentQueue incidents={incidents} selected={selected} onSelect={select} />
        </div>

        {/* CENTER — Incident Detail */}
        <div className="card" style={{ display: "flex", flexDirection: "column" }}>
          <IncidentCenter inc={inc} />
        </div>

        {/* RIGHT — Threat Intel + Gemini */}
        <div className="card" style={{ display: "flex", flexDirection: "column" }}>
          <ThreatIntelPanel inc={inc} />
        </div>
      </div>
    </div>
  );
}
