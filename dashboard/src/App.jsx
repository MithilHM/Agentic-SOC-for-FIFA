import { useEffect, useState } from "react";
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

function VideoFeedsView() {
  const [ticks, setTicks] = useState(0);
  useEffect(() => {
    const interval = setInterval(() => setTicks(t => t + 1), 1000);
    return () => clearInterval(interval);
  }, []);

  const cams = [
    { id: "CAM-01", name: "TICKET PORTAL PERIMETER", status: "SECURE", alerts: 0, ip: "10.0.4.12", activity: "Incoming ticket sales request queue" },
    { id: "CAM-02", name: "PAYMENT ROUTER FIREWALL", status: "ANOMALY", alerts: 3, ip: "185.174.21.14", activity: "Brute-force attempts detected on API port 443" },
    { id: "CAM-03", name: "MEDIA STREAMING PLATFORM", status: "SECURE", alerts: 0, ip: "10.0.12.80", activity: "RTMP ingest nominal. Concurrency: 148,204 viewers" },
    { id: "CAM-04", name: "ADMIN COMMAND INTERFACE", status: "CRITICAL", alerts: 5, ip: "91.108.4.0", activity: "SSH login collision: simultaneous admin badge scans" },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 flex-grow">
      {cams.map((cam) => (
        <div key={cam.id} className="rounded bg-slate-surface border border-border-subtle p-5 flex flex-col justify-between shadow relative overflow-hidden group">
          <div className="scan-line"></div>
          <div className="flex justify-between items-start mb-3 z-10">
            <div>
              <span className="font-mono text-[10px] text-on-tertiary-container uppercase tracking-wider font-bold">{cam.id} // {cam.ip}</span>
              <h3 className="font-display text-sm font-bold text-on-surface uppercase tracking-wider mt-1">{cam.name}</h3>
            </div>
            <span className={`px-2 py-0.5 rounded-sm font-mono text-[9px] font-bold uppercase tracking-wider border
              ${cam.status === "SECURE" ? "bg-security-green/10 border-security-green/30 text-security-green" :
                cam.status === "ANOMALY" ? "bg-alert-orange/10 border-alert-orange/30 text-alert-orange animate-pulse" :
                "bg-critical-red/10 border-critical-red/30 text-critical-red animate-pulse"}`}>
              {cam.status}
            </span>
          </div>

          <div className="h-44 bg-midnight-base/80 border border-border-subtle/40 rounded flex flex-col justify-between p-4 relative overflow-hidden my-3">
            <div className="flex justify-between items-center text-[9px] font-mono text-on-tertiary-container/80">
              <span>FPS: 30.00 // BITRATE: 4500 KBPS</span>
              <span className="flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-critical-red animate-ping"></span>
                LIVE SIGNAL
              </span>
            </div>
            
            <div className="absolute inset-0 flex items-center justify-center pointer-events-none opacity-5">
              <div className="w-full h-full grid grid-cols-12 grid-rows-6 border border-primary/20">
                {Array.from({ length: 72 }).map((_, i) => (
                  <div key={i} className="border-r border-b border-primary/20"></div>
                ))}
              </div>
            </div>

            <div className="z-10 flex flex-col gap-1 font-mono text-[10px]">
              {cam.status !== "SECURE" && (
                <div className="border border-critical-red/40 bg-critical-red/5 p-2 rounded-sm text-critical-red max-w-[85%] self-start animate-pulse">
                  WARNING: Threat detected. Asset target: {cam.name}. IOC Source IP: {cam.ip}.
                </div>
              )}
              <div className="text-on-tertiary-container/70 italic mt-auto">
                System telemetry: {cam.activity}...
              </div>
            </div>

            <div className="text-[9px] font-mono text-on-tertiary-container/60 text-right">
              UTC: {new Date().toISOString()}
            </div>
          </div>

          <div className="flex justify-between items-center mt-2 z-10">
            <span className="font-mono text-[9px] text-on-tertiary-container uppercase tracking-wider">ACTIVE THREAT COUNT: {cam.alerts}</span>
            <button className="px-3 py-1 bg-midnight-base hover:bg-surface-container border border-border-subtle text-on-surface font-mono text-[9px] uppercase tracking-wider font-bold rounded-sm transition-colors cursor-pointer">
              INSPECT FEED
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}

function EventLogsView() {
  const { incidents } = useSoc();
  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState("All");

  const allAlerts = incidents.flatMap(inc => (inc.alerts || []).map(a => ({
    ...a,
    incident_id: inc.incident_id,
    campaign_name: inc.campaign_name,
  }))).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

  const filtered = allAlerts.filter(a => {
    const matchesSearch = 
      (a.alert_id && a.alert_id.toLowerCase().includes(search.toLowerCase())) ||
      (a.event_source && a.event_source.toLowerCase().includes(search.toLowerCase())) ||
      (a.source_ip && a.source_ip.toLowerCase().includes(search.toLowerCase())) ||
      (a.domain && a.domain.toLowerCase().includes(search.toLowerCase())) ||
      (a.mitre_tactic && a.mitre_tactic.toLowerCase().includes(search.toLowerCase()));

    const matchesSev = sevFilter === "All" || a.severity === sevFilter;
    return matchesSearch && matchesSev;
  });

  return (
    <div className="rounded bg-slate-surface border border-border-subtle p-5 shadow flex flex-col flex-grow overflow-hidden">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-5 border-b border-border-subtle/50 pb-4">
        <div>
          <h2 className="font-mono text-xs uppercase tracking-wider font-bold text-primary">Security Events Log</h2>
          <p className="text-[10px] text-on-tertiary-container font-mono uppercase tracking-wider mt-1">Normalized OCSF Alerts Stream</p>
        </div>
        <div className="flex flex-wrap gap-2 w-full sm:w-auto">
          <input 
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="bg-midnight-base border border-border-subtle rounded-sm px-3.5 py-1.5 text-xs font-mono text-on-surface placeholder-on-tertiary-container/60 focus:outline-none focus:border-primary/50 w-full sm:w-56" 
            placeholder="FILTER BY IP, SRC, IOC..." 
            type="text"
          />
          <div className="flex gap-1">
            {["All", "Critical", "High", "Medium", "Low"].map(sev => (
              <button 
                key={sev}
                onClick={() => setSevFilter(sev)}
                className={`text-[9px] font-mono border rounded-sm px-2.5 py-1.5 uppercase font-bold tracking-wider transition-colors cursor-pointer
                  ${sevFilter === sev 
                    ? "bg-primary border-primary text-midnight-base" 
                    : "bg-midnight-base border-border-subtle text-on-tertiary-container hover:text-on-surface"}`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="overflow-y-auto flex-grow scroll-hide">
        <table className="w-full text-left">
          <thead>
            <tr className="text-[9px] font-mono uppercase tracking-widest text-on-tertiary-container border-b border-border-subtle bg-midnight-base/20">
              <th className="px-4 py-3 font-bold">TIMESTAMP</th>
              <th className="px-3 py-3 font-bold">ALERT ID</th>
              <th className="px-3 py-3 font-bold">SOURCE</th>
              <th className="px-3 py-3 font-bold">EVENT TYPE</th>
              <th className="px-3 py-3 text-center font-bold">SEVERITY</th>
              <th className="px-3 py-3 font-bold">IP / USER</th>
              <th className="px-3 py-3 font-bold">MITRE TACTIC</th>
              <th className="px-4 py-3 font-bold">INCIDENT ID</th>
            </tr>
          </thead>
          <tbody className="font-mono text-xs">
            {filtered.map(a => (
              <tr key={a.alert_id} className="border-b border-border-subtle/30 hover:bg-surface-container/20 transition-all duration-100">
                <td className="px-4 py-3 text-on-tertiary-container text-[11px] whitespace-nowrap">{a.timestamp ? a.timestamp.replace("T", " ").replace("Z", "") : "—"}</td>
                <td className="px-3 py-3 text-primary font-bold">{a.alert_id}</td>
                <td className="px-3 py-3 text-on-surface font-semibold">{a.event_source}</td>
                <td className="px-3 py-3 text-on-surface-variant">{a.event_type}</td>
                <td className="px-3 py-3 text-center">
                  <span className={`px-2 py-0.5 rounded-sm text-[9px] font-bold uppercase tracking-wider border
                    ${a.severity === "Critical" ? "bg-critical-red/10 border-critical-red/20 text-critical-red" :
                      a.severity === "High" ? "bg-alert-orange/10 border-alert-orange/20 text-alert-orange" :
                      a.severity === "Medium" ? "bg-caution-amber/10 border-caution-amber/20 text-caution-amber" :
                      "bg-security-green/10 border-security-green/20 text-security-green"}`}>
                    {a.severity}
                  </span>
                </td>
                <td className="px-3 py-3 text-on-surface font-medium">{a.source_ip || a.user || "—"}</td>
                <td className="px-3 py-3 text-secondary font-bold text-[11px] max-w-[120px] truncate">{a.mitre_tactic || "—"}</td>
                <td className="px-4 py-3 text-primary/85 font-bold">{a.incident_id}</td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={8} className="text-center py-16 text-on-tertiary-container/60 uppercase tracking-wider font-bold">
                  NO ALERTS MATCHING FILTER CRITERIA.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function IntelligenceCardsView() {
  const cards = [
    {
      title: "FAKE FIFA TICKET DOMAINS",
      category: "TYPOSQUATTING",
      risk: "HIGH",
      desc: "Simulated registration of campaign domains targeting ticket portals. Threat indicators trigger alert filters on DNS lookups and phishing gateways.",
      details: [
        { label: "Target Domain", val: "fifa-ticket-secure2026.com" },
        { label: "Registry Age", val: "2 days old" },
        { label: "Visual Sim Similarity", val: "98% (High Impersonation)" },
        { label: "IP Host", val: "185.174.21.14 (Russian Federation)" },
      ]
    },
    {
      title: "PUBLIC IP REPUTATION FEED",
      category: "THREAT-INTEL",
      risk: "MEDIUM",
      desc: "Outbound correlation checker gating live indicators of compromise against free public blocks. Offline heuristics trigger block rules during demo simulations.",
      details: [
        { label: "Block Feed Lists", val: "Spamhaus DROP, Tor exit list, FireHOL" },
        { label: "Refresh Time", val: "Every 6 Hours (Configured)" },
        { label: "Active Block Rules", val: "11,842 Indicators Loaded" },
        { label: "Outbound Gateway State", val: "ONLINE Heuristics Enabled" },
      ]
    },
    {
      title: "MITRE ATT&CK CATALOGUE MAP",
      category: "TACTICS & TECHNIQUES",
      risk: "INFO",
      desc: "End-to-end mapping of ingested events against the full 697-technique MITRE framework. Pinpoints specific stages of penetration from Initial Access to Impact.",
      details: [
        { label: "Tactics Indexed", val: "12 tactics (Full Kill-Chain)" },
        { label: "Techniques Loaded", val: "142 common enterprise techniques" },
        { label: "Seeded RAG Index", val: "Pinecone (Index: fifa-soc-incidents)" },
        { label: "RAG Embeddings State", val: "Operational / Running" },
      ]
    },
    {
      title: "CRITICAL CLIENT APP CHANNELS",
      category: "ASSETS & BUSINESS IMPACT",
      risk: "HIGH",
      desc: "Business impact evaluation scoring assets based on customer traffic. Gateways and ticket portals are mapped to high tier risk classes to enforce automated escalation rules.",
      details: [
        { label: "Critical Assets", val: "Official Ticket Portal, Payment Gateway" },
        { label: "Medium Assets", val: "Streaming Platform, Media Portal" },
        { label: "Automated Escalation", val: "Active (>80 Risk = P1 Incident)" },
        { label: "Downtime Threshold", val: "99.999% SLA" },
      ]
    }
  ];

  return (
    <div className="flex flex-col gap-6 flex-grow">
      <div className="border-b border-border-subtle pb-4 shrink-0">
        <h2 className="font-mono text-xs uppercase tracking-wider font-bold text-primary">Intelligence Card dossiers</h2>
        <p className="text-[10px] text-on-tertiary-container font-mono uppercase tracking-wider mt-1">Grounded Threat Intel Campaigns & Indicators</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 flex-grow overflow-y-auto scroll-hide pr-1">
        {cards.map(card => (
          <div key={card.title} className="rounded bg-slate-surface border border-border-subtle p-5 shadow flex flex-col justify-between hover:border-primary/20 transition-all duration-300">
            <div>
              <div className="flex justify-between items-center mb-3">
                <span className="font-mono text-[9px] bg-secondary/10 border border-secondary/20 text-secondary rounded-sm px-2 py-0.5 uppercase tracking-wider font-bold">{card.category}</span>
                <span className={`px-2 py-0.5 rounded-sm font-mono text-[9px] font-bold uppercase tracking-wider border
                  ${card.risk === "HIGH" ? "bg-critical-red/10 border-critical-red/20 text-critical-red animate-pulse" :
                    card.risk === "MEDIUM" ? "bg-alert-orange/10 border-alert-orange/20 text-alert-orange" :
                    "bg-on-tertiary-container/15 border-border-subtle/60 text-on-tertiary-container"}`}>
                  {card.risk} RISK
                </span>
              </div>
              <h3 className="font-display text-sm font-bold text-on-surface uppercase tracking-wider mb-2">{card.title}</h3>
              <p className="text-xs text-on-surface-variant/80 leading-relaxed mb-4">{card.desc}</p>
            </div>

            <div className="bg-midnight-base/40 border border-border-subtle/50 rounded-sm p-3 flex flex-col gap-1.5 font-mono text-[10px]">
              {card.details.map(detail => (
                <div key={detail.label} className="flex justify-between items-center py-1 border-b border-border-subtle/30 last:border-0">
                  <span className="text-on-tertiary-container/85 font-bold uppercase tracking-wider">{detail.label}</span>
                  <span className="text-on-surface font-semibold">{detail.val}</span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function SystemHealthView() {
  const { connected } = useSoc();

  const services = [
    { name: "REDIS INGESTION BUS", status: connected ? "ONLINE" : "OFFLINE", details: "alerts.raw stream processing at ~2.0 events/sec. Consumer group 'soc' active.", health: 100 },
    { name: "XGBOOST CLASSIFIER MODEL", status: "ONLINE", details: "Training accuracy: 85.67%. Model file: ml/model/xgboost_model.json loaded successfully.", health: 95 },
    { name: "CORRELATION RULE ENGINE", status: "ONLINE", details: "Active windows: 900s. Grouping filters active. 6 correlation keys tracked.", health: 100 },
    { name: "LANGGRAPH AGENT ANALYST", status: "STANDBY", details: "Grounding index: Pinecone. Model: Gemini-2.5-flash. API key loaded.", health: 98 },
  ];

  return (
    <div className="flex flex-col gap-6 flex-grow">
      <div className="border-b border-border-subtle pb-4 shrink-0">
        <h2 className="font-mono text-xs uppercase tracking-wider font-bold text-primary">System Telemetry & Health Monitor</h2>
        <p className="text-[10px] text-on-tertiary-container font-mono uppercase tracking-wider mt-1">Docker Container Infrastructure & Service Probes</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 shrink-0">
        <div className="rounded bg-slate-surface border border-border-subtle p-5 shadow flex flex-col justify-between">
          <div className="flex justify-between items-center mb-2">
            <span className="font-mono text-[9px] text-on-tertiary-container uppercase tracking-wider font-bold">REDIS CAP LIMIT</span>
            <span className="material-symbols-outlined text-primary text-sm">memory</span>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="font-mono text-2xl font-bold text-primary">512.4</span>
            <span className="font-mono text-[10px] text-on-tertiary-container">/ 2,048 MB</span>
          </div>
          <div className="mt-4 h-1.5 w-full bg-border-subtle rounded-sm">
            <div className="h-full bg-primary rounded-sm" style={{ width: "25%" }}></div>
          </div>
          <div className="mt-3 flex justify-between font-mono text-[9px] text-on-tertiary-container">
            <span>MEM CAP NOMINAL</span>
            <span>25.0% USED</span>
          </div>
        </div>

        <div className="rounded bg-slate-surface border border-border-subtle p-5 shadow flex flex-col justify-between">
          <div className="flex justify-between items-center mb-2">
            <span className="font-mono text-[9px] text-on-tertiary-container uppercase tracking-wider font-bold">INgestion latency</span>
            <span className="material-symbols-outlined text-primary text-sm">speed</span>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="font-mono text-2xl font-bold text-primary">12.8</span>
            <span className="font-mono text-[10px] text-on-tertiary-container">MS</span>
          </div>
          <div className="mt-4 h-1.5 w-full bg-border-subtle rounded-sm">
            <div className="h-full bg-primary rounded-sm" style={{ width: "12%" }}></div>
          </div>
          <div className="mt-3 flex justify-between font-mono text-[9px] text-on-tertiary-container">
            <span>XADD QUEUE DELAY</span>
            <span>EXCELLENT</span>
          </div>
        </div>

        <div className="rounded bg-slate-surface border border-border-subtle p-5 shadow flex flex-col justify-between">
          <div className="flex justify-between items-center mb-2">
            <span className="font-mono text-[9px] text-on-tertiary-container uppercase tracking-wider font-bold">CPU load metrics</span>
            <span className="material-symbols-outlined text-primary text-sm">dns</span>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="font-mono text-2xl font-bold text-on-surface">32.4</span>
            <span className="font-mono text-[10px] text-on-tertiary-container">% LOAD</span>
          </div>
          <div className="mt-4 h-1.5 w-full bg-border-subtle rounded-sm">
            <div className="h-full bg-primary rounded-sm animate-pulse" style={{ width: "32%" }}></div>
          </div>
          <div className="mt-3 flex justify-between font-mono text-[9px] text-on-tertiary-container">
            <span>8 CORES ALLOCATED</span>
            <span>SYSTEM STABLE</span>
          </div>
        </div>
      </div>

      <div className="rounded bg-slate-surface border border-border-subtle p-5 shadow flex-grow overflow-y-auto scroll-hide">
        <h3 className="font-mono text-xs uppercase tracking-wider font-bold text-primary mb-4">ACTIVE PIPELINE SERVICES</h3>
        <div className="flex flex-col gap-4">
          {services.map(srv => (
            <div key={srv.name} className="bg-midnight-base/40 border border-border-subtle/50 rounded-sm p-4 flex flex-col sm:flex-row justify-between sm:items-center gap-4 hover:border-primary/10 transition-colors">
              <div className="max-w-[75%]">
                <div className="flex items-center gap-2 mb-1.5">
                  <span className={`w-2 h-2 rounded-full ${srv.status === "ONLINE" ? "bg-security-green" : srv.status === "STANDBY" ? "bg-secondary" : "bg-critical-red"} animate-pulse`}></span>
                  <span className="font-mono text-xs font-bold text-on-surface uppercase tracking-wider">{srv.name}</span>
                  <span className="font-mono text-[9px] text-on-tertiary-container">({srv.status})</span>
                </div>
                <p className="text-xs text-on-surface-variant/80 leading-relaxed font-sans">{srv.details}</p>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <span className="font-mono text-xs text-on-tertiary-container">HEALTH: {srv.health}%</span>
                <div className="w-20 h-2 bg-border-subtle rounded-sm overflow-hidden">
                  <div className="h-full bg-security-green rounded-sm" style={{ width: `${srv.health}%` }}></div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const { currentTab, setTab, startPolling, connect, connected } = useSoc();

  useEffect(() => {
    startPolling(10000);   // initial load + refresh every 10s
    connect();             // WebSocket live feed
  }, []);                  // intentionally no deps — run once

  return (
    <div className="h-screen w-screen flex flex-col bg-midnight-base text-on-surface overflow-hidden font-sans">
      
      {/* ── Top Navigation Bar ─────────────────────────────────────────── */}
      <header className="flex justify-between items-center w-full px-6 h-16 z-50 bg-midnight-base border-b border-border-subtle shrink-0">
        <div className="flex items-center gap-8">
          <span className="font-display text-base font-bold tracking-tight text-primary flex items-center gap-2">
            <span className="material-symbols-outlined text-primary text-lg animate-pulse" style={{ fontVariationSettings: "'FILL' 1" }}>radar</span>
            VANGUARD SOC
          </span>
          <nav className="hidden md:flex gap-6 items-center">
            {["Command Center", "Video Feeds", "Event Logs", "Intelligence Cards", "System Health"].map(tab => (
              <button 
                key={tab}
                onClick={() => setTab(tab)}
                className={`font-mono text-[10px] tracking-wider uppercase font-bold transition-all cursor-pointer py-1
                  ${currentTab === tab 
                    ? "text-primary border-b-2 border-primary" 
                    : "text-on-tertiary-container hover:text-on-surface"}`}
              >
                {tab}
              </button>
            ))}
          </nav>
        </div>
        <div className="flex items-center gap-4">
          <div className="bg-slate-surface flex items-center px-3.5 py-1.5 border border-border-subtle gap-2 rounded-sm">
            <span className="material-symbols-outlined text-on-tertiary-container text-sm">search</span>
            <input 
              className="bg-transparent border-none outline-none focus:ring-0 font-mono text-xs w-48 text-on-surface placeholder-on-tertiary-container/60" 
              placeholder="QUERY DATABASE..." 
              type="text"
            />
          </div>
          <div className="flex items-center gap-3">
            <span className="material-symbols-outlined text-primary hover:opacity-80 transition-opacity cursor-pointer text-lg">sensors</span>
            <span className="material-symbols-outlined text-primary hover:opacity-80 transition-opacity cursor-pointer text-lg">notifications_active</span>
            <span className="material-symbols-outlined text-primary hover:opacity-80 transition-opacity cursor-pointer text-lg">settings</span>
            <div className="w-8 h-8 rounded-full border border-primary/30 bg-slate-surface flex items-center justify-center overflow-hidden">
              <img 
                alt="Analyst Profile" 
                className="w-full h-full object-cover" 
                src="https://lh3.googleusercontent.com/aida-public/AB6AXuA5KOpCmjJjg4pkLF4TdGoP_VyF90MREMe62bA49x49uK3HcSQvoUtO0CaD5lLIih8knJPsBJ_asiWv0rQcauUT4wE8RHCp4tfze6gAix-e2NAdS483IzKD4AkXILsUgshWSweigkn8Nqq3QZtyxredmy4ujVHUvyGoAksKpZ4ZibO99BWtZawGp3GoyhQoiAgDssLLWnHDUFDDUh7j8Jg_DZIQJWz0ubdGp-Vpz8pbl99tajJsEJ6Ftf1f9g4PE7RauUvgV4CbIpz8"
              />
            </div>
          </div>
        </div>
      </header>

      {/* ── Workspace ─────────────────────────────────────────────────── */}
      <div className="flex flex-1 overflow-hidden">
        
        {/* Left Sidebar Navigation */}
        <aside className="flex flex-col h-full border-r border-border-subtle w-[240px] bg-slate-surface shrink-0 hidden md:flex">
          <div className="p-5 border-b border-border-subtle bg-primary-container/10">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-9 h-9 bg-primary/10 border border-primary/30 flex items-center justify-center rounded-sm">
                <span className="material-symbols-outlined text-primary text-lg" style={{ fontVariationSettings: "'FILL' 1" }}>shield</span>
              </div>
              <div>
                <div className="font-mono text-xs text-primary font-bold">OPERATOR_01</div>
                <div className="text-[9px] font-mono text-on-tertiary-container uppercase tracking-wider font-bold">LEVEL 3 CLEARANCE</div>
              </div>
            </div>
            <div className={`w-full border py-2 text-center text-xs font-mono tracking-wider font-bold rounded-sm flex items-center justify-center gap-1.5
              ${connected 
                ? "bg-security-green/10 border-security-green/20 text-security-green" 
                : "bg-slate-800/50 border-slate-700 text-on-tertiary-container"}`}>
              <span className="w-2.5 h-2.5 rounded-full bg-current animate-pulse"></span>
              {connected ? "LIVE TELEMETRY" : "OFFLINE CONTEXT"}
            </div>
          </div>
          <div className="flex-1 py-4 flex flex-col gap-0.5">
            {[
              { id: "Command Center", icon: "dashboard_customize" },
              { id: "Video Feeds", icon: "videocam" },
              { id: "Event Logs", icon: "list_alt" },
              { id: "Intelligence Cards", icon: "psychology" },
              { id: "System Health", icon: "health_and_safety" },
            ].map(item => (
              <button 
                key={item.id}
                onClick={() => setTab(item.id)}
                className={`px-4 py-3 flex items-center gap-3 transition-all font-mono text-[10px] tracking-wider uppercase font-bold cursor-pointer text-left border-l-4
                  ${currentTab === item.id 
                    ? "bg-midnight-base text-primary border-l-primary" 
                    : "text-on-tertiary-container border-l-transparent hover:text-on-surface hover:bg-midnight-base/30"}`}
              >
                <span className="material-symbols-outlined text-base">{item.icon}</span>
                {item.id}
              </button>
            ))}
          </div>
          <div className="p-4 border-t border-border-subtle flex flex-col gap-0.5">
            <a className="text-on-tertiary-container hover:text-on-surface px-4 py-1.5 flex items-center gap-2 text-xs font-mono" href="#">
              <span className="material-symbols-outlined text-sm">description</span> Documentation
            </a>
            <a className="text-on-tertiary-container hover:text-on-surface px-4 py-1.5 flex items-center gap-2 text-xs font-mono" href="#">
              <span className="material-symbols-outlined text-sm">help_center</span> Support
            </a>
          </div>
        </aside>

        {/* Main Dashboard Space */}
        <main className="flex-1 overflow-y-auto scroll-hide p-6 bg-midnight-base flex flex-col gap-6">
          {currentTab === "Command Center" && (
            <>
              <MetricsRow />
              
              <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 flex-grow">
                {/* Left columns — Incident Ledger, MITRE Matrix, Charts */}
                <div className="xl:col-span-2 flex flex-col gap-6 overflow-hidden">
                  <IncidentLedger />
                  <MitreMatrix />
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <AttackTrends />
                    <SeverityDonut />
                  </div>
                </div>

                {/* Right column — incident Details, Timeline, Analyst Chat, Asset Map */}
                <div className="xl:col-span-1 flex flex-col gap-6">
                  <IncidentDetail />
                  <AttackTimeline />
                  <AnalystChat />
                  <AssetMap />
                </div>
              </div>
            </>
          )}

          {currentTab === "Video Feeds" && <VideoFeedsView />}
          {currentTab === "Event Logs" && <EventLogsView />}
          {currentTab === "Intelligence Cards" && <IntelligenceCardsView />}
          {currentTab === "System Health" && <SystemHealthView />}
        </main>

      </div>
    </div>
  );
}
