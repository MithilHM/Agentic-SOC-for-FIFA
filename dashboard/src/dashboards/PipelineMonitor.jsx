import { useState, useEffect } from "react";
import { useNexus } from "../store";


/* ── Pipeline stage definitions ── */
const STAGES = [
  {
    id: "ocsf", label: "OCSF\nNormalization", icon: "⬡",
    color: "#3b82f6", bgColor: "#eff6ff",
    desc: "Normalizes raw logs from all 11 sources into unified OCSF schema.",
    detail: { "Parser": "Pydantic BaseParser", "Input Formats": "11 native", "Output": "OCSF Schema", "Alert ID": "ALT-###### seq" },
    rateBase: 124, latBase: 8,
  },
  {
    id: "redis", label: "Redis\nStreams", icon: "⬡",
    color: "#ef4444", bgColor: "#fef2f2",
    desc: "Durable event bus. Consumer groups for replayable delivery. 15-min retention window.",
    detail: { "Stream": "alerts.raw", "Group": "soc/consumer-1", "Transport": "XADD → XREADGROUP", "Retention": "900s window" },
    rateBase: 2341, latBase: 18, isQueue: true,
  },
  {
    id: "xgboost", label: "XGBoost\nAI Triage", icon: "⬡",
    color: "#8b5cf6", bgColor: "#f5f3ff",
    desc: "Multi-class classifier predicts attack type from 9 engineered features. False-positive gate suppresses low-confidence events.",
    detail: { "Model": "XGBoost multi-class", "Classes": "10 attack types", "Features": "9 (conf,geo,entropy…)", "FP Gate": "Conf < 40% → drop" },
    rateBase: 118, latBase: 145,
  },
  {
    id: "enrichment", label: "Threat\nIntelligence", icon: "⬡",
    color: "#f59e0b", bgColor: "#fffbeb",
    desc: "Enriches every alert with GeoIP, WHOIS domain age, threat reputation score, and MITRE ATT&CK mapping.",
    detail: { "GeoIP": "Source IP → country", "WHOIS": "Domain age (days)", "MITRE": "Tactic + Technique", "TI Score": "Reputation 0–100" },
    rateBase: 118, latBase: 420,
  },
  {
    id: "correlation", label: "Correlation\nEngine", icon: "⬡",
    color: "#f97316", bgColor: "#fff7ed",
    desc: "Groups enriched alerts into incidents by matching IOCs, assets, users within a 15-minute window.",
    detail: { "Window": "900 seconds", "Keys": "IOC·asset·user·IP", "Priority": "P1–P4 risk score", "Chain": "Kill-chain detection" },
    rateBase: 32, latBase: 210,
  },
  {
    id: "gemini", label: "MITRE RAG\nEngine", icon: "⬡",
    color: "#8b5cf6", bgColor: "#f5f3ff",
    desc: "MITRE RAG Engine retrieves threat patterns and matches attacks via LangGraph + MITRE ATT&CK RAG.",
    detail: { "Model": "MITRE ATT&CK RAG", "RAG": "MITRE + Pinecone", "Output": "summary+mappings", "Q&A": "RAG chat" },
    rateBase: 32, latBase: 80,
  },
  {
    id: "dashboard", label: "Incident\nDashboard", icon: "⬡",
    color: "#14b8a6", bgColor: "#f0fdfa",
    desc: "Finished incidents pushed live via WebSocket to SOC analysts with full context.",
    detail: { "Transport": "WebSocket push", "Channel": "incidents.live", "Views": "Investigation+Ops", "Chat": "Gemini Q&A" },
    rateBase: 12, latBase: 1200,
  },
];

const LOG_SOURCES = [
  { name: "Firewall",          base: 1245, code: "FW" },
  { name: "WAF",               base: 842,  code: "WAF" },
  { name: "EDR",               base: 1102, code: "EDR" },
  { name: "Authentication",    base: 932,  code: "AUTH" },
  { name: "DNS",               base: 412,  code: "DNS" },
  { name: "Email Gateway",     base: 318,  code: "MAIL" },
  { name: "Cloud Security",    base: 730,  code: "CLD" },
  { name: "IDS / IPS",         base: 657,  code: "IDS" },
  { name: "SIEM",              base: 509,  code: "SIEM" },
  { name: "Ticketing Platform",base: 236,  code: "TKT" },
  { name: "Streaming Platform",base: 127,  code: "STR" },
];

const ATTACK_TYPES = [
  { name: "Web Attack",  value: 42, color: "#3b82f6" },
  { name: "Brute Force", value: 21, color: "#ef4444" },
  { name: "Malware",     value: 19, color: "#8b5cf6" },
  { name: "Phishing",    value: 12, color: "#f59e0b" },
  { name: "DDoS",        value: 3,  color: "#f97316" },
  { name: "Other",       value: 3,  color: "#94a3b8" },
];

function rand(base, spread = 0.12) {
  return Math.round(base * (1 + (Math.random() - 0.5) * spread));
}

function useSimData() {
  const [data, setData] = useState({
    ingested: 124, processed: 118, queueLen: 2341, latency: 320,
    fpSuppressed: 6418, fpPct: 71,
    sourceCounts: LOG_SOURCES.map(s => rand(s.base)),
    history: Array.from({ length: 20 }, (_, i) => ({
      t: i, ing: 110 + Math.random() * 30, proc: 100 + Math.random() * 28,
    })),
    throughput: Array.from({ length: 20 }, (_, i) => ({
      t: i, ing: 120 + Math.random() * 80, proc: 100 + Math.random() * 70,
    })),
  });

  useEffect(() => {
    const id = setInterval(() => {
      setData(prev => ({
        ingested:    rand(124, 0.08),
        processed:   rand(118, 0.08),
        queueLen:    rand(2341, 0.05),
        latency:     rand(320,  0.1),
        fpSuppressed: prev.fpSuppressed + Math.floor(Math.random() * 3),
        fpPct:       70 + Math.round(Math.random() * 4),
        sourceCounts: LOG_SOURCES.map(s => rand(s.base, 0.06)),
        history:     [...prev.history.slice(1), { t: Date.now(), ing: rand(124, 0.12), proc: rand(118, 0.12) }],
        throughput:  [...prev.throughput.slice(1), { t: Date.now(), ing: rand(160, 0.15), proc: rand(130, 0.15) }],
      }));
    }, 2000);
    return () => clearInterval(id);
  }, []);

  return data;
}

/* ── Tiny sparkline ── */
function Spark({ data, color }) {
  const vals = data.map(d => d.v ?? d.ing ?? d.proc ?? d);
  const min = Math.min(...vals), max = Math.max(...vals);
  const h = 32, w = 80;
  const pts = vals.map((v, i) => {
    const x = (i / (vals.length - 1)) * w;
    const y = h - ((v - min) / (max - min || 1)) * h;
    return `${x},${y}`;
  }).join(" ");
  return (
    <svg width={w} height={h} style={{ display: "block" }}>
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" />
    </svg>
  );
}

function InnerWorkingsDiagram({ stageId }) {
  if (stageId === "ocsf") {
    return (
      <div style={{ padding: "14px 10px", background: "#f8fafc", borderRadius: 8, border: "1px solid var(--color-border)", marginBottom: 14 }}>
        <div style={{ fontSize: 10, fontWeight: 700, color: "var(--color-text-3)", marginBottom: 8, textTransform: "uppercase" }}>Inner Workings: Ingestion & Normalization</div>
        <style>{`
          @keyframes ingestionFlow {
            0% { left: 0%; }
            100% { left: 100%; }
          }
        `}</style>
        <div style={{ display: "flex", alignItems: "center", gap: 4, position: "relative" }}>
          {[
            { t: "Log Collectors", s: "Connectors & agents" },
            { t: "Kafka Event Bus", s: "Streaming pipeline" },
            { t: "Normalize to OCSF", s: "Unified schema" }
          ].map((box, idx) => (
            <div key={box.t} style={{ display: "flex", alignItems: "center", flex: 1 }}>
              <div style={{
                background: "var(--color-blue-light)",
                border: "1.5px solid var(--color-blue)",
                borderRadius: 6,
                padding: "6px 4px",
                flex: 1,
                textAlign: "center",
                boxShadow: "0 2px 4px rgba(59,130,246,0.05)"
              }}>
                <div style={{ fontSize: 9, fontWeight: 700, color: "var(--color-blue-dark)" }}>{box.t}</div>
                <div style={{ fontSize: 7, color: "var(--color-text-3)", marginTop: 2 }}>{box.s}</div>
              </div>
              {idx < 2 && (
                <div style={{ width: 10, height: 2, background: "#93c5fd", position: "relative" }}>
                  <div style={{
                    position: "absolute",
                    width: 4, height: 4, borderRadius: "50%",
                    background: "var(--color-blue)",
                    top: -1,
                    animation: "ingestionFlow 1.2s linear infinite"
                  }} />
                  {/* Rightward Arrowhead */}
                  <div style={{
                    position: "absolute",
                    right: -2, top: -2,
                    width: 0, height: 0,
                    borderTop: "3px solid transparent",
                    borderBottom: "3px solid transparent",
                    borderLeft: "4px solid #93c5fd",
                  }} />
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (stageId === "xgboost") {
    return (
      <div style={{ padding: "14px 10px", background: "#f8fafc", borderRadius: 8, border: "1px solid var(--color-border)", marginBottom: 14 }}>
        <div style={{ fontSize: 10, fontWeight: 700, color: "var(--color-text-3)", marginBottom: 8, textTransform: "uppercase" }}>Inner Workings: AI Processing Pipeline</div>
        <style>{`
          @keyframes processPulse {
            0% { transform: scale(1); opacity: 0.9; }
            100% { transform: scale(1.02); opacity: 1; box-shadow: 0 0 6px rgba(139,92,246,0.15); }
          }
        `}</style>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6 }}>
          {[
            { t: "Feature Extract", s: "Entity & behavior" },
            { t: "Threat Classify", s: "Phishing, malware+" },
            { t: "FP Reduction", s: "Confidence scoring" },
            { t: "Intel Enrichment", s: "VirusTotal, CVE+" },
            { t: "MITRE Mapping", s: "Tactics & techniques" },
            { t: "Risk Scoring", s: "Severity x impact" }
          ].map((box, idx) => (
            <div key={box.t} style={{
              background: "var(--color-purple-light)",
              border: "1.5px solid var(--color-purple)",
              borderRadius: 6,
              padding: "6px 4px",
              textAlign: "center",
              animation: `processPulse 1.5s infinite alternate`,
              animationDelay: `${idx * 150}ms`
            }}>
              <div style={{ fontSize: 9, fontWeight: 700, color: "var(--color-purple)" }}>{box.t}</div>
              <div style={{ fontSize: 7, color: "var(--color-text-3)", marginTop: 2 }}>{box.s}</div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (stageId === "correlation") {
    return (
      <div style={{ padding: "14px 10px", background: "#f8fafc", borderRadius: 8, border: "1px solid var(--color-border)", marginBottom: 14 }}>
        <div style={{ fontSize: 10, fontWeight: 700, color: "var(--color-text-3)", marginBottom: 8, textTransform: "uppercase" }}>Inner Workings: Incident Correlation Engine</div>
        <style>{`
          @keyframes mergeFlow {
            0% { transform: translateX(0); opacity: 0; }
            30% { opacity: 1; }
            100% { transform: translateX(50px); opacity: 0; }
          }
        `}</style>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          {/* Alerts Stack */}
          <div style={{ display: "flex", flexDirection: "column", gap: 4, width: "90px" }}>
            {["Firewall Alert", "Failed Login", "Email Alert", "Malware Alert"].map((a, idx) => (
              <div key={a} style={{
                background: "#fef2f2",
                border: "1px solid #fca5a5",
                borderRadius: 4,
                padding: "3px 4px",
                fontSize: 8,
                fontWeight: 600,
                color: "var(--color-red)",
                textAlign: "center",
                position: "relative"
              }}>
                {a}
                <div style={{
                  position: "absolute",
                  right: -10, top: "50%", marginTop: -2,
                  width: 3, height: 3, borderRadius: "50%",
                  background: "var(--color-red)",
                  animation: "mergeFlow 1.5s linear infinite",
                  animationDelay: `${idx * 250}ms`
                }} />
              </div>
            ))}
          </div>

          {/* Merge Arrow Graphic */}
          <div style={{ flex: 1, height: 2, background: "#10b981", margin: "0 6px", position: "relative" }}>
            <div style={{ position: "absolute", right: -3, top: -3, borderLeft: "5px solid #10b981", borderTop: "4px solid transparent", borderBottom: "4px solid transparent" }} />
          </div>

          {/* Incident Box */}
          <div style={{
            background: "#ecfdf5",
            border: "1.5px solid #10b981",
            borderRadius: 8,
            padding: "8px 6px",
            width: "120px",
            textAlign: "center",
            boxShadow: "0 4px 6px rgba(16,185,129,0.05)"
          }}>
            <div style={{ fontSize: 9, fontWeight: 700, color: "var(--color-green-dark)" }}>Single Security Incident</div>
            <div style={{ fontSize: 7, color: "var(--color-text-3)", marginTop: 2 }}>Merged: IP, user, time</div>
          </div>
        </div>
      </div>
    );
  }

  if (stageId === "gemini") {
    return (
      <div style={{ padding: "14px 10px", background: "#f8fafc", borderRadius: 8, border: "1px solid var(--color-border)", marginBottom: 14 }}>
        <div style={{ fontSize: 10, fontWeight: 700, color: "var(--color-text-3)", marginBottom: 6, textTransform: "uppercase" }}>Inner Workings: MITRE RAG Engine</div>
        <style>{`
          @keyframes copilotActive {
            0% { background: #f0fdf4; border-color: #86efac; }
            100% { background: #dcfce7; border-color: #22c55e; }
          }
        `}</style>
        <div style={{ display: "flex", alignItems: "center", gap: 2 }}>
          {["Perceive", "Reason", "Plan", "Act", "Learn"].map((step, idx) => (
            <div key={step} style={{ display: "flex", alignItems: "center", flex: 1 }}>
              <div style={{
                background: "#f0fdf4",
                border: "1.5px solid #86efac",
                borderRadius: 6,
                padding: "4px 1px",
                flex: 1,
                textAlign: "center",
                animation: "copilotActive 2s infinite alternate",
                animationDelay: `${idx * 150}ms`
              }}>
                <div style={{ fontSize: 9, fontWeight: 700, color: "var(--color-green-dark)" }}>{step}</div>
                <div style={{ fontSize: 6, color: "var(--color-text-4)", marginTop: 1 }}>
                  {step === "Perceive" ? "Gather intel"
                   : step === "Reason" ? "Infer intent"
                   : step === "Plan" ? "Set strategy"
                   : step === "Act" ? "Take action"
                   : "Refine model"}
                </div>
              </div>
              {idx < 4 && <span style={{ color: "#86efac", fontSize: 10 }}>→</span>}
            </div>
          ))}
        </div>
        <div style={{ fontSize: 8, color: "var(--color-text-4)", textAlign: "center", marginTop: 6, fontStyle: "italic" }}>
          learns continuously from analyst feedback and outcomes
        </div>
      </div>
    );
  }

  if (stageId === "soc") {
    return (
      <div style={{ padding: "14px 10px", background: "#f8fafc", borderRadius: 8, border: "1px solid var(--color-border)", marginBottom: 14 }}>
        <div style={{ fontSize: 10, fontWeight: 700, color: "var(--color-text-3)", marginBottom: 8, textTransform: "uppercase" }}>Inner Workings: SOC Dashboards</div>
        <div style={{ display: "flex", gap: 4 }}>
          {[
            { t: "Analyst Dashboard", s: "Live alerts & IOCs" },
            { t: "Manager Dashboard", s: "MTTR, MTTD, workload" },
            { t: "Executive View", s: "Business risk score" }
          ].map(box => (
            <div key={box.t} style={{
              background: "#fef3c7",
              border: "1.5px solid #f59e0b",
              borderRadius: 6,
              padding: "6px 2px",
              flex: 1,
              textAlign: "center"
            }}>
              <div style={{ fontSize: 8, fontWeight: 700, color: "var(--color-yellow-dark)" }}>{box.t}</div>
              <div style={{ fontSize: 6, color: "var(--color-text-3)", marginTop: 1 }}>{box.s}</div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return null;
}

/* ── Walkthrough stages ── */
const WALKTHROUGH_STEPS = [
  {
    step: 0,
    id: null,
    title: "New Security Alert Detected",
    subtitle: "A malicious web request hits the FIFA Payment Gateway",
    color: "#ef4444",
    text: "An alert comes from the Firewall. The system detects a suspicious web request targeting the payment gateway API. This raw event needs to be processed to determine if it is a real attack.",
    innerTitle: "Incoming Raw Log Payload",
    payload: {
      "Source IP": "185.174.21.14",
      "Timestamp": new Date().toISOString(),
      "Payload": "GET /payment/checkout?id=42' OR 1=1-- HTTP/1.1",
      "User-Agent": "Mozilla/5.0 ExploitKit/v4.2"
    }
  },
  {
    step: 1,
    id: "ocsf",
    title: "Step 1: OCSF Normalization",
    subtitle: "Mapping raw logs into a standardized security schema",
    color: "#3b82f6",
    text: "The raw log is converted into the Open Cybersecurity Schema Framework (OCSF). Normalizing data formats across all security log sources ensures the downstream AI can analyze them uniformly.",
    innerTitle: "OCSF Normalized Event JSON",
    payload: {
      "class_name": "Web_Activity",
      "device": "WAF-Edge-01",
      "src_endpoint": { "ip": "185.174.21.14" },
      "http_request": { "uri": "/payment/checkout", "query": "id=42' OR 1=1--" }
    }
  },
  {
    step: 2,
    id: "redis",
    title: "Step 2: Redis Event Bus",
    subtitle: "Buffering normalized alerts for real-time processing",
    color: "#ef4444",
    text: "The normalized OCSF event is pushed into a Redis stream. This acts as a durable event bus, ensuring zero packet loss during massive traffic spikes and allowing the AI classifiers to consume events asynchronously.",
    innerTitle: "Redis Stream Buffer",
    payload: {
      "Stream Key": "soc:alerts.raw",
      "Message ID": "1710928374-0",
      "Queue Length": "1,482 pending",
      "Retention": "15-minute rolling window"
    }
  },
  {
    step: 3,
    id: "xgboost",
    title: "Step 3: XGBoost AI Triage",
    subtitle: "Predicting attack types and filtering false positives",
    color: "#8b5cf6",
    text: "The XGBoost model processes the OCSF features. It predicts the attack class as 'Web Attack' with 94% confidence. Because confidence exceeds the 40% threshold, it bypasses the False Positive filter to continue ingestion.",
    innerTitle: "ML Classifier Output",
    payload: {
      "Predicted Class": "Web Attack",
      "Confidence Score": "94.2%",
      "False Positive": "No (TP)",
      "Action": "Ingest & Alert"
    }
  },
  {
    step: 4,
    id: "enrichment",
    title: "Step 4: Threat Intelligence Enrichment",
    subtitle: "Adding context from GeoIP, WHOIS, and MITRE ATT&CK",
    color: "#f59e0b",
    text: "Threat Intelligence enriches the event. It identifies the IP origin as Russia, domain age as 3 days (highly suspicious), and maps the tactic to MITRE ATT&CK technique T1190 (Exploit Public-Facing Application).",
    innerTitle: "Enriched Context Data",
    payload: {
      "Country Origin": "Russia (RU)",
      "WHOIS Domain Age": "3 days",
      "MITRE Technique": "T1190 - Exploit Public-Facing App",
      "TI Reputation Score": "85 / 100 (Malicious)"
    }
  },
  {
    step: 5,
    id: "correlation",
    title: "Step 5: Incident Correlation Engine",
    subtitle: "Grouping related alerts into a single cohesive incident",
    color: "#f97316",
    text: "The Correlation Engine scans the 15-minute sliding window. It correlates this SQL injection alert with other events (like a failed admin login and a shell execution) matching the same attacker IP and user, creating Incident #42.",
    innerTitle: "Correlated Security Incident",
    payload: {
      "Incident ID": "INC-42",
      "Primary Tactic": "Initial Access → Privilege Escalation",
      "Asset Impacted": "Payment Gateway",
      "Alerts Grouped": "4 correlated events"
    }
  },
  {
    step: 6,
    id: "gemini",
    title: "Step 6: Gemini AI Analyst",
    subtitle: "Synthesizing natural language summaries and response playbooks",
    color: "#8b5cf6",
    text: "Gemini 2.5 Pro reviews the correlated incident timeline. It generates a clear narrative explanation of the attack, assesses the business impact, and writes step-by-step remediation recommendations for the analyst.",
    innerTitle: "Gemini Synthesis Output",
    payload: {
      "Summary": "Multi-stage SQL injection and account brute-force on Payment Gateway.",
      "Root Cause": "Vulnerability on checkout endpoint.",
      "Playbook": "Block IP 185.174.21.14, patch checkout API, reset admin credentials."
    }
  },
  {
    step: 7,
    id: "dashboard",
    title: "Step 7: WebSocket Push to SOC",
    subtitle: "Real-time delivery to the Incident Dashboard",
    color: "#14b8a6",
    text: "The finalized Incident #42 is broadcasted over WebSockets. This immediately updates Dashboard 2, alerting the SOC analysts and triggering the investigation workflow.",
    innerTitle: "SOC Event Dispatcher",
    payload: {
      "Transport": "WebSocket Broadcast",
      "Client View": "Dashboard 2 (Incident Investigation)",
      "Status": "Dispatched to SOC Analysts",
      "Action": "Awaiting Human Containment"
    }
  }
];

export default function PipelineMonitor() {
  const { metrics, health, connected } = useNexus();
  const sim = useSimData();

  const [activeStage, setActiveStage] = useState(null);
  const [walkStep, setWalkStep]       = useState(null);
  const inWalk = walkStep !== null;
  const walkthroughStage = inWalk ? WALKTHROUGH_STEPS[walkStep] : null;

  // Which stage is spotlit
  const highlightId = inWalk ? walkthroughStage.id : activeStage;

  const selStage = STAGES.find(s => s.id === highlightId);

  // Incoming alert example (simulated)
  const [incoming, setIncoming] = useState({
    src: "Firewall", ip: "185.212.134.58", type: "web-attack-detected", time: "10:24:35 AM",
  });
  useEffect(() => {
    const types = ["web-attack-detected", "brute-force-attempt", "malware-download", "dns-tunnel-detected", "phish-click"];
    const ips   = ["185.212.134.58","103.41.9.212","91.92.251.7","45.147.229.101"];
    const id = setInterval(() => setIncoming({
      src:  ["Firewall","WAF","EDR","DNS","Auth"][Math.floor(Math.random() * 5)],
      ip:   ips[Math.floor(Math.random() * ips.length)],
      type: types[Math.floor(Math.random() * types.length)],
      time: new Date().toLocaleTimeString(),
    }), 3500);
    return () => clearInterval(id);
  }, []);

  const metricCards = [
    { label: "Alerts Ingested / sec", icon: "📥", value: sim.ingested,  delta: "+18.6% vs last 5m", up: true,  color: "#3b82f6",  key: "ing" },
    { label: "Alerts Processed / sec", icon: "⚙️", value: sim.processed, delta: "+16.3% vs last 5m", up: true,  color: "#22c55e",  key: "proc" },
    { label: "Redis Queue Length",     icon: "⬡",  value: sim.queueLen.toLocaleString(), delta: "+8.4% vs last 5m", up: false, color: "#8b5cf6",  key: "queue" },
    { label: "Pipeline Latency",       icon: "⏱",  value: `${sim.latency} ms`,           delta: "↓12.7% vs last 5m", up: true, color: "#f59e0b", key: "lat" },
    { label: "MITRE RAG Engine",       icon: "✦",  value: "Active",                      delta: "All systems operational", up: true, color: "#8b5cf6", isText: true },
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", minHeight: "100%", background: "var(--color-bg)", paddingBottom: 40 }}>

      {/* ── Page header ── */}
      <div style={{ padding: "16px 24px 0", background: "var(--color-bg)", flexShrink: 0 }}>
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 16 }}>
          <div>
            <h1 style={{ fontSize: 22, fontWeight: 700, color: "var(--color-text)", margin: 0, lineHeight: 1.2 }}>
              AI Pipeline Monitor
            </h1>
            <p style={{ fontSize: 13, color: "var(--color-text-3)", marginTop: 4 }}>
              Real-time view of alert processing and AI analysis pipeline
            </p>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "6px 14px", borderRadius: 20, background: connected ? "var(--color-green-light)" : "#f1f5f9", border: `1px solid ${connected ? "#bbf7d0" : "var(--color-border)"}` }}>
              <span className={`status-dot ${connected ? "live" : "offline"}`} style={{ width: 6, height: 6 }} />
              <span style={{ fontSize: 12, fontWeight: 500, color: connected ? "var(--color-green-dark)" : "var(--color-text-3)" }}>
                {connected ? "Live" : "Offline"}
              </span>
            </div>
            {!inWalk
              ? <button className="btn btn-primary" onClick={() => setWalkStep(0)}>▶ Start Guided Tour</button>
              : <button className="btn btn-secondary" onClick={() => setWalkStep(null)}>✕ Exit Tour</button>
            }
          </div>
        </div>

        {/* Metric cards */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 12, marginBottom: 16 }}>
          {metricCards.map((m, i) => (
            <div key={m.key} className="metric-card anim" style={{ animationDelay: `${i * 50}ms` }}>
              <div className="metric-label">
                <span style={{ fontSize: 14 }}>{m.icon}</span>
                {m.label}
              </div>
              <div style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between", gap: 8 }}>
                <div>
                  <div className="metric-value" style={{ fontSize: m.isText ? 20 : 26, color: m.isText ? m.color : "var(--color-text)" }}>
                    {m.value}
                  </div>
                  <div className={`metric-delta ${m.up ? "up" : "down"}`} style={{ marginTop: 3 }}>
                    {m.up ? "▲" : "▼"} {m.delta}
                  </div>
                </div>
                {!m.isText && (
                  <Spark
                    data={sim.history.map(h => ({ v: h.ing }))}
                    color={m.color}
                  />
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Body: 1 column scrollable ── */}
      <div style={{ flex: 1, padding: "0 24px" }}>

        {/* TOP — Horizontal Live Log Sources */}
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="card-header" style={{ padding: "10px 16px", borderBottom: "1px solid var(--color-border)" }}>
            <span className="card-title" style={{ fontSize: 12 }}>Live Log Sources (11)</span>
            <span className="status-dot live" style={{ width: 6, height: 6 }} />
          </div>
          <div style={{ display: "flex", gap: 10, overflowX: "auto", padding: "12px 16px", background: "var(--color-bg)", justifyContent: "space-between" }}>
            {LOG_SOURCES.map((src, i) => {
              const cnt = sim.sourceCounts[i] || src.base;
              const rate = Math.floor(cnt / 14);
              return (
                <div key={src.name} style={{
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                  background: "var(--color-surface)",
                  border: "1px solid var(--color-border)",
                  borderRadius: 8,
                  padding: "6px 12px",
                  minWidth: 80,
                  flex: 1,
                  textAlign: "center",
                  position: "relative"
                }}>
                  <span style={{ fontSize: 9, fontWeight: 800, color: "var(--color-blue)", background: "var(--color-blue-light)", padding: "2px 6px", borderRadius: 4, marginBottom: 4 }}>{src.code}</span>
                  <span style={{ fontSize: 10, fontWeight: 700, color: "var(--color-text)", whiteSpace: "nowrap" }}>{src.name}</span>
                  <span style={{ fontSize: 9, color: "var(--color-text-3)", fontFamily: "var(--font-mono)", marginTop: 1 }}>{rate} eps</span>
                </div>
              );
            })}
          </div>
        </div>

        {/* BOTTOM — AI Processing Pipeline */}
        <div className="card" style={{ display: "flex", flexDirection: "column", position: "relative" }}>
          <div className="card-header">
            <span className="card-title">AI Processing Pipeline</span>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span className="status-dot live" style={{ width: 7, height: 7 }} />
              <span style={{ fontSize: 11, color: "var(--color-green-dark)", fontWeight: 500 }}>Live</span>
            </div>
          </div>

          {/* Pipeline diagram */}
          <div style={{ padding: "24px", flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
            <style>{`
              @keyframes verticalFlowDot {
                0% { top: 0%; opacity: 0; }
                20% { opacity: 1; }
                80% { opacity: 1; }
                100% { top: 100%; opacity: 0; }
              }
              @keyframes activeStagePulse {
                0% { transform: scale(1); box-shadow: 0 0 0 0px rgba(59,130,246,0.1), 0 4px 12px rgba(59,130,246,0.05); }
                100% { transform: scale(1.03); box-shadow: 0 0 0 6px rgba(59,130,246,0.12), 0 6px 18px rgba(59,130,246,0.18); }
              }
              @keyframes flowText {
                0% { transform: translateY(0px) scale(0.8); opacity: 0; }
                20% { opacity: 0.8; }
                80% { opacity: 0.8; }
                100% { transform: translateY(40px) scale(1); opacity: 0; }
              }
            `}</style>

            {/* Connecting Flow Line with text labels */}
            <div style={{
              position: "relative",
              height: 48,
              width: "100%",
              marginBottom: 10,
              zIndex: 1,
            }}>
              {[
                { text: "JSON",  left: "20%", delay: "0s",  color: "#3b82f6" },
                { text: "Syslog",left: "35%", delay: "0.4s",color: "#ef4444" },
                { text: "CEF",   left: "50%", delay: "0.8s",color: "#10b981" },
                { text: "CSV",   left: "65%", delay: "0.2s",color: "#f59e0b" },
                { text: "Netflow",left:"80%", delay: "0.6s",color: "#8b5cf6" },
              ].map((item, idx) => (
                <div key={idx} style={{
                  position: "absolute",
                  left: item.left,
                  fontSize: 9,
                  fontWeight: 700,
                  fontFamily: "var(--font-mono)",
                  background: `${item.color}15`,
                  color: item.color,
                  border: `1px solid ${item.color}44`,
                  borderRadius: 4,
                  padding: "1px 6px",
                  boxShadow: `0 2px 4px ${item.color}11`,
                  animation: "flowText 2s linear infinite",
                  animationDelay: item.delay,
                }} >
                  {item.text}
                </div>
              ))}
            </div>

            {/* Downward Arrow connecting Log flow into vertical pipeline */}
            <div style={{
              width: 2,
              height: 16,
              background: "#93c5fd",
              margin: "0 auto 10px",
              position: "relative",
              zIndex: 1,
            }}>
              <div style={{
                position: "absolute",
                bottom: -4,
                left: "50%",
                marginLeft: -4,
                width: 0, height: 0,
                borderLeft: "4px solid transparent",
                borderRight: "4px solid transparent",
                borderTop: "5px solid #93c5fd",
              }} />
            </div>

            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 0, width: "100%", maxWidth: 760 }}>
              {STAGES.map((stage, idx) => {
                const isActive   = highlightId === stage.id;
                const isDimmed   = inWalk && !isActive;
                const stageRate  = idx === 1 ? sim.queueLen.toLocaleString() : rand(stage.rateBase, 0.06);
                const stageLat   = idx === 1 ? "18 ms" : idx === 3 ? "420 ms" : idx === 6 ? "1.2 s" : `${rand(stage.latBase, 0.1)} ms`;
                return (
                  <div key={stage.id} style={{ display: "flex", flexDirection: "column", alignItems: "center", width: "100%" }}>
                    
                    {/* Row with Stage Card + Inner Workings */}
                    <div style={{ display: "flex", alignItems: "center", gap: 16, width: "100%", justifyContent: "center" }}>
                      
                      {/* Left: Stage Card */}
                      <div
                        className={`pipeline-stage ${isActive ? "active" : ""} ${isDimmed ? "dimmed" : ""}`}
                        onClick={() => setActiveStage(stage.id)}
                        style={{
                          width: "240px",
                          borderColor: isActive ? stage.color : "var(--color-border)",
                          background: "var(--color-surface)",
                          border: "1.5px solid var(--color-border)",
                          borderRadius: "10px",
                          padding: "10px 14px",
                          cursor: "pointer",
                          transition: "all 0.3s ease",
                          display: "flex",
                          alignItems: "center",
                          gap: 10,
                          zIndex: isActive ? 45 : 2,
                          position: "relative",
                          animation: isActive ? "activeStagePulse 1.5s infinite alternate" : "none",
                          flexShrink: 0,
                        }}
                      >
                        {/* Icon/Initials */}
                        <div style={{
                          width: 32, height: 32, borderRadius: 8,
                          background: isActive ? stage.bgColor : "#f8fafc",
                          border: `1.5px solid ${isActive ? stage.color : "var(--color-border)"}`,
                          display: "flex", alignItems: "center", justifyContent: "center",
                          fontSize: 9, fontWeight: 800, color: isActive ? stage.color : "var(--color-text-4)",
                          flexShrink: 0,
                        }}>
                          {stage.id === "ocsf" ? "IN"
                           : stage.id === "redis" ? "QUE"
                           : stage.id === "xgboost" ? "ML"
                           : stage.id === "enrichment" ? "INT"
                           : stage.id === "correlation" ? "COR"
                           : stage.id === "gemini" ? "AI"
                           : "OUT"}
                        </div>
                        
                        {/* Middle: Info */}
                        <div style={{ flex: 1, textAlign: "left" }}>
                          <div style={{ fontSize: 11, fontWeight: 700, color: isActive ? stage.color : "var(--color-text-2)", lineHeight: 1.2 }}>
                            {stage.label.replace("\n", " ")}
                          </div>
                          <div style={{ fontSize: 9, color: "var(--color-text-4)", marginTop: 2 }}>
                            Latency: {stageLat}
                          </div>
                        </div>

                        {/* Right: Rate */}
                        <div style={{ textAlign: "right", flexShrink: 0 }}>
                          <div style={{ fontSize: 10, color: "var(--color-text-3)", fontFamily: "var(--font-mono)", fontWeight: 600 }}>
                            {stageRate}
                          </div>
                          <div style={{ fontSize: 8, color: "var(--color-text-4)", marginTop: 1 }}>
                            {idx === 1 ? "pending" : "events/s"}
                          </div>
                        </div>
                      </div>

                      {/* Connector Arrow */}
                      <span style={{ fontSize: 16, color: isActive ? stage.color : "var(--color-text-4)", fontWeight: 600 }}>→</span>

                      {/* Right: Inner Workings Diagram */}
                      <div style={{ width: "420px", flexShrink: 0, opacity: isDimmed ? 0.3 : 1, transition: "opacity 0.3s" }}>
                        <InnerWorkingsDiagram stageId={stage.id} />
                      </div>

                    </div>

                    {/* Vertical Connector Line (offset to align with center of Left Stage Card) */}
                    {idx < STAGES.length - 1 && (
                      <div style={{
                        position: "relative",
                        height: 32,
                        width: 2,
                        background: "linear-gradient(180deg, #bfdbfe, #93c5fd, #bfdbfe)",
                        zIndex: isActive ? 42 : 1,
                        margin: "-2px 0",
                        transform: "translateX(-226px)", // shifts left directly below the 240px card
                      }}>
                        <div style={{
                          position: "absolute",
                          width: 6, height: 6,
                          borderRadius: "50%",
                          background: isActive ? stage.color : "var(--color-blue)",
                          left: "50%",
                          marginLeft: -3,
                          boxShadow: `0 0 6px ${isActive ? stage.color : "var(--color-blue)"}`,
                          animation: "verticalFlowDot 1.4s linear infinite",
                          animationDelay: `${idx * 200}ms`,
                        }} />
                        {/* Downward Arrowhead */}
                        <div style={{
                          position: "absolute",
                          bottom: -4,
                          left: "50%",
                          marginLeft: -4,
                          width: 0,
                          height: 0,
                          borderLeft: "4px solid transparent",
                          borderRight: "4px solid transparent",
                          borderTop: `5px solid ${isActive ? stage.color : "#93c5fd"}`,
                        }} />
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            {/* Legend */}
            <div style={{ display: "flex", gap: 16, marginTop: 20, justifyContent: "center" }}>
              {[
                { dot: "var(--color-blue)",   label: "Data Flow" },
                { dot: "var(--color-blue-dark)", label: "Active Stage" },
                { dot: "var(--color-green)",  label: "Completed" },
              ].map(l => (
                <div key={l.label} style={{ display: "flex", alignItems: "center", gap: 5 }}>
                  <span style={{ width: 8, height: 8, borderRadius: "50%", background: l.dot, display: "inline-block" }} />
                  <span style={{ fontSize: 10, color: "var(--color-text-3)" }}>{l.label}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

      </div>

      {/* ── Stage Details Modal Pop-up (manual click) ── */}
      {activeStage && !inWalk && (
        <>
          <div className="walkthrough-backdrop" onClick={() => setActiveStage(null)} style={{ pointerEvents: "auto", cursor: "pointer" }} />
          <div style={{
            position: "fixed",
            top: "50%",
            left: "50%",
            transform: "translate(-50%, -50%)",
            width: "420px",
            background: "var(--color-surface)",
            border: "1px solid var(--color-border)",
            borderRadius: "12px",
            boxShadow: "0 20px 60px rgba(0,0,0,0.15)",
            zIndex: 50,
            display: "flex",
            flexDirection: "column",
            maxHeight: "85vh",
            overflowY: "auto",
          }}>
            <div className="card-header" style={{ borderBottom: "1px solid var(--color-border)", padding: "12px 18px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span className="card-title" style={{ fontSize: 13, fontWeight: 700 }}>Stage Details</span>
              <button
                style={{ background: "none", border: "none", cursor: "pointer", color: "var(--color-text-4)", fontSize: 18, lineHeight: 1 }}
                onClick={() => setActiveStage(null)}
              >×</button>
            </div>
            
            <div style={{ padding: "18px" }}>
              {/* Stage header */}
              <div style={{
                display: "flex", alignItems: "center", justifyContent: "space-between",
                padding: "10px 12px",
                background: selStage?.bgColor,
                border: `1px solid ${selStage?.color}33`,
                borderRadius: 8, marginBottom: 14,
              }}>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 700, color: selStage?.color }}>
                    {selStage?.label.replace("\n", " ")}
                  </div>
                  <div style={{ fontSize: 10, color: "var(--color-text-3)", marginTop: 2 }}>
                    {selStage?.id === "xgboost" ? "Machine Learning Classification"
                    : selStage?.id === "redis"  ? "Event Bus / Stream"
                    : selStage?.id === "ocsf"   ? "Schema Normalization"
                    : selStage?.id === "enrichment" ? "Threat Intelligence"
                    : selStage?.id === "correlation" ? "Incident Grouping"
                    : selStage?.id === "gemini" ? "LLM Summarization"
                    : "SOC Interface"}
                  </div>
                </div>
                <span className="badge badge-active" style={{ fontSize: 10 }}>Active</span>
              </div>

              {/* Custom Architectural Inner Workings Diagram */}
              {selStage && <InnerWorkingsDiagram stageId={selStage.id} />}

              {/* Incoming Alert */}
              <div style={{ marginBottom: 14 }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: "var(--color-text)", marginBottom: 8 }}>Incoming Alert</div>
                {[
                  { k: "Source",     v: incoming.src },
                  { k: "Source IP",  v: incoming.ip },
                  { k: "Event Type", v: incoming.type },
                  { k: "Time",       v: incoming.time },
                ].map(r => (
                  <div key={r.k} style={{ display: "flex", justifyContent: "space-between", padding: "5px 0", borderBottom: "1px solid var(--color-border)" }}>
                    <span style={{ fontSize: 11, color: "var(--color-text-3)" }}>{r.k}</span>
                    <span style={{ fontSize: 10, fontWeight: 500, color: "var(--color-text)", fontFamily: "var(--font-mono)" }}>{r.v}</span>
                  </div>
                ))}
              </div>

              {/* AI Prediction (for xgboost) */}
              {selStage?.id === "xgboost" && (
                <div style={{ marginBottom: 14 }}>
                  <div style={{ fontSize: 11, fontWeight: 600, color: "var(--color-text)", marginBottom: 8 }}>AI Prediction</div>
                  {[
                    { k: "Attack Type",       v: "Web Attack",   vc: "var(--color-red)" },
                    { k: "Confidence",        v: "94%",          vc: "var(--color-green-dark)" },
                    { k: "False Positive",    v: "No",           vc: "var(--color-green-dark)" },
                    { k: "Dynamic Risk Score",v: "81 / 100",     vc: "var(--color-red)" },
                  ].map(r => (
                    <div key={r.k} style={{ display: "flex", justifyContent: "space-between", padding: "5px 0", borderBottom: "1px solid var(--color-border)" }}>
                      <span style={{ fontSize: 11, color: "var(--color-text-3)" }}>{r.k}</span>
                      <span style={{ fontSize: 11, fontWeight: 600, color: r.vc }}>{r.v}</span>
                    </div>
                  ))}
                </div>
              )}

              {/* Stage config */}
              <div style={{ marginBottom: 18 }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: "var(--color-text)", marginBottom: 8 }}>Stage Config</div>
                {selStage && Object.entries(selStage.detail).map(([k, v]) => (
                  <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "5px 0", borderBottom: "1px solid var(--color-border)" }}>
                    <span style={{ fontSize: 11, color: "var(--color-text-3)" }}>{k}</span>
                    <span style={{ fontSize: 10, fontWeight: 500, color: "var(--color-text)", fontFamily: "var(--font-mono)", textAlign: "right", maxWidth: 200, wordBreak: "break-word" }}>{v}</span>
                  </div>
                ))}
              </div>

              <button className="btn btn-primary" onClick={() => setActiveStage(null)} style={{ width: "100%", justifyContent: "center" }}>
                Close Details
              </button>
            </div>
          </div>
        </>
      )}

      {/* ── Walkthrough overlay ── */}
      {inWalk && (
        <>
          <div className="walkthrough-backdrop" />
          <div className="walkthrough-panel">
            {/* Header */}
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <div style={{
                  width: 26, height: 26, borderRadius: 6,
                  background: `${walkthroughStage.color}18`,
                  border: `1.5px solid ${walkthroughStage.color}`,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontSize: 11, fontWeight: 700, color: walkthroughStage.color,
                }}>
                  {walkStep + 1}
                </div>
                <span style={{ fontSize: 13, fontWeight: 600, color: "var(--color-text)" }}>
                  {walkthroughStage.title}
                </span>
              </div>
              <span style={{ fontSize: 11, color: "var(--color-text-4)" }}>{walkStep + 1} / {WALKTHROUGH_STEPS.length}</span>
            </div>

            {/* Progress */}
            <div className="progress-bar" style={{ marginBottom: 14, height: 3 }}>
              <div className="progress-fill" style={{ width: `${((walkStep + 1) / WALKTHROUGH_STEPS.length) * 100}%`, background: walkthroughStage.color }} />
            </div>

            <div style={{ fontSize: 11, fontWeight: 600, color: walkthroughStage.color, marginBottom: 6 }}>{walkthroughStage.subtitle}</div>
            <p style={{ fontSize: 12, color: "var(--color-text-2)", lineHeight: 1.6, marginBottom: 14 }}>
              {walkthroughStage.text}
            </p>

            {/* Story State Payload */}
            <div style={{ background: "var(--color-surface-2)", border: "1px solid var(--color-border)", borderRadius: 8, padding: "12px", marginBottom: 16 }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: "var(--color-text-3)", textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 8, borderBottom: "1px solid var(--color-border)", paddingBottom: 4 }}>
                {walkthroughStage.innerTitle}
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {Object.entries(walkthroughStage.payload).map(([k, v]) => (
                  <div key={k} style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 10 }}>
                    <span style={{ fontSize: 10, color: "var(--color-text-3)", fontWeight: 500, flexShrink: 0 }}>{k}:</span>
                    <span style={{ fontSize: 10, color: "var(--color-text)", fontWeight: 600, fontFamily: "var(--font-mono)", textAlign: "right", wordBreak: "break-all" }}>
                      {typeof v === "object" ? JSON.stringify(v) : String(v)}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <button className="btn btn-secondary" onClick={() => setWalkStep(null)}>Exit Tour</button>
              <div style={{ display: "flex", gap: 8 }}>
                {walkStep > 0 && <button className="btn btn-secondary" onClick={() => setWalkStep(w => w - 1)}>← Prev</button>}
                {walkStep < WALKTHROUGH_STEPS.length - 1
                  ? <button className="btn btn-primary" onClick={() => setWalkStep(w => w + 1)}>Next Stage →</button>
                  : <button className="btn btn-primary" onClick={() => setWalkStep(null)}>Finish ✓</button>
                }
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
