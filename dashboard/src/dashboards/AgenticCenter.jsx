import { useState, useEffect, useRef } from "react";
import { useNexus } from "../store";
import LiveSandbox from "../components/LiveSandbox";

const PRIO_BADGE = { P1: "badge-p1", P2: "badge-p2", P3: "badge-p3", P4: "badge-p4" };

const DEMO_INCIDENT = {
  incident_id: "INC-DEMO-SANDBOX",
  priority: "P1",
  asset: "FIFA Ticketing Portal Sandbox",
  max_risk: 98,
  campaign_name: "Automated SQLi Extraction",
  tactics: ["Initial Access", "Credential Access"],
  techniques: ["T1190 - Exploit Public-Facing Application", "T1059 - Command and Scripting Interpreter"],
  summary: "An automated SQL injection attack (1' OR 1=1--) is continuously hitting the ticketing sandbox portal on the /checkout endpoint.",
  attack_narrative: "The attacker is exploiting a vulnerability in the /checkout parameter parsing to extract the full database schema. The attack script runs every 3 seconds, resulting in repeated 200 OK extractions.",
  recommended_action: "Block the attacker's IP address at the network edge firewall to sever connection before payload executes."
};

const DEMO_ACTION = {
  action_id: "ACT-DEMO-BLOCK",
  incident_id: "INC-DEMO-SANDBOX",
  action_type: "block_ip",
  target: "ALL (Network Level Sandbox Block)",
  message: "Approval required to block_ip on ALL Sandbox traffic: Block the ongoing SQL Injection attack.",
  status: "pending_approval"
};

export default function AgenticCenter() {
  const { connected } = useNexus();
  const [mitigatingId, setMitigatingId] = useState(null);
  const [successId, setSuccessId] = useState(null);
  const [rejectedId, setRejectedId] = useState(null);
  const [consoleLogs, setConsoleLogs] = useState([]);
  const logEndRef = useRef(null);

  const inc = DEMO_INCIDENT;
  const selectedId = inc.incident_id;

  // Sync log scroll
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [consoleLogs]);

  // Generate logs simulating agent thoughts when incident changes
  useEffect(() => {
    if (!selectedId) return;

    setConsoleLogs([
      `[INFO] Initializing Agent for Incident ${selectedId}...`,
      `[PROCESS] Loading asset context for "${inc.asset || "Unknown Asset"}"...`,
    ]);

    const steps = [
      `[THOUGHT] Risk score is ${inc.max_risk || 0}/100. Investigating event chain.`,
      `[TOOL] query_similar: Retrieving RAG grounding documentation...`,
      `[INFO] RAG Search complete. Found 2 similar past incidents in vector db.`,
      `[MITRE] Mapping techniques: ${inc.tactics?.join(" -> ") || "Recon -> Discovery"}`,
      `[THOUGHT] Incident requires active remediation. Evaluating mitigation options...`,
    ];

    let delay = 600;
    steps.forEach((step, idx) => {
      setTimeout(() => {
        if (selectedId === inc.incident_id) {
          setConsoleLogs(prev => [...prev, step]);
        }
      }, delay * (idx + 1));
    });
  }, [selectedId]);

  const pendingAction = successId ? null : DEMO_ACTION;
  const executedActions = successId ? [{ ...DEMO_ACTION, status: "executed" }] : [];

  const handleApprove = async (actionId) => {
    setMitigatingId(actionId);
    try {
      setConsoleLogs(prev => [...prev, `[HITL] Human approved Action ${actionId}. Deploying fix...`]);
      await fetch("http://localhost:8080/api/sandbox/remediate", { method: "POST" });
      setTimeout(() => {
        setMitigatingId(null);
        setSuccessId(actionId);
        setConsoleLogs(prev => [...prev, `[SUCCESS] Fix applied successfully. Asset returned to secure state.`]);
      }, 1500);
    } catch (e) {
      setMitigatingId(null);
      setConsoleLogs(prev => [...prev, `[ERROR] Failed to apply fix: ${e.message}`]);
    }
  };

  const handleReject = async (actionId) => {
    setRejectedId(actionId);
    try {
      setConsoleLogs(prev => [...prev, `[HITL] Action ${actionId} rejected by human analyst.`]);
      // Demo rejection just clears it
      setSuccessId("REJECTED");
      setTimeout(() => {
        setRejectedId(null);
      }, 1000);
    } catch (e) {
      setRejectedId(null);
      setConsoleLogs(prev => [...prev, `[ERROR] Failed to reject: ${e.message}`]);
    }
  };

  const handleReset = async () => {
    try {
      setConsoleLogs(prev => [...prev, `[INFO] Analyst requested sandbox reset. Reversing mitigations...`]);
      await fetch("http://localhost:8080/api/sandbox/reset", { method: "POST" });
      setSuccessId(null);
      setMitigatingId(null);
      setRejectedId(null);
      setConsoleLogs(prev => [...prev, `[SUCCESS] Sandbox firewall reset. Environment is vulnerable again.`]);
    } catch (e) {
      setConsoleLogs(prev => [...prev, `[ERROR] Failed to reset sandbox: ${e.message}`]);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", minHeight: "100%", background: "var(--color-bg)", padding: "16px 24px 40px" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: "var(--color-text)", margin: 0 }}>Agent Response Center</h1>
          <p style={{ fontSize: 13, color: "var(--color-text-3)", marginTop: 4 }}>
            Monitor autonomous AI actions, review MITRE RAG reports, and authorize mitigations
          </p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <button onClick={handleReset} style={{ background: "rgba(255,255,255,0.05)", border: "1px solid var(--color-border)", color: "var(--color-text-2)", padding: "4px 12px", borderRadius: 4, fontSize: 11, cursor: "pointer", display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ fontSize: 12 }}>🔄</span> Reset Scenario
          </button>
          <span className="badge badge-purple" style={{ fontSize: 11, padding: "4px 10px", marginLeft: 10 }}>Active RAG Agent</span>
          <span className={`status-dot ${connected ? "live" : "offline"}`} style={{ width: 8, height: 8 }} />
        </div>
      </div>

      {/* Main Grid */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: 20, alignItems: "stretch", minHeight: 700 }}>

        {/* Middle Column: RAG Security Report & Sandbox */}
        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
          <div className="card" style={{ flex: 1, display: "flex", flexDirection: "column", padding: 20 }}>
          <div style={{ borderBottom: "1px solid var(--color-border)", paddingBottom: 12, marginBottom: 16, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: 15, fontWeight: 700, color: "var(--color-text)" }}>📄 Grounded RAG Security Report</span>
            <span className="badge badge-blue">Mitre Grounded</span>
          </div>

          <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 20, overflowY: "auto" }}>
            {/* Risk score & Asset info */}
            <div style={{ display: "flex", gap: 24, alignItems: "center", background: "var(--color-bg)", padding: 16, borderRadius: 10 }}>
              {/* Circular progress ring for Risk */}
              <div style={{ position: "relative", width: 70, height: 70, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <svg width="70" height="70" style={{ transform: "rotate(-90deg)" }}>
                  <circle cx="35" cy="35" r="30" fill="transparent" stroke="var(--color-border)" strokeWidth="6" />
                  <circle
                    cx="35" cy="35" r="30" fill="transparent"
                    stroke={inc.max_risk > 75 ? "var(--color-red)" : "var(--color-yellow)"}
                    strokeWidth="6"
                    strokeDasharray={2 * Math.PI * 30}
                    strokeDashoffset={2 * Math.PI * 30 * (1 - (inc.max_risk || 0) / 100)}
                    strokeLinecap="round"
                    style={{ transition: "stroke-dashoffset 0.5s ease" }}
                  />
                </svg>
                <div style={{ position: "absolute", fontSize: 15, fontWeight: 800, color: "var(--color-text)" }}>
                  {inc.max_risk || 0}
                </div>
              </div>

              <div>
                <div style={{ fontSize: 11, color: "var(--color-text-4)", textTransform: "uppercase" }}>Target Asset</div>
                <div style={{ fontSize: 16, fontWeight: 700, color: "var(--color-text)" }}>{inc.asset || "Core digital Infrastructure"}</div>
                <div style={{ fontSize: 12, color: "var(--color-text-3)", marginTop: 2 }}>
                  Priority: <span style={{ fontWeight: 600 }}>{inc.priority}</span> | Campaigns: <span style={{ fontWeight: 600 }}>{inc.campaign_name || "None"}</span>
                </div>
              </div>
            </div>

            {/* MITRE Mapping */}
            <div>
              <div style={{ fontSize: 12, fontWeight: 600, color: "var(--color-text-2)", marginBottom: 8 }}>🎯 MITRE ATT&CK Mapping</div>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                {inc.tactics?.map(t => (
                  <span key={t} className="badge badge-purple" style={{ padding: "4px 10px", fontSize: 11 }}>{t}</span>
                ))}
                {inc.techniques?.map(tc => (
                  <span key={tc} style={{
                    fontFamily: "var(--font-mono)", fontSize: 11, background: "rgba(139, 92, 246, 0.1)",
                    border: "1px solid rgba(139, 92, 246, 0.2)", color: "var(--color-purple)",
                    padding: "2px 8px", borderRadius: 4
                  }}>{tc}</span>
                ))}
              </div>
            </div>

            {/* Report Content */}
            <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              <div>
                <div style={{ fontSize: 11, fontWeight: 600, color: "var(--color-blue)", textTransform: "uppercase", marginBottom: 4 }}>Executive Summary</div>
                <div style={{ fontSize: 13, color: "var(--color-text-2)", lineHeight: 1.6 }}>{inc.summary || "Pending agent RAG summarization..."}</div>
              </div>

              <div>
                <div style={{ fontSize: 11, fontWeight: 600, color: "var(--color-purple)", textTransform: "uppercase", marginBottom: 4 }}>Attack Narrative</div>
                <div style={{ fontSize: 13, color: "var(--color-text-2)", lineHeight: 1.6 }}>{inc.attack_narrative || "No attack narrative generated yet."}</div>
              </div>

              <div>
                <div style={{ fontSize: 11, fontWeight: 600, color: "var(--color-green)", textTransform: "uppercase", marginBottom: 4 }}>Suggested Fixes</div>
                <div style={{ fontSize: 13, color: "var(--color-text-2)", lineHeight: 1.6 }}>{inc.recommended_action || "Investigating solution playbooks..."}</div>
              </div>

              {/* Action Area */}
              <div style={{ marginTop: 20, padding: 20, border: pendingAction ? "1px solid var(--color-blue)" : "1px solid var(--color-border)", borderRadius: 10, background: pendingAction ? "rgba(59, 130, 246, 0.05)" : "var(--color-surface)" }}>
                <div style={{ fontSize: 14, fontWeight: 700, color: "var(--color-text)", display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                  ⚡ Autonomous Remediation
                </div>
                {pendingAction ? (
                  <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <div>
                        <div style={{ fontSize: 13, fontWeight: 700, color: "var(--color-text)" }}>{pendingAction.action_type.toUpperCase()}</div>
                        <div style={{ fontSize: 12, color: "var(--color-text-3)", marginTop: 4 }}>Target: <code style={{ background: "rgba(0,0,0,0.1)", padding: "2px 6px", borderRadius: 4 }}>{pendingAction.target}</code></div>
                      </div>
                      <div style={{ display: "flex", gap: 10 }}>
                        {mitigatingId === pendingAction.action_id ? (
                          <button className="btn btn-primary" disabled style={{ width: 140, justifyContent: "center", height: 36 }}>
                            <div className="typing-dot" style={{ background: "#fff" }} />
                            <div className="typing-dot" style={{ background: "#fff" }} />
                            <div className="typing-dot" style={{ background: "#fff" }} />
                            <span style={{ marginLeft: 8 }}>Applying...</span>
                          </button>
                        ) : (
                          <button
                            className="btn"
                            onClick={() => handleApprove(pendingAction.action_id)}
                            style={{ background: "var(--color-green)", color: "#000", width: 140, justifyContent: "center", border: "none", height: 36 }}
                          >
                            Approve Fix
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                ) : successId ? (
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <div style={{ width: 32, height: 32, borderRadius: "50%", background: "rgba(34, 197, 94, 0.15)", display: "flex", alignItems: "center", justifyContent: "center", color: "var(--color-green)", fontSize: 16 }}>✓</div>
                    <div>
                      <div style={{ fontSize: 14, fontWeight: 700, color: "var(--color-text)" }}>Mitigation Applied</div>
                      <div style={{ fontSize: 12, color: "var(--color-text-3)" }}>The security threat was neutralized successfully.</div>
                    </div>
                  </div>
                ) : null}
              </div>
            </div>
          </div>
        </div>
          
        <div style={{ display: "grid", gridTemplateColumns: "350px 1fr", gap: 20, height: 320 }}>
          {/* Agent Thinking Console */}
          <div className="card" style={{ display: "flex", flexDirection: "column", padding: "16px 20px", background: "#090d16", border: "1px solid #1e293b", overflow: "hidden" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid #1e293b", paddingBottom: 10, marginBottom: 12 }}>
              <span style={{ fontSize: 12, fontWeight: 600, color: "#38bdf8", fontFamily: "var(--font-mono)" }}>🤖 AGENT COGNITIVE LOOP</span>
              <span className="status-dot live" style={{ width: 6, height: 6 }} />
            </div>

            <div style={{ flex: 1, overflowY: "auto", fontFamily: "var(--font-mono)", fontSize: 11, color: "#e2e8f0", display: "flex", flexDirection: "column", gap: 8 }}>
              {consoleLogs.map((log, i) => (
                <div key={i} style={{
                  color: log.startsWith("[ERROR]") ? "#ef4444" : 
                         log.startsWith("[SUCCESS]") ? "#22c55e" : 
                         log.startsWith("[HITL]") ? "#facc15" : 
                         log.startsWith("[TOOL]") ? "#a855f7" :
                         log.startsWith("[MITRE]") ? "#f59e0b" : "#38bdf8"
                }}>
                  {log}
                </div>
              ))}
              <div ref={logEndRef} />
            </div>
          </div>

          {/* Live Sandbox Terminal */}
          <LiveSandbox />
        </div>
      </div>
    </div>
  </div>
  );
}
