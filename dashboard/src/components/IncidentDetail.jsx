import { useSoc } from "../store";

const PRIO_STYLE = {
  P1: "bg-critical-red/15 border border-critical-red/30 text-critical-red animate-pulse",
  P2: "bg-alert-orange/15 border border-alert-orange/30 text-alert-orange",
  P3: "bg-caution-amber/15 border border-caution-amber/30 text-caution-amber",
  P4: "bg-on-tertiary-container/15 border border-on-tertiary-container/30 text-on-tertiary-container",
};

const SEV_STYLE = {
  Critical: "text-critical-red",
  High:     "text-alert-orange",
  Medium:   "text-caution-amber",
  Low:      "text-security-green",
  Info:     "text-on-tertiary-container",
};

function InfoRow({ label, value, mono }) {
  if (!value && value !== 0) return null;
  return (
    <div className="flex justify-between items-start gap-4 py-1.5 border-b border-border-subtle/30 last:border-0">
      <span className="text-[9px] font-mono text-on-tertiary-container uppercase tracking-wider font-bold shrink-0">{label}</span>
      <span className={`text-xs text-right truncate ${mono ? "font-mono text-primary font-bold" : "text-on-surface"}`}>
        {value}
      </span>
    </div>
  );
}

export default function IncidentDetail() {
  const { incidents, selected } = useSoc();
  const inc = incidents.find(i => i.incident_id === selected);

  if (!inc) {
    return (
      <div className="rounded bg-slate-surface border border-border-subtle p-5 shadow text-on-tertiary-container font-mono text-xs uppercase tracking-wider">
        SELECT AN INCIDENT TO INITIALIZE INVESTIGATION REPORT.
      </div>
    );
  }

  const tactics = (inc.tactics || []).join(" → ");
  const iocs    = (inc.ioc_values || []).slice(0, 5).join(", ");
  const hasLLM  = !!(inc.summary && inc.summary !== "LLM API Key missing.");

  return (
    <div className="rounded bg-slate-surface border border-border-subtle p-5 shadow flex flex-col gap-4">
      {/* Header */}
      <div className="flex justify-between items-start">
        <div>
          <h2 className="text-base font-bold text-primary font-mono">{inc.incident_id}</h2>
          <p className="text-[10px] text-on-tertiary-container font-mono uppercase tracking-wider mt-1">{inc.asset}</p>
        </div>
        <div className="flex flex-col items-end gap-1">
          <span className={`rounded-sm px-2.5 py-0.5 text-[10px] font-mono font-bold uppercase tracking-wider ${PRIO_STYLE[inc.priority] || "bg-slate-800 text-slate-400"}`}>
            {inc.priority}
          </span>
          <span className="text-[10px] font-mono text-on-tertiary-container mt-1 uppercase tracking-wider">
            RISK: <span className={`font-bold ${SEV_STYLE[inc.severity] || "text-on-surface"}`}>{inc.max_risk}</span>
          </span>
        </div>
      </div>

      {/* Meta Detail Box */}
      <div className="bg-midnight-base/50 border border-border-subtle rounded-sm p-3 flex flex-col">
        <InfoRow label="Campaign"        value={inc.campaign_name}                  />
        <InfoRow label="MITRE Chain"     value={tactics || "—"}                     />
        <InfoRow label="Key IOCs"        value={iocs || "—"}              mono       />
        <InfoRow label="Alerts"          value={inc.alert_ids?.length}              />
        <InfoRow label="Agent Steps"     value={inc.steps_taken != null ? `${inc.steps_taken} steps, ${inc.tool_calls} tools` : "—"} />
        <InfoRow label="Confidence"      value={inc.confidence != null ? `${inc.confidence}%` : "—"} />
      </div>

      {/* AI Summary Section */}
      <div>
        <div className="flex items-center gap-2 mb-2">
          <h3 className="text-[10px] font-mono font-bold text-primary uppercase tracking-wider">🔍 Investigation Summary</h3>
          {!hasLLM && <span className="text-[9px] font-mono bg-caution-amber/10 border border-caution-amber/30 text-caution-amber rounded-sm px-1.5 py-0.5 uppercase tracking-wider font-semibold">Heuristic</span>}
          {hasLLM  && <span className="text-[9px] font-mono bg-security-green/10 border border-security-green/30 text-security-green rounded-sm px-1.5 py-0.5 uppercase tracking-wider font-semibold">AI Agent</span>}
        </div>
        <p className="text-xs text-on-surface/90 leading-relaxed bg-midnight-base/40 border border-border-subtle/60 p-3.5 rounded-sm">
          {inc.summary || "Pending analysis…"}
        </p>
      </div>

      {/* Attack Narrative Section */}
      {inc.attack_narrative && (
        <div>
          <h3 className="text-[10px] font-mono font-bold text-primary uppercase tracking-wider mb-2">⚔️ Attack Narrative</h3>
          <p className="text-xs text-on-surface/90 leading-relaxed bg-midnight-base/20 border border-border-subtle/60 border-l-[3px] border-l-primary/60 p-3.5 rounded-sm">
            {inc.attack_narrative}
          </p>
        </div>
      )}

      {/* Recommended Action Section */}
      {inc.recommended_action && (
        <div>
          <h3 className="text-[10px] font-mono font-bold text-security-green uppercase tracking-wider mb-2">✅ Recommended Action</h3>
          <p className="text-xs text-on-surface/90 leading-relaxed bg-security-green/5 border border-security-green/20 border-l-[3px] border-l-security-green p-3.5 rounded-sm">
            {inc.recommended_action}
          </p>
        </div>
      )}
    </div>
  );
}
