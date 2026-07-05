import { useSoc } from "../store";

const PRIO_STYLE = {
  P1: "bg-red-600 text-white animate-pulse",
  P2: "bg-orange-500 text-white",
  P3: "bg-yellow-500 text-black",
  P4: "bg-slate-600 text-white",
};

const SEV_STYLE = {
  Critical: "text-red-400",
  High:     "text-orange-400",
  Medium:   "text-yellow-400",
  Low:      "text-green-400",
  Info:     "text-slate-400",
};

function InfoRow({ label, value, mono }) {
  if (!value && value !== 0) return null;
  return (
    <div className="flex justify-between items-start gap-2 py-1.5 border-b border-slate-800 last:border-0">
      <span className="text-xs text-slate-500 shrink-0">{label}</span>
      <span className={`text-xs text-right ${mono ? "font-mono text-blue-300" : "text-slate-300"}`}>
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
      <div className="rounded-xl bg-slate-900 p-4 shadow-lg text-slate-500 text-sm">
        Select an incident to view its investigation report.
      </div>
    );
  }

  const tactics = (inc.tactics || []).join(" → ");
  const iocs    = (inc.ioc_values || []).slice(0, 5).join(", ");
  const hasLLM  = !!(inc.summary && inc.summary !== "LLM API Key missing.");

  return (
    <div className="rounded-xl bg-slate-900 p-4 shadow-lg flex flex-col gap-4">
      {/* Header */}
      <div className="flex justify-between items-start">
        <div>
          <h2 className="text-lg font-bold text-white font-mono">{inc.incident_id}</h2>
          <p className="text-xs text-slate-400 mt-0.5">{inc.asset}</p>
        </div>
        <div className="flex flex-col items-end gap-1">
          <span className={`rounded px-2 py-0.5 text-xs font-bold ${PRIO_STYLE[inc.priority] || "bg-slate-600 text-white"}`}>
            {inc.priority}
          </span>
          <span className="text-xs text-slate-400">Risk: <span className={`font-bold ${SEV_STYLE[inc.severity] || "text-slate-300"}`}>{inc.max_risk}</span></span>
        </div>
      </div>

      {/* Meta */}
      <div className="bg-slate-800 rounded-lg p-3">
        <InfoRow label="Campaign"        value={inc.campaign_name}                  />
        <InfoRow label="MITRE Chain"     value={tactics || "—"}                     />
        <InfoRow label="Key IOCs"        value={iocs || "—"}              mono       />
        <InfoRow label="Alerts"          value={inc.alert_ids?.length}              />
        <InfoRow label="Agent Steps"     value={inc.steps_taken != null ? `${inc.steps_taken} steps, ${inc.tool_calls} tools` : "—"} />
        <InfoRow label="Confidence"      value={inc.confidence != null ? `${inc.confidence}%` : "—"} />
      </div>

      {/* AI Summary */}
      <div>
        <div className="flex items-center gap-2 mb-1">
          <h3 className="text-sm font-semibold text-slate-200">🔍 Investigation Summary</h3>
          {!hasLLM && <span className="text-[10px] bg-yellow-900 text-yellow-300 rounded px-1.5 py-0.5">Heuristic</span>}
          {hasLLM  && <span className="text-[10px] bg-emerald-900 text-emerald-300 rounded px-1.5 py-0.5">AI Agent</span>}
        </div>
        <p className="text-xs text-slate-300 leading-relaxed bg-slate-800 p-3 rounded">
          {inc.summary || "Pending analysis…"}
        </p>
      </div>

      {/* Attack Narrative */}
      {inc.attack_narrative && (
        <div>
          <h3 className="text-sm font-semibold text-slate-200 mb-1">⚔️ Attack Narrative</h3>
          <p className="text-xs text-slate-300 leading-relaxed bg-slate-800/50 p-3 rounded border-l-2 border-blue-600">
            {inc.attack_narrative}
          </p>
        </div>
      )}

      {/* Recommended Action */}
      {inc.recommended_action && (
        <div>
          <h3 className="text-sm font-semibold text-emerald-400 mb-1">✅ Recommended Action</h3>
          <p className="text-xs text-slate-300 leading-relaxed bg-emerald-950/30 p-3 rounded border-l-2 border-emerald-500">
            {inc.recommended_action}
          </p>
        </div>
      )}
    </div>
  );
}
