import { useSoc } from "../store";

const SEV_COLOR = {
  Critical: "bg-red-600 text-white",
  High:     "bg-orange-500 text-white",
  Medium:   "bg-yellow-500 text-black",
  Low:      "bg-green-600 text-white",
  Info:     "bg-slate-600 text-white",
};

function relTime(ts) {
  if (!ts) return "";
  const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (diff < 60)   return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

export default function AttackTimeline() {
  const { incidents, selected } = useSoc();
  const inc = incidents.find(i => i.incident_id === selected);

  if (!selected) {
    return (
      <div className="rounded-xl bg-slate-900 p-4 shadow-lg">
        <h2 className="text-base font-semibold text-slate-200 mb-2">Attack Timeline</h2>
        <p className="text-slate-500 text-sm">Select an incident to see its kill-chain.</p>
      </div>
    );
  }
  if (!inc) return null;

  const alerts = (inc.alerts || []).slice().sort(
    (a, b) => new Date(a.timestamp) - new Date(b.timestamp)
  );

  return (
    <div className="rounded-xl bg-slate-900 p-4 shadow-lg">
      <h2 className="text-base font-semibold text-slate-200 mb-4">
        Kill-Chain Timeline — <span className="font-mono text-blue-400">{inc.incident_id}</span>
      </h2>

      {alerts.length === 0 ? (
        <p className="text-slate-500 text-sm">No alert detail loaded yet. Re-select the incident.</p>
      ) : (
        <div className="relative">
          {/* Vertical line */}
          <div className="absolute left-4 top-0 bottom-0 w-px bg-slate-700" />

          <ol className="space-y-4">
            {alerts.map((a, idx) => (
              <li key={a.alert_id} className="relative pl-12">
                {/* Step dot */}
                <div className={`absolute left-0 w-8 h-8 rounded-full flex items-center justify-center
                                text-xs font-bold border-2 border-slate-700
                                ${idx === 0 ? "bg-blue-600" : "bg-slate-800"} text-white`}>
                  {idx + 1}
                </div>

                <div className="bg-slate-800 rounded-lg p-3 border border-slate-700">
                  <div className="flex items-center gap-2 flex-wrap mb-1">
                    <span className={`rounded px-2 py-0.5 text-xs font-bold ${SEV_COLOR[a.severity] || "bg-slate-600 text-white"}`}>
                      {a.severity}
                    </span>
                    <span className="text-xs text-blue-400 font-semibold">{a.event_type}</span>
                    <span className="text-xs text-slate-400 ml-auto">{relTime(a.timestamp)}</span>
                  </div>
                  <div className="text-xs text-slate-300 font-mono">
                    {a.event_source} → {a.source_ip || a.user || "—"}
                    {a.mitre_tactic && (
                      <span className="ml-2 text-purple-400">
                        [{a.mitre_tactic} / {a.mitre_technique}]
                      </span>
                    )}
                  </div>
                  {a.description && (
                    <p className="text-xs text-slate-400 mt-1 leading-relaxed">{a.description}</p>
                  )}
                </div>
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  );
}
