import { useSoc } from "../store";

const PRIO = {
  P1: "bg-red-600 text-white",
  P2: "bg-orange-500 text-white",
  P3: "bg-yellow-500 text-black",
  P4: "bg-slate-600 text-slate-200",
};

const SEV_DOT = {
  Critical: "bg-red-500",
  High:     "bg-orange-500",
  Medium:   "bg-yellow-500",
  Low:      "bg-green-500",
  Info:     "bg-slate-500",
};

const API = import.meta.env.VITE_API || "http://localhost:8080";

export default function IncidentLedger() {
  const { incidents, select, selected } = useSoc();

  const handleSelect = async (inc_id) => {
    select(inc_id);
    // Load full alert detail into the incident object
    try {
      const detail = await fetch(`${API}/api/incidents/${inc_id}`).then(r => r.json());
      // Merge alerts into existing state
      useSoc.setState(state => ({
        incidents: state.incidents.map(i =>
          i.incident_id === inc_id ? { ...i, alerts: detail.alerts } : i
        ),
      }));
    } catch (e) {
      console.warn("Could not load incident detail:", e.message);
    }
  };

  const sorted = [...incidents].sort((a, b) => {
    const pord = { P1: 0, P2: 1, P3: 2, P4: 3 };
    return (pord[a.priority] ?? 4) - (pord[b.priority] ?? 4);
  });

  return (
    <div className="rounded-xl bg-slate-900 shadow-lg flex flex-col">
      <div className="flex items-center justify-between px-4 pt-4 pb-2">
        <h2 className="text-base font-semibold text-slate-200">
          Incident Ledger
          <span className="ml-2 text-xs text-slate-500 font-normal">
            ({incidents.length} total)
          </span>
        </h2>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-[11px] uppercase tracking-wide text-slate-500
                           border-b border-slate-800">
              <th className="text-left px-4 py-2">ID</th>
              <th className="px-2 py-2">Priority</th>
              <th className="px-2 py-2">Risk</th>
              <th className="text-left px-2 py-2">Asset</th>
              <th className="px-2 py-2">Tactics</th>
              <th className="px-2 py-2">Alerts</th>
              <th className="text-left px-2 py-2">Campaign</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((inc) => (
              <tr
                key={inc.incident_id}
                onClick={() => handleSelect(inc.incident_id)}
                className={`cursor-pointer border-b border-slate-800/60
                            hover:bg-slate-800/70 transition-colors
                            ${selected === inc.incident_id ? "bg-blue-950/30 border-l-2 border-l-blue-500" : ""}`}
              >
                <td className="px-4 py-2.5 font-mono text-xs text-blue-400">
                  {inc.incident_id}
                </td>
                <td className="px-2 py-2.5 text-center">
                  <span className={`rounded px-2 py-0.5 text-xs font-bold
                                   ${PRIO[inc.priority] || "bg-slate-700 text-slate-300"}`}>
                    {inc.priority || "—"}
                  </span>
                </td>
                <td className="px-2 py-2.5 text-center">
                  <span className={`font-bold text-sm ${
                    inc.max_risk >= 90 ? "text-red-400" :
                    inc.max_risk >= 70 ? "text-orange-400" :
                    inc.max_risk >= 40 ? "text-yellow-400" : "text-green-400"
                  }`}>
                    {inc.max_risk ?? 0}
                  </span>
                </td>
                <td className="px-2 py-2.5 text-xs text-slate-300 max-w-[140px] truncate">
                  {inc.asset || "—"}
                </td>
                <td className="px-2 py-2.5 text-center">
                  <div className="flex items-center justify-center gap-0.5 flex-wrap">
                    {(inc.tactics || []).slice(0, 3).map(t => (
                      <span key={t}
                            className="text-[9px] bg-purple-900/50 text-purple-300
                                       rounded px-1 py-0.5 border border-purple-800">
                        {t.split(" ")[0]}
                      </span>
                    ))}
                    {(inc.tactics?.length || 0) > 3 && (
                      <span className="text-[9px] text-slate-500">
                        +{inc.tactics.length - 3}
                      </span>
                    )}
                  </div>
                </td>
                <td className="px-2 py-2.5 text-center text-slate-400 text-xs">
                  {inc.alert_ids?.length ?? 0}
                </td>
                <td className="px-2 py-2.5 text-xs text-slate-500 max-w-[120px] truncate">
                  {inc.campaign_name || "—"}
                </td>
              </tr>
            ))}
            {incidents.length === 0 && (
              <tr>
                <td colSpan={7} className="text-center py-10 text-slate-600 text-sm">
                  No incidents yet — start the simulator to generate alerts.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
