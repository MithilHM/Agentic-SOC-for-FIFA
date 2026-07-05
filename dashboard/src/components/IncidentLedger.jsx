import { useSoc } from "../store";

const PRIO = {
  P1: "bg-critical-red/10 border border-critical-red/30 text-critical-red",
  P2: "bg-alert-orange/10 border border-alert-orange/30 text-alert-orange",
  P3: "bg-caution-amber/10 border border-caution-amber/30 text-caution-amber",
  P4: "bg-on-tertiary-container/10 border border-on-tertiary-container/30 text-on-tertiary-container",
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
    <div className="rounded bg-slate-surface border border-border-subtle flex flex-col shadow">
      <div className="flex items-center justify-between px-5 py-4 border-b border-border-subtle">
        <h2 className="font-mono text-xs uppercase tracking-wider font-bold text-primary">
          Incident Ledger
          <span className="ml-2 text-[10px] text-on-tertiary-container font-mono font-normal">
            ({incidents.length} TOTAL)
          </span>
        </h2>
      </div>

      <div className="overflow-x-auto scroll-hide">
        <table className="w-full text-left">
          <thead>
            <tr className="text-[10px] font-mono uppercase tracking-widest text-on-tertiary-container
                           border-b border-border-subtle bg-midnight-base/20">
              <th className="px-5 py-3 font-bold">ID</th>
              <th className="px-3 py-3 text-center font-bold">Priority</th>
              <th className="px-3 py-3 text-center font-bold">Risk</th>
              <th className="px-3 py-3 font-bold">Asset</th>
              <th className="px-3 py-3 text-center font-bold">Tactics</th>
              <th className="px-3 py-3 text-center font-bold">Alerts</th>
              <th className="px-3 py-3 font-bold">Campaign</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((inc) => (
              <tr
                key={inc.incident_id}
                onClick={() => handleSelect(inc.incident_id)}
                className={`cursor-pointer border-b border-border-subtle/40
                            hover:bg-surface-container/20 transition-all duration-150
                            ${selected === inc.incident_id ? "bg-surface-container/40 border-l-[3px] border-l-primary" : "border-l-[3px] border-l-transparent"}`}
              >
                <td className="px-5 py-3 font-mono text-xs text-primary font-bold">
                  {inc.incident_id}
                </td>
                <td className="px-3 py-3 text-center">
                  <span className={`rounded-sm px-2 py-0.5 text-[10px] font-mono font-bold uppercase tracking-wider
                                   ${PRIO[inc.priority] || "bg-slate-800 text-slate-400"}`}>
                    {inc.priority || "—"}
                  </span>
                </td>
                <td className="px-3 py-3 text-center">
                  <span className={`font-mono font-bold text-xs ${
                    inc.max_risk >= 90 ? "text-critical-red" :
                    inc.max_risk >= 70 ? "text-alert-orange" :
                    inc.max_risk >= 40 ? "text-caution-amber" : "text-security-green"
                  }`}>
                    {inc.max_risk ?? 0}
                  </span>
                </td>
                <td className="px-3 py-3 text-xs text-on-surface font-medium max-w-[140px] truncate">
                  {inc.asset || "—"}
                </td>
                <td className="px-3 py-3 text-center">
                  <div className="flex items-center justify-center gap-1 flex-wrap">
                    {(inc.tactics || []).slice(0, 3).map(t => (
                      <span key={t}
                            className="text-[9px] bg-surface-container border border-border-subtle text-primary/80
                                       rounded-sm px-1.5 py-0.5 font-mono">
                        {t.split(" ")[0]}
                      </span>
                    ))}
                    {(inc.tactics?.length || 0) > 3 && (
                      <span className="text-[9px] font-mono text-on-tertiary-container">
                        +{inc.tactics.length - 3}
                      </span>
                    )}
                  </div>
                </td>
                <td className="px-3 py-3 text-center text-on-surface-variant font-mono text-xs">
                  {inc.alert_ids?.length ?? 0}
                </td>
                <td className="px-3 py-3 text-xs text-on-surface-variant max-w-[120px] truncate">
                  {inc.campaign_name || "—"}
                </td>
              </tr>
            ))}
            {incidents.length === 0 && (
              <tr>
                <td colSpan={7} className="text-center py-12 text-on-tertiary-container/70 font-mono text-xs">
                  NO INCIDENTS DETECTED — START THE SIMULATOR TO GEN DATA.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
