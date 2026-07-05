import { useSoc } from "../store";

export default function MetricsRow() {
  const { metrics, incidents, connected } = useSoc();
  const bySev = metrics.by_severity || {};

  const cards = [
    {
      label: "Open Incidents",
      value: metrics.open_incidents ?? incidents.length,
      color: "text-primary",
      sub:   connected ? "LIVE TELEMETRY" : "OFFLINE CONTEXT",
    },
    {
      label: "P1 Critical",
      value: metrics.p1 ?? incidents.filter(i => i.priority === "P1").length,
      color: "text-critical-red",
      sub:   "IMMEDIATE ACTION",
    },
    {
      label: "Critical Alerts",
      value: bySev.Critical || 0,
      color: "text-critical-red",
      sub:   "SEVERITY: CRITICAL",
    },
    {
      label: "High Alerts",
      value: bySev.High || 0,
      color: "text-alert-orange",
      sub:   "SEVERITY: HIGH",
    },
    {
      label: "Total Alerts",
      value: Object.values(bySev).reduce((s, v) => s + v, 0),
      color: "text-secondary",
      sub:   "ALL SEVERITIES",
    },
  ];

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
      {cards.map(({ label, value, color, sub }) => (
        <div key={label}
             className="rounded bg-slate-surface border border-border-subtle p-4
                        flex flex-col justify-between shadow transition-all hover:border-primary/20 duration-300">
          <div>
            <div className="font-mono text-[9px] text-on-tertiary-container uppercase tracking-wider font-bold mb-2">
              {label}
            </div>
            <div className={`font-display text-3xl font-bold tracking-tight leading-none ${color}`}>
              {value}
            </div>
          </div>
          <div className="text-[9px] font-mono text-on-tertiary-container/70 uppercase tracking-widest mt-4">
            {sub}
          </div>
        </div>
      ))}
    </div>
  );
}
