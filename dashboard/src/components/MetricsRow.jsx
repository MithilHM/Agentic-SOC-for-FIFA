import { useSoc } from "../store";

const PRIO_STYLE = {
  P1: "bg-red-600 text-white ring-1 ring-red-400",
  P2: "bg-orange-500 text-white",
  P3: "bg-yellow-500 text-black",
  P4: "bg-slate-600 text-slate-200",
};

export default function MetricsRow() {
  const { metrics, incidents, connected } = useSoc();
  const bySev = metrics.by_severity || {};

  const cards = [
    {
      label: "Open Incidents",
      value: metrics.open_incidents ?? incidents.length,
      color: "text-slate-200",
      sub:   connected ? "🟢 Live feed" : "🔴 Offline",
    },
    {
      label: "P1 Critical",
      value: metrics.p1 ?? incidents.filter(i => i.priority === "P1").length,
      color: "text-red-500",
      sub:   "Immediate action",
    },
    {
      label: "Critical Alerts",
      value: bySev.Critical || 0,
      color: "text-red-400",
      sub:   "Severity: Critical",
    },
    {
      label: "High Alerts",
      value: bySev.High || 0,
      color: "text-orange-400",
      sub:   "Severity: High",
    },
    {
      label: "Total Alerts",
      value: Object.values(bySev).reduce((s, v) => s + v, 0),
      color: "text-slate-300",
      sub:   "All severities",
    },
  ];

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
      {cards.map(({ label, value, color, sub }) => (
        <div key={label}
             className="rounded-xl bg-slate-900 border border-slate-800 px-4 py-3
                        flex flex-col gap-1 shadow hover:border-slate-700 transition-colors">
          <div className={`text-3xl font-black tabular-nums ${color}`}>{value}</div>
          <div className="text-xs font-semibold text-slate-300 leading-tight">{label}</div>
          <div className="text-[10px] text-slate-500 uppercase tracking-wide">{sub}</div>
        </div>
      ))}
    </div>
  );
}
