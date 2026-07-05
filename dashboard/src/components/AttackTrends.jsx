import { useSoc } from "../store";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, Cell,
  ResponsiveContainer, CartesianGrid,
} from "recharts";

const TYPE_COLORS = {
  Phishing:        "#f97316",
  BruteForce:      "#ef4444",
  Malware:         "#a855f7",
  WebAttack:       "#3b82f6",
  InsiderThreat:   "#eab308",
  DDoS:            "#ec4899",
  CredentialTheft: "#14b8a6",
  Recon:           "#64748b",
  DataExfil:       "#f43f5e",
  Other:           "#475569",
};

export default function AttackTrends() {
  const { metrics } = useSoc();
  const byType = metrics.by_type || {};

  const data = Object.entries(byType)
    .filter(([, v]) => v > 0)
    .sort(([, a], [, b]) => b - a)
    .map(([name, value]) => ({ name, value }));

  if (data.length === 0) {
    return (
      <div className="rounded-xl bg-slate-900 p-4 shadow-lg flex flex-col">
        <h2 className="text-base font-semibold text-slate-200 mb-2">Attack Types</h2>
        <div className="flex-1 flex items-center justify-center text-slate-500 text-sm h-48">
          Waiting for alerts…
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-xl bg-slate-900 p-4 shadow-lg flex flex-col">
      <h2 className="text-base font-semibold text-slate-200 mb-3">Attack Types (Alert Count)</h2>
      <ResponsiveContainer width="100%" height={230}>
        <BarChart data={data} margin={{ top: 0, right: 10, left: -20, bottom: 45 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
          <XAxis
            dataKey="name"
            tick={{ fill: "#94a3b8", fontSize: 10 }}
            angle={-35}
            textAnchor="end"
            interval={0}
          />
          <YAxis tick={{ fill: "#94a3b8", fontSize: 11 }} allowDecimals={false} />
          <Tooltip
            contentStyle={{ background: "#1e293b", border: "none", borderRadius: 8 }}
            labelStyle={{ color: "#f1f5f9" }}
            itemStyle={{ color: "#94a3b8" }}
            formatter={(v) => [v, "Alerts"]}
          />
          <Bar dataKey="value" radius={[4, 4, 0, 0]}>
            {data.map((entry) => (
              <Cell
                key={entry.name}
                fill={TYPE_COLORS[entry.name] || "#475569"}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
