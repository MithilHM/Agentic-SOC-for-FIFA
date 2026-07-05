import { useSoc } from "../store";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, Cell,
  ResponsiveContainer, CartesianGrid,
} from "recharts";

const TYPE_COLORS = {
  Phishing:        "#ff9500", // alert-orange
  BruteForce:      "#ff3b30", // critical-red
  Malware:         "#ccff00", // primary
  WebAttack:       "#8b5cf6", // secondary
  InsiderThreat:   "#ff9500", // caution-amber
  DDoS:            "#ff3b30", // critical-red
  CredentialTheft: "#34c759", // security-green
  Recon:           "#767697", // on-tertiary-container
  DataExfil:       "#ff9500", // alert-orange
  Other:           "#1c1c2e", // border-subtle
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
      <div className="rounded bg-slate-surface border border-border-subtle p-5 shadow flex flex-col">
        <h2 className="font-mono text-xs uppercase tracking-wider font-bold text-primary mb-3">Attack Types</h2>
        <div className="flex-1 flex items-center justify-center text-on-tertiary-container/60 font-mono text-xs py-12">
          WAITING FOR TELEMETRY…
        </div>
      </div>
    );
  }

  return (
    <div className="rounded bg-slate-surface border border-border-subtle p-5 shadow flex flex-col">
      <h2 className="font-mono text-xs uppercase tracking-wider font-bold text-primary mb-4">Attack Types (Alert Count)</h2>
      <ResponsiveContainer width="100%" height={230}>
        <BarChart data={data} margin={{ top: 0, right: 10, left: -20, bottom: 45 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
          <XAxis
            dataKey="name"
            tick={{ fill: "#768197", fontSize: 9, fontFamily: "monospace" }}
            angle={-35}
            textAnchor="end"
            interval={0}
          />
          <YAxis tick={{ fill: "#768197", fontSize: 9, fontFamily: "monospace" }} allowDecimals={false} />
          <Tooltip
            contentStyle={{ background: "#020617", border: "1px solid #1e293b", borderRadius: 2 }}
            labelStyle={{ color: "#d4e4fa", fontFamily: "monospace" }}
            itemStyle={{ color: "#768197", fontFamily: "monospace", fontSize: 11 }}
            formatter={(v) => [v, "Alerts"]}
          />
          <Bar dataKey="value" radius={[2, 2, 0, 0]}>
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
