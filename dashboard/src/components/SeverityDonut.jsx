import { useSoc } from "../store";
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from "recharts";

const COLORS = {
  Critical: "#ff3b30", // critical-red
  High:     "#ff9500", // alert-orange
  Medium:   "#ff9500", // caution-amber
  Low:      "#34c759", // security-green
  Info:     "#767697", // on-tertiary-container
};

const RADIAN = Math.PI / 180;

function CustomLabel({ cx, cy, midAngle, innerRadius, outerRadius, percent, name }) {
  if (percent < 0.06) return null;
  const r  = innerRadius + (outerRadius - innerRadius) * 0.5;
  const x  = cx + r * Math.cos(-midAngle * RADIAN);
  const y  = cy + r * Math.sin(-midAngle * RADIAN);
  return (
    <text x={x} y={y} fill="#020617" textAnchor="middle" dominantBaseline="central"
          fontSize={10} fontFamily="monospace" fontWeight="bold">
      {`${(percent * 100).toFixed(0)}%`}
    </text>
  );
}

export default function SeverityDonut() {
  const { metrics } = useSoc();
  const bySev = metrics.by_severity || {};

  const data = Object.entries(bySev)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }));

  if (data.length === 0) {
    return (
      <div className="rounded bg-slate-surface border border-border-subtle p-5 shadow flex flex-col">
        <h2 className="font-mono text-xs uppercase tracking-wider font-bold text-primary mb-3">Severity Distribution</h2>
        <div className="flex-1 flex items-center justify-center text-on-tertiary-container/60 font-mono text-xs py-12">
          WAITING FOR TELEMETRY…
        </div>
      </div>
    );
  }

  return (
    <div className="rounded bg-slate-surface border border-border-subtle p-5 shadow flex flex-col">
      <h2 className="font-mono text-xs uppercase tracking-wider font-bold text-primary mb-3">Severity Distribution</h2>
      <ResponsiveContainer width="100%" height={220}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={55}
            outerRadius={90}
            dataKey="value"
            labelLine={false}
            label={<CustomLabel />}
          >
            {data.map((entry) => (
              <Cell key={entry.name} fill={COLORS[entry.name] || "#475569"} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{ background: "#020617", border: "1px solid #1e293b", borderRadius: 2 }}
            itemStyle={{ color: "#d4e4fa", fontFamily: "monospace", fontSize: 11 }}
          />
          <Legend
            wrapperStyle={{ fontSize: 10, fontFamily: "monospace", color: "#768197" }}
            iconType="circle"
            iconSize={6}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
