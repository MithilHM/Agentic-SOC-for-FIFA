import { useSoc } from "../store";
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from "recharts";

const COLORS = {
  Critical: "#ef4444",
  High:     "#f97316",
  Medium:   "#eab308",
  Low:      "#22c55e",
  Info:     "#64748b",
};

const RADIAN = Math.PI / 180;

function CustomLabel({ cx, cy, midAngle, innerRadius, outerRadius, percent, name }) {
  if (percent < 0.06) return null;
  const r  = innerRadius + (outerRadius - innerRadius) * 0.5;
  const x  = cx + r * Math.cos(-midAngle * RADIAN);
  const y  = cy + r * Math.sin(-midAngle * RADIAN);
  return (
    <text x={x} y={y} fill="white" textAnchor="middle" dominantBaseline="central"
          fontSize={11} fontWeight="bold">
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
      <div className="rounded-xl bg-slate-900 p-4 shadow-lg flex flex-col">
        <h2 className="text-base font-semibold text-slate-200 mb-2">Severity Distribution</h2>
        <div className="flex-1 flex items-center justify-center text-slate-500 text-sm">
          Waiting for alerts…
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-xl bg-slate-900 p-4 shadow-lg flex flex-col">
      <h2 className="text-base font-semibold text-slate-200 mb-2">Severity Distribution</h2>
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
            contentStyle={{ background: "#1e293b", border: "none", borderRadius: 8 }}
            itemStyle={{ color: "#f1f5f9" }}
          />
          <Legend
            wrapperStyle={{ fontSize: 12, color: "#94a3b8" }}
            iconType="circle"
            iconSize={8}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
