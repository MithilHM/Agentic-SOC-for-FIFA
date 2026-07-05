import { useSoc } from "../store";

const SEV_COLOR = {
  Critical: "bg-critical-red/15 border border-critical-red/30 text-critical-red",
  High:     "bg-alert-orange/15 border border-alert-orange/30 text-alert-orange",
  Medium:   "bg-caution-amber/15 border border-caution-amber/30 text-caution-amber",
  Low:      "bg-security-green/15 border border-security-green/30 text-security-green",
  Info:     "bg-on-tertiary-container/15 border border-on-tertiary-container/30 text-on-tertiary-container",
};

function relTime(ts) {
  if (!ts) return "";
  const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (diff < 60)   return `${diff}S AGO`;
  if (diff < 3600) return `${Math.floor(diff / 60)}M AGO`;
  return `${Math.floor(diff / 3600)}H AGO`;
}

export default function AttackTimeline() {
  const { incidents, selected } = useSoc();
  const inc = incidents.find(i => i.incident_id === selected);

  if (!selected) {
    return (
      <div className="rounded bg-slate-surface border border-border-subtle p-5 shadow">
        <h2 className="font-mono text-xs uppercase tracking-wider font-bold text-primary mb-3">Attack Timeline</h2>
        <p className="text-on-tertiary-container/60 font-mono text-xs">SELECT AN INCIDENT TO INITIALIZE KILL-CHAIN TIMELINE.</p>
      </div>
    );
  }
  if (!inc) return null;

  const alerts = (inc.alerts || []).slice().sort(
    (a, b) => new Date(a.timestamp) - new Date(b.timestamp)
  );

  return (
    <div className="rounded bg-slate-surface border border-border-subtle p-5 shadow">
      <h2 className="font-mono text-xs uppercase tracking-wider font-bold text-primary mb-4 flex items-center">
        Kill-Chain Timeline
        <span className="ml-2 text-[10px] text-on-tertiary-container font-mono font-normal">({inc.incident_id})</span>
      </h2>

      {alerts.length === 0 ? (
        <p className="text-on-tertiary-container/60 font-mono text-xs">NO ALERT DETAIL LOADED YET. SELECT AND MERGE INCIDENT RECORDS.</p>
      ) : (
        <div className="relative">
          {/* Vertical line */}
          <div className="absolute left-4 top-0 bottom-0 w-px bg-border-subtle/70" />

          <ol className="space-y-4">
            {alerts.map((a, idx) => (
              <li key={a.alert_id} className="relative pl-12">
                {/* Step dot */}
                <div className={`absolute left-0 w-8 h-8 rounded-full flex items-center justify-center
                                text-xs font-mono font-bold border
                                ${idx === 0 ? "bg-primary text-midnight-base border-primary" : "bg-midnight-base text-on-tertiary-container border-border-subtle"}`}>
                  {idx + 1}
                </div>

                <div className="bg-midnight-base/40 rounded-sm p-3.5 border border-border-subtle/60">
                  <div className="flex items-center gap-2 flex-wrap mb-2">
                    <span className={`rounded-sm px-2 py-0.5 text-[9px] font-mono font-bold uppercase tracking-wider ${SEV_COLOR[a.severity] || "bg-slate-800 text-slate-400"}`}>
                      {a.severity}
                    </span>
                    <span className="text-xs text-primary font-mono uppercase tracking-wider font-bold">{a.event_type}</span>
                    <span className="text-[9px] text-on-tertiary-container/85 font-mono uppercase ml-auto">{relTime(a.timestamp)}</span>
                  </div>
                  <div className="text-xs text-on-surface-variant font-mono leading-relaxed">
                    <span className="text-on-surface font-semibold">{a.event_source}</span> → {a.source_ip || a.user || "—"}
                    {a.mitre_tactic && (
                      <span className="ml-2 text-primary font-semibold">
                        [{a.mitre_tactic.toUpperCase()} / {a.mitre_technique}]
                      </span>
                    )}
                  </div>
                  {a.description && (
                    <p className="text-xs text-on-surface-variant/75 mt-2 leading-relaxed">{a.description}</p>
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
