import { useSoc } from "../store";

const FIFA_ASSETS = [
  { name: "Official Ticket Portal", icon: "🎫", color: "border-alert-orange/50" },
  { name: "Payment Gateway",        icon: "💳", color: "border-critical-red/50" },
  { name: "Admin Console",          icon: "⚙️",  color: "border-primary/40" },
  { name: "Mobile App API",         icon: "📱", color: "border-primary/40" },
  { name: "Media Portal",           icon: "📺", color: "border-primary/40" },
  { name: "Streaming Platform",     icon: "🎙️", color: "border-security-green/50" },
];

export default function AssetMap() {
  const { incidents } = useSoc();

  // Count alerts per asset across all incidents
  const alertsByAsset = {};
  const incsByAsset   = {};
  for (const inc of incidents) {
    const asset = inc.asset;
    if (!asset) continue;
    incsByAsset[asset]   = (incsByAsset[asset]   || 0) + 1;
    alertsByAsset[asset] = (alertsByAsset[asset] || 0) + (inc.alert_ids?.length || 0);
  }

  return (
    <div className="rounded bg-slate-surface border border-border-subtle p-5 shadow">
      <h2 className="font-mono text-xs uppercase tracking-wider font-bold text-primary mb-4">
        FIFA Asset Threat Map
      </h2>
      <div className="grid grid-cols-2 gap-4">
        {FIFA_ASSETS.map(({ name, icon, color }) => {
          const alerts   = alertsByAsset[name]  || 0;
          const incs     = incsByAsset[name]    || 0;
          const isHot    = alerts > 5;
          return (
            <div key={name}
                 className={`relative rounded bg-midnight-base/40 border ${color} p-3.5
                             transition-all hover:scale-[1.01] cursor-default flex flex-col justify-between
                             ${isHot ? "shadow-md shadow-critical-red/10 border-critical-red/60" : ""}`}>
              {/* Pulse badge if active */}
              {isHot && (
                <span className="absolute -top-1.5 -right-1.5 flex h-4 w-4">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-critical-red opacity-75" />
                  <span className="relative inline-flex rounded-full h-4 w-4 bg-critical-red" />
                </span>
              )}
              <div className="flex items-center gap-2 mb-3">
                <span className="text-lg">{icon}</span>
                <span className="text-[10px] font-mono font-bold text-on-surface uppercase tracking-wider leading-tight">{name}</span>
              </div>
              <div className="flex gap-4">
                <div className="flex flex-col">
                  <div className={`font-mono text-base font-bold leading-none ${alerts > 0 ? "text-critical-red" : "text-on-tertiary-container/50"}`}>
                    {alerts}
                  </div>
                  <div className="text-on-tertiary-container/80 uppercase tracking-widest font-mono text-[9px] mt-1">Alerts</div>
                </div>
                <div className="flex flex-col">
                  <div className={`font-mono text-base font-bold leading-none ${incs > 0 ? "text-alert-orange" : "text-on-tertiary-container/50"}`}>
                    {incs}
                  </div>
                  <div className="text-on-tertiary-container/80 uppercase tracking-widest font-mono text-[9px] mt-1">Incidents</div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
