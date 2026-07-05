import { useSoc } from "../store";

const FIFA_ASSETS = [
  { name: "Official Ticket Portal", icon: "🎫", color: "border-orange-500" },
  { name: "Payment Gateway",        icon: "💳", color: "border-red-500" },
  { name: "Admin Console",          icon: "⚙️",  color: "border-purple-500" },
  { name: "Mobile App API",         icon: "📱", color: "border-blue-500" },
  { name: "Media Portal",           icon: "📺", color: "border-cyan-500" },
  { name: "Streaming Platform",     icon: "🎙️", color: "border-green-500" },
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
    <div className="rounded-xl bg-slate-900 p-4 shadow-lg">
      <h2 className="text-base font-semibold text-slate-200 mb-3">
        FIFA Asset Threat Map
      </h2>
      <div className="grid grid-cols-2 gap-3">
        {FIFA_ASSETS.map(({ name, icon, color }) => {
          const alerts   = alertsByAsset[name]  || 0;
          const incs     = incsByAsset[name]    || 0;
          const isHot    = alerts > 5;
          return (
            <div key={name}
                 className={`relative rounded-lg bg-slate-800 border-2 ${color} p-3
                             transition-all hover:scale-[1.02] cursor-default
                             ${isHot ? "shadow-lg shadow-red-900/40" : ""}`}>
              {/* Pulse badge if active */}
              {isHot && (
                <span className="absolute -top-1.5 -right-1.5 flex h-4 w-4">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-500 opacity-75" />
                  <span className="relative inline-flex rounded-full h-4 w-4 bg-red-600" />
                </span>
              )}
              <div className="flex items-center gap-2 mb-2">
                <span className="text-xl">{icon}</span>
                <span className="text-xs font-medium text-slate-200 leading-tight">{name}</span>
              </div>
              <div className="flex gap-3 text-xs">
                <div className="text-center">
                  <div className={`text-lg font-black ${alerts > 0 ? "text-red-400" : "text-slate-600"}`}>
                    {alerts}
                  </div>
                  <div className="text-slate-500 uppercase tracking-wide text-[9px]">Alerts</div>
                </div>
                <div className="text-center">
                  <div className={`text-lg font-black ${incs > 0 ? "text-orange-400" : "text-slate-600"}`}>
                    {incs}
                  </div>
                  <div className="text-slate-500 uppercase tracking-wide text-[9px]">Incidents</div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
