import { useSoc } from "../store";

/**
 * MITRE ATT&CK Matrix — shows which tactics/techniques are active in the selected incident.
 * Columns = tactics (left-to-right kill-chain order)
 * Rows    = techniques per tactic
 */
const TACTIC_ORDER = [
  "Reconnaissance", "Initial Access", "Execution", "Persistence",
  "Privilege Escalation", "Defense Evasion", "Credential Access",
  "Discovery", "Lateral Movement", "Collection", "Exfiltration", "Impact",
];

const TECHNIQUE_MAP = {
  "Reconnaissance":       [{ id: "T1595", name: "Active Scanning" }, { id: "T1592", name: "Gather Victim Info" }],
  "Initial Access":       [{ id: "T1566", name: "Phishing" }, { id: "T1190", name: "Exploit Public App" }, { id: "T1133", name: "External Remote Services" }],
  "Execution":            [{ id: "T1204", name: "User Execution" }, { id: "T1059", name: "Command & Script" }],
  "Persistence":          [{ id: "T1078", name: "Valid Accounts" }, { id: "T1547", name: "Boot Autostart" }],
  "Privilege Escalation": [{ id: "T1068", name: "Exploit for Priv Esc" }, { id: "T1055", name: "Process Injection" }],
  "Defense Evasion":      [{ id: "T1070", name: "Indicator Removal" }, { id: "T1036", name: "Masquerading" }],
  "Credential Access":    [{ id: "T1110", name: "Brute Force" }, { id: "T1555", name: "Credentials from Stores" }],
  "Discovery":            [{ id: "T1046", name: "Network Service Scan" }, { id: "T1082", name: "System Info Discovery" }],
  "Lateral Movement":     [{ id: "T1021", name: "Remote Services" }],
  "Collection":           [{ id: "T1560", name: "Archive Data" }],
  "Exfiltration":         [{ id: "T1041", name: "Exfil Over C2" }, { id: "T1052", name: "Exfil Physical Medium" }],
  "Impact":               [{ id: "T1498", name: "Network DoS" }, { id: "T1491", name: "Defacement" }],
};

export default function MitreMatrix() {
  const { incidents, selected } = useSoc();
  const inc = selected ? incidents.find(i => i.incident_id === selected) : null;

  // Active tactics + techniques for the selected (or all recent) incident
  const activeTactics     = new Set(inc?.tactics  || incidents.flatMap(i => i.tactics  || []));
  const activeTechniques  = new Set(inc?.techniques || incidents.flatMap(i => i.techniques || []));

  return (
    <div className="rounded-xl bg-slate-900 p-4 shadow-lg overflow-x-auto">
      <h2 className="text-base font-semibold text-slate-200 mb-3">
        MITRE ATT&amp;CK Matrix
        {inc && <span className="ml-2 text-xs text-blue-400 font-mono">({inc.incident_id})</span>}
        {!inc && <span className="ml-2 text-xs text-slate-500">(all incidents)</span>}
      </h2>

      <div className="flex gap-2 min-w-max">
        {TACTIC_ORDER.map(tactic => {
          const isActive = activeTactics.has(tactic);
          const techniques = TECHNIQUE_MAP[tactic] || [];
          return (
            <div key={tactic} className="flex flex-col gap-1 min-w-[110px]">
              {/* Tactic header */}
              <div className={`rounded-t px-2 py-1 text-center text-xs font-bold uppercase tracking-wide
                ${isActive
                  ? "bg-red-700 text-white"
                  : "bg-slate-800 text-slate-500"}`}>
                {tactic.replace(" ", "\u00A0")}
              </div>
              {/* Technique cells */}
              {techniques.map(tech => {
                const techActive = activeTechniques.has(tech.id) || isActive;
                return (
                  <div key={tech.id}
                       title={`${tech.id}: ${tech.name}`}
                       className={`rounded px-2 py-1 text-xs cursor-default transition-all
                         ${techActive
                           ? "bg-red-900/70 text-red-300 border border-red-700 font-semibold"
                           : "bg-slate-800/50 text-slate-500 border border-slate-700"}`}>
                    <div className="font-mono text-[10px] text-slate-400">{tech.id}</div>
                    <div className="leading-tight">{tech.name}</div>
                  </div>
                );
              })}
            </div>
          );
        })}
      </div>
    </div>
  );
}
