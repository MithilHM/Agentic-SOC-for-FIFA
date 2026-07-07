import React, { useEffect, useRef } from "react";
import { useNexus } from "../store";

export default function LiveSandbox() {
  const { sandboxLogs } = useNexus();
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [sandboxLogs]);

  const getColor = (level) => {
    switch (level) {
      case "error": return "text-red-400 font-bold drop-shadow-[0_0_8px_rgba(248,113,113,0.8)]";
      case "success": return "text-green-400 font-bold drop-shadow-[0_0_8px_rgba(74,222,128,0.8)]";
      case "warning": return "text-yellow-400";
      case "critical": return "text-purple-400 font-black animate-pulse";
      default: return "text-blue-300";
    }
  };

  return (
    <div className="flex flex-col h-full w-full bg-slate-900/80 backdrop-blur-xl border border-slate-700/50 rounded-2xl overflow-hidden shadow-2xl">
      {/* Header Bar */}
      <div className="flex items-center px-4 py-3 bg-slate-950/60 border-b border-slate-700/50">
        <div className="flex space-x-2 mr-4">
          <div className="w-3 h-3 rounded-full bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.6)]"></div>
          <div className="w-3 h-3 rounded-full bg-yellow-500 shadow-[0_0_10px_rgba(234,179,8,0.6)]"></div>
          <div className="w-3 h-3 rounded-full bg-green-500 shadow-[0_0_10px_rgba(34,197,94,0.6)]"></div>
        </div>
        <h3 className="text-slate-300 text-sm font-mono tracking-widest uppercase">Live Sandbox Environment</h3>
        <div className="ml-auto flex items-center space-x-2">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
          </span>
          <span className="text-xs text-green-400/80 font-mono">CONNECTED</span>
        </div>
      </div>

      {/* Terminal View */}
      <div className="flex-1 p-4 font-mono text-sm overflow-y-auto space-y-1.5 custom-scrollbar">
        {sandboxLogs.length === 0 ? (
          <div className="text-slate-500 italic">Waiting for telemetry from Sandbox...</div>
        ) : (
          sandboxLogs.map((log, idx) => {
            const time = new Date(log.timestamp).toLocaleTimeString('en-US', { hour12: false, fractionalSecondDigits: 3 });
            return (
              <div key={idx} className="flex space-x-3 items-start animate-fade-in">
                <span className="text-slate-600 shrink-0 select-none">[{time}]</span>
                <span className={`text-slate-500 shrink-0 uppercase w-20`}>
                  [{log.source}]
                </span>
                <span className={`${getColor(log.level)} break-words leading-tight`}>
                  {log.message}
                </span>
              </div>
            );
          })
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
