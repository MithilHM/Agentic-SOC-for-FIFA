import { useState, useRef, useEffect } from "react";
import { useSoc } from "../store";

const API = import.meta.env.VITE_API || "http://localhost:8080";

export default function AnalystChat() {
  const { incidents, selected } = useSoc();
  const inc = incidents.find(i => i.incident_id === selected);
  const [messages, setMessages] = useState([
    { role: "system", text: "AI Security Analyst ready. Select an incident and ask anything." }
  ]);
  const [input, setInput]   = useState("");
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef(null);

  // Reset chat when incident changes
  useEffect(() => {
    if (selected) {
      setMessages([{
        role: "system",
        text: `Loaded incident ${selected}. Ask me anything about this threat.`,
      }]);
    }
  }, [selected]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const send = async (e) => {
    e.preventDefault();
    if (!input.trim() || !selected) return;

    const question = input.trim();
    setInput("");
    setMessages(prev => [...prev, { role: "user", text: question }]);
    setLoading(true);

    try {
      const res = await fetch(`${API}/api/incidents/${selected}/ask`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setMessages(prev => [...prev, { role: "assistant", text: data.answer }]);
    } catch (err) {
      setMessages(prev => [...prev, {
        role: "error",
        text: `Error: ${err.message}. Is the backend running?`,
      }]);
    } finally {
      setLoading(false);
    }
  };

  const ROLE_STYLE = {
    system:    "text-slate-400 italic text-xs text-center",
    user:      "bg-blue-700/30 border border-blue-800 text-slate-200 self-end",
    assistant: "bg-slate-800 border border-slate-700 text-slate-300",
    error:     "bg-red-900/30 border border-red-800 text-red-300 text-xs",
  };

  const QUICK = [
    "Why is this P1?",
    "What assets are at risk?",
    "List IOCs to block",
    "Explain the kill-chain",
  ];

  return (
    <div className="rounded-xl bg-slate-900 p-4 shadow-lg flex flex-col gap-3">
      <h2 className="text-base font-semibold text-slate-200">
        🤖 AI Security Analyst
        {inc && (
          <span className="ml-2 text-xs text-blue-400 font-mono font-normal">
            ({inc.incident_id})
          </span>
        )}
      </h2>

      {/* Quick actions */}
      {selected && (
        <div className="flex flex-wrap gap-1">
          {QUICK.map(q => (
            <button key={q}
                    onClick={() => setInput(q)}
                    className="text-xs bg-slate-800 hover:bg-slate-700 text-slate-300
                               rounded-full px-2 py-0.5 border border-slate-700 transition-colors">
              {q}
            </button>
          ))}
        </div>
      )}

      {/* Message thread */}
      <div className="flex flex-col gap-2 max-h-64 overflow-y-auto pr-1 scroll-smooth">
        {messages.map((m, i) => (
          <div key={i} className={`rounded-lg px-3 py-2 text-sm ${ROLE_STYLE[m.role]}`}>
            {m.role === "user" && (
              <span className="text-[10px] text-blue-400 block mb-0.5 font-semibold">You</span>
            )}
            {m.role === "assistant" && (
              <span className="text-[10px] text-emerald-400 block mb-0.5 font-semibold">AI Analyst</span>
            )}
            <p className="whitespace-pre-wrap leading-relaxed">{m.text}</p>
          </div>
        ))}
        {loading && (
          <div className="flex items-center gap-2 text-slate-400 text-sm px-3">
            <span className="animate-pulse">●●●</span>
            <span className="text-xs">AI is investigating…</span>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <form onSubmit={send} className="flex gap-2 mt-auto">
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder={selected ? "Ask AI about this incident…" : "Select an incident first…"}
          disabled={!selected || loading}
          className="flex-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2
                     text-sm text-white placeholder-slate-500 focus:outline-none
                     focus:border-blue-500 disabled:opacity-50 transition-colors"
        />
        <button
          type="submit"
          disabled={!selected || !input.trim() || loading}
          className="bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white
                     px-4 py-2 rounded-lg text-sm font-semibold transition-colors">
          Send
        </button>
      </form>
    </div>
  );
}
