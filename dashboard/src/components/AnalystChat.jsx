import { useState, useRef, useEffect } from "react";
import { useSoc } from "../store";

const API = import.meta.env.VITE_API || "http://localhost:8080";
const API_KEY = import.meta.env.VITE_API_KEY || "";

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
        headers: {
          "Content-Type": "application/json",
          ...(API_KEY ? { "X-API-Key": API_KEY } : {}),
        },
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
    system:    "text-on-tertiary-container/85 italic text-[10px] font-mono text-center bg-midnight-base/30 border border-border-subtle/40 py-2 rounded-sm w-full",
    user:      "bg-secondary/5 border border-secondary/20 text-on-surface self-end max-w-[85%] rounded-sm shadow-sm",
    assistant: "bg-midnight-base/40 border border-border-subtle text-on-surface/95 max-w-[85%] rounded-sm shadow-sm",
    error:     "bg-critical-red/10 border border-critical-red/30 text-critical-red text-[10px] font-mono rounded-sm w-full",
  };

  const QUICK = [
    "Why is this P1?",
    "What assets are at risk?",
    "List IOCs to block",
    "Explain the kill-chain",
  ];

  return (
    <div className="rounded bg-slate-surface border border-border-subtle p-5 shadow flex flex-col gap-4">
      <h2 className="font-mono text-xs uppercase tracking-wider font-bold text-primary flex items-center">
        🤖 AI Security Analyst
        {inc && (
          <span className="ml-2 text-[10px] text-on-tertiary-container font-mono font-normal">
            ({inc.incident_id})
          </span>
        )}
      </h2>

      {/* Quick actions */}
      {selected && (
        <div className="flex flex-wrap gap-1.5">
          {QUICK.map(q => (
            <button key={q}
                    onClick={() => setInput(q)}
                    className="text-[9px] font-mono bg-midnight-base hover:bg-surface-container text-on-tertiary-container
                               border border-border-subtle rounded-sm px-2.5 py-1.5 transition-colors uppercase tracking-wider font-bold active:scale-[0.98]">
              {q}
            </button>
          ))}
        </div>
      )}

      {/* Message thread */}
      <div className="flex flex-col gap-3 max-h-64 overflow-y-auto pr-1 scroll-smooth scroll-hide">
        {messages.map((m, i) => (
          <div key={i} className={`rounded-sm px-3.5 py-2.5 text-xs ${ROLE_STYLE[m.role]} flex flex-col`}>
            {m.role === "user" && (
              <span className="text-[9px] font-mono text-secondary block mb-1 font-bold uppercase tracking-wider">YOU</span>
            )}
            {m.role === "assistant" && (
              <span className="text-[9px] font-mono text-security-green block mb-1 font-bold uppercase tracking-wider">AI ANALYST</span>
            )}
            <p className="whitespace-pre-wrap leading-relaxed">{m.text}</p>
          </div>
        ))}
        {loading && (
          <div className="flex items-center gap-2 text-on-tertiary-container font-mono text-xs px-2.5">
            <span className="animate-pulse">●●●</span>
            <span>AI IS INVESTIGATING…</span>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <form onSubmit={send} className="flex gap-2 mt-auto">
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder={selected ? "ASK AI ABOUT THIS INCIDENT…" : "SELECT AN INCIDENT FIRST…"}
          disabled={!selected || loading}
          className="flex-1 bg-midnight-base border border-border-subtle rounded-sm px-3.5 py-2.5
                     text-xs font-mono text-on-surface placeholder-on-tertiary-container/60 focus:outline-none
                     focus:border-primary/50 disabled:opacity-50 transition-colors"
        />
        <button
          type="submit"
          disabled={!selected || !input.trim() || loading}
          className="bg-primary hover:bg-primary/95 text-midnight-base disabled:opacity-40
                     px-5 py-2.5 rounded-sm text-xs font-mono font-bold tracking-wider uppercase transition-colors shrink-0"
        >
          SEND
        </button>
      </form>
    </div>
  );
}
