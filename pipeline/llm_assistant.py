"""
pipeline/llm_assistant.py — LangGraph Agentic Security Analyst

Architecture (agentic loop):
  [analyst_node] → decides which tool to call
       ↓
  [tool_node]    → executes chosen tool (enrich_ip, lookup_mitre, etc.)
       ↓
  [observe_node] → processes tool result, appends to state
       ↓
  loops back to analyst_node until DONE or max steps

Tools available to the agent:
  - enrich_ip(ip)          → geo + reputation + ASN
  - lookup_mitre(technique) → tactic/technique description
  - check_whois(domain)    → domain age + registrar
  - assess_business_impact(asset) → FIFA criticality + blast radius
  - escalate_priority(incident_id, reason) → bumps incident priority in Redis

When GEMINI_API_KEY is missing, summarize_incident() returns a static
heuristic summary so the pipeline never crashes.
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Literal, TypedDict

import redis

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Redis
# ---------------------------------------------------------------------------
r = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))

# ---------------------------------------------------------------------------
# Known intelligence (offline fallbacks)
# ---------------------------------------------------------------------------

_KNOWN_BAD_IPS: dict[str, dict] = {
    "185.174.21.14": {"country": "Russia",      "asn": "AS-BFNET",   "reputation": 95},
    "45.155.205.99": {"country": "Netherlands", "asn": "AS-SERVERS", "reputation": 88},
    "193.169.255.10":{"country": "Belarus",     "asn": "AS-BYNET",   "reputation": 82},
}

_MITRE_DESCRIPTIONS: dict[str, str] = {
    "T1566":  "Phishing — adversary sends malicious emails to gain initial access.",
    "T1566.002": "Spear-phishing Link — targeted phishing with crafted URL.",
    "T1110":  "Brute Force — repeated credential guessing against auth service.",
    "T1555":  "Credentials from Password Stores — stealing stored credentials.",
    "T1204":  "User Execution — adversary relies on user to execute malicious code.",
    "T1190":  "Exploit Public-Facing Application — exploiting web vulnerabilities.",
    "T1052":  "Exfiltration Over Physical Medium — using insider/USB to exfil data.",
    "T1041":  "Exfiltration Over C2 Channel — sending data over C2 connection.",
    "T1498":  "Network Denial of Service — flooding resources to disrupt availability.",
    "T1595":  "Active Scanning — systematic probing to map target infrastructure.",
}

_ASSET_CRITICALITY: dict[str, dict] = {
    "Payment Gateway":       {"level": "CRITICAL", "blast_radius": "Financial transactions, fraud risk"},
    "Official Ticket Portal":{"level": "HIGH",     "blast_radius": "Ticket fraud, reputation damage"},
    "Admin Console":         {"level": "CRITICAL", "blast_radius": "Full platform access, lateral movement"},
    "Media Portal":          {"level": "MEDIUM",   "blast_radius": "Content disruption, DDoS amplification"},
    "Streaming Platform":    {"level": "MEDIUM",   "blast_radius": "Service disruption, credential stuffing"},
    "Mobile App API":        {"level": "HIGH",     "blast_radius": "User data exposure, API abuse"},
}

# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def _tool_enrich_ip(ip: str) -> dict:
    """Look up IP reputation and geolocation. Returns inline for offline demo."""
    if ip in _KNOWN_BAD_IPS:
        info = _KNOWN_BAD_IPS[ip]
        return {
            "ip": ip,
            "country": info["country"],
            "asn": info["asn"],
            "reputation_score": info["reputation"],
            "is_known_threat": True,
            "source": "offline-intel",
        }
    if os.getenv("ENABLE_LIVE_INTEL") == "1":
        try:
            import httpx
            data = httpx.get(f"https://ipapi.co/{ip}/json/", timeout=3).json()
            return {
                "ip": ip,
                "country": data.get("country_name", "Unknown"),
                "asn": data.get("org", "Unknown"),
                "reputation_score": 20,
                "is_known_threat": False,
                "source": "ipapi.co",
            }
        except Exception as e:
            logger.debug("Live IP lookup failed for %s: %s", ip, e)
    return {"ip": ip, "country": "Unknown", "reputation_score": 10,
            "is_known_threat": False, "source": "default"}


def _tool_lookup_mitre(technique: str) -> dict:
    """Look up MITRE ATT&CK technique description."""
    desc = _MITRE_DESCRIPTIONS.get(technique, "No description available for this technique.")
    return {"technique": technique, "description": desc, "source": "mitre-static-db"}


def _tool_check_whois(domain: str) -> dict:
    """Estimate WHOIS domain age. Suspicious if < 30 days."""
    suspicious_patterns = ["secure2026", "ticket2026", "fifalogin", "wc2026"]
    is_suspicious = any(p in domain.lower() for p in suspicious_patterns)
    age_days = 2 if is_suspicious else 365
    return {
        "domain": domain,
        "estimated_age_days": age_days,
        "is_suspicious": is_suspicious,
        "note": "Newly registered typosquatting domain" if is_suspicious else "Established domain",
    }


def _tool_assess_business_impact(asset: str) -> dict:
    """Return FIFA asset criticality and blast radius."""
    info = _ASSET_CRITICALITY.get(asset, {
        "level": "LOW", "blast_radius": "Limited operational impact"})
    return {"asset": asset, **info}


def _tool_escalate_priority(incident_id: str, reason: str) -> dict:
    """Agent-initiated priority escalation stored back to Redis."""
    raw = r.get(f"incident:{incident_id}")
    if not raw:
        return {"status": "error", "message": "Incident not found"}
    inc = json.loads(raw)
    old_priority = inc.get("priority", "P4")
    # Escalate one step: P4→P3→P2→P1
    escalation = {"P4": "P3", "P3": "P2", "P2": "P1", "P1": "P1"}
    inc["priority"] = escalation.get(old_priority, "P1")
    inc["escalation_reason"] = reason
    inc["escalated_at"] = time.time()
    r.set(f"incident:{incident_id}", json.dumps(inc))
    return {
        "status": "escalated",
        "old_priority": old_priority,
        "new_priority": inc["priority"],
        "reason": reason,
    }


_TOOLS = {
    "enrich_ip":             _tool_enrich_ip,
    "lookup_mitre":          _tool_lookup_mitre,
    "check_whois":           _tool_check_whois,
    "assess_business_impact":_tool_assess_business_impact,
    "escalate_priority":     _tool_escalate_priority,
}

_TOOL_SCHEMA = """Available tools (call ONE per step):
  enrich_ip(ip: str)                           → IP reputation + country + ASN
  lookup_mitre(technique: str)                 → MITRE ATT&CK technique description
  check_whois(domain: str)                     → domain age + suspicion flag
  assess_business_impact(asset: str)           → FIFA asset criticality + blast radius
  escalate_priority(incident_id: str, reason: str) → bump incident priority in Redis

To call a tool, output EXACTLY this JSON (no other text):
{"tool": "<name>", "args": {"<param>": "<value>"}}

When you have enough information, output EXACTLY this JSON:
{"done": true, "summary": "...", "attack_narrative": "...",
 "recommended_action": "...", "confidence": <int 0-100>}
"""

_SYSTEM_PROMPT = """You are a FIFA World Cup 2026 SOC Tier-3 Security Analyst AI agent.
You have access to tools to investigate security incidents.
Investigate the incident step-by-step: use tools to gather intel, then produce a final report.
Be concise and actionable. Address Tier-1 analysts who need clear guidance."""


def _build_initial_prompt(inc: dict, alerts: list[dict]) -> str:
    return f"""{_SYSTEM_PROMPT}

{_TOOL_SCHEMA}

=== INCIDENT {inc['incident_id']} ===
Priority : {inc.get('priority', 'UNKNOWN')}
Max risk : {inc.get('max_risk', 0)}
Asset    : {inc.get('asset', 'Unknown')}
Tactics  : {inc.get('tactics', [])}
Campaign : {inc.get('campaign_name', 'N/A')}

Alerts ({len(alerts)} total):
{json.dumps(alerts[:5], indent=2)[:4000]}

Begin your investigation. Use tools to gather intelligence before writing the final report.
"""


# ---------------------------------------------------------------------------
# Agentic loop (LangGraph-style state machine, works with or without LG)
# ---------------------------------------------------------------------------

class _AgentState(TypedDict):
    messages: list[dict]     # conversation history
    tool_outputs: list[dict] # accumulated tool results
    step: int
    done: bool
    result: dict


_MAX_STEPS = 6  # max tool calls per investigation


def _run_agentic_loop(llm, inc_id: str, inc: dict, alerts: list[dict]) -> dict:
    """
    Agentic reasoning loop:
      analyst → tool → observe → analyst → … → done
    Returns the final structured result dict.
    """
    state: _AgentState = {
        "messages":    [{"role": "user", "content": _build_initial_prompt(inc, alerts)}],
        "tool_outputs":[],
        "step":        0,
        "done":        False,
        "result":      {},
    }

    while not state["done"] and state["step"] < _MAX_STEPS:
        state["step"] += 1

        # Build context string for LLM
        context = "\n".join(
            f"[Step {i+1} Tool Result]: {json.dumps(t)}"
            for i, t in enumerate(state["tool_outputs"])
        )
        conversation = state["messages"].copy()
        if context:
            conversation.append({"role": "assistant", "content": context})

        # Call LLM
        full_prompt = "\n".join(
            m["content"] for m in conversation
        )
        try:
            response_text = llm.invoke(full_prompt).content.strip()
        except Exception as e:
            logger.error("LLM call failed at step %d: %s", state["step"], e)
            break

        # Parse response
        try:
            # Find JSON block
            start = response_text.find("{")
            end   = response_text.rfind("}") + 1
            if start == -1 or end == 0:
                logger.warning("Step %d: no JSON found in LLM response", state["step"])
                break
            parsed = json.loads(response_text[start:end])
        except json.JSONDecodeError as e:
            logger.warning("Step %d: JSON parse error: %s", state["step"], e)
            break

        # Check if agent is done
        if parsed.get("done"):
            state["done"] = True
            state["result"] = {
                "summary":           parsed.get("summary", ""),
                "attack_narrative":  parsed.get("attack_narrative", ""),
                "recommended_action":parsed.get("recommended_action", ""),
                "confidence":        parsed.get("confidence", 70),
                "steps_taken":       state["step"],
                "tool_calls":        len(state["tool_outputs"]),
            }
            logger.info("Agent finished %s in %d steps", inc_id, state["step"])
            break

        # Execute tool call
        tool_name = parsed.get("tool")
        tool_args = parsed.get("args", {})
        if tool_name and tool_name in _TOOLS:
            logger.info("Agent calling tool '%s' args=%s", tool_name, tool_args)
            try:
                output = _TOOLS[tool_name](**tool_args)
            except Exception as e:
                output = {"error": str(e)}
            state["tool_outputs"].append({
                "tool": tool_name, "args": tool_args, "result": output})
            state["messages"].append({
                "role": "assistant",
                "content": f"Tool '{tool_name}' result: {json.dumps(output)}"
            })
        else:
            logger.warning("Unknown tool '%s' — skipping", tool_name)
            break

    # If loop ended without a structured result, use fallback
    if not state["result"]:
        tools_used = [t["tool"] for t in state["tool_outputs"]]
        state["result"] = {
            "summary":           f"Agent collected intel via {tools_used} but did not produce a final report.",
            "attack_narrative":  "Multi-step investigation incomplete.",
            "recommended_action":"Manual Tier-2 review required.",
            "confidence":        40,
            "steps_taken":       state["step"],
            "tool_calls":        len(state["tool_outputs"]),
        }

    return state["result"]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _get_llm():
    """Return LangChain LLM if API key is configured, else None."""
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key or api_key.startswith("your_"):
        return None
    try:
        from langchain_google_genai import ChatGoogleGenerativeAI
        return ChatGoogleGenerativeAI(
            model="gemini-2.0-flash",
            google_api_key=api_key,
            temperature=0.2,
        )
    except Exception as e:
        logger.error("Failed to init LLM: %s", e)
        return None


def _heuristic_summary(inc: dict, alerts: list[dict]) -> dict:
    """Fast rule-based summary when no LLM is available."""
    tactics = inc.get("tactics", [])
    asset   = inc.get("asset", "Unknown Asset")
    impact  = _ASSET_CRITICALITY.get(asset, {}).get("level", "UNKNOWN")
    is_multistage = len(set(tactics)) >= 2

    if is_multistage:
        narrative = (f"Multi-stage attack chain detected: {' → '.join(set(tactics))}. "
                     f"Attackers progressed through {len(tactics)} distinct MITRE tactics.")
        action = ("Isolate affected systems immediately. Block IOCs at perimeter. "
                  "Escalate to Tier-2 for forensic investigation.")
        confidence = 75
    else:
        narrative = (f"Single-stage incident on {asset} "
                     f"({'via ' + tactics[0] if tactics else 'unknown tactic'}).")
        action = "Review logs, block offending IPs, notify asset owner."
        confidence = 55

    return {
        "summary": (f"Incident on {asset} (impact={impact}). "
                    f"{len(alerts)} alerts correlated. Priority={inc.get('priority','?')}."),
        "attack_narrative":   narrative,
        "recommended_action": action,
        "confidence":         confidence,
        "steps_taken":        0,
        "tool_calls":         0,
    }


def summarize_incident(inc_id: str) -> dict:
    """
    Run the agentic investigation loop for an incident.
    Falls back to heuristic summary if no LLM key is set.
    Persists result to Redis.
    """
    raw = r.get(f"incident:{inc_id}")
    if not raw:
        logger.error("summarize_incident: incident %s not found in Redis", inc_id)
        return {}

    inc    = json.loads(raw)
    alerts = []
    for aid in inc.get("alert_ids", []):
        a_raw = r.get(f"alert:{aid}")
        if a_raw:
            alerts.append(json.loads(a_raw))

    llm = _get_llm()
    if llm:
        result = _run_agentic_loop(llm, inc_id, inc, alerts)
    else:
        logger.info("No LLM key configured — using heuristic summary for %s", inc_id)
        result = _heuristic_summary(inc, alerts)

    inc.update(result)
    r.set(f"incident:{inc_id}", json.dumps(inc))
    return result


def answer_query(incident_id: str, question: str) -> str:
    """
    Answer an analyst's ad-hoc question about an incident.
    Uses the agentic loop if LLM is available.
    """
    raw = r.get(f"incident:{incident_id}")
    if not raw:
        return "Incident not found."

    inc = json.loads(raw)
    llm = _get_llm()

    if not llm:
        # Heuristic answer
        return (f"[Heuristic] Incident {incident_id}: priority={inc.get('priority','?')}, "
                f"max_risk={inc.get('max_risk',0)}, asset={inc.get('asset','?')}. "
                f"Configure GEMINI_API_KEY for AI-powered Q&A.")

    # Build a focused Q&A prompt (single turn — no full agentic loop needed)
    q_prompt = (
        f"You are a FIFA SOC analyst. Answer concisely and factually.\n\n"
        f"Incident context:\n{json.dumps(inc, indent=2)[:5000]}\n\n"
        f"Question: {question}\n\n"
        f"If the question warrants it, recommend next steps."
    )
    try:
        return llm.invoke(q_prompt).content
    except Exception as e:
        logger.error("answer_query LLM error: %s", e)
        return f"LLM error: {e}"
