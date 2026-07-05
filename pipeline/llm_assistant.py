"""
pipeline/llm_assistant.py — LangGraph Agentic Security Analyst

Architecture:
  A real LangGraph ReAct agent (langgraph.prebuilt.create_react_agent) reasons
  over the incident, calling tools (enrich_ip, lookup_mitre, check_whois,
  assess_business_impact, escalate_priority) to gather intel, then calls
  `submit_report` — itself a tool — to emit its structured final answer. That
  sidesteps fragile "please output exactly this JSON" text parsing: the
  model's tool call *is* the structured output.

Retrieval augmentation (intel/rag.py, Pinecone): before the agent runs, it's
given similar past incidents and MITRE technique guidance retrieved from a
vector index as grounding context. After the agent finishes, the incident is
embedded and upserted back into the index so future incidents can retrieve it.

When GEMINI_API_KEY is missing, summarize_incident() returns a static
heuristic summary so the pipeline never crashes.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time

import redis

from intel import rag
from intel.mitre import lookup_technique
from intel.reputation import ip_reputation
from intel.whois_lookup import lookup_domain_age

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Redis
# ---------------------------------------------------------------------------
r = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))

# ---------------------------------------------------------------------------
# Known intelligence (offline fallbacks — used when live intel is unavailable)
# ---------------------------------------------------------------------------

_KNOWN_BAD_IPS: dict[str, dict] = {
    "185.174.21.14": {"country": "Russia",      "asn": "AS-BFNET",   "reputation": 95},
    "45.155.205.99": {"country": "Netherlands", "asn": "AS-SERVERS", "reputation": 88},
    "193.169.255.10":{"country": "Belarus",     "asn": "AS-BYNET",   "reputation": 82},
}

_ASSET_CRITICALITY: dict[str, dict] = {
    "Payment Gateway":       {"level": "CRITICAL", "blast_radius": "Financial transactions, fraud risk"},
    "Official Ticket Portal":{"level": "HIGH",     "blast_radius": "Ticket fraud, reputation damage"},
    "Admin Console":         {"level": "CRITICAL", "blast_radius": "Full platform access, lateral movement"},
    "Media Portal":          {"level": "MEDIUM",   "blast_radius": "Content disruption, DDoS amplification"},
    "Streaming Platform":    {"level": "MEDIUM",   "blast_radius": "Service disruption, credential stuffing"},
    "Mobile App API":        {"level": "HIGH",     "blast_radius": "User data exposure, API abuse"},
}

_MAX_STEPS = 8  # tool-call budget per investigation

# ---------------------------------------------------------------------------
# Tool implementations (plain functions — wrapped as LangChain tools below)
# ---------------------------------------------------------------------------

def _tool_enrich_ip(ip: str) -> dict:
    """IP reputation + geolocation: offline curated list first, then live
    geolocation + public-blocklist reputation (Spamhaus/Tor/FireHOL) when
    ENABLE_LIVE_INTEL=1."""
    if ip in _KNOWN_BAD_IPS:
        info = _KNOWN_BAD_IPS[ip]
        return {"ip": ip, "country": info["country"], "asn": info["asn"],
                "reputation_score": info["reputation"], "is_known_threat": True,
                "source": "offline-intel"}

    country, asn = "Unknown", "Unknown"
    if os.getenv("ENABLE_LIVE_INTEL") == "1":
        try:
            import httpx
            data = httpx.get(f"https://ipapi.co/{ip}/json/", timeout=3).json()
            country = data.get("country_name", "Unknown")
            asn     = data.get("org", "Unknown")
        except Exception as e:
            logger.debug("Live IP geolocation failed for %s: %s", ip, e)

        blocklist = ip_reputation(ip)
        if blocklist["reputation_score"] is not None:
            return {"ip": ip, "country": country, "asn": asn,
                    "reputation_score": blocklist["reputation_score"],
                    "is_known_threat": blocklist["is_listed"],
                    "blocklist_sources": blocklist["sources"],
                    "source": "public-blocklists" if blocklist["is_listed"] else "public-blocklists-clean"}

    return {"ip": ip, "country": country, "asn": asn, "reputation_score": 10,
            "is_known_threat": False, "source": "default"}


def _tool_lookup_mitre(technique: str) -> dict:
    """Look up a MITRE ATT&CK technique against the full 697-technique catalogue."""
    return lookup_technique(technique)


def _tool_check_whois(domain: str) -> dict:
    """Domain registration age — real WHOIS when ENABLE_LIVE_INTEL=1, heuristic otherwise."""
    info = lookup_domain_age(domain)
    return {
        "domain": domain,
        "estimated_age_days": info["age_days"],
        "is_suspicious": info["is_suspicious"],
        "source": info["source"],
        "note": "Newly registered domain" if info["is_suspicious"] else "Established domain",
    }


def _tool_assess_business_impact(asset: str) -> dict:
    """Return FIFA asset criticality and blast radius."""
    info = _ASSET_CRITICALITY.get(asset, {"level": "LOW", "blast_radius": "Limited operational impact"})
    return {"asset": asset, **info}


def _tool_escalate_priority(incident_id: str, reason: str) -> dict:
    """Agent-initiated priority escalation stored back to Redis."""
    raw = r.get(f"incident:{incident_id}")
    if not raw:
        return {"status": "error", "message": "Incident not found"}
    inc = json.loads(raw)
    old_priority = inc.get("priority", "P4")
    escalation = {"P4": "P3", "P3": "P2", "P2": "P1", "P1": "P1"}
    inc["priority"] = escalation.get(old_priority, "P1")
    inc["escalation_reason"] = reason
    inc["escalated_at"] = time.time()
    r.set(f"incident:{incident_id}", json.dumps(inc))
    return {"status": "escalated", "old_priority": old_priority,
            "new_priority": inc["priority"], "reason": reason}


# ---------------------------------------------------------------------------
# LangGraph ReAct agent
# ---------------------------------------------------------------------------

def _build_tools():
    from langchain_core.tools import tool

    @tool
    def enrich_ip(ip: str) -> dict:
        """Look up an IP's reputation, geolocation, and ASN."""
        return _tool_enrich_ip(ip)

    @tool
    def lookup_mitre(technique: str) -> dict:
        """Look up a MITRE ATT&CK technique ID (e.g. 'T1566.002') for its name, description, and tactics."""
        return _tool_lookup_mitre(technique)

    @tool
    def check_whois(domain: str) -> dict:
        """Check a domain's registration age and whether it looks newly-registered/suspicious."""
        return _tool_check_whois(domain)

    @tool
    def assess_business_impact(asset: str) -> dict:
        """Assess a FIFA asset's criticality level and blast radius if compromised."""
        return _tool_assess_business_impact(asset)

    @tool
    def escalate_priority(incident_id: str, reason: str) -> dict:
        """Escalate an incident's priority by one level (e.g. P3 -> P2), with a reason."""
        return _tool_escalate_priority(incident_id, reason)

    @tool
    def submit_report(summary: str, attack_narrative: str, recommended_action: str, confidence: int) -> dict:
        """Submit the final investigation report. Call this exactly once, after you've
        gathered enough intel with the other tools. `confidence` is an integer 0-100."""
        return {"summary": summary, "attack_narrative": attack_narrative,
                "recommended_action": recommended_action, "confidence": confidence}

    return [enrich_ip, lookup_mitre, check_whois, assess_business_impact,
            escalate_priority, submit_report]


_SYSTEM_PROMPT = """You are a FIFA World Cup 2026 SOC Tier-3 Security Analyst AI agent.
Investigate the incident step-by-step using your tools — check IPs, domains, MITRE
techniques, and business impact before concluding. RAG_CONTEXT below (if present) has
similar past incidents and ATT&CK guidance retrieved for grounding — use it, but verify
with tools rather than assuming it's authoritative. When you have enough information,
call `submit_report` exactly once with your final findings. Be concise and actionable
for a Tier-1 analyst audience."""


def _rag_context_block(inc: dict) -> str:
    """Retrieve similar past incidents + MITRE technique guidance for grounding."""
    query_text = (f"{inc.get('asset', '')} {inc.get('campaign_name', '')} "
                  f"{' '.join(inc.get('tactics', []))} {' '.join(inc.get('techniques', []))}").strip()
    if not query_text:
        return ""

    similar_incidents = rag.query_similar(query_text, top_k=2, kind="incident",
                                           exclude_id=inc.get("incident_id"))
    technique_docs = rag.query_similar(query_text, top_k=2, kind="technique")
    if not similar_incidents and not technique_docs:
        return ""

    lines = ["=== RAG_CONTEXT (retrieved, verify — not ground truth) ==="]
    for m in similar_incidents:
        lines.append(f"- Similar past incident {m.get('id')}: asset={m.get('asset')}, "
                      f"priority={m.get('priority')}, prior_action={m.get('recommended_action', 'N/A')}")
    for m in technique_docs:
        lines.append(f"- ATT&CK {m.get('technique')} ({m.get('name')}): tactics={m.get('tactics')}")
    return "\n".join(lines)


def _build_initial_prompt(inc: dict, alerts: list[dict]) -> str:
    rag_block = _rag_context_block(inc)
    return f"""{_SYSTEM_PROMPT}

{rag_block}

=== INCIDENT {inc['incident_id']} ===
Priority : {inc.get('priority', 'UNKNOWN')}
Max risk : {inc.get('max_risk', 0)}
Asset    : {inc.get('asset', 'Unknown')}
Tactics  : {inc.get('tactics', [])}
Campaign : {inc.get('campaign_name', 'N/A')}

Alerts ({len(alerts)} total):
{json.dumps(alerts[:5], indent=2)[:4000]}

Begin your investigation.
"""


def _parse_tool_content(content) -> dict | None:
    """submit_report's ToolMessage content may arrive as a JSON string, a
    str(dict) repr, or an already-parsed dict depending on LangGraph version."""
    if isinstance(content, dict):
        return content
    if not isinstance(content, str):
        return None
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    try:
        import ast
        parsed = ast.literal_eval(content)
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def _run_agentic_loop(llm, inc_id: str, inc: dict, alerts: list[dict]) -> dict:
    """Run the LangGraph ReAct agent to investigate an incident."""
    from langgraph.prebuilt import create_react_agent
    from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

    agent  = create_react_agent(llm, _build_tools())
    prompt = _build_initial_prompt(inc, alerts)

    try:
        state = agent.invoke(
            {"messages": [HumanMessage(content=prompt)]},
            config={"recursion_limit": _MAX_STEPS * 2},
        )
    except Exception as e:
        logger.error("LangGraph agent run failed for %s: %s", inc_id, e)
        return {}

    messages        = state.get("messages", [])
    tool_call_count = sum(1 for m in messages if isinstance(m, ToolMessage))

    report = None
    for msg in messages:
        if isinstance(msg, ToolMessage) and msg.name == "submit_report":
            report = _parse_tool_content(msg.content)
            break

    if report:
        logger.info("Agent finished %s via %d tool calls", inc_id, tool_call_count)
        return {
            "summary":            report.get("summary", ""),
            "attack_narrative":   report.get("attack_narrative", ""),
            "recommended_action": report.get("recommended_action", ""),
            "confidence":         report.get("confidence", 70),
            "steps_taken":        tool_call_count,
            "tool_calls":         tool_call_count,
        }

    # Agent exhausted its step budget without calling submit_report — fall
    # back to its last free-text message so something useful still surfaces.
    last_text = ""
    for msg in reversed(messages):
        if isinstance(msg, AIMessage) and msg.content:
            last_text = msg.content if isinstance(msg.content, str) else str(msg.content)
            break

    logger.warning("Agent for %s did not call submit_report — using last message", inc_id)
    return {
        "summary":            last_text or f"Investigation incomplete after {tool_call_count} tool calls.",
        "attack_narrative":   "Multi-step investigation did not conclude with a structured report.",
        "recommended_action": "Manual Tier-2 review required.",
        "confidence":         40,
        "steps_taken":        tool_call_count,
        "tool_calls":         tool_call_count,
    }


# ---------------------------------------------------------------------------
# RAG corpus seeding — non-blocking, runs once in the background per process
# ---------------------------------------------------------------------------

def _background_seed():
    try:
        rag.seed_mitre_techniques()
    except Exception as e:
        logger.warning("RAG technique-corpus seed failed: %s", e)


threading.Thread(target=_background_seed, daemon=True).start()


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
            model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
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
    Run the agentic investigation for an incident (LangGraph ReAct agent if an
    LLM key is configured, heuristic otherwise). Persists result to Redis and
    the RAG corpus.
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
        result = _run_agentic_loop(llm, inc_id, inc, alerts) or _heuristic_summary(inc, alerts)
    else:
        logger.info("No LLM key configured — using heuristic summary for %s", inc_id)
        result = _heuristic_summary(inc, alerts)

    inc.update(result)
    r.set(f"incident:{inc_id}", json.dumps(inc))

    rag_text = (f"Incident on {inc.get('asset')} ({inc.get('campaign_name', '')}): "
                f"{result.get('summary', '')} {result.get('attack_narrative', '')}")
    rag.upsert_incident(inc_id, rag_text, {
        "asset":              inc.get("asset"),
        "priority":           inc.get("priority"),
        "campaign_name":      inc.get("campaign_name"),
        "recommended_action": result.get("recommended_action"),
    })

    return result


def answer_query(incident_id: str, question: str) -> str:
    """Answer an analyst's ad-hoc question about an incident, grounded with RAG context."""
    raw = r.get(f"incident:{incident_id}")
    if not raw:
        return "Incident not found."

    inc = json.loads(raw)
    llm = _get_llm()

    if not llm:
        return (f"[Heuristic] Incident {incident_id}: priority={inc.get('priority','?')}, "
                f"max_risk={inc.get('max_risk',0)}, asset={inc.get('asset','?')}. "
                f"Configure GEMINI_API_KEY for AI-powered Q&A.")

    rag_block = _rag_context_block(inc)
    q_prompt = (
        f"You are a FIFA SOC analyst. Answer concisely and factually.\n\n"
        f"{rag_block}\n\n"
        f"Incident context:\n{json.dumps(inc, indent=2)[:5000]}\n\n"
        f"Question: {question}\n\n"
        f"If the question warrants it, recommend next steps."
    )
    try:
        return llm.invoke(q_prompt).content
    except Exception as e:
        logger.error("answer_query LLM error: %s", e)
        return f"LLM error: {e}"
