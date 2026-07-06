# LLM Security Assistant

`pipeline/llm_assistant.py` is the agentic investigation layer. On a **new**
incident, it produces a structured summary, attack narrative, and recommended
action; it also answers analysts' ad-hoc questions. It degrades to a deterministic
heuristic when no LLM key is configured.

## The LangGraph ReAct agent

With `GEMINI_API_KEY` set, `summarize_incident(inc_id)` runs a real
`langgraph.prebuilt.create_react_agent` over the incident. The agent reasons
step-by-step and calls tools to gather intel, then emits its final answer **as a
tool call** — sidestepping fragile "please output exactly this JSON" parsing.

### Tools

| Tool | Backing function | Purpose |
|---|---|---|
| `enrich_ip(ip)` | `_tool_enrich_ip` | Reputation, geolocation, ASN (offline curated list, then live blocklists when enabled). |
| `lookup_mitre(technique)` | `intel/mitre.lookup_technique` | Look up an ATT&CK technique against the full 697-technique catalogue. |
| `check_whois(domain)` | `intel/whois_lookup.lookup_domain_age` | Domain registration age / suspicious-newness. |
| `assess_business_impact(asset)` | `_tool_assess_business_impact` | FIFA asset criticality + blast radius. |
| `escalate_priority(incident_id, reason)` | `_tool_escalate_priority` | Agent-initiated one-level priority bump, persisted to Redis. |
| `submit_report(summary, attack_narrative, recommended_action, confidence)` | — | The structured final answer. Called exactly once. |

The agent runs under a tool-call budget (`_MAX_STEPS = 8`, `recursion_limit =
_MAX_STEPS × 2`). The result — read from the `submit_report` tool message — is
merged into the incident record and persisted. If the agent exhausts its budget
without calling `submit_report`, it falls back to its last free-text message with
a low confidence and a "manual Tier-2 review required" action.

## RAG grounding (Pinecone)

When `PINECONE_API_KEY` is set (`intel/rag.py`):

- **Before** the agent runs, `_rag_context_block()` retrieves the top similar
  past incidents and relevant ATT&CK technique guidance from a vector index and
  injects them as `RAG_CONTEXT` — explicitly labeled "verify, not ground truth."
- **After** the investigation, the incident is embedded and upserted back into
  the index so future incidents can retrieve it.

RAG no-ops gracefully without a Pinecone key. The MITRE technique corpus is
seeded in the background by `initialize_rag()` — see below.

## Explicit initialization (no import side-effects)

RAG seeding used to fire from a bare module-level `threading.Thread` at import,
meaning importing the module (e.g. in a unit test) silently spawned a
network-bound thread hitting Pinecone/Gemini. Now:

- `initialize_rag()` starts the background seed thread **explicitly** and is
  idempotent (a no-op if a seed is already running).
- It's called deliberately at process startup — from `pipeline/worker.py::run`
  and from the FastAPI `lifespan` handler in `api/server.py`.

Seeding resumes across runs from a persisted checkpoint
(`intel/data/rag_seed_checkpoint.json`, up to 100 techniques per run) so free-tier
embedding limits don't force a restart from zero. Covered by
`tests/test_rag_seed.py`.

## Heuristic fallback

Without a Gemini key (or with `DISABLE_LLM=1`), `_heuristic_summary()` produces a
rule-based summary: it detects multi-stage chains (≥2 distinct tactics), composes
a narrative and recommended action, and assigns a confidence. This keeps the
pipeline fully functional offline.

## Analyst Q&A

`answer_query(incident_id, question)` powers `POST /api/incidents/{id}/ask`. It
grounds the question with the same RAG context block and the incident JSON, then
calls the LLM. Without a key it returns a heuristic summary of the incident. The
API runs this via `asyncio.to_thread` so the blocking LLM call never stalls the
event loop — see [API](api.md).
