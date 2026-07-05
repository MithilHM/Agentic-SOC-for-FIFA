#!/usr/bin/env python
"""
Agent evaluation harness (item #4).

Runs the LangGraph SOC analyst (pipeline.llm_assistant.summarize_incident)
against a small labeled set of known incidents and reports pass/fail per case,
so a future model swap or prompt change can be regression-checked.

Each case in evals/agent_eval_cases.json carries the pre-correlated incident +
alerts and a set of `checks` (expected confidence band, priority direction, and
keyword groups the agent's output should touch). A case passes only if every
check passes.

Usage (inside the api/worker container, which has GEMINI_API_KEY):
    python -m evals.run_agent_eval             # human-readable table
    python -m evals.run_agent_eval --json      # machine-readable
    python -m evals.run_agent_eval --limit 2   # first N cases

Exit code is nonzero if any case fails (CI-friendly).

Note: the harness disables rag.upsert_incident so EVAL-* incidents never
pollute the production Pinecone corpus, and deletes its Redis keys afterward.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

import redis

from intel import rag
from pipeline import llm_assistant

_CASES_PATH = os.path.join(os.path.dirname(__file__), "agent_eval_cases.json")
_PRIO_RANK = {"P4": 1, "P3": 2, "P2": 3, "P1": 4}

r = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))


def _load_cases():
    with open(_CASES_PATH, encoding="utf-8") as f:
        return json.load(f)


def _load_case_into_redis(case: dict) -> str:
    inc = dict(case["incident"])
    inc_id = inc["incident_id"]
    now = time.time()
    inc.setdefault("created", now)
    inc["last_seen"] = now
    inc["alert_ids"] = [a["alert_id"] for a in case["alerts"]]
    for a in case["alerts"]:
        r.set(f"alert:{a['alert_id']}", json.dumps(a))
    r.set(f"incident:{inc_id}", json.dumps(inc))
    return inc_id


def _cleanup(case: dict) -> None:
    r.delete(f"incident:{case['incident']['incident_id']}")
    for a in case["alerts"]:
        r.delete(f"alert:{a['alert_id']}")


def _grade(case: dict, result: dict, final_inc: dict):
    checks = case.get("checks", {})
    reasons: list[str] = []

    if not result:
        return False, ["agent returned no result"]

    text = " ".join(str(result.get(k, "")) for k in
                    ("summary", "attack_narrative", "recommended_action")).lower()
    conf = int(result.get("confidence", 0) or 0)
    prio = final_inc.get("priority", "P4")
    prio_rank = _PRIO_RANK.get(prio, 1)

    if "min_confidence" in checks and conf < checks["min_confidence"]:
        reasons.append(f"confidence {conf} < min {checks['min_confidence']}")
    if "max_confidence" in checks and conf > checks["max_confidence"]:
        reasons.append(f"confidence {conf} > max {checks['max_confidence']}")
    if "priority_at_least" in checks and prio_rank < _PRIO_RANK[checks["priority_at_least"]]:
        reasons.append(f"priority {prio} weaker than {checks['priority_at_least']}")
    if "priority_at_most" in checks and prio_rank > _PRIO_RANK[checks["priority_at_most"]]:
        reasons.append(f"priority {prio} stronger than {checks['priority_at_most']} (over-escalated)")
    for group in checks.get("keywords_any", []):
        if not any(kw.lower() in text for kw in group):
            reasons.append(f"none of {group} present in output")

    return (len(reasons) == 0), reasons


def run(limit: int | None = None) -> list[dict]:
    # Keep eval incidents out of the production RAG corpus.
    llm_assistant.rag.upsert_incident = lambda *a, **k: None  # type: ignore

    # Is an LLM even configured? If not, the agent never runs and grading the
    # heuristic fallback would be meaningless — those cases are SKIPped.
    configured = llm_assistant._get_llm() is not None

    cases = _load_cases()
    if limit:
        cases = cases[:limit]

    results = []
    for case in cases:
        inc_id = _load_case_into_redis(case)
        base_prio = case["incident"].get("priority")
        t0 = time.time()
        try:
            result = llm_assistant.summarize_incident(inc_id) or {}
            err = None
        except Exception as e:  # pragma: no cover - defensive
            result, err = {}, str(e)
        elapsed = time.time() - t0

        final_inc = json.loads(r.get(f"incident:{inc_id}") or "{}")
        ran_agent = (result.get("tool_calls") or 0) > 0

        # Classify: only cases the agent actually ran are PASS/FAIL. A configured
        # agent that produced 0 tool calls fell back to the heuristic (LLM error
        # or free-tier quota) — reported as SKIP so infra issues don't look like
        # a judgment regression. No key at all -> SKIP too.
        if err:
            status, reasons = "FAIL", [f"exception: {err}"]
        elif not configured:
            status, reasons = "SKIP", ["GEMINI_API_KEY not configured — agent not exercised"]
        elif not ran_agent:
            status, reasons = "SKIP", ["agent fell back to heuristic (LLM error/quota) — not graded"]
        else:
            passed, grade_reasons = _grade(case, result, final_inc)
            status, reasons = ("PASS" if passed else "FAIL"), grade_reasons

        results.append({
            "name": case["name"],
            "status": status,
            "reasons": reasons,
            "base_priority": base_prio,
            "final_priority": final_inc.get("priority"),
            "confidence": result.get("confidence"),
            "tool_calls": result.get("tool_calls", 0),
            "elapsed_sec": round(elapsed, 1),
            "summary": result.get("summary", ""),
            "recommended_action": result.get("recommended_action", ""),
        })
        _cleanup(case)
    return results


def _print_table(results: list[dict]) -> None:
    agent_runs = sum(1 for x in results if (x["tool_calls"] or 0) > 0)
    print(f"\n  Agent eval — {agent_runs}/{len(results)} cases exercised the live LLM agent\n")
    print(f"  {'CASE':<30} {'RESULT':<6} {'PRIO(base→final)':<18} {'CONF':<5} {'TOOLS':<6} {'TIME':<6}")
    print("  " + "-" * 82)
    for x in results:
        prio = f"{x['base_priority']}→{x['final_priority']}"
        print(f"  {x['name']:<30} {x['status']:<6} {prio:<18} "
              f"{str(x['confidence']):<5} {str(x['tool_calls']):<6} {str(x['elapsed_sec'])+'s':<6}")
        if x["status"] != "PASS":
            for reason in x["reasons"]:
                print(f"       ↳ {reason}")
    passed = sum(1 for x in results if x["status"] == "PASS")
    failed = sum(1 for x in results if x["status"] == "FAIL")
    skipped = sum(1 for x in results if x["status"] == "SKIP")
    print("  " + "-" * 82)
    print(f"  {passed} passed, {failed} failed, {skipped} skipped "
          f"(of {len(results)} cases)\n")


def main() -> int:
    ap = argparse.ArgumentParser(description="Run the SOC agent against labeled incidents.")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    ap.add_argument("--limit", type=int, default=None, help="run only the first N cases")
    args = ap.parse_args()

    results = run(limit=args.limit)
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        _print_table(results)

    # Only genuine agent-run failures break the build; SKIPs (no key / quota) don't.
    return 1 if any(x["status"] == "FAIL" for x in results) else 0


if __name__ == "__main__":
    sys.exit(main())
