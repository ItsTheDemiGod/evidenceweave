"""--no-llm narrative: the deterministic facts rendered verbatim, one sentence per fact in priority order.

Each sentence is verified with layers 1 (structure), facts, 2 (entities) and 3a (semantics) only; there is no narrator and no judge.
Writes the same three files as the LLM path so the report builder needs no special case (verification.no_llm is True).
"""
from __future__ import annotations

import time
import json
from pathlib import Path

from ..narrator import facts as F
from ..narrator.narrate import now_iso, summary_facts_info, template_sections, write_json
from ..narrator.packs import load_events
from ..narrator import prompts as P
from .repair import EXEC, VerifyConfig, _fallback, _finish, fallback_sentences
from .verify import Verifier, load_case_data


def narrate_deterministic(out: Path, max_facts: int = 8) -> dict:
    """narrative.json for the no-LLM path: facts and allowed cites, no sentences, no model."""
    chain = json.loads((out / "chain.json").read_text(encoding="utf-8"))
    findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))["findings"]
    events = load_events(out / "events.jsonl")
    facts = F.build_facts(chain, findings, events, max_facts)
    stages = []
    for st in chain["stages"]:
        allowed = F.allowed_ids(facts[st["stage"]], events)
        stages.append({"stage": st["stage"], "status": st["status"], "source": "deterministic", "sentences": [], "parse_ok": True,
                       "attempts": 0, "seconds": 0, "facts": facts[st["stage"]], "evidence_shown": len(allowed),
                       "evidence_total": len(st["evidence_event_ids"]), "allowed_cite_ids": allowed, "raw_output_file": None})
    shown = [f for s in summary_facts_info(chain, facts) for f in s["facts"]]
    attempts_only, unprovable = template_sections(chain, findings, events)
    doc = {"case_name": chain["case_name"], "mode": "chain", "model": None, "prompt_version": None, "narration_mode": "facts",
           "max_facts_per_stage": max_facts, "ollama_options": None, "json_mode": None, "total_seconds": 0.0,
           "created_at": now_iso(), "max_evidence_per_stage": 12, "executive_summary": [],
           "executive_summary_meta": {"parse_ok": True, "attempts": 0, "seconds": 0,
                                      "allowed_cite_ids": list(dict.fromkeys(c for f in shown for c in f["cites"])),
                                      "raw_output_file": None, "facts": shown},
           "stages": stages, "attempts_only": attempts_only, "unprovable": unprovable,
           "stats": {"calls": 0, "failed_parses": 0, "retries": 0, "total_tokens": None},
           "run_metadata": {"collected": False, "no_llm": True}}
    write_json(out / "narrative.json", doc)
    return doc


def verify_deterministic(out: Path, hosts: dict, max_cites: int = 8, max_facts: int = 8, progress=None) -> dict:
    """Build + verify the deterministic narrative; returns {"verified", "report"} like verify_chain."""
    t0 = time.time()
    out = Path(out)
    narrative = narrate_deterministic(out, max_facts)
    data = load_case_data(out, hosts, narrative=narrative)
    verifier = Verifier(data.events, data.host_names, max_cites)
    units = [p.stage for p in data.packs] + [EXEC]
    final, fallback_verdicts = {}, []
    for u in units:
        sents = []
        fallback_verdicts += _fallback(data, verifier, u, 0, sents, "deterministic")
        total = len(fallback_sentences(data, u))
        final[u] = {"sentences": sents, "best_attempt": 0, "attempts_used": 0, "fallback": False, "accepted": len(sents),
                    "dropped": total - len(sents)}
    fact_total = sum(len(s["facts"]) for s in narrative["stages"])
    fact_cov = {"facts_total": fact_total, "facts_expressed_by_accepted_llm_sentences": 0, "coverage_rate": None,
                "facts_per_stage": {s["stage"]: {"total": len(s["facts"]), "expressed": 0} for s in narrative["stages"]},
                "stages_with_accepted_llm_sentence": [], "stages_fallback_only": []}
    eff = {"basis": "no LLM: nothing to repair", "failing_at_attempt0": 0, "fixed_by_round": {}, "fixed_total": 0,
           "still_failing": 0, "per_code": None}
    res = _finish(data, None, None, VerifyConfig(0, max_cites, False), verifier, units, final, [], [], [], fallback_verdicts,
                  {u: [] for u in units}, [], {}, t0, False, False, None, None, progress, eff, fact_cov,
                  {"collected": False, "no_llm": True})
    ver = res["verified"]["verification"]
    ver.update({"no_llm": True, "judge_mode": "none (--no-llm: deterministic layers 1, 2, 3a only)", "max_retries": 0})
    for st in res["verified"]["stages"]:
        st["source"] = "deterministic"
    res["report"]["verification"] = ver
    write_json(out / "narrative_verified.json", res["verified"])
    write_json(out / "verification_report.json", res["report"])
    return res
