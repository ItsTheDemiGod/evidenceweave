"""Chain verification with batched repair rounds (narrator calls first, then the judge, so models swap rarely).

Two engines share the final assembly:
- raw mode (Phase 5 behaviour): a failing unit is regenerated whole, the best attempt wins;
- facts mode (Phase 5b): repair is sentence-level - accepted sentences are frozen and only the rejected ones are rewritten.
Both use a different seed and a small temperature in repair rounds so the model can actually change its output.
"""
from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass

from ..narrator import prompts as P
from ..narrator.facts import PRIORITY
from ..narrator.narrate import (narrate_stage, narrate_stage_facts, narrate_summary, narrate_summary_facts, now_iso,
                                save_raw, summary_facts_info, summary_info, write_json)
from .verdicts import LAYERS, WORDS
from .verify import (CaseData, Verifier, entity_coverage, fallback_ctx, feedback_text, needs_judge, rates, template_ctx)

EXEC = "executive_summary"
REPAIR_TEMPERATURE = 0.3  # attempt 0 stays at temperature 0 / seed 42
REPAIR_SEED_STEP = 1  # repair round r uses seed (base seed + r * step)


@dataclass
class VerifyConfig:
    max_retries: int = 2
    max_cites: int = 8
    use_judge: bool = True
    repair_temperature: float = REPAIR_TEMPERATURE
    repair_seed_step: int = REPAIR_SEED_STEP


def _say(cb, msg):
    if cb:
        cb(msg)


def count_swaps(call_log: list[dict], same_model: bool) -> int:
    kinds = [c["kind"] for c in call_log]
    return 0 if same_model else sum(1 for a, b in zip(kinds, kinds[1:]) if a != b)


def repair_options(narrator, cfg: VerifyConfig, r: int) -> dict:
    base = getattr(narrator, "options", {}).get("seed", 42)
    return {"temperature": cfg.repair_temperature, "seed": base + r * cfg.repair_seed_step}


def fallback_sentences(data: CaseData, unit: str) -> list[dict]:
    """Deterministic template text for a unit whose every LLM sentence was rejected.

    Facts mode: the unit's facts verbatim (one sentence per fact, priority order; executive summary = first fact of each stage).
    Raw mode: the finding summaries.
    """
    ctx = data.ctxs[unit]
    if ctx.fact_map is not None:
        if unit == EXEC:
            firsts = [data.narrative_stage_facts(st["stage"])[0] for st in data.chain["stages"] if data.narrative_stage_facts(st["stage"])]
            return [{"text": f["text"], "cites": f["cites"], "fact_ids": [f["fact_id"]]} for f in firsts]
        facts = data.narrative_stage_facts(unit)
        order = sorted(range(len(facts)), key=lambda i: (PRIORITY[facts[i]["kind"]], i))
        return [{"text": facts[i]["text"], "cites": facts[i]["cites"], "fact_ids": [facts[i]["fact_id"]]} for i in order]
    if unit == EXEC:
        out = []
        for p in data.packs:
            ids = list(dict.fromkeys([p.allowed_cite_ids[0], p.allowed_cite_ids[-1]]))
            out.append({"text": " ".join(p.summaries) or f"Stage {p.stage} ({p.status}) ran from {p.start_time} to {p.end_time}.",
                        "cites": ids})
        return out
    p = data.pack(unit)
    ids = list(dict.fromkeys([p.allowed_cite_ids[0], p.allowed_cite_ids[-1]]))
    return [{"text": " ".join(p.summaries) or f"Stage {p.stage} ({p.status}) ran from {p.start_time} to {p.end_time}.",
             "cites": ids}]


def judge_stats(llm_verdicts) -> dict:
    judged = [v for v in llm_verdicts if v.judge]
    double = [v for v in judged if "agreement" in v.judge]
    return {
        "judged_sentences": len(judged),
        "judge_agreement_rate": round(sum(v.judge["agreement"] for v in double) / len(double), 4) if double else None,
        "judge_disagree_count": sum(1 for v in double if not v.judge["agreement"]),
        "judge_error_count": sum(1 for v in judged if v.judge["verdict"] == "judge_error"),
        "judge_quote_invalid_count": sum(1 for v in judged if any(r["code"] == "JUDGE_QUOTE_INVALID" for r in v.failures())),
        "judge_own_vs_derived_disagreements": sum(v.judge.get("own_vs_derived_disagreements", 0) for v in judged)}


def sentence_feedback(failed) -> str:
    """Facts mode: plain-words, sentence-level feedback for ONLY the rejected sentences."""
    lines = [f"\n\nREPAIR: {len(failed)} of your sentences were rejected. Rewrite ONLY the rejected sentences listed below. "
             f"Return exactly {len(failed)} sentence(s), in the same order, one replacement per rejected sentence. Base each "
             f"replacement on the same facts, fix the listed problems, add no new information, and do not repeat any other sentence."]
    for i, slot in enumerate(failed, 1):
        v = slot["verdict"]
        probs = "; ".join(f"{WORDS.get(r['code'], r['code'])} [{r['code']}: {r['detail']}]" for r in v.failures()) or "it was not accepted"
        lines.append(f"Rejected sentence {i} (based on facts: {', '.join(v.fact_ids) or 'none listed'}): "
                     f"\"{v.text_normalized or v.text_original}\"\n   problems: {probs}")
    return "\n".join(lines)


def _units(data):
    return [p.stage for p in data.packs] + [EXEC]


def verify_chain(data: CaseData, narrator, judge, cfg: VerifyConfig, progress=None, run_meta: dict | None = None) -> dict:
    if data.ctxs[EXEC].fact_map is not None:
        return _verify_facts(data, narrator, judge, cfg, progress, run_meta)
    return _verify_raw(data, narrator, judge, cfg, progress, run_meta)


# ======================================================================================================
# raw mode (Phase 5 behaviour)
# ======================================================================================================
def _verify_raw(data: CaseData, narrator, judge, cfg: VerifyConfig, progress, run_meta) -> dict:
    t_all = time.time()
    nar = data.narrative
    units = _units(data)
    verifier = Verifier(data.events, data.host_names, cfg.max_cites)
    use_judge = judge is not None and cfg.use_judge
    narrator_model = getattr(narrator, "model", None) or nar.get("model")
    judge_model = judge.model if use_judge else None
    independent = bool(use_judge and judge_model != narrator_model)
    if use_judge and not independent:
        _say(progress, f"!!! WARNING: judge model == narrator model ({judge_model}); the judge is NOT independent !!!")
    call_log, phases = [], {}
    attempts: dict[str, list[dict]] = {u: [] for u in units}
    info = summary_info(data.packs)

    def new_attempt(unit, n, sentences, parse_ok, feedback=None, raw=None, seconds=0.0, options=None):
        ctx = data.ctxs[unit]
        vs = [verifier.det(ctx, s["text"], s["cites"], i, n, "llm", use_judge) for i, s in enumerate(sentences)]
        return {"attempt": n, "parse_ok": parse_ok, "sentences": sentences, "verdicts": vs, "feedback_used": feedback is not None,
                "feedback": feedback, "raw_output_file": raw, "narrator_seconds": round(seconds, 2), "options": options}

    def judge_round(r: int, fresh: list[str]) -> None:
        t0, n = time.time(), 0
        if use_judge:
            for u in fresh:
                for v in attempts[u][-1]["verdicts"]:
                    if needs_judge(v):
                        call_log.append({"round": r, "kind": "judge", "label": f"{u}#{v.sentence_index}"})
                        verifier.apply_judge(judge, data.ctxs[u], v)
                        n += 1
        phases[f"round{r}_judge"] = round(time.time() - t0, 2)
        acc = sum(v.accepted for u in fresh for v in attempts[u][-1]["verdicts"])
        tot = sum(len(attempts[u][-1]["verdicts"]) for u in fresh)
        _say(progress, f"  round {r} judge: {n} calls, {phases[f'round{r}_judge']:.1f}s; accepted {acc}/{tot} sentences")

    t0 = time.time()
    for u in units:
        if u == EXEC:
            meta = nar.get("executive_summary_meta", {})
            attempts[u].append(new_attempt(u, 0, nar["executive_summary"], meta.get("parse_ok", bool(nar["executive_summary"])),
                                           raw=meta.get("raw_output_file")))
        else:
            st = next(s for s in nar["stages"] if s["stage"] == u)
            attempts[u].append(new_attempt(u, 0, st["sentences"], st["parse_ok"], raw=st.get("raw_output_file")))
    phases["round0_deterministic"] = round(time.time() - t0, 2)
    _say(progress, f"round 0: deterministic layers on {sum(len(attempts[u][0]['verdicts']) for u in units)} sentences "
                   f"({phases['round0_deterministic']:.1f}s)")
    judge_round(0, units)

    done = lambda u: bool(attempts[u][-1]["verdicts"]) and all(v.accepted for v in attempts[u][-1]["verdicts"])
    for r in range(1, cfg.max_retries + 1):
        todo = [u for u in units if not done(u)]
        if not todo:
            break
        opts = repair_options(narrator, cfg, r)
        _say(progress, f"repair round {r} (seed {opts['seed']}, temperature {opts['temperature']}): "
                       f"{len(todo)} unit(s) need repair: {', '.join(todo)}")
        t0 = time.time()
        for u in todo:
            fb = feedback_text(attempts[u][-1]["verdicts"])
            call_log.append({"round": r, "kind": "narrator", "label": u})
            rec = (narrate_summary(narrator, info, fb, options=opts) if u == EXEC
                   else narrate_stage(narrator, data.pack(u), fb, options=opts))
            raw = save_raw(data.out_dir, "chain", narrator_model, f"{u}_repair{r}", rec.transcript)
            attempts[u].append(new_attempt(u, r, rec.parsed["sentences"] if rec.parsed else [], rec.parsed is not None,
                                           fb, raw, rec.seconds, opts))
            _say(progress, f"  narrator {u}: {rec.seconds:.1f}s parse_ok={rec.parsed is not None}")
        phases[f"round{r}_narrator"] = round(time.time() - t0, 2)
        judge_round(r, todo)

    final, fallback_verdicts = {}, []
    for u in units:
        atts = attempts[u]
        best = max(atts, key=lambda a: (sum(v.accepted for v in a["verdicts"]), -a["attempt"]))
        accepted = [v for v in best["verdicts"] if v.accepted]
        fb = not accepted
        for a in atts:
            for v in a["verdicts"]:
                if a is best and v.accepted:
                    v.disposition = "kept"
                elif a is best and fb:
                    v.disposition = "replaced_by_fallback"
                else:
                    v.disposition = "dropped"
        sents = [{"text": v.text_normalized, "cites": v.cites_final, "source": "llm", "attempt": v.attempt} for v in accepted]
        if fb:
            fallback_verdicts += _fallback(data, verifier, u, atts[-1]["attempt"], sents)
        final[u] = {"sentences": sents, "best_attempt": best["attempt"], "attempts_used": len(atts), "fallback": fb,
                    "accepted": len(accepted), "dropped": len(best["verdicts"]) - len(accepted)}
        if fb:
            _say(progress, f"  {u}: no accepted sentence after {len(atts)} attempt(s) -> template fallback")
    att0 = [v for u in units for v in attempts[u][0]["verdicts"]]
    best_vs = []
    for u in units:
        best_vs += next(a for a in attempts[u] if a["attempt"] == final[u]["best_attempt"])["verdicts"]
    llm_verdicts = [v for u in units for a in attempts[u] for v in a["verdicts"]]
    fixed = {}
    for u in units:
        b = final[u]["best_attempt"]
        if b > 0:
            fixed[str(b)] = fixed.get(str(b), 0) + max(0, final[u]["accepted"] - sum(v.accepted for v in attempts[u][0]["verdicts"]))
    failing0 = sum(1 for v in att0 if not v.accepted)
    fixed_total = sum(fixed.values())
    effectiveness = {"basis": "raw mode regenerates whole units: fixed = accepted sentences gained by the winning attempt",
                     "failing_at_attempt0": failing0, "fixed_by_round": fixed, "fixed_total": fixed_total,
                     "still_failing": max(0, failing0 - fixed_total), "per_code": None}
    attempts_report = {u: [{"attempt": a["attempt"], "parse_ok": a["parse_ok"], "feedback_used": a["feedback_used"],
                            "feedback": a["feedback"], "raw_output_file": a["raw_output_file"],
                            "narrator_seconds": a["narrator_seconds"], "options": a["options"]} for a in attempts[u]]
                       for u in units}
    return _finish(data, narrator, judge, cfg, verifier, units, final, att0, best_vs, llm_verdicts, fallback_verdicts,
                   attempts_report, call_log, phases, t_all, use_judge, independent, narrator_model, judge_model, progress,
                   effectiveness, None, run_meta)


def _fallback(data, verifier, unit, last_attempt, sents, source: str = "template_fallback") -> list:
    out = []
    for i, s in enumerate(fallback_sentences(data, unit)):
        ctx = fallback_ctx(data, unit, s["cites"])
        v = verifier.det(ctx, s["text"], s["cites"], i, last_attempt, source, False, s.get("fact_ids"))
        out.append(v)
        if v.accepted:
            d = {"text": v.text_normalized, "cites": v.cites_final, "source": source, "attempt": v.attempt}
            if v.fact_ids:
                d["fact_ids"] = v.fact_ids
            sents.append(d)
    return out


# ======================================================================================================
# facts mode: sentence-level repair, accepted sentences are frozen
# ======================================================================================================
def _verify_facts(data: CaseData, narrator, judge, cfg: VerifyConfig, progress, run_meta) -> dict:
    t_all = time.time()
    nar = data.narrative
    units = _units(data)
    verifier = Verifier(data.events, data.host_names, cfg.max_cites)
    use_judge = judge is not None and cfg.use_judge
    narrator_model = getattr(narrator, "model", None) or nar.get("model")
    judge_model = judge.model if use_judge else None
    independent = bool(use_judge and judge_model != narrator_model)
    if use_judge and not independent:
        _say(progress, f"!!! WARNING: judge model == narrator model ({judge_model}); the judge is NOT independent !!!")
    call_log, phases = [], {}
    stage_narr = {s["stage"]: s for s in nar["stages"]}
    facts_by_stage = {u: stage_narr[u]["facts"] for u in units if u != EXEC}
    info = summary_facts_info(data.chain, facts_by_stage)
    status = {st["stage"]: st["status"] for st in data.chain["stages"]}
    slots: dict[str, list[dict]] = {u: [] for u in units}
    attempts_report: dict[str, list[dict]] = {u: [] for u in units}
    all_verdicts = []  # every LLM verdict of every attempt, in generation order

    def make_slot_verdict(u, i, s, n):
        v = verifier.det(data.ctxs[u], s["text"], s["cites"], i, n, "llm", use_judge, s.get("fact_ids"))
        all_verdicts.append(v)
        return v

    def judge_new(r, fresh: list):
        t0, n = time.time(), 0
        if use_judge:
            for u, v in fresh:
                if needs_judge(v):
                    call_log.append({"round": r, "kind": "judge", "label": f"{u}#{v.sentence_index}"})
                    verifier.apply_judge(judge, data.ctxs[u], v)
                    n += 1
        phases[f"round{r}_judge"] = round(time.time() - t0, 2)
        _say(progress, f"  round {r} judge: {n} sentences ({'2 runs each' if getattr(judge, 'double', False) else '1 run each'}), "
                       f"{phases[f'round{r}_judge']:.1f}s; accepted {sum(v.accepted for _, v in fresh)}/{len(fresh)}")

    t0 = time.time()
    fresh = []
    for u in units:
        if u == EXEC:
            meta = nar.get("executive_summary_meta", {})
            sents, ok, raw = nar["executive_summary"], meta.get("parse_ok", bool(nar["executive_summary"])), meta.get("raw_output_file")
        else:
            st = stage_narr[u]
            sents, ok, raw = st["sentences"], st["parse_ok"], st.get("raw_output_file")
        for i, s in enumerate(sents):
            v = make_slot_verdict(u, i, s, 0)
            slots[u].append({"verdict": v, "first": v, "fixed_round": None})
            fresh.append((u, v))
        attempts_report[u].append({"attempt": 0, "parse_ok": ok, "feedback_used": False, "feedback": None, "raw_output_file": raw,
                                   "narrator_seconds": None, "options": getattr(narrator, "options", None), "sentences": len(sents)})
    phases["round0_deterministic"] = round(time.time() - t0, 2)
    _say(progress, f"round 0: deterministic layers on {len(fresh)} sentences ({phases['round0_deterministic']:.1f}s)")
    judge_new(0, fresh)

    done = lambda u: bool(slots[u]) and all(s["verdict"].accepted for s in slots[u])
    for r in range(1, cfg.max_retries + 1):
        todo = [u for u in units if not done(u)]
        if not todo:
            break
        opts = repair_options(narrator, cfg, r)
        _say(progress, f"repair round {r} (seed {opts['seed']}, temperature {opts['temperature']}): "
                       f"{len(todo)} unit(s) need repair: {', '.join(todo)}")
        t0, fresh, pending = time.time(), [], []
        for u in todo:
            failed = [s for s in slots[u] if not s["verdict"].accepted]
            suffix = (sentence_feedback(failed) if slots[u] else
                      "\n\nREPAIR: your previous answer was unusable (it could not be parsed or contained no sentences). "
                      "Write the prose for all the facts again, following the rules.")
            call_log.append({"round": r, "kind": "narrator", "label": u})
            rec = (narrate_summary_facts(narrator, info, suffix, opts) if u == EXEC
                   else narrate_stage_facts(narrator, u, status[u], facts_by_stage[u], stage_narr[u]["allowed_cite_ids"], suffix, opts))
            raw = save_raw(data.out_dir, "chain", narrator_model, f"{u}_repair{r}", rec.transcript)
            reps = rec.parsed["sentences"] if rec.parsed else []
            attempts_report[u].append({"attempt": r, "parse_ok": rec.parsed is not None, "feedback_used": True, "feedback": suffix,
                                       "raw_output_file": raw, "narrator_seconds": round(rec.seconds, 2), "options": opts,
                                       "sentences": len(reps), "replaced_positions": [s["verdict"].sentence_index for s in failed]})
            _say(progress, f"  narrator {u}: {rec.seconds:.1f}s parse_ok={rec.parsed is not None} ({len(failed)} to rewrite, {len(reps)} returned)")
            if slots[u]:
                for slot, s in zip(failed, reps):
                    nv = make_slot_verdict(u, slot["verdict"].sentence_index, s, r)
                    pending.append((slot, nv, r))
                    fresh.append((u, nv))
            else:  # nothing usable at attempt 0: the repair answer defines the slots
                for i, s in enumerate(reps):
                    nv = make_slot_verdict(u, i, s, r)
                    slots[u].append({"verdict": nv, "first": None, "fixed_round": None})
                    fresh.append((u, nv))
        phases[f"round{r}_narrator"] = round(time.time() - t0, 2)
        judge_new(r, fresh)
        for slot, nv, rr in pending:
            slot["verdict"] = nv  # the latest attempt for this position; accepted ones are frozen
            if nv.accepted:
                slot["fixed_round"] = rr

    # ---- final assembly ----
    final, fallback_verdicts = {}, []
    for u in units:
        kept = [s["verdict"] for s in slots[u] if s["verdict"].accepted]
        fb = not kept
        keep_ids = {id(v) for v in kept}
        for v in all_verdicts:
            if v.stage == u:
                v.disposition = "kept" if id(v) in keep_ids else (
                    "replaced_by_fallback" if fb and any(id(v) == id(s["verdict"]) for s in slots[u]) else "dropped")
        sents = []
        for v in kept:
            sents.append({"text": v.text_normalized, "cites": v.cites_final, "fact_ids": v.fact_ids, "source": "llm", "attempt": v.attempt})
        if fb:
            fallback_verdicts += _fallback(data, verifier, u, max((a["attempt"] for a in attempts_report[u]), default=0), sents)
            _say(progress, f"  {u}: no accepted sentence after {len(attempts_report[u])} attempt(s) -> facts fallback")
        final[u] = {"sentences": sents, "best_attempt": max([s["attempt"] for s in sents if s["source"] == "llm"] or [0]),
                    "attempts_used": len(attempts_report[u]), "fallback": fb, "accepted": len(kept),
                    "dropped": sum(1 for s in slots[u] if not s["verdict"].accepted)}
    att0 = [s["first"] for u in units for s in slots[u] if s["first"] is not None]
    final_vs = [s["verdict"] for u in units for s in slots[u]]

    # ---- repair effectiveness (sentence level) ----
    rounds = sorted({s["fixed_round"] for u in units for s in slots[u] if s["fixed_round"]})
    failing0 = [(u, s) for u in units for s in slots[u] if s["first"] is not None and not s["first"].accepted]
    empty_units = [u for u in units if all(s["first"] is None for s in slots[u]) and slots[u]]
    per_code = {}
    for u, s in failing0:
        for c in set(s["first"].codes()):
            e = per_code.setdefault(c, {"failing_at_attempt0": 0, "still_failing": 0, **{f"fixed_round_{k}": 0 for k in range(1, cfg.max_retries + 1)}})
            e["failing_at_attempt0"] += 1
            if s["fixed_round"]:
                e[f"fixed_round_{s['fixed_round']}"] += 1
            else:
                e["still_failing"] += 1
    fixed_by = {str(k): sum(1 for _, s in failing0 if s["fixed_round"] == k) for k in range(1, cfg.max_retries + 1)}
    effectiveness = {"basis": "facts mode: sentence-level repair; accepted sentences are frozen",
                     "failing_at_attempt0": len(failing0), "fixed_by_round": fixed_by, "fixed_total": sum(fixed_by.values()),
                     "still_failing": sum(1 for _, s in failing0 if not s["fixed_round"]),
                     "units_with_no_usable_attempt0": empty_units, "per_code": dict(sorted(per_code.items()))}
    # ---- fact coverage ----
    expressed = {u: sorted({f for s in final[u]["sentences"] if s["source"] == "llm" for f in s["fact_ids"]}) for u in units if u != EXEC}
    fact_cov = {
        "facts_total": sum(len(f) for f in facts_by_stage.values()),
        "facts_expressed_by_accepted_llm_sentences": sum(len(v) for v in expressed.values()),
        "facts_per_stage": {u: {"total": len(facts_by_stage[u]), "expressed": len(expressed[u])} for u in facts_by_stage},
        "stages_with_accepted_llm_sentence": [u for u in facts_by_stage if any(s["source"] == "llm" for s in final[u]["sentences"])],
        "stages_fallback_only": [u for u in facts_by_stage if final[u]["fallback"]]}
    fact_cov["coverage_rate"] = (round(fact_cov["facts_expressed_by_accepted_llm_sentences"] / fact_cov["facts_total"], 4)
                                 if fact_cov["facts_total"] else None)
    for a in attempts_report.values():
        for x in a:
            x.setdefault("narrator_seconds", None)
    return _finish(data, narrator, judge, cfg, verifier, units, final, att0, final_vs, all_verdicts, fallback_verdicts,
                   attempts_report, call_log, phases, t_all, use_judge, independent, narrator_model, judge_model, progress,
                   effectiveness, fact_cov, run_meta)


# ======================================================================================================
# shared final assembly
# ======================================================================================================
def _finish(data, narrator, judge, cfg, verifier, units, final, att0, best_vs, llm_verdicts, fallback_verdicts, attempts_report,
            call_log, phases, t_all, use_judge, independent, narrator_model, judge_model, progress, effectiveness, fact_cov,
            run_meta) -> dict:
    nar = data.narrative
    template_failures, template_verdicts, sections = [], [], {}
    for u in units:  # a fallback sentence that fails is a bug in the template/facts builder
        for v in fallback_verdicts:
            if v.stage == u and not v.accepted and not any(t["text"] == v.text_original for t in template_failures):
                template_failures.append({"unit": u, "text": v.text_original, "failures": v.failures()})
    for kind in ("attempts_only", "unprovable"):
        sections[kind] = []
        for i, s in enumerate(nar.get(kind, [])):
            ctx = template_ctx(data, kind, i, s["cites"])
            v = verifier.det(ctx, s["text"], s["cites"], i, 0, "template", False)
            template_verdicts.append(v)
            sections[kind].append({"text": v.text_normalized, "cites": v.cites_final, "source": "template", "attempt": 0,
                                   "verified": v.accepted})
            if not v.accepted:
                template_failures.append({"unit": kind, "text": s["text"], "failures": v.failures()})
    for tf in template_failures:
        _say(progress, f"!!! TEMPLATE SENTENCE FAILED VERIFICATION (bug): {tf['unit']}: {tf['text'][:90]} {tf['failures']}")

    by_attempt = Counter(v.attempt for v in llm_verdicts)
    layer_counts = {l: Counter(str(v.layer_results.get(l, {}).get("passed")) for v in llm_verdicts if l in v.layer_results)
                    for l in LAYERS}
    hist = Counter(c for v in llm_verdicts for c in v.codes())
    jv = Counter(v.judge["verdict"] for v in llm_verdicts if v.judge)
    text_final = " ".join(s["text"] for u in units for s in final[u]["sentences"])
    summary = {
        "total_sentences_per_attempt": {str(k): n for k, n in sorted(by_attempt.items())},
        "layer_pass_counts": {l: dict(c) for l, c in layer_counts.items() if c},
        "failure_code_histogram": dict(sorted(hist.items())),
        "judge_verdict_counts": dict(jv),
        "sentences_reaching_judge": sum(1 for v in llm_verdicts if v.judge),
        **judge_stats(llm_verdicts),
        "drops": sum(f["dropped"] for f in final.values()),
        "repair_narrator_calls": sum(1 for c in call_log if c["kind"] == "narrator"),
        "fallbacks": [u for u in units if final[u]["fallback"]],
        "repair": {"temperature": cfg.repair_temperature, "seed_step": cfg.repair_seed_step,
                   "base_seed": getattr(narrator, "options", {}).get("seed", 42), "max_retries": cfg.max_retries,
                   "attempt0_temperature": getattr(narrator, "options", {}).get("temperature", 0)},
        "repair_effectiveness": effectiveness,
        "seconds_per_phase": phases,
        "model_swaps": count_swaps(call_log, not independent) if use_judge else 0,
        "supported_rate": {"before_repair": rates(att0), "after_repair": rates(best_vs)},
        "ablation_attempt0": {"total": len(att0), "deterministic_only_accepted": sum(v.det_passed() for v in att0),
                              "with_judge_accepted": sum(v.accepted for v in att0) if use_judge else None},
        "entity_coverage_final_text": entity_coverage(data.chain, data.findings, data.hosts, text_final),
        "template_failures": template_failures}
    if fact_cov is not None:
        summary["fact_coverage"] = fact_cov
    verification = {
        "mode": "chain", "narration_mode": "facts" if fact_cov is not None else "raw",
        "judge_mode": "with_judge" if use_judge else "deterministic_only (--no-judge)",
        "judge_model": judge_model, "narrator_model": narrator_model, "judge_independent": independent,
        "judge_double": bool(use_judge and getattr(judge, "double", False)),
        "max_retries": cfg.max_retries, "max_cites": cfg.max_cites,
        "per_unit": {u: {k: final[u][k] for k in ("attempts_used", "best_attempt", "accepted", "dropped", "fallback")} for u in units},
        "accepted_total": sum(f["accepted"] for f in final.values()), "dropped_total": summary["drops"],
        "fallback_units": summary["fallbacks"]}
    stage_out = []
    for p in data.packs:
        f = final[p.stage]
        sn = next((s for s in nar["stages"] if s["stage"] == p.stage), {})
        stage_out.append({"stage": p.stage, "status": p.status, "source": "template_fallback" if f["fallback"] else "llm",
                          "sentences": f["sentences"], "attempts_used": f["attempts_used"], "accepted": f["accepted"],
                          "dropped": f["dropped"], "fallback": f["fallback"],
                          "evidence_shown": sn.get("evidence_shown", p.evidence_shown), "evidence_total": p.evidence_total,
                          "allowed_cite_ids": sn.get("allowed_cite_ids", p.allowed_cite_ids),
                          **({"facts": sn["facts"]} if "facts" in sn else {})})
    verified = {
        "case_name": data.name, "mode": "chain", "verified": True, "model": narrator_model,
        "prompt_version": nar.get("prompt_version", P.PROMPT_VERSION), "narration_mode": verification["narration_mode"],
        "ollama_options": getattr(narrator, "options", nar.get("ollama_options")),
        "created_at": now_iso(), "total_seconds": round(time.time() - t_all, 2),
        "executive_summary": final[EXEC]["sentences"],
        "executive_summary_meta": {k: final[EXEC][k] for k in ("attempts_used", "accepted", "dropped", "fallback")},
        "stages": stage_out, "attempts_only": sections["attempts_only"], "unprovable": sections["unprovable"],
        "verification": verification,
        **({"fact_coverage": fact_cov} if fact_cov is not None else {}),
        "run_metadata": run_meta if run_meta is not None else {"collected": False}}
    report = {
        "case_name": data.name, "mode": "chain", "created_at": now_iso(), "total_seconds": verified["total_seconds"],
        "verification": verification, "summary": summary, "call_log": call_log, "attempts": attempts_report,
        "verdicts": [v.to_dict() for v in llm_verdicts + fallback_verdicts + template_verdicts],
        "run_metadata": run_meta if run_meta is not None else {"collected": False}}
    write_json(data.out_dir / "narrative_verified.json", verified)
    write_json(data.out_dir / "verification_report.json", report)
    return {"verified": verified, "report": report}
