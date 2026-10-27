"""Chain verification with batched repair rounds (narrator calls first, then the judge, so models swap rarely)."""
from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass

from ..narrator import prompts as P
from ..narrator.narrate import narrate_stage, narrate_summary, now_iso, save_raw, summary_info, write_json
from .verdicts import LAYERS
from .verify import CaseData, Verifier, entity_coverage, fallback_ctx, feedback_text, needs_judge, rates, template_ctx

EXEC = "executive_summary"


@dataclass
class VerifyConfig:
    max_retries: int = 2
    max_cites: int = 8
    use_judge: bool = True


def _say(cb, msg):
    if cb:
        cb(msg)


def count_swaps(call_log: list[dict], same_model: bool) -> int:
    kinds = [c["kind"] for c in call_log]
    return 0 if same_model else sum(1 for a, b in zip(kinds, kinds[1:]) if a != b)


def fallback_sentences(data: CaseData, unit: str) -> list[dict]:
    """Deterministic template text for a unit whose every LLM sentence was rejected."""
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


def verify_chain(data: CaseData, narrator, judge, cfg: VerifyConfig, progress=None) -> dict:
    t_all = time.time()
    nar = data.narrative
    units = [p.stage for p in data.packs] + [EXEC]
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

    def new_attempt(unit, n, sentences, parse_ok, feedback=None, raw=None, seconds=0.0):
        ctx = data.ctxs[unit]
        vs = [verifier.det(ctx, s["text"], s["cites"], i, n, "llm", use_judge) for i, s in enumerate(sentences)]
        return {"attempt": n, "parse_ok": parse_ok, "sentences": sentences, "verdicts": vs, "feedback_used": feedback is not None,
                "feedback": feedback, "raw_output_file": raw, "narrator_seconds": round(seconds, 2)}

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

    # ---- round 0: the existing narrative is attempt 0 ----
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
        _say(progress, f"repair round {r}: {len(todo)} unit(s) need repair: {', '.join(todo)}")
        t0 = time.time()
        for u in todo:
            fb = feedback_text(attempts[u][-1]["verdicts"])
            call_log.append({"round": r, "kind": "narrator", "label": u})
            rec = narrate_summary(narrator, info, fb) if u == EXEC else narrate_stage(narrator, data.pack(u), fb)
            raw = save_raw(data.out_dir, "chain", narrator_model, f"{u}_repair{r}", rec.transcript)
            attempts[u].append(new_attempt(u, r, rec.parsed["sentences"] if rec.parsed else [], rec.parsed is not None,
                                           fb, raw, rec.seconds))
            _say(progress, f"  narrator {u}: {rec.seconds:.1f}s parse_ok={rec.parsed is not None}")
        phases[f"round{r}_narrator"] = round(time.time() - t0, 2)
        judge_round(r, todo)

    # ---- choose the best attempt per unit; fall back to templates when nothing was accepted ----
    final, fallback_verdicts, template_failures = {}, [], []
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
            for i, s in enumerate(fallback_sentences(data, u)):
                ctx = fallback_ctx(data, u, s["cites"])
                v = verifier.det(ctx, s["text"], s["cites"], i, atts[-1]["attempt"], "template_fallback", False)
                fallback_verdicts.append(v)
                if v.accepted:
                    sents.append({"text": v.text_normalized, "cites": v.cites_final, "source": "template_fallback",
                                  "attempt": v.attempt})
                else:
                    template_failures.append({"unit": u, "text": v.text_original, "failures": v.failures()})
        final[u] = {"sentences": sents, "best_attempt": best["attempt"], "attempts_used": len(atts), "fallback": fb,
                    "accepted": len(accepted), "dropped": len(best["verdicts"]) - len(accepted)}
        if fb:
            _say(progress, f"  {u}: no accepted sentence after {len(atts)} attempt(s) -> template fallback")

    # ---- template sections: layers 1 and 2 only ----
    template_verdicts, sections = [], {}
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

    # ---- summaries ----
    llm_verdicts = [v for u in units for a in attempts[u] for v in a["verdicts"]]
    att0 = [v for u in units for v in attempts[u][0]["verdicts"]]
    best_vs = []
    for u in units:
        b = next(a for a in attempts[u] if a["attempt"] == final[u]["best_attempt"])
        best_vs += b["verdicts"]
    by_attempt = Counter(v.attempt for v in llm_verdicts)
    layer_counts = {l: Counter(str(v.layer_results.get(l, {}).get("passed")) for v in llm_verdicts) for l in LAYERS}
    hist = Counter(c for v in llm_verdicts for c in v.codes())
    jv = Counter(v.judge["verdict"] for v in llm_verdicts if v.judge)
    text_final = " ".join(s["text"] for u in units for s in final[u]["sentences"])
    summary = {
        "total_sentences_per_attempt": {str(k): n for k, n in sorted(by_attempt.items())},
        "layer_pass_counts": {l: dict(c) for l, c in layer_counts.items()},
        "failure_code_histogram": dict(sorted(hist.items())),
        "judge_verdict_counts": dict(jv),
        "sentences_reaching_judge": sum(1 for v in llm_verdicts if v.judge),
        "drops": sum(f["dropped"] for f in final.values()),
        "repair_narrator_calls": sum(1 for c in call_log if c["kind"] == "narrator"),
        "fallbacks": [u for u in units if final[u]["fallback"]],
        "seconds_per_phase": phases,
        "model_swaps": count_swaps(call_log, not independent) if use_judge else 0,
        "supported_rate": {"before_repair": rates(att0), "after_repair": rates(best_vs)},
        "ablation_attempt0": {"total": len(att0), "deterministic_only_accepted": sum(v.det_passed() for v in att0),
                              "with_judge_accepted": sum(v.accepted for v in att0) if use_judge else None},
        "entity_coverage_final_text": entity_coverage(data.chain, data.findings, data.hosts, text_final),
        "template_failures": template_failures}
    verification = {
        "mode": "chain", "judge_mode": "with_judge" if use_judge else "deterministic_only (--no-judge)",
        "judge_model": judge_model, "narrator_model": narrator_model, "judge_independent": independent,
        "max_retries": cfg.max_retries, "max_cites": cfg.max_cites,
        "per_unit": {u: {k: final[u][k] for k in ("attempts_used", "best_attempt", "accepted", "dropped", "fallback")} for u in units},
        "accepted_total": sum(f["accepted"] for f in final.values()), "dropped_total": summary["drops"],
        "fallback_units": summary["fallbacks"]}
    stage_out = []
    for p in data.packs:
        f = final[p.stage]
        stage_out.append({"stage": p.stage, "status": p.status, "source": "template_fallback" if f["fallback"] else "llm",
                          "sentences": f["sentences"], "attempts_used": f["attempts_used"], "accepted": f["accepted"],
                          "dropped": f["dropped"], "fallback": f["fallback"], "evidence_shown": p.evidence_shown,
                          "evidence_total": p.evidence_total, "allowed_cite_ids": p.allowed_cite_ids})
    verified = {
        "case_name": data.name, "mode": "chain", "verified": True, "model": narrator_model,
        "prompt_version": P.PROMPT_VERSION, "ollama_options": getattr(narrator, "options", nar.get("ollama_options")),
        "created_at": now_iso(), "total_seconds": round(time.time() - t_all, 2),
        "executive_summary": final[EXEC]["sentences"],
        "executive_summary_meta": {k: final[EXEC][k] for k in ("attempts_used", "accepted", "dropped", "fallback")},
        "stages": stage_out, "attempts_only": sections["attempts_only"], "unprovable": sections["unprovable"],
        "verification": verification}
    report = {
        "case_name": data.name, "mode": "chain", "created_at": now_iso(), "total_seconds": verified["total_seconds"],
        "verification": verification, "summary": summary, "call_log": call_log,
        "attempts": {u: [{"attempt": a["attempt"], "parse_ok": a["parse_ok"], "feedback_used": a["feedback_used"],
                          "feedback": a["feedback"], "raw_output_file": a["raw_output_file"],
                          "narrator_seconds": a["narrator_seconds"]} for a in attempts[u]] for u in units},
        "verdicts": [v.to_dict() for v in llm_verdicts + fallback_verdicts + template_verdicts]}
    write_json(data.out_dir / "narrative_verified.json", verified)
    write_json(data.out_dir / "verification_report.json", report)
    return {"verified": verified, "report": report}
