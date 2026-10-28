"""Orchestration for the verify command: clients, narrate-if-needed, chain / corruption passes and --repeat."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from .. import runmeta
from ..narrator import llm as llm_mod
from ..narrator import prompts as P
from ..narrator.narrate import NarratorConfig, narrate_chain, write_json
from .corruption import run_corruption
from .judge import CLAIMS_SCHEMA, JUDGE_PROMPT_VERSION, ClaimJudge, parse_claims
from .repair import VerifyConfig, repair_options, verify_chain
from .verify import load_case_data

COPY = ("chain.json", "findings.json", "events.jsonl", "pipeline_meta.json")


def build_clients(narrator_model: str, judge_model: str, num_ctx: int, no_judge: bool, single_judge: bool):
    """The OllamaClient is looked up at call time (tests replace it with fakes)."""
    narrator = llm_mod.OllamaClient(narrator_model, num_ctx=num_ctx)
    judge = None
    if not no_judge:
        jc = llm_mod.OllamaClient(judge_model, num_ctx=8192, schema=CLAIMS_SCHEMA, validator=parse_claims, timeout=300)
        jc.options["num_predict"] = 900  # bound runaway generation: a judge call normally takes ~10-20 s
        judge = ClaimJudge(jc, double=not single_judge)
    return narrator, judge


def make_meta(narrator, judge, vcfg: VerifyConfig, ncfg: NarratorConfig) -> dict:
    jopts = dict(getattr(judge.client, "options", {})) if judge is not None else None
    options = {"narrator_attempt0": dict(narrator.options),
               "repair": {**narrator.options, **repair_options(narrator, vcfg, 1), "seed_rule": f"base seed + round * {vcfg.repair_seed_step}"},
               "judge_run1": jopts, "judge_run2": ({**jopts, "seed": judge.second_seed} if judge is not None and judge.double else None)}
    models = [narrator.model] + ([judge.model] if judge is not None else [])
    versions = {"narrator": P.PROMPT_VERSION_FACTS if ncfg.mode == "facts" else P.PROMPT_VERSION,
                "judge": JUDGE_PROMPT_VERSION if judge is not None and not isinstance(judge, type(None)) else None}
    return runmeta.collect(models, options, versions, ncfg.mode, vcfg.max_cites, ncfg.max_facts if ncfg.mode == "facts" else None)


def narrative_is_stale(rec: dict | None, model: str, ncfg: NarratorConfig, out: Path | None = None) -> bool:
    """A narrative is reused only if model, mode and (facts mode) the facts it was written from are all current."""
    if (rec is None or not all("allowed_cite_ids" in s for s in rec["stages"]) or rec["model"] != model
            or rec.get("narration_mode", "raw") != ncfg.mode
            or (ncfg.mode == "facts" and rec.get("max_facts_per_stage") != ncfg.max_facts)):
        return True
    if ncfg.mode == "facts" and out is not None:  # the facts builder may have changed since the narrative was written
        from ..narrator.facts import build_facts
        from ..narrator.packs import load_events
        chain, events = _load(Path(out) / "chain.json"), load_events(Path(out) / "events.jsonl")
        now = build_facts(chain, _load(Path(out) / "findings.json")["findings"], events, ncfg.max_facts)
        return {s["stage"]: s.get("facts") for s in rec["stages"]} != now
    return False


def run_chain(out: Path, hosts, narrator, judge, vcfg, ncfg, progress=None, meta=None, force_narrate=False) -> dict:
    npath = Path(out) / "narrative.json"
    rec = json.loads(npath.read_text(encoding="utf-8")) if npath.exists() else None
    if force_narrate or narrative_is_stale(rec, narrator.model, ncfg, out):
        if progress:
            progress(f"narrating first ({narrator.model}, {ncfg.mode} mode):")
        narrate_chain(out, narrator, ncfg, progress=progress, run_meta=meta)
    data = load_case_data(out, hosts)
    return verify_chain(data, narrator, judge, vcfg, progress=progress, run_meta=meta)


# ---------------- metrics: always computed from the run's OWN files ----------------
def _load(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def chain_metrics(run_dir: Path) -> dict:
    rep, nar = _load(run_dir / "verification_report.json"), _load(run_dir / "narrative.json")
    s = rep["summary"]
    return {"attempt0_supported_rate": s["supported_rate"]["before_repair"]["rate"],
            "final_accepted_sentences": rep["verification"]["accepted_total"],
            "fact_coverage": (s.get("fact_coverage") or {}).get("coverage_rate"),
            "fallback_units": len(s["fallbacks"]),
            "sentences_fixed_by_repair": s["repair_effectiveness"]["fixed_total"],
            "judge_agreement_rate": s["judge_agreement_rate"],
            "judge_error_count": s["judge_error_count"],
            "total_seconds": round(nar["total_seconds"] + rep["total_seconds"], 2)}


def corruption_metrics(run_dir: Path) -> dict:
    c = _load(run_dir / "corruption_report.json")
    return {"overall_catch_rate": c["overall"]["catch_rate"], "injected": c["overall"]["injected"],
            "base_sentences": c["base_sentences"],
            "false_rejection_rate": c["control"]["false_rejection_rate"],
            "catch_rate_per_type": {t: p["catch_rate"] for t, p in c["per_type"].items()}}


def summarize(values: list) -> dict:
    nums = [v for v in values if v is not None]
    return {"values": values, "mean": round(sum(nums) / len(nums), 4) if nums else None,
            "min": min(nums) if nums else None, "max": max(nums) if nums else None}


def summarize_runs(per_run: list[dict]) -> dict:
    out = {}
    for k in per_run[0]:
        if isinstance(per_run[0][k], dict):  # catch_rate_per_type
            out[k] = {t: summarize([r[k][t] for r in per_run]) for t in per_run[0][k]}
        else:
            out[k] = summarize([r[k] for r in per_run])
    return out


def repeat(case_out: Path, hosts, mode: str, n: int, narrator, judge, vcfg, ncfg, progress=None, meta=None) -> dict:
    """n complete, independent passes (re-narrate attempt 0, repair, verify[, corruption]) under runs/<mode>_run<k>/."""
    case_out, per_run, dirs = Path(case_out), [], []
    for k in range(1, n + 1):
        rd = case_out / "runs" / f"{mode}_run{k}"
        if rd.exists():
            shutil.rmtree(rd)
        rd.mkdir(parents=True)
        for f in COPY:
            if (case_out / f).exists():
                shutil.copy2(case_out / f, rd / f)
        if progress:
            progress(f"=== {mode} run {k}/{n} -> {rd}")
        res = run_chain(rd, hosts, narrator, judge, vcfg, ncfg, progress, meta, force_narrate=True)
        if mode == "corruption":
            run_corruption(load_case_data(rd, hosts), res["verified"], judge, vcfg.max_cites, progress=progress, run_meta=meta)
            per_run.append(corruption_metrics(rd))
        else:
            per_run.append(chain_metrics(rd))
        dirs.append(str(rd))
    sp = case_out / "repeat_summary.json"
    doc = _load(sp) if sp.exists() else {}
    doc.update({"case_name": case_out.name, mode: {"runs": n, "narration_mode": ncfg.mode, "run_dirs": dirs,
                                                    "per_run": per_run, "metrics": summarize_runs(per_run)}})
    write_json(sp, doc)
    return doc[mode]
