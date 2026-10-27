"""Verify the naive baseline's sentences with the same layers and judge. Verdicts only: no repair, no dropping."""
from __future__ import annotations

import json
import time
from collections import Counter

from ..narrator.narrate import now_iso, write_json
from .entities import Facts
from .verdicts import LAYERS
from .verify import CaseData, UnitCtx, Verifier, entity_coverage, needs_judge, rates


def verify_baseline(data: CaseData, judge, max_cites: int = 8, progress=None) -> dict:
    t0 = time.time()
    bl = json.loads((data.out_dir / "baseline_narrative.json").read_text(encoding="utf-8"))
    use_judge = judge is not None
    ctx = UnitCtx("baseline", "baseline", None, Facts())  # cites need only exist; pool = cited events only
    verifier = Verifier(data.events, data.host_names, max_cites)
    vs = [verifier.det(ctx, s["text"], s["cites"], i, 0, "llm", use_judge) for i, s in enumerate(bl["sentences"])]
    n = 0
    if use_judge:
        for v in vs:
            if needs_judge(v):
                verifier.apply_judge(judge, ctx, v)
                n += 1
    if progress:
        progress(f"  baseline: {len(vs)} sentences, {n} reached the judge, {time.time() - t0:.1f}s")
    text = " ".join(v.text_normalized for v in vs)
    cov_b = entity_coverage(data.chain, data.findings, data.hosts, text)
    out = {
        "case_name": data.name, "mode": "baseline", "created_at": now_iso(), "total_seconds": round(time.time() - t0, 2),
        "judge_mode": "with_judge" if use_judge else "deterministic_only (--no-judge)",
        "judge_model": judge.model if use_judge else None, "max_cites": max_cites,
        "narrator_model": bl["model"], "rates": rates(vs),
        "failure_code_histogram": dict(sorted(Counter(c for v in vs for c in v.codes()).items())),
        "layer_pass_counts": {l: dict(Counter(str(v.layer_results.get(l, {}).get("passed")) for v in vs)) for l in LAYERS},
        "judge_verdict_counts": dict(Counter(v.judge["verdict"] for v in vs if v.judge)),
        "sentences_reaching_judge": n, "entity_coverage": {"baseline": cov_b},
        "verdicts": [v.to_dict() for v in vs]}
    vpath = data.out_dir / "narrative_verified.json"
    rpath = data.out_dir / "verification_report.json"
    if vpath.exists() and rpath.exists():  # the same two numbers + coverage for the chain narrator
        nv = json.loads(vpath.read_text(encoding="utf-8"))
        rep = json.loads(rpath.read_text(encoding="utf-8"))["summary"]
        ctext = " ".join(s["text"] for s in nv["executive_summary"] + [x for st in nv["stages"] for x in st["sentences"]])
        out["entity_coverage"]["chain"] = entity_coverage(data.chain, data.findings, data.hosts, ctext)
        out["comparison"] = {"chain_attempt0": rep["supported_rate"]["before_repair"],
                             "chain_final": rep["supported_rate"]["after_repair"], "baseline": out["rates"]}
    write_json(data.out_dir / "baseline_verification.json", out)
    return out
