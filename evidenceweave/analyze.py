"""One-command pipeline (analyze) and the report-only command."""
from __future__ import annotations

import json
import time
import webbrowser
from pathlib import Path

import requests

from .config import OLLAMA_MODEL, OLLAMA_URL
from .narrator.llm import LLMError

NO_LLM_HINT = "To get a deterministic report without any LLM, re-run with --no-llm."


def check_models(models: list[str], url: str = OLLAMA_URL) -> None:
    """Fail early (before minutes of narration) when Ollama is down or a model is missing."""
    try:
        tags = requests.get(f"{url}/api/tags", timeout=5).json()
    except Exception as e:
        raise LLMError(f"Ollama is not reachable at {url} ({type(e).__name__}). Start it with: ollama serve") from e
    have = {m["name"] for m in tags.get("models", [])}
    for m in models:
        if m not in have and f"{m}:latest" not in have:
            raise LLMError(f"Model '{m}' is not installed. Run: ollama pull {m}")


def open_report(path: Path) -> None:
    try:
        webbrowser.open(path.resolve().as_uri())
    except Exception:
        pass  # opening the browser is a convenience, never a failure


def cmd_report(args) -> None:
    from .report import build_report

    case_dir, out = Path(args.case_dir), Path(args.out) / Path(args.case_dir).name
    if not all((out / f).exists() for f in ("chain.json", "findings.json", "events.jsonl")):
        raise SystemExit(f"error: no pipeline outputs in {out}; run analyze (or parse + correlate) first")
    path = build_report(out, case_dir)
    note = "" if (out / "narrative_verified.json").exists() else "  (narrative_verified.json missing: facts only, notice shown)"
    print(f"report -> {path}{note}")
    if not args.no_open:
        open_report(path)


def _step(n: int, total: int, label: str, t0: float, extra: str = "") -> None:
    print(f"[{n}/{total}] {label:<34} {time.time() - t0:7.1f}s {extra}".rstrip())


def _reusable(out: Path, no_llm: bool) -> bool:
    nv, vr, ch = out / "narrative_verified.json", out / "verification_report.json", out / "chain.json"
    if no_llm or not (nv.exists() and vr.exists() and ch.exists()):
        return False
    if min(nv.stat().st_mtime, vr.stat().st_mtime) <= ch.stat().st_mtime:
        return False
    return not json.loads(nv.read_text(encoding="utf-8")).get("verification", {}).get("no_llm")


def cmd_analyze(args) -> None:
    from .cli import _ensure_pipeline
    from .narrator.narrate import NarratorConfig, narrate_chain
    from .parsers.pipeline import load_hosts
    from .report import build_report
    from .verifier import runner
    from .verifier.deterministic import verify_deterministic
    from .verifier.repair import VerifyConfig, verify_chain
    from .verifier.verify import load_case_data

    case_dir = Path(args.case_dir)
    if not case_dir.is_dir():
        raise SystemExit(f"error: case dir not found: {case_dir}")
    out = Path(args.out) / case_dir.name
    hosts = load_hosts(case_dir)
    total = 3 if args.no_llm else 4
    t0 = time.time()
    _ensure_pipeline(args, case_dir, out)
    _step(1, total, "parse + correlate", t0)
    reused = args.reuse and _reusable(out, args.no_llm)
    judge_used, summary = False, {}
    if args.no_llm:
        t0 = time.time()
        res = verify_deterministic(out, hosts, args.max_cites, args.max_facts_per_stage, progress=print)
        _step(2, total, "deterministic facts + verify (no LLM)", t0)
    elif reused:
        print(f"--reuse applied: narrative_verified.json and verification_report.json are newer than chain.json; "
              f"narrate and verify skipped, only the report is rebuilt.")
        res = {"verified": json.loads((out / "narrative_verified.json").read_text(encoding="utf-8")),
               "report": json.loads((out / "verification_report.json").read_text(encoding="utf-8"))}
    else:
        if args.reuse:
            print("--reuse requested but the verified outputs are missing, stale or from --no-llm: running narrate + verify.")
        model = args.model or OLLAMA_MODEL
        try:
            check_models([model, args.judge_model])
            narrator, judge = runner.build_clients(model, args.judge_model, args.num_ctx, False, args.single_judge)
            vcfg = VerifyConfig(args.max_retries, args.max_cites, True, args.repair_temperature)
            ncfg = NarratorConfig(mode=args.narration_mode, max_facts=args.max_facts_per_stage)
            if args.judge_model == model:
                print("!!! WARNING: judge model == narrator model: the judge is NOT independent !!!")
            meta = runner.make_meta(narrator, judge, vcfg, ncfg)
            t0 = time.time()
            narrate_chain(out, narrator, ncfg, progress=print, run_meta=meta)
            _step(2, total, f"narrate ({model}, {ncfg.mode})", t0)
            t0 = time.time()
            res = verify_chain(load_case_data(out, hosts), narrator, judge, vcfg, progress=print, run_meta=meta)
            _step(3, total, f"verify + repair (judge {args.judge_model})", t0)
        except LLMError as e:
            raise SystemExit(f"error: {e}\n{NO_LLM_HINT}")
    t0 = time.time()
    path = build_report(out, case_dir)
    _step(total, total, "report", t0)
    ver = res["verified"]["verification"]
    sm = res["report"].get("summary", {})
    judge_used = ver.get("judge_model") is not None
    print(f"\nreport: {path}\n  mode: {'no-llm (deterministic)' if ver.get('no_llm') else 'llm'}"
          f"{' (reused)' if reused else ''}; judge used: {'yes, ' + str(ver['judge_model']) if judge_used else 'no'}")
    print(f"  sentences accepted={ver['accepted_total']} dropped={ver['dropped_total']} "
          f"fallback units={ver['fallback_units'] or 'none'}"
          + (f"; judge agreement={sm.get('judge_agreement_rate')}" if judge_used else ""))
    print(f"  outputs in {out}")
    if not args.no_open:
        open_report(path)
