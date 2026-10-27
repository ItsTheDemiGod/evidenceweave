import argparse
import dataclasses
import os
from collections import Counter
from pathlib import Path

from .config import DATA_DIR, OUTPUT_DIR

PHASES = {"analyze": 4, "evaluate": 6}
OVERRIDES = {"cross_host_tolerance_seconds": ["--tolerance-seconds"]}  # extra CLI spellings


def cmd_generate(args) -> None:
    from .generator.core import generate

    r = generate(args.case, args.difficulty, args.seed, Path(args.out))
    print(f"case {args.case} ({args.difficulty}, seed {args.seed}) -> {r['path']}")
    for src, n in r["counts"].items():
        print(f"  {src}: {n} lines")
    print(f"  attack evidence lines: {r['evidence']}  (missing from logs: {r['missing']})")


def clock_offset(s: str) -> tuple[str, int]:
    host, sep, secs = s.partition("=")
    try:
        if not (sep and host.strip()):
            raise ValueError
        return host.strip(), int(secs)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"bad --clock-offset {s!r}: expected HOST=SECONDS, e.g. ws-fin01=+90") from None


def cmd_parse(args) -> None:
    from .parsers.pipeline import parse_case, write_events

    case_dir = Path(args.case_dir)
    if not case_dir.is_dir():
        raise SystemExit(f"error: case dir not found: {case_dir}")
    try:
        case = parse_case(case_dir, args.year, dict(args.clock_offset or []))
    except ValueError as e:
        raise SystemExit(f"error: {e}")
    out = Path(args.out) / case.name / "events.jsonl"
    write_events(case, out)
    print(f"case {case.name} -> {out}  ({len(case.events)} events)")
    for s, st in case.stats.items():
        print(f"  {s:8} lines={st['lines']} events={st['events']} unparsed={st['unparsed']} blank={st['blank']}")
    if case.events:
        ts = [e.timestamp for e in case.events]
        print(f"  time range: {min(ts):%Y-%m-%dT%H:%M:%S}Z .. {max(ts):%Y-%m-%dT%H:%M:%S}Z")
    if case.clock_offsets:
        fixed = Counter(e.host for e in case.events if e.clock_corrected)
        for h, off in case.clock_offsets.items():
            print(f"  clock offset applied: {h}={off:+d}s (corrected = raw - {off}s), {fixed[h]} events corrected")
    else:
        print("  clock offsets: none (timestamp == raw_timestamp)")
    print("  actions:")
    for a, n in sorted(Counter(e.action for e in case.events).items()):
        print(f"    {a:24}{n}")


def cmd_correlate(args) -> None:
    from .correlation.config import CorrelationConfig
    from .correlation.engine import correlate_case, write_outputs

    case_dir = Path(args.case_dir)
    if not case_dir.is_dir():
        raise SystemExit(f"error: case dir not found: {case_dir}")
    cfg = CorrelationConfig(**{k: v for k, v in vars(args).items()
                               if k in CorrelationConfig.__dataclass_fields__ and v is not None})
    try:
        case, findings, chain = correlate_case(case_dir, cfg, args.year, dict(args.clock_offset or []))
    except ValueError as e:
        raise SystemExit(f"error: {e}")
    out = write_outputs(case.name, findings, chain, args.out)
    st = chain["stats"]
    print(f"case {case.name} -> {out}{os.sep}{{findings,chain}}.json")
    print(f"  events read={st['events_read']}  unparsed skipped={st['unparsed_skipped']}  "
          f"clock offsets={chain['applied_clock_offsets'] or 'none'}")
    print("  findings per rule: " + ", ".join(f"{k}={v}" for k, v in st["findings_per_rule"].items()))
    ae = chain["attacker_entities"]
    print(f"  attacker: ips={ae['ips']} users={ae['users']} associated_users={ae['associated_users']} hosts={ae['hosts']}")
    print("  chain:")
    for s in chain["stages"]:
        print(f"    {s['stage']:21}{s['status']:10}{s['start_time']} .. {s['end_time']}  "
              f"evidence={len(s['evidence_event_ids']):3}  findings={','.join(s['finding_ids'])}")
    for a in chain["attempts_only_actors"]:
        print(f"  attempts-only actor {a['ip']}: {a['stages']} ({len(a['evidence_event_ids'])} events) - no successful access")
    for u in chain["unprovable_items"]:
        print(f"  unprovable: {u['finding_id']} (affects {u['affects_stage']}): {u['summary']}")
    for u in chain["unlinked_findings"]:
        print(f"  unlinked: {u['finding_id']} ({u['stage']}): {u['reason']}")
    for n in chain["notes"]:
        print(f"  note: {n}")


def _ensure_pipeline(args, case_dir: Path, out: Path) -> None:
    """Run parse + correlate when chain/findings/events are missing (or offsets/tolerance/year were given)."""
    from .correlation.config import CorrelationConfig
    from .correlation.engine import correlate_case, write_outputs
    from .parsers.pipeline import write_events

    flags = args.clock_offset or args.tolerance_seconds is not None or args.year is not None
    if flags or not all((out / f).exists() for f in ("chain.json", "findings.json", "events.jsonl")):
        cfg = CorrelationConfig(**({"cross_host_tolerance_seconds": args.tolerance_seconds}
                                   if args.tolerance_seconds is not None else {}))
        try:
            case, findings, chain = correlate_case(case_dir, cfg, args.year, dict(args.clock_offset or []))
        except ValueError as e:
            raise SystemExit(f"error: {e}")
        write_outputs(case.name, findings, chain, args.out)
        write_events(case, out / "events.jsonl")
        print(f"parsed + correlated {case.name} -> {out}")


def cmd_narrate(args) -> None:
    from .config import OLLAMA_MODEL
    from .correlation.config import CorrelationConfig
    from .correlation.engine import correlate_case, write_outputs
    from .narrator.baseline import run_baseline
    from .narrator.llm import LLMError, OllamaClient
    from .narrator.narrate import NarratorConfig, narrate_chain
    from .parsers.pipeline import write_events

    case_dir = Path(args.case_dir)
    if not case_dir.is_dir():
        raise SystemExit(f"error: case dir not found: {case_dir}")
    out = Path(args.out) / case_dir.name
    _ensure_pipeline(args, case_dir, out)
    client = OllamaClient(args.model or OLLAMA_MODEL, num_ctx=args.num_ctx)
    ncfg = NarratorConfig(args.max_evidence_per_stage, chunk_size=args.chunk_size)
    results = []
    try:
        if args.mode in ("chain", "both"):
            print(f"chain narrator ({client.model}):")
            r = narrate_chain(out, client, ncfg, progress=print)
            results.append(("chain", r, out / "narrative.json"))
        if args.mode in ("baseline", "both"):
            print(f"baseline ({client.model}, chunk_size={args.chunk_size}):")
            r = run_baseline(out, client, ncfg, progress=print)
            results.append(("baseline", r, out / "baseline_narrative.json"))
    except (LLMError, ValueError) as e:
        raise SystemExit(f"error: {e}")
    print(f"json mode used: {client.json_mode}   options: {client.options}")
    for mode, r, path in results:
        st = r["stats"]
        print(f"  {mode}: calls={st['calls']} failed_parses={st['failed_parses']} retries={st['retries']} "
              f"tokens={st['total_tokens']} seconds={r['total_seconds']} -> {path}")


def cmd_verify(args) -> None:
    import json

    from .config import OLLAMA_MODEL
    from .narrator.baseline import run_baseline
    from .narrator.llm import LLMError, OllamaClient
    from .narrator.narrate import NarratorConfig, narrate_chain
    from .parsers.pipeline import load_hosts
    from .verifier.baseline_verify import verify_baseline
    from .verifier.corruption import run_corruption
    from .verifier.judge import VERDICT_SCHEMA, Judge, parse_verdict
    from .verifier.repair import VerifyConfig, verify_chain
    from .verifier.verify import load_case_data

    case_dir = Path(args.case_dir)
    if not case_dir.is_dir():
        raise SystemExit(f"error: case dir not found: {case_dir}")
    out = Path(args.out) / case_dir.name
    _ensure_pipeline(args, case_dir, out)
    hosts = load_hosts(case_dir)
    npath = out / "narrative.json"
    recorded = json.loads(npath.read_text(encoding="utf-8")) if npath.exists() else None
    model = args.model or (recorded or {}).get("model") or OLLAMA_MODEL
    narrator = OllamaClient(model, num_ctx=args.num_ctx)
    judge = None if args.no_judge else Judge(OllamaClient(
        args.judge_model, num_ctx=8192, schema=VERDICT_SCHEMA, validator=parse_verdict))
    vcfg = VerifyConfig(args.max_retries, args.max_cites, not args.no_judge)
    ncfg = NarratorConfig(args.max_evidence_per_stage)
    print(f"verify mode={args.mode} narrator={model} judge={'(none: deterministic only)' if judge is None else args.judge_model}")
    if judge is not None and args.judge_model == model:
        print("!!! WARNING: judge model == narrator model: the judge is NOT independent !!!")
    try:
        if recorded is None or not all("allowed_cite_ids" in s for s in recorded["stages"]) or recorded["model"] != model:
            print(f"narrating first ({model}):")
            narrate_chain(out, narrator, ncfg, progress=print)
        if args.mode in ("chain", "all") or not (out / "narrative_verified.json").exists() and args.mode == "corruption":
            data = load_case_data(out, hosts)
            print("chain verification:")
            r = verify_chain(data, narrator, judge, vcfg, progress=print)
            sm, ver = r["report"]["summary"], r["verified"]["verification"]
            sr = sm["supported_rate"]
            print(f"  accepted={ver['accepted_total']} dropped={ver['dropped_total']} fallbacks={sm['fallbacks'] or 'none'} "
                  f"repair narrator calls={sm['repair_narrator_calls']} model swaps={sm['model_swaps']}")
            print(f"  supported-rate before repair {sr['before_repair']['accepted']}/{sr['before_repair']['total']}="
                  f"{sr['before_repair']['rate']}  after repair {sr['after_repair']['accepted']}/{sr['after_repair']['total']}="
                  f"{sr['after_repair']['rate']}  (judge mode: {ver['judge_mode']})")
            print(f"  failure codes: {sm['failure_code_histogram']}")
            print(f"  seconds per phase: {sm['seconds_per_phase']}  total={r['report']['total_seconds']}")
            print(f"  -> {out / 'narrative_verified.json'}\n  -> {out / 'verification_report.json'}")
        if args.mode in ("baseline", "all"):
            if not (out / "baseline_narrative.json").exists():
                print(f"baseline narrative missing: running the baseline narrator (num_ctx={args.num_ctx})")
                run_baseline(out, narrator, NarratorConfig(args.max_evidence_per_stage, chunk_size=args.chunk_size), progress=print)
            data = load_case_data(out, hosts)
            print("baseline verification:")
            b = verify_baseline(data, judge, args.max_cites, progress=print)
            cov = b["entity_coverage"]
            print(f"  supported-rate {b['rates']['accepted']}/{b['rates']['total']}={b['rates']['rate']}  "
                  f"excluding cap-only failures {b['rates']['rate_excluding_cap_only']}  codes={b['failure_code_histogram']}")
            print(f"  entity coverage: baseline {cov['baseline']['present']}/{cov['baseline']['total']}"
                  + (f"  chain {cov['chain']['present']}/{cov['chain']['total']}" if 'chain' in cov else ""))
            print(f"  -> {out / 'baseline_verification.json'}")
        if args.mode in ("corruption", "all"):
            data = load_case_data(out, hosts)
            verified = json.loads((out / "narrative_verified.json").read_text(encoding="utf-8"))
            print("corruption test:")
            c = run_corruption(data, verified, judge, args.max_cites, progress=print)
            for t, p in c["per_type"].items():
                print(f"  {t:28} injected={p['injected']:2} det={p['caught_deterministic']:2} judge={p['caught_judge_only']:2} "
                      f"missed={p['missed']:2} rate={p['catch_rate']}")
            o, ctl = c["overall"], c["control"]
            print(f"  overall catch rate {o['caught']}/{o['injected']}={o['catch_rate']}; false rejection "
                  f"{ctl['rejected']}/{ctl['count']}={ctl['false_rejection_rate']}  -> {out / 'corruption_report.json'}")
    except (LLMError, ValueError) as e:
        raise SystemExit(f"error: {e}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="evidenceweave", description="Log-correlation agent")
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate", help="generate a synthetic log case + answer key")
    g.add_argument("--case", required=True)
    g.add_argument("--difficulty", choices=["easy", "hard"], default="easy")
    g.add_argument("--seed", type=int, default=42)
    g.add_argument("--out", default=str(DATA_DIR / "cases"))
    g.set_defaults(func=cmd_generate)
    q = sub.add_parser("parse", help="parse a case's logs into normalized events.jsonl")
    q.add_argument("--case-dir", required=True)
    q.add_argument("--clock-offset", type=clock_offset, action="append", metavar="HOST=SECONDS",
                   help="host clock is this many seconds AHEAD of true time (repeatable)")
    q.add_argument("--year", type=int, help="syslog year (default: manifest assumed_syslog_year)")
    q.add_argument("--out", default=str(OUTPUT_DIR))
    q.set_defaults(func=cmd_parse)
    c = sub.add_parser("correlate", help="run correlation rules + attack chain builder on a case")
    c.add_argument("--case-dir", required=True)
    c.add_argument("--clock-offset", type=clock_offset, action="append", metavar="HOST=SECONDS",
                   help="host clock is this many seconds AHEAD of true time (repeatable)")
    c.add_argument("--year", type=int)
    c.add_argument("--out", default=str(OUTPUT_DIR))
    from .correlation.config import CorrelationConfig
    for f in dataclasses.fields(CorrelationConfig):
        if type(f.default) in (int, float):
            c.add_argument(*OVERRIDES.get(f.name, []), "--" + f.name.replace("_", "-"), dest=f.name,
                           type=type(f.default), default=None, help=f"default {f.default}")
    c.set_defaults(func=cmd_correlate)
    n = sub.add_parser("narrate", help="LLM narrative of the chain (and/or the naive baseline) via local Ollama")
    n.add_argument("--case-dir", required=True)
    n.add_argument("--mode", choices=["chain", "baseline", "both"], default="chain")
    n.add_argument("--model", help="default: env EVIDENCEWEAVE_MODEL or qwen2.5:7b-instruct")
    n.add_argument("--max-evidence-per-stage", type=int, default=12)
    n.add_argument("--chunk-size", type=int, default=120)
    n.add_argument("--num-ctx", type=int, default=8192)
    n.add_argument("--clock-offset", type=clock_offset, action="append", metavar="HOST=SECONDS")
    n.add_argument("--tolerance-seconds", type=int)
    n.add_argument("--year", type=int)
    n.add_argument("--out", default=str(OUTPUT_DIR))
    n.set_defaults(func=cmd_narrate)
    v = sub.add_parser("verify", help="verify the narrative's citations/claims, repair, baseline check, corruption test")
    v.add_argument("--case-dir", required=True)
    v.add_argument("--mode", choices=["chain", "baseline", "corruption", "all"], default="chain")
    v.add_argument("--model", help="narrator model (default: the model recorded in narrative.json)")
    v.add_argument("--judge-model", default="llama3.1:8b")
    v.add_argument("--max-retries", type=int, default=2)
    v.add_argument("--max-cites", type=int, default=8)
    v.add_argument("--no-judge", action="store_true", help="deterministic layers only (ablation)")
    v.add_argument("--num-ctx", type=int, default=16384)
    v.add_argument("--max-evidence-per-stage", type=int, default=12)
    v.add_argument("--chunk-size", type=int, default=120)
    v.add_argument("--clock-offset", type=clock_offset, action="append", metavar="HOST=SECONDS")
    v.add_argument("--tolerance-seconds", type=int)
    v.add_argument("--year", type=int)
    v.add_argument("--out", default=str(OUTPUT_DIR))
    v.set_defaults(func=cmd_verify)
    for name in PHASES:
        sub.add_parser(name, help=f"{name} (placeholder)")
    args = p.parse_args(argv)
    if hasattr(args, "func"):
        args.func(args)
    else:
        print(f"not implemented yet (Phase {PHASES[args.cmd]})")


if __name__ == "__main__":
    main()
