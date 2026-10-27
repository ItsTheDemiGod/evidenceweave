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
    for name in PHASES:
        sub.add_parser(name, help=f"{name} (placeholder)")
    args = p.parse_args(argv)
    if hasattr(args, "func"):
        args.func(args)
    else:
        print(f"not implemented yet (Phase {PHASES[args.cmd]})")


if __name__ == "__main__":
    main()
