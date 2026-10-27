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
    for name in PHASES:
        sub.add_parser(name, help=f"{name} (placeholder)")
    args = p.parse_args(argv)
    if hasattr(args, "func"):
        args.func(args)
    else:
        print(f"not implemented yet (Phase {PHASES[args.cmd]})")


if __name__ == "__main__":
    main()
