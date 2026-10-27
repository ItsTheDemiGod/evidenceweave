import argparse
from collections import Counter
from pathlib import Path

from .config import DATA_DIR, OUTPUT_DIR

PHASES = {"analyze": 4, "evaluate": 6}


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
    for name in PHASES:
        sub.add_parser(name, help=f"{name} (placeholder)")
    args = p.parse_args(argv)
    if hasattr(args, "func"):
        args.func(args)
    else:
        print(f"not implemented yet (Phase {PHASES[args.cmd]})")


if __name__ == "__main__":
    main()
