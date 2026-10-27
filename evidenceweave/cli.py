import argparse
from pathlib import Path

from .config import DATA_DIR

PHASES = {"analyze": 4, "evaluate": 6}


def cmd_generate(args) -> None:
    from .generator.core import generate

    r = generate(args.case, args.difficulty, args.seed, Path(args.out))
    print(f"case {args.case} ({args.difficulty}, seed {args.seed}) -> {r['path']}")
    for src, n in r["counts"].items():
        print(f"  {src}: {n} lines")
    print(f"  attack evidence lines: {r['evidence']}  (missing from logs: {r['missing']})")


def main(argv=None):
    p = argparse.ArgumentParser(prog="evidenceweave", description="Log-correlation agent")
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate", help="generate a synthetic log case + answer key")
    g.add_argument("--case", required=True)
    g.add_argument("--difficulty", choices=["easy", "hard"], default="easy")
    g.add_argument("--seed", type=int, default=42)
    g.add_argument("--out", default=str(DATA_DIR / "cases"))
    g.set_defaults(func=cmd_generate)
    for name in PHASES:
        sub.add_parser(name, help=f"{name} (placeholder)")
    args = p.parse_args(argv)
    if args.cmd == "generate":
        args.func(args)
    else:
        print(f"not implemented yet (Phase {PHASES[args.cmd]})")


if __name__ == "__main__":
    main()
