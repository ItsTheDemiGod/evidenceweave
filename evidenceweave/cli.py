import argparse

PHASES = {"generate": 1, "analyze": 4, "evaluate": 6}


def main(argv=None):
    p = argparse.ArgumentParser(prog="evidenceweave", description="Log-correlation agent")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in PHASES:
        sub.add_parser(name, help=f"{name} (placeholder)")
    args = p.parse_args(argv)
    print(f"not implemented yet (Phase {PHASES[args.cmd]})")


if __name__ == "__main__":
    main()
