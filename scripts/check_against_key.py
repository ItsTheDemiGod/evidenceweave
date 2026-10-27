"""Measure chain.json against answer_key.json. The ONLY non-test code allowed to read the key.

Usage: python scripts/check_against_key.py --case-dir data/cases/case02 [--chain output/case02/chain.json]
A measurement tool, not a test: always exits 0.
"""
import argparse
import json
from pathlib import Path

PREFIX = {"linux_auth.log": "AUTH", "nginx_access.log": "NGX", "windows_events.jsonl": "WIN"}
PREFIX_FILE = {v: k for k, v in PREFIX.items()}


def to_id(ev: dict) -> str:
    return f"{PREFIX[ev['source_file']]}-L{ev['line_number']}"


def raw_line(case_dir: Path, event_id: str) -> str:
    prefix, _, n = event_id.rpartition("-L")
    lines = (case_dir / "logs" / PREFIX_FILE[prefix]).read_text(encoding="utf-8").split("\n")
    return lines[int(n) - 1]


def check(case_dir, chain_path=None) -> dict:
    case_dir = Path(case_dir)
    key = json.loads((case_dir / "answer_key.json").read_text(encoding="utf-8"))
    chain = json.loads(Path(chain_path or Path("output") / case_dir.name / "chain.json").read_text(encoding="utf-8"))
    got = {s["stage"]: set(s["evidence_event_ids"]) for s in chain["stages"]}
    rows, tp_all, fn_all, fp_all = [], 0, 0, 0
    for step in key["steps"]:
        want = {to_id(e) for e in step["evidence"]}
        have = got.get(step["name"], set())
        tp, fn, fp = want & have, want - have, have - want
        tp_all, fn_all, fp_all = tp_all + len(tp), fn_all + len(fn), fp_all + len(fp)
        rows.append({"step": step["step_id"], "name": step["name"], "key": len(want), "chain": len(have),
                     "tp": len(tp), "fn": sorted(fn), "fp": sorted(fp),
                     "precision": len(tp) / len(have) if have else 0.0, "recall": len(tp) / len(want) if want else 1.0})
    chain_ids = set().union(*got.values()) if got else set()
    decoys = key["decoy_ips"]
    decoy_hits = sorted(i for i in chain_ids if any(d in raw_line(case_dir, i) for d in decoys))
    benign = {to_id(b) for b in key["benign_but_suspicious_looking"]}
    missing_expected = [m for s in key["steps"] for m in s["evidence_missing"]]
    persistence = next((s for s in chain["stages"] if s["stage"] == "persistence"), None)
    detected = [u for u in chain["unprovable_items"] if key["created_user"] in u["users"]]
    return {"rows": rows, "tp": tp_all, "fn": fn_all, "fp": fp_all, "decoy_hits": decoy_hits,
            "benign_hits": sorted(chain_ids & benign, key=lambda i: (i[:3], int(i.rpartition("-L")[2]))),
            "missing_expected": bool(missing_expected),
            "persistence_partial": bool(persistence and persistence["status"] == "partial"),
            "missing_detected": bool(detected)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-dir", required=True)
    ap.add_argument("--chain")
    a = ap.parse_args()
    r = check(a.case_dir, a.chain)
    print(f"{'step':4} {'name':21}{'key':>5}{'chain':>6}{'TP':>5}{'FN':>4}{'FP':>5}{'precision':>11}{'recall':>8}")
    for x in r["rows"]:
        print(f"{x['step']:<4} {x['name']:21}{x['key']:>5}{x['chain']:>6}{x['tp']:>5}{len(x['fn']):>4}"
              f"{len(x['fp']):>5}{x['precision']:>11.3f}{x['recall']:>8.3f}")
    tp, fn, fp = r["tp"], r["fn"], r["fp"]
    print(f"{'ALL':4} {'':21}{tp + fn:>5}{tp + fp:>6}{tp:>5}{fn:>4}{fp:>5}"
          f"{(tp / (tp + fp) if tp + fp else 0):>11.3f}{(tp / (tp + fn) if tp + fn else 1):>8.3f}")
    case_dir = Path(a.case_dir)
    for x in r["rows"]:
        for label, ids in (("MISSED (FN)", x["fn"]), ("EXTRA (FP)", x["fp"])):
            for i in ids:
                print(f"  step {x['step']} {label} {i}: {raw_line(case_dir, i)[:110]}")
    print(f"decoy IP evidence in chain stages: {len(r['decoy_hits'])} {r['decoy_hits']}  -> {'OK' if not r['decoy_hits'] else 'FAIL'}")
    print(f"benign-but-suspicious lines in chain: {len(r['benign_hits'])} {r['benign_hits']}  -> {'OK' if not r['benign_hits'] else 'FAIL'}")
    if r["missing_expected"]:
        print(f"key has missing evidence: persistence stage partial={r['persistence_partial']}, "
              f"missing account creation detected={r['missing_detected']}  -> "
              f"{'OK' if r['persistence_partial'] and r['missing_detected'] else 'FAIL'}")
    else:
        print(f"key has no missing evidence: persistence partial={r['persistence_partial']} "
              f"(expected False), spurious unprovable items -> {'OK' if not r['persistence_partial'] else 'FAIL'}")


if __name__ == "__main__":
    main()
