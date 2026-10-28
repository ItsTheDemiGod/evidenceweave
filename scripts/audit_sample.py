"""Blind manual-audit kit: sample 32 sentences from the default-pairing runs (seed 42, deterministic).

Usage: python scripts/audit_sample.py [--cases eval_e1 eval_e2 eval_h1 eval_h2] [--output output] [--out eval/audit]
The CSV given to the labeller carries nothing about acceptance, stage, source, failure codes or judge output.
"""
import argparse
import csv
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

CASES = ["eval_e1", "eval_e2", "eval_h1", "eval_h2"]
N_ACC, N_REJ, MAX_SHOWN = 6, 2, 12
ITEM_COLS = ["item_id", "case", "sentence", "cited_events", "label", "notes"]
KEY_COLS = ["item_id", "case", "stage", "accepted", "source", "attempt", "failure_codes", "judge_verdicts", "hidden_marker"]


def codes(v):
    return sorted({r["code"] for lr in v["layer_results"].values() for r in lr.get("reasons", []) if r.get("code")})


def judge_verdicts(v):
    j = v.get("judge")
    if not j:
        return ""
    return ";".join([str(j.get("verdict"))] + [f"{r.get('seed')}:{r.get('derived')}" for r in j.get("runs", [])])


def spread(items, k):
    if len(items) <= k:
        return list(items)
    return [items[round(i * (len(items) - 1) / (k - 1))] for i in range(k)]


def pick_round_robin(verdicts, n, rng):
    """n verdicts spread over units (stage / executive summary): shuffle inside each unit, then take in turn."""
    by = {}
    for v in verdicts:
        by.setdefault(v["stage"], []).append(v)
    units = sorted(by)
    rng.shuffle(units)
    for u in units:
        rng.shuffle(by[u])
    out = []
    while len(out) < n and any(by.values()):
        for u in units:
            if by[u] and len(out) < n:
                out.append(by[u].pop())
    return out


def render_cites(events, ids):
    from evidenceweave.schema import format_ts
    known = [i for i in ids if i in events]
    shown = spread(sorted(known, key=lambda i: (events[i].timestamp, i)), MAX_SHOWN)
    text = " || ".join(f"{i} | {format_ts(events[i].timestamp)} | {events[i].raw_text}" for i in shown)
    if len(known) > len(shown):
        text += f" || (+{len(known) - len(shown)} more cited events not shown)"
    return text


def sample(output_dir, cases=CASES, seed=42):
    from evidenceweave.narrator.packs import load_events
    rng = random.Random(f"audit/{seed}")
    acc_pool, rej_pool, events = {}, {}, {}
    for c in cases:
        d = Path(output_dir) / c
        events[c] = load_events(d / "events.jsonl")
        vs = json.loads((d / "verification_report.json").read_text(encoding="utf-8"))["verdicts"]
        acc_pool[c] = [v for v in vs if v["accepted"] and v["source"] == "llm" and v["disposition"] == "kept"]
        rej_pool[c] = [v for v in vs if not v["accepted"]]
    picked = []  # (case, verdict, kind)
    for c in cases:
        picked += [(c, v, "ACCEPTED_LLM") for v in pick_round_robin(acc_pool[c], N_ACC, rng)]
    chosen = {c: pick_round_robin(rej_pool[c], N_REJ, rng) for c in cases}
    spare = [(c, v) for c in cases for v in rej_pool[c] if all(v is not u for u in chosen[c])]
    rng.shuffle(spare)
    missing = N_REJ * len(cases) - sum(len(x) for x in chosen.values())
    for c, v in spare[:max(0, missing)]:  # a case with too few rejected sentences is topped up from the others
        chosen[c].append(v)
    for c in cases:
        picked += [(c, v, "REJECTED") for v in chosen[c]]
    rng.shuffle(picked)
    items, keys = [], []
    for n, (c, v, kind) in enumerate(picked, 1):
        iid = f"A{n:03d}"
        items.append({"item_id": iid, "case": c, "sentence": v["text_normalized"],
                      "cited_events": render_cites(events[c], v["cites_final"]), "label": "", "notes": ""})
        keys.append({"item_id": iid, "case": c, "stage": v["stage"], "accepted": str(bool(v["accepted"])).lower(),
                     "source": v["source"], "attempt": v["attempt"], "failure_codes": ";".join(codes(v)),
                     "judge_verdicts": judge_verdicts(v), "hidden_marker": kind})
    return items, keys


README = """# Blind manual audit

You are labelling {n} sentences from the EvidenceWeave evaluation. This is a single-labeller audit.

1. **Do NOT open `audit_key.csv` before you have finished labelling.** It reveals which sentences the verifier accepted.
2. Open `audit_items.csv` (Excel works; it is UTF-8 with BOM). Each row has a sentence and the log lines it cites.
3. Fill the `label` column with one of:
   - **S** - every factual claim in the sentence is shown by the listed log lines.
   - **P** - some claims are shown and some are not, or the sentence goes beyond the lines.
   - **U** - the claim is not shown, or it is contradicted, by the listed lines.
4. Judge ONLY by the listed log lines, not by outside knowledge. Ignore writing style.
5. Use `notes` freely. Save as CSV (keep the same file name and columns).
6. Score with: `python scripts/audit_score.py --labels eval/audit/audit_items.csv`
"""


def write(items, keys, out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    for name, cols, rows in (("audit_items.csv", ITEM_COLS, items), ("audit_key.csv", KEY_COLS, keys)):
        with open(out / name, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            w.writerows(rows)
    (out / "README.md").write_text(README.format(n=len(items)), encoding="utf-8")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", nargs="+", default=CASES)
    ap.add_argument("--output", default=str(ROOT / "output"))
    ap.add_argument("--out", default=str(ROOT / "eval" / "audit"))
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args(argv)
    items, keys = sample(a.output, a.cases, a.seed)
    write(items, keys, a.out)
    print(f"wrote {len(items)} items to {a.out}")


if __name__ == "__main__":
    main()
