"""Score the human labels of the blind audit against the hidden key (single labeller).

Usage: python scripts/audit_score.py --labels eval/audit/audit_items.csv [--key eval/audit/audit_key.csv] [--out eval/audit/audit_scores.json]
"""
import argparse
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from stats import rate  # noqa: E402

MIN_LABELLED = 0.8


def read(p):
    with open(p, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def score(items, key):
    kmap = {k["item_id"]: k for k in key}
    lab = {}
    for r in items:
        l = (r.get("label") or "").strip().upper()
        if l in ("S", "P", "U"):
            lab[r["item_id"]] = l
    completeness = len(lab) / len(items) if items else 0.0
    if completeness < MIN_LABELLED:
        return {"refused": True, "labelling_completeness": completeness,
                "reason": f"only {len(lab)}/{len(items)} items labelled ({completeness:.0%}); need >= {MIN_LABELLED:.0%}"}
    conf = {a: {"S": 0, "P": 0, "U": 0} for a in ("accepted", "rejected")}
    for iid, l in lab.items():
        conf["accepted" if kmap[iid]["accepted"] == "true" else "rejected"][l] += 1
    acc, rej = conf["accepted"], conf["rejected"]
    n_acc, n_rej = sum(acc.values()), sum(rej.values())
    text = {r["item_id"]: r["sentence"] for r in items}
    return {
        "refused": False, "single_labeller": True,
        "note": "SINGLE LABELLER: no inter-annotator agreement was measured; treat as indicative.",
        "items_total": len(items), "items_labelled": len(lab), "labelling_completeness": round(completeness, 4),
        "confusion_matrix": conf,
        "precision_accepted_S": rate(acc["S"], n_acc), "precision_accepted_S_or_P": rate(acc["S"] + acc["P"], n_acc),
        "false_rejection_rate": rate(rej["S"], n_rej),
        "false_rejections": [{"item_id": i, "case": kmap[i]["case"], "failure_codes": kmap[i]["failure_codes"], "sentence": text[i]}
                             for i, l in lab.items() if kmap[i]["accepted"] == "false" and l == "S"],
        "verifier_misses": [{"item_id": i, "label": l, "case": kmap[i]["case"], "stage": kmap[i]["stage"], "sentence": text[i]}
                            for i, l in lab.items() if kmap[i]["accepted"] == "true" and l in ("P", "U")]}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", required=True)
    ap.add_argument("--key")
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    lp = Path(a.labels)
    res = score(read(lp), read(a.key or lp.parent / "audit_key.csv"))
    if res["refused"]:
        print("REFUSED:", res["reason"])
        raise SystemExit(2)
    out = Path(a.out or lp.parent / "audit_scores.json")
    out.write_text(json.dumps(res, indent=2), encoding="utf-8")
    print("SINGLE LABELLER - indicative only")
    for k in ("items_labelled", "confusion_matrix", "precision_accepted_S", "precision_accepted_S_or_P", "false_rejection_rate"):
        print(f"{k}: {res[k]}")
    print(f"{len(res['verifier_misses'])} accepted sentences labelled P/U; {len(res['false_rejections'])} rejected labelled S -> {out}")


if __name__ == "__main__":
    main()
