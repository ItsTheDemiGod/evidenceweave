"""Phase 5b: print the comparison / narrative / corruption tables from the saved output files (read-only)."""
import json
import sys
from pathlib import Path

OUT = Path("output")
CASES = ("case01", "case02")
CHAIN_METRICS = ["attempt0_supported_rate", "final_accepted_sentences", "fact_coverage", "fallback_units",
                 "sentences_fixed_by_repair", "judge_agreement_rate", "judge_error_count", "total_seconds"]


def load(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def fmt(x):
    return "-" if x is None else (f"{x:.3f}" if isinstance(x, float) else str(x))


def comparison():
    print("\n## raw (1 run) vs facts (mean [min, max] over 3 runs)")
    for c in CASES:
        d = OUT / c
        if not (d / "repeat_summary.json").exists():
            continue
        facts = load(d / "repeat_summary.json").get("chain")
        raw = None
        if (d / "verification_report.json").exists() and load(d / "narrative_verified.json").get("narration_mode") == "raw":
            sys.path.insert(0, ".")
            from evidenceweave.verifier.runner import chain_metrics
            raw = chain_metrics(d)
        print(f"\n### {c}   (facts runs: {facts['runs'] if facts else 0})")
        print(f"| metric | raw (1 run) | facts mean | facts min | facts max | facts per-run |\n|---|---|---|---|---|---|")
        for m in CHAIN_METRICS:
            f = facts["metrics"][m] if facts else {"mean": None, "min": None, "max": None, "values": []}
            print(f"| {m} | {fmt(raw[m]) if raw else '-'} | {fmt(f['mean'])} | {fmt(f['min'])} | {fmt(f['max'])} | {f['values']} |")


def narrative(case, run="runs/chain_run1"):
    d = OUT / case / run
    if not (d / "narrative_verified.json").exists():
        return
    v, r = load(d / "narrative_verified.json"), load(d / "verification_report.json")
    print(f"\n## FINAL verified narrative: {case} ({run})")
    print("Executive summary:")
    for s in v["executive_summary"]:
        print(f"  - [{s['source']}/a{s['attempt']}] {s['text']}  {s['cites']}")
    for st in v["stages"]:
        print(f"[{st['stage']}] {st['status']} source={st['source']} accepted={st['accepted']} dropped={st['dropped']}")
        for s in st["sentences"]:
            print(f"    - [{s['source']}/a{s['attempt']}] {s['text']}  {s['cites']}")
    print("Template sections:", [(s["text"][:90], s["verified"]) for s in v["attempts_only"] + v["unprovable"]])
    print(f"\nDropped / rejected LLM sentences ({case}, {run}):")
    for x in r["verdicts"]:
        if x["source"] == "llm" and not x["accepted"] and x["disposition"] in ("dropped", "replaced_by_fallback"):
            fl = [f"{q['code']}: {q['detail'][:70]}" for lr in x["layer_results"].values() for q in lr["reasons"] if q["code"] != "NORMALIZED"]
            j = x["judge"] and f"judge={x['judge']['verdict']}: {x['judge']['reason'][:90]}"
            print(f"  a{x['attempt']} {x['stage']}#{x['sentence_index']} {x['text_original'][:110]!r}\n      {fl} {j or ''}")
    s = r["summary"]
    print("\nrepair effectiveness:", json.dumps(s["repair_effectiveness"]))
    print("failure codes:", s["failure_code_histogram"], "| judge:", {k: s[k] for k in s if k.startswith("judge_")})


def corruption():
    print("\n## corruption results (mean [min, max] over runs)")
    for c in CASES:
        p = OUT / c / "repeat_summary.json"
        if not p.exists() or "corruption" not in load(p):
            continue
        s = load(p)["corruption"]
        m = s["metrics"]
        print(f"\n### {c}  runs={s['runs']}  base sentences per run={m['base_sentences']['values']}  injected={m['injected']['values']}")
        print(f"overall catch rate: values={m['overall_catch_rate']['values']} mean={fmt(m['overall_catch_rate']['mean'])} "
              f"min={fmt(m['overall_catch_rate']['min'])} max={fmt(m['overall_catch_rate']['max'])}")
        print(f"false-rejection on controls: values={m['false_rejection_rate']['values']}")
        reps = [load(Path(d) / "corruption_report.json") for d in s["run_dirs"]]
        print("| type | injected (per run) | det (per run) | judge-only (per run) | missed (per run) | catch rate mean [min,max] |\n|---|---|---|---|---|---|")
        for t in reps[0]["per_type"]:
            g = lambda k: [r["per_type"][t][k] for r in reps]
            cr = m["catch_rate_per_type"][t]
            print(f"| {t} | {g('injected')} | {g('caught_deterministic')} | {g('caught_judge_only')} | {g('missed')} | "
                  f"{fmt(cr['mean'])} [{fmt(cr['min'])}, {fmt(cr['max'])}] |")
        for i, r in enumerate(reps, 1):
            for x in r["missed"]:
                print(f"  MISSED run{i} {x['type']} ({x['unit']}):\n      original : {x['original_text'][:140]}\n      corrupted: ...{x['corrupted_text'][-110:]}")
            for x in r["control"]["rejected_sentences"]:
                print(f"  CONTROL REJECTED run{i} {x['unit']}: {x['text'][:100]!r} codes={x['codes']}")


def bugfix_examples():
    print("\n## bug-fix evidence in live output")
    found = {"closing_quote": [], "dangling": []}
    for p in list(OUT.glob("case0*/runs/*/verification_report.json")) + list(OUT.glob("case0*/verification_report.json")):
        for x in load(p)["verdicts"]:
            notes = [q["detail"] for lr in x["layer_results"].values() for q in lr["reasons"] if q["code"] == "NORMALIZED"]
            if any("dangling" in n for n in notes) and len(found["dangling"]) < 2:
                found["dangling"].append((p.parent.name, x["text_original"][-110:], x["text_normalized"][-110:]))
            o, n = x["text_original"], x["text_normalized"]
            if o != n and ("`" in n or "'" in n) and n.rstrip(".").endswith(("`", "'")) and len(found["closing_quote"]) < 2:
                found["closing_quote"].append((p.parent.name, o[-100:], n[-100:]))
    for k, v in found.items():
        print(k, "->", v or "no occurrence in these runs")


if __name__ == "__main__":
    comparison()
    for c in CASES:
        narrative(c)
    corruption()
    bugfix_examples()
