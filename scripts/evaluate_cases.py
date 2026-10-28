"""Phase 6b evaluation harness. The ONLY evaluation code (besides check_against_key.py, tests) allowed to read answer_key.json.

Usage:
  python scripts/evaluate_cases.py [--resume] [--stages detect,facts,...] [--skip raw,swap]
Stages in order: detect facts audit baseline corruption raw swap aggregate.
Each finished (stage, case) is written to eval/results.json immediately; --resume skips finished entries.
The harness itself never calls an LLM (it launches `python -m evidenceweave.cli ...` subprocesses).
"""
import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))

from stats import rate  # noqa: E402

CASES = {"eval_e1": ("easy", 101), "eval_e2": ("easy", 102), "eval_h1": ("hard", 201), "eval_h2": ("hard", 202)}
STAGES = ["detect", "facts", "audit", "baseline", "corruption", "raw", "swap", "aggregate"]
CORRUPTION_CASES = ["eval_e1", "eval_h1"]
RAW_CASES = ["eval_e1", "eval_h1"]
SWAP_CASES = ["eval_e2", "eval_h2"]
NARRATOR, JUDGE = "qwen2.5:7b-instruct", "llama3.1:8b"
NUM_CTX, MAX_CITES, CAP = 16384, 8, 60
PREFIX = {"linux_auth.log": "AUTH", "nginx_access.log": "NGX", "windows_events.jsonl": "WIN"}
ARMS = ["facts", "baseline", "raw", "swap"]


# ------------------------------------------------------------------ pure metric helpers
def key_ids(ev_list):
    return {f"{PREFIX[e['source_file']]}-L{e['line_number']}" for e in ev_list}


def covered_steps(sentences, steps, max_cites=None):
    """Steps (1..6) with at least one sentence citing one of their key IDs; strict = at most max_cites cites."""
    out = set()
    for s in sentences:
        c = s.get("cites") or []
        if max_cites is not None and len(c) > max_cites:
            continue
        out |= {sid for sid, ids in steps.items() if ids & set(c)}
    return out


def host_of_url(u):
    m = re.match(r"^[a-z][a-z0-9+.-]*://([^/:?#]+)", u, re.I)
    return m.group(1) if m else None


def entity_set(key, chain):
    ae = chain.get("attacker_entities", {})
    ents = {key["attacker_ip"], key["compromised_user"]}
    ents |= set(ae.get("ips", [])) | set(ae.get("users", [])) | set(ae.get("hosts", []))
    ents |= {h for h in map(host_of_url, ae.get("urls", [])) if h}
    return ents


def token_present(token, text):
    """Exact, case-sensitive token match; dotted tokens (IPs) need non-digit/dot-digit boundaries."""
    return re.search(rf"(?<![\w.]){re.escape(token)}(?![\w]|\.\d)", text) is not None


def entity_coverage(entities, text):
    hit = sorted(e for e in entities if token_present(e, text))
    return {"covered": len(hit), "total": len(entities), "covered_list": hit, "missing": sorted(set(entities) - set(hit))}


def decoy_mentions(decoys, sentences):
    return [{"decoy": d, "sentence": s["text"]} for s in sentences for d in decoys if token_present(d, s["text"])]


def false_alarms(sentences, benign, max_cites=MAX_CITES):
    return sum(1 for s in sentences if len(s.get("cites") or []) <= max_cites and benign & set(s.get("cites") or []))


def chain_sentences(nv):
    """(llm, fallback_and_template) sentences of a narrative_verified.json."""
    llm, other = [], []
    secs = [nv.get("executive_summary", [])] + [st["sentences"] for st in nv["stages"]]
    for sec in secs:
        for s in sec:
            (llm if s.get("source") == "llm" else other).append(s)
    for name in ("attempts_only", "unprovable"):
        other += [s for s in nv.get(name, []) if isinstance(s, dict) and "text" in s]
    return llm, other


# ------------------------------------------------------------------ io helpers
def load(p):
    p = Path(p)
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def save_results(path, results):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    tmp = Path(str(path) + ".tmp")
    tmp.write_text(json.dumps(results, indent=2), encoding="utf-8")
    tmp.replace(path)


def run_cmd(args, log):
    """Run `python -m evidenceweave.cli <args>`, stream to a log file, return (returncode, seconds)."""
    Path(log).parent.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    with open(log, "w", encoding="utf-8") as f:
        f.write("$ " + " ".join(map(str, args)) + "\n")
        f.flush()
        rc = subprocess.call([sys.executable, "-u", "-m", "evidenceweave.cli", *map(str, args)], cwd=ROOT, stdout=f,
                             stderr=subprocess.STDOUT)
    return rc, round(time.time() - t0, 1)


class StageError(RuntimeError):
    pass


def must(rc_sec, what):
    if rc_sec[0] != 0:
        raise StageError(f"{what} failed (exit {rc_sec[0]}); see its log under eval/logs/")
    return rc_sec[1]


# ------------------------------------------------------------------ stages
def paths(o):
    return {"data": Path(o.data_dir), "facts": Path(o.output), "raw": Path(o.output_raw), "swap": Path(o.output_swap),
            "baseline": Path(o.output), "logs": Path(o.eval_dir) / "logs"}


def common(o, case, out, model=NARRATOR, judge=JUDGE):
    return ["--case-dir", Path(o.data_dir) / case, "--model", model, "--num-ctx", NUM_CTX, "--out", out]


def stage_detect(o, case, res):
    import check_against_key as K
    p = paths(o)
    cdir = p["data"] / case
    diff, seed = CASES[case]
    t = 0.0
    if not cdir.exists():
        t += must(run_cmd(["generate", "--case", case, "--difficulty", diff, "--seed", seed, "--out", p["data"]], p["logs"] / f"detect_gen_{case}.log"), "generate")
    t += must(run_cmd(["correlate", "--case-dir", cdir, "--out", p["facts"]], p["logs"] / f"detect_{case}.log"), "correlate")
    r = K.check(cdir, p["facts"] / case / "chain.json")
    return {"seconds": t, "check": r}


def verify_args(o, case, out, mode, narration="facts", model=NARRATOR, judge=JUDGE, extra=()):
    return ["verify", "--case-dir", Path(o.data_dir) / case, "--mode", mode, "--narration-mode", narration, "--model", model,
            "--judge-model", judge, "--max-retries", 2, "--max-cites", MAX_CITES, "--num-ctx", NUM_CTX, "--out", out, *extra]


def stage_facts(o, case, res):
    p = paths(o)
    return {"seconds": must(run_cmd(verify_args(o, case, p["facts"], "chain"), p["logs"] / f"facts_{case}.log"), "verify facts")}


def stage_audit(o, case, res):
    import audit_sample
    items, keys = audit_sample.sample(paths(o)["facts"], list(CASES))
    audit_sample.write(items, keys, Path(o.eval_dir) / "audit")
    d = Path(o.eval_dir) / "audit"
    print("\n" + "=" * 78 + f"\nAUDIT KIT READY - you can start labelling now:\n  {d / 'audit_items.csv'}\n  {d / 'README.md'}\n"
          f"Do NOT open {d / 'audit_key.csv'} before labelling.\n" + "=" * 78 + "\n", flush=True)
    return {"items": len(items), "dir": str(d)}


def stage_baseline(o, case, res):
    p = paths(o)
    t = must(run_cmd(["narrate", "--case-dir", Path(o.data_dir) / case, "--mode", "baseline", "--model", NARRATOR,
                      "--chunk-size", 120, "--num-ctx", NUM_CTX, "--out", p["baseline"]], p["logs"] / f"baseline_narrate_{case}.log"), "narrate baseline")
    t += must(run_cmd(verify_args(o, case, p["baseline"], "baseline", extra=["--chunk-size", 120]), p["logs"] / f"baseline_verify_{case}.log"), "verify baseline")
    return {"seconds": t}


def stage_corruption(o, case, res):
    p = paths(o)
    return {"seconds": must(run_cmd(verify_args(o, case, p["facts"], "corruption", extra=["--pool", "heldout", "--corruption-cap", CAP]),
                                    p["logs"] / f"corruption_{case}.log"), "verify corruption")}


def stage_raw(o, case, res):
    p = paths(o)
    return {"seconds": must(run_cmd(verify_args(o, case, p["raw"], "chain", narration="raw"), p["logs"] / f"raw_{case}.log"), "verify raw")}


def stage_swap(o, case, res):
    p = paths(o)
    return {"seconds": must(run_cmd(verify_args(o, case, p["swap"], "chain", model=JUDGE, judge=NARRATOR), p["logs"] / f"swap_{case}.log"), "verify swap")}


STAGE_CASES = {"detect": list(CASES), "facts": list(CASES), "audit": ["_all"], "baseline": list(CASES),
               "corruption": CORRUPTION_CASES, "raw": RAW_CASES, "swap": SWAP_CASES, "aggregate": ["_all"]}


# ------------------------------------------------------------------ aggregation (reads files only)
def read_key(o, case):
    return load(Path(o.data_dir) / case / "answer_key.json")


def verification_numbers(out_dir):
    nv, rep, nar = (load(out_dir / f) for f in ("narrative_verified.json", "verification_report.json", "narrative.json"))
    if not (nv and rep and nar):
        return None
    s, v = rep["summary"], nv["verification"]
    eff = s.get("repair_effectiveness") or {}
    fb = eff.get("fixed_by_round") or {}
    return {"accepted": v["accepted_total"], "dropped": v["dropped_total"], "fallback_units": v["fallback_units"],
            "attempt0_supported_rate": s["supported_rate"]["before_repair"]["rate"],
            "final_supported_rate": s["supported_rate"]["after_repair"]["rate"],
            "judge_agreement_rate": s.get("judge_agreement_rate"), "judge_error_count": s.get("judge_error_count"),
            "repair_failing_at_attempt0": eff.get("failing_at_attempt0"), "fixed_round_1": fb.get("1"), "fixed_round_2": fb.get("2"),
            "narrator_model": v.get("narrator_model"), "judge_model": v.get("judge_model"),
            "judge_independent": v.get("judge_independent"), "judge_double": v.get("judge_double"),
            "narration_mode": v.get("narration_mode"), "no_llm": bool(v.get("no_llm")),
            "narrate_seconds": nar.get("total_seconds"), "verify_seconds": rep.get("total_seconds"),
            "total_seconds": round((nar.get("total_seconds") or 0) + (rep.get("total_seconds") or 0), 1),
            "tokens": (nar.get("stats") or {}).get("total_tokens"),
            "narrator_calls": (nar.get("stats") or {}).get("calls", 0) + s.get("repair_narrator_calls", 0),
            "judged_sentences": s.get("judged_sentences")}


def coverage_block(sent_strict_sets, steps, decoys, benign, entities):
    """sent_strict_sets: dict name -> list of sentences. Returns coverage / entity / alarm numbers per named set."""
    out = {}
    for name, sents in sent_strict_sets.items():
        text = " ".join(s["text"] for s in sents)
        strict, loose = covered_steps(sents, steps, MAX_CITES), covered_steps(sents, steps)
        out[name] = {"sentences": len(sents), "steps_covered_strict": sorted(strict), "steps_covered_loose": sorted(loose),
                     "coverage_strict": round(len(strict) / len(steps), 4), "coverage_loose": round(len(loose) / len(steps), 4),
                     "entities": entity_coverage(entities, text), "decoy_mentions": decoy_mentions(decoys, sents),
                     "false_alarms": false_alarms(sents, benign), "sentences_over_cap": sum(1 for s in sents if len(s.get("cites") or []) > MAX_CITES)}
    return out


def arm_metrics(o, arm, case):
    p = paths(o)
    key = read_key(o, case)
    chain = load(p["facts"] / case / "chain.json")
    if key is None or chain is None:
        return {"status": "not run"}
    steps = {s["step_id"]: key_ids(s["evidence"]) for s in key["steps"]}
    benign = key_ids(key["benign_but_suspicious_looking"])
    decoys, ents = key["decoy_ips"], entity_set(key, chain)
    if arm == "baseline":
        d = p["baseline"] / case
        bn, bv = load(d / "baseline_narrative.json"), load(d / "baseline_verification.json")
        if not (bn and bv):
            return {"status": "not run"}
        written = [{"text": s["text"], "cites": s.get("cites", [])} for s in bn["sentences"]]
        ver = [{"text": v["text_normalized"], "cites": v["cites_final"]} for v in bv["verdicts"] if v["accepted"]]
        m = coverage_block({"as_written": written, "verified_subset": ver}, steps, decoys, benign, ents)
        rates = bv["rates"]
        stats = bn.get("stats", {})
        return {"status": "ok", "coverage": m,
                "verification": {"accepted": rates["accepted"], "total": rates["total"], "supported_rate": rates["rate"],
                                 "supported_rate_excluding_cap_only": rates["rate_excluding_cap_only"],
                                 "judge_verdict_counts": bv.get("judge_verdict_counts"), "judge_model": bv.get("judge_model"),
                                 "narrator_model": bv.get("narrator_model")},
                "efficiency": {"narrate_seconds": bn.get("total_seconds"), "verify_seconds": bv.get("total_seconds"),
                               "total_seconds": round((bn.get("total_seconds") or 0) + (bv.get("total_seconds") or 0), 1),
                               "tokens": stats.get("total_tokens"), "llm_calls": stats.get("calls"),
                               "chunks": bn.get("number_of_chunks"), "failed_parses": stats.get("failed_parses")}}
    d = p[arm] / case
    nv = load(d / "narrative_verified.json")
    vn = verification_numbers(d)
    if nv is None or vn is None:
        return {"status": "not run"}
    llm, other = chain_sentences(nv)
    m = coverage_block({"llm": llm, "llm_plus_fallback_and_template": llm + other}, steps, decoys, benign, ents)
    return {"status": "ok", "coverage": m, "verification": vn,
            "efficiency": {k: vn[k] for k in ("narrate_seconds", "verify_seconds", "total_seconds", "tokens", "narrator_calls")}}


def detection_tables(results):
    per, tp = {}, {"tp": 0, "fn": 0, "fp": 0}
    steps = {}
    for case, e in (results["stages"].get("detect") or {}).items():
        r = e["check"]
        per[case] = {"rows": r["rows"], "tp": r["tp"], "fn": r["fn"], "fp": r["fp"], "decoy_hits": r["decoy_hits"],
                     "benign_hits": r["benign_hits"], "missing_expected": r["missing_expected"], "missing_detected": r["missing_detected"],
                     "persistence_partial": r["persistence_partial"]}
        for k in tp:
            tp[k] += r[k]
        for row in r["rows"]:
            s = steps.setdefault(row["step"], {"name": row["name"], "tp": 0, "fn": 0, "fp": 0})
            s["tp"] += row["tp"]
            s["fn"] += len(row["fn"])
            s["fp"] += len(row["fp"])
    for s in steps.values():
        s["recall"] = s["tp"] / (s["tp"] + s["fn"]) if s["tp"] + s["fn"] else None
        s["precision"] = s["tp"] / (s["tp"] + s["fp"]) if s["tp"] + s["fp"] else None
    pooled = {**tp, "recall": tp["tp"] / (tp["tp"] + tp["fn"]) if tp["tp"] + tp["fn"] else None,
              "precision": tp["tp"] / (tp["tp"] + tp["fp"]) if tp["tp"] + tp["fp"] else None, "per_step": steps}
    return {"per_case": per, "pooled": pooled}


def corruption_tables(o):
    p = paths(o)
    types, kinds, missed = {}, {}, []
    ctl_n = ctl_rej = 0
    ran = []
    for case in CORRUPTION_CASES:
        r = load(p["facts"] / case / "corruption_report.json")
        if not r or r.get("pool", {}).get("name") != "heldout":
            continue
        ran.append(case)
        for t, x in r["per_type"].items():
            a = types.setdefault(t, {"injected": 0, "deterministic": 0, "judge_only": 0, "judge_error": 0, "missed": 0})
            a["injected"] += x["injected"]
            a["deterministic"] += x["caught_deterministic"]
            a["judge_only"] += x["caught_judge_only"]
            a["judge_error"] += x["caught_judge_error"]
            a["missed"] += x["missed"]
        for sm in r["samples"]:
            if sm["type"] == "fabricated_entity":
                k = kinds.setdefault(sm.get("entity_kind"), {"injected": 0, "caught": 0})
                k["injected"] += 1
                k["caught"] += 1 if sm["rejected"] else 0
        missed += [{"case": case, **m} for m in r["missed"]]
        ctl_n += r["control"]["count"]
        ctl_rej += r["control"]["rejected"]
        pool = r["pool"]
    if not ran:
        return {"status": "not run"}
    for a in types.values():
        caught = a["injected"] - a["missed"]
        a["caught"] = caught
        a["catch"] = rate(caught, a["injected"])
    for k in kinds.values():
        k["catch"] = rate(k["caught"], k["injected"])
    inj = sum(a["injected"] for a in types.values())
    miss = sum(a["missed"] for a in types.values())
    return {"status": "ok", "cases": ran, "pool": pool, "per_type": types, "fabricated_entity_by_kind": kinds,
            "overall": {"injected": inj, "det": sum(a["deterministic"] for a in types.values()),
                        "judge_only": sum(a["judge_only"] for a in types.values()), "missed": miss, "catch": rate(inj - miss, inj)},
            "control": {"n": ctl_n, "rejected": ctl_rej, "false_rejection": rate(ctl_rej, ctl_n)}, "missed": missed}


def stage_aggregate(o, case, res):
    arms = {a: {c: arm_metrics(o, a, c) for c in CASES} for a in ARMS}
    swap = {}
    for c in SWAP_CASES:
        swap[c] = {"default": arms["facts"][c], "swapped": arms["swap"][c]}
    tables = {"cases": {c: {"difficulty": d, "seed": s} for c, (d, s) in CASES.items()},
              "detection": detection_tables(res), "arms": arms, "corruption": corruption_tables(o), "swap": swap}
    Path(o.eval_dir).mkdir(parents=True, exist_ok=True)
    (Path(o.eval_dir) / "tables.json").write_text(json.dumps(tables, indent=2), encoding="utf-8")
    return {"tables": str(Path(o.eval_dir) / "tables.json")}


STAGE_FUNCS = {"detect": stage_detect, "facts": stage_facts, "audit": stage_audit, "baseline": stage_baseline,
               "corruption": stage_corruption, "raw": stage_raw, "swap": stage_swap, "aggregate": stage_aggregate}


# ------------------------------------------------------------------ driver
def run(o):
    rpath = Path(o.eval_dir) / "results.json"
    results = load(rpath) if (o.resume and rpath.exists()) else {"stages": {}}
    results.setdefault("stages", {})
    wanted = [s for s in STAGES if (not o.stages or s in o.stages) and s not in o.skip]
    for stage in wanted:
        for case in STAGE_CASES[stage]:
            done = results["stages"].get(stage, {}).get(case)
            if o.resume and done and done.get("done"):
                print(f"[skip] {stage}/{case} (already done)", flush=True)
                continue
            print(f"[run] {stage}/{case}", flush=True)
            t0 = time.time()
            try:
                entry = STAGE_FUNCS[stage](o, case, results)
            except StageError as e:
                save_results(rpath, results)
                raise SystemExit(f"STAGE FAILED: {stage}/{case}: {e}")
            entry.update({"done": True, "wall_seconds": round(time.time() - t0, 1)})
            results["stages"].setdefault(stage, {})[case] = entry
            save_results(rpath, results)
            print(f"[done] {stage}/{case} in {entry['wall_seconds']}s", flush=True)
    return results


def parse(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--stages", type=lambda s: [x for x in s.split(",") if x], default=[])
    ap.add_argument("--skip", type=lambda s: [x for x in s.split(",") if x], default=[])
    ap.add_argument("--data-dir", default=str(ROOT / "data" / "cases"))
    ap.add_argument("--output", default=str(ROOT / "output"))
    ap.add_argument("--output-raw", default=str(ROOT / "output_raw"))
    ap.add_argument("--output-swap", default=str(ROOT / "output_swap"))
    ap.add_argument("--eval-dir", default=str(ROOT / "eval"))
    o = ap.parse_args(argv)
    bad = [s for s in o.stages + o.skip if s not in STAGES]
    if bad:
        ap.error(f"unknown stage(s): {bad}; choose from {STAGES}")
    return o


def main(argv=None):
    run(parse(argv))


if __name__ == "__main__":
    main()
