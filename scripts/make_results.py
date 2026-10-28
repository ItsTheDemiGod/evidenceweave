"""Generate docs/RESULTS.md from eval/tables.json, eval/results.json, eval/provenance.json (+ audit scores if present).

Also fills the region between <!-- RESULTS:START --> and <!-- RESULTS:END --> in docs/DEMO.md. Idempotent.
Usage: python scripts/make_results.py [--eval-dir eval] [--docs-dir docs] [--readme README.md]
"""
import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

NR = "not run"
ARM_LABEL = {"facts": "facts (chain)", "baseline": "baseline", "raw": "raw (chain)", "swap": "facts, roles swapped"}


def load(p):
    p = Path(p)
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def pct(x, d=1):
    return NR if x is None else f"{100 * x:.{d}f}%"


def num(x, d=1):
    return "n/a" if x is None else (f"{x:.{d}f}" if isinstance(x, float) else str(x))


def ci(r):
    if not r or r.get("rate") is None:
        return "n/a"
    return f"{r['k']}/{r['n']} = {pct(r['rate'])} [{pct(r['ci_lo'])}, {pct(r['ci_hi'])}]"


def table(head, rows):
    out = ["| " + " | ".join(head) + " |", "|" + "|".join("---" for _ in head) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out) + "\n"


def ok(m):
    return m and m.get("status") == "ok"


def variants(m):
    """(label, coverage dict) pairs for an arm-case metrics block."""
    return [(k, v) for k, v in m["coverage"].items()]


VAR_LABEL = {"llm": "accepted LLM sentences", "llm_plus_fallback_and_template": "incl. deterministic fallback + template sections",
             "as_written": "as written", "verified_subset": "verified subset"}


# ------------------------------------------------------------------ sections
def setup(prov, tables):
    L = ["## Setup\n"]
    L.append(table(["case", "difficulty", "seed"], [[c, v["difficulty"], v["seed"]] for c, v in tables["cases"].items()]))
    if not prov:
        return "\n".join(L) + "\n_provenance.json missing._\n"
    s, e = prov.get("start", {}), prov.get("end")
    L.append(table(["item", "value"], [
        ["narrator / default judge", "qwen2.5:7b-instruct / llama3.1:8b (roles swapped in the swap arm)"],
        ["model digests", "; ".join(f"{m}: `{(d or 'n/a')[:12]}`" for m, d in s.get("model_digests", {}).items())],
        ["Ollama", s.get("ollama_version")], ["Python", s.get("python")],
        ["git commit at start", f"`{s.get('git_commit', '')[:10]}` (tracked tree clean: {s.get('working_tree_clean_tracked')})"],
        ["held-out pool commit (frozen before any run)", f"`{prov.get('heldout_pool_commit', 'n/a')[:10]}`"],
        ["held-out pool SHA-256", f"`{(tables.get('corruption') or {}).get('pool', {}).get('sha256', 'not run')}`"],
        ["code SHA-256 (evidenceweave/) at start", f"`{s.get('code_sha256')}`"],
        ["code SHA-256 at end", f"`{e.get('code_sha256')}`" if e else "not recorded yet"],
        ["date", s.get("date")]]))
    if e:
        if prov.get("code_changed"):
            L.append("> **WARNING: the code under evidenceweave/ changed between the start and the end of the evaluation.** "
                     f"Changed files: {', '.join(prov['changed_files'])}. Only fixes logged in eval/CHANGES.md are acceptable; see that file for the reason.\n")
        else:
            L.append("Code hash unchanged between start and end of the evaluation (freeze respected).\n")
    return "\n".join(L)


def t1(tables):
    d = tables["detection"]
    L = ["## Table 1 - Chain detection (deterministic rules, no LLM)\n"]
    if not d["per_case"]:
        return "\n".join(L) + NR + "\n"
    rows = []
    for c, r in d["per_case"].items():
        tp, fn, fp = r["tp"], r["fn"], r["fp"]
        rows.append([c, f"{tp}/{tp + fn}", pct(tp / (tp + fn) if tp + fn else None), pct(tp / (tp + fp) if tp + fp else None), fp,
                     len(r["decoy_hits"]), len(r["benign_hits"]),
                     ("yes" if r["missing_detected"] else "NO") if r["missing_expected"] else "n/a (none planted)"])
    p = d["pooled"]
    rows.append(["**pooled**", f"{p['tp']}/{p['tp'] + p['fn']}", pct(p["recall"]), pct(p["precision"]), p["fp"], "", "", ""])
    L.append(table(["case", "TP / key lines", "recall", "precision", "FP lines", "decoy lines in chain", "benign lines in chain", "missing evidence detected"], rows))
    L.append("Per step, pooled over the cases:\n")
    L.append(table(["step", "name", "TP", "FN", "FP", "recall", "precision"],
                   [[k, v["name"], v["tp"], v["fn"], v["fp"], pct(v["recall"]), pct(v["precision"])] for k, v in sorted(d["pooled"]["per_step"].items())]))
    return "\n".join(L)


def t2(tables):
    L = ["## Table 2 - Narrative step coverage and attacker-entity coverage\n",
         "Strict = a sentence with at most 8 cites, at least one of which is key evidence of the step. Loose = no cite cap. "
         "Entities = distinct attacker entities (key attacker IP and user, plus chain.json IPs, users, hosts and URL hosts) found as exact tokens in the final text.\n"]
    rows = []
    for arm in ["facts", "baseline", "raw", "swap"]:
        for case in tables["cases"]:
            m = tables["arms"][arm][case]
            if not ok(m):
                rows.append([ARM_LABEL[arm], case, NR, "", "", "", "", "", ""])
                continue
            for var, cv in variants(m):
                rows.append([ARM_LABEL[arm], case, VAR_LABEL[var], f"{len(cv['steps_covered_strict'])}/6", f"{len(cv['steps_covered_loose'])}/6",
                             f"{cv['entities']['covered']}/{cv['entities']['total']}", cv["false_alarms"], len(cv["decoy_mentions"]), cv["sentences"]])
    L.append("The raw arm was designed to run on eval_e1 and eval_h1 only and the role-swap arm on eval_e2 and eval_h2 only; other cells say `not run` for that reason.\n")
    L.append(table(["arm", "case", "sentence set", "steps strict", "steps loose", "entities covered", "false alarms (strict)", "decoy mentions", "sentences"], rows))
    L.append("A false alarm or decoy mention in the 'incl. fallback + template' rows of hard cases is the deterministic template sentence about the decoy actor: "
             "it cites the decoy's own (benign-listed) web requests and states that no successful access was observed. It is not an LLM claim.\n")
    miss = [(a, c, v, e) for a in tables["arms"] for c, m in tables["arms"][a].items() if ok(m) for v, cv in variants(m) for e in [cv["entities"]["missing"]] if e]
    if miss:
        L.append("Entities not found in the final text:\n")
        L += [f"- {ARM_LABEL[a]} / {c} / {VAR_LABEL[v]}: {', '.join(e)}" for a, c, v, e in miss]
        L.append("")
    dm = [(a, c, v, x) for a in tables["arms"] for c, m in tables["arms"][a].items() if ok(m) for v, cv in variants(m) for x in cv["decoy_mentions"]]
    if dm:
        L.append("Sentences mentioning a decoy IP (an attempts-only actor; it is correct to mention it as unsuccessful):\n")
        L += [f"- {ARM_LABEL[a]} / {c}: {x['decoy']}: {x['sentence']}" for a, c, v, x in dm]
        L.append("")
    return "\n".join(L)


def t3(tables):
    rows = []
    for arm in ["facts", "baseline", "raw", "swap"]:
        for case in tables["cases"]:
            m = tables["arms"][arm][case]
            if not ok(m):
                rows.append([ARM_LABEL[arm], case, NR, "", "", "", ""])
                continue
            e = m["efficiency"]
            rows.append([ARM_LABEL[arm], case, num(e.get("narrate_seconds")), num(e.get("verify_seconds")), num(e.get("total_seconds")),
                         e.get("tokens") if e.get("tokens") is not None else "not recorded", e.get("narrator_calls", e.get("llm_calls"))])
    return "## Table 3 - Efficiency\n\n" + table(["arm", "case", "narrate s", "verify s", "total s", "tokens", "narrator LLM calls (incl. repair)"], rows) + \
        "\nJudge calls are not included in the call count; the verify seconds are dominated by the double judge.\n"


def t4(tables):
    rows = []
    for arm in ["facts", "baseline", "raw", "swap"]:
        for case in tables["cases"]:
            m = tables["arms"][arm][case]
            if not ok(m):
                rows.append([ARM_LABEL[arm], case, NR] + [""] * 8)
                continue
            v = m["verification"]
            if arm == "baseline":
                rows.append([ARM_LABEL[arm], case, f"{v['accepted']}/{v['total']}", "-", "-", pct(v["supported_rate"]), "-", "-", "-", "-", "-"])
            else:
                rows.append([ARM_LABEL[arm], case, v["accepted"], v["dropped"], v["fallback_units"] or "none", pct(v["attempt0_supported_rate"]),
                             pct(v["final_supported_rate"]), num(v["judge_agreement_rate"], 3), v["judge_error_count"],
                             v["fixed_round_1"], v["fixed_round_2"]])
    return ("## Table 4 - Verification statistics\n\nBaseline: accepted/total sentences as written (no repair). Chain arms: accepted = sentences kept in the final "
            "narrative, dropped = sentences rejected in any attempt, supported rate = accepted share of all judged sentences before / after repair.\n\n" +
            table(["arm", "case", "accepted", "dropped", "fallback units", "attempt-0 supported", "final supported", "judge agreement", "judge errors", "fixed round 1", "fixed round 2"], rows))


def t5(tables):
    c = tables["corruption"]
    L = ["## Table 5 - Held-out corruption test\n"]
    if c.get("status") != "ok":
        return "\n".join(L) + NR + "\n"
    L.append(f"Pool `{c['pool']['name']}` (SHA-256 `{c['pool']['sha256']}`), cases {', '.join(c['cases'])}, seed 42, cap 60 per case, one run. "
             "Wilson 95% intervals. 'Judge only' = passed every deterministic layer and was rejected by the judge.\n")
    rows = [[t, a["injected"], a["deterministic"], a["judge_only"] + a["judge_error"], a["missed"], ci(a["catch"])] for t, a in c["per_type"].items()]
    o = c["overall"]
    rows.append(["**overall**", o["injected"], o["det"], o["judge_only"], o["missed"], ci(o["catch"])])
    L.append(table(["corruption type", "injected", "deterministic", "judge only", "missed", "catch rate [95% CI]"], rows))
    L.append("fabricated_entity by entity kind:\n")
    L.append(table(["kind", "injected", "caught", "catch rate [95% CI]"], [[k, v["injected"], v["caught"], ci(v["catch"])] for k, v in sorted(c["fabricated_entity_by_kind"].items(), key=lambda x: str(x[0]))]))
    L.append(f"False rejection of clean control sentences: {ci(c['control']['false_rejection'])}\n")
    L.append(f"### Missed corruptions ({len(c['missed'])})\n")
    for m in c["missed"]:
        L.append(f"- **{m['type']}**" + (f" ({m['entity_kind']})" if m.get("entity_kind") else "") + f" [{m['case']}, {m['unit']}]\n  - original: {m['original_text']}\n  - corrupted: {m['corrupted_text']}")
    if not c["missed"]:
        L.append("None.")
    return "\n".join(L) + "\n"


def t6(tables):
    L = ["## Table 6 - Role swap (eval_e2, eval_h2)\n", "Default = narrator qwen2.5:7b-instruct, judge llama3.1:8b. Swapped = narrator llama3.1:8b, judge qwen2.5:7b-instruct.\n"]
    rows = []
    for case, d in tables["swap"].items():
        for name in ("default", "swapped"):
            m = d[name]
            if not ok(m):
                rows.append([case, name, NR] + [""] * 9)
                continue
            cv, v, e = m["coverage"]["llm"], m["verification"], m["efficiency"]
            rows.append([case, name, f"{v['narrator_model']} / {v['judge_model']}", v["judge_independent"], f"{len(cv['steps_covered_strict'])}/6",
                         f"{cv['entities']['covered']}/{cv['entities']['total']}", cv["false_alarms"], f"{v['accepted']}/{v['dropped']}/{v['fallback_units'] or 'none'}",
                         pct(v["attempt0_supported_rate"]), num(v["judge_agreement_rate"], 3), num(e["total_seconds"])])
    L.append(table(["case", "pairing", "narrator / judge", "judge_independent", "steps strict", "entities", "false alarms", "accepted/dropped/fallback", "attempt-0 supported", "judge agreement", "total s"], rows))
    return "\n".join(L)


def audit_body(audit):
    cm = audit["confusion_matrix"]
    L = [table(["verifier", "S", "P", "U"], [[k, v["S"], v["P"], v["U"]] for k, v in cm.items()])]
    L.append(f"- Labelled {audit['items_labelled']}/{audit['items_total']} items.")
    L.append(f"- Accepted sentences labelled S: {ci(audit['precision_accepted_S'])}")
    L.append(f"- Accepted sentences labelled S or P: {ci(audit['precision_accepted_S_or_P'])}")
    L.append(f"- Rejected sentences labelled S (false rejections): {ci(audit['false_rejection_rate'])}")
    for f in audit["false_rejections"]:
        L.append(f"  - {f['item_id']} [{f['failure_codes']}]: {f['sentence']}")
    L.append(f"\nAccepted sentences labelled P or U (verifier misses): {len(audit['verifier_misses'])}")
    for m in audit["verifier_misses"]:
        L.append(f"- {m['item_id']} ({m['label']}, {m['case']}/{m['stage']}): {m['sentence']}")
    return "\n".join(L) + "\n"


LLM_NOTE = ("> **The 32 labels below were produced by an LLM from the same model family as the narrator. No human labelled them. "
            "The labeller saw only `audit_items.csv` (never `audit_key.csv`) before labelling. The results are indicative only "
            "and are not independent ground truth.**\n")


def t7(audit, llm=None):
    def usable(a):
        return a and not a.get("refused")
    if usable(audit):
        L = ["## Table 7 - Manual audit (single human labeller)\n", audit_body(audit)]
        if usable(llm):
            L += ["### Second opinion: LLM-labelled audit (not independent ground truth)\n", LLM_NOTE, audit_body(llm)]
        return "\n".join(L)
    if usable(llm):
        return "\n".join(["## Table 7 - LLM-labelled audit (not independent ground truth)\n", LLM_NOTE, audit_body(llm),
                          "Human audit: pending (`eval/audit/audit_scores.json` not present).\n"])
    return "## Table 7 - Manual audit (single labeller)\n\naudit pending" + (f" ({audit['reason']})" if audit else "") + "\n"


# ------------------------------------------------------------------ findings (computed from the numbers)
def mean(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


def arm_mean(tables, arm, var, key, cases=None):
    vals = []
    for c, m in tables["arms"][arm].items():
        if (cases is None or c in cases) and ok(m) and var in m["coverage"]:
            vals.append(m["coverage"][var][key])
    return mean(vals), len(vals)


def findings(tables, audit):
    f, head = [], []
    d = tables["detection"]["pooled"] if tables["detection"]["per_case"] else None
    if d:
        s = f"The deterministic rules recovered {d['tp']} of {d['tp'] + d['fn']} key evidence lines (recall {pct(d['recall'])}) with {d['fp']} extra lines (precision {pct(d['precision'])}) on the {len(tables['detection']['per_case'])} held-out generated cases."
        f.append(s)
        head.append(s + " The cases come from the same generator the rules were developed against.")
    fs, nf = arm_mean(tables, "facts", "llm", "coverage_strict")
    fl, _ = arm_mean(tables, "facts", "llm", "coverage_loose")
    bs, nb = arm_mean(tables, "baseline", "as_written", "coverage_strict")
    bl, _ = arm_mean(tables, "baseline", "as_written", "coverage_loose")
    bv, _ = arm_mean(tables, "baseline", "verified_subset", "coverage_strict")
    if nf and nb:
        s = (f"Mean strict step coverage over cases: chain narrator (accepted LLM sentences) {pct(fs)}, baseline as written {pct(bs)} "
             f"(loose, no cite cap: {pct(fl)} vs {pct(bl)}); baseline verified subset strict {pct(bv)}.")
        f.append(s)
        head.append(s)
        if bs is not None and fs is not None and bs >= fs:
            f.append("The baseline did as well as or better than the chain narrator on strict step coverage in this measurement.")
    c = tables["corruption"]
    if c.get("status") == "ok":
        o = c["overall"]
        s = f"Held-out corruption: {o['injected'] - o['missed']} of {o['injected']} injected corruptions rejected ({ci(o['catch'])}); {o['missed']} missed; false rejection of clean controls {ci(c['control']['false_rejection'])}."
        f.append(s)
        head.append(s)
    ent = {a: mean([m["coverage"][v]["entities"]["covered"] / m["coverage"][v]["entities"]["total"] for m in tables["arms"][a].values() if ok(m) for v in [("llm" if a != "baseline" else "as_written")]]) for a in ("facts", "baseline")}
    if ent["facts"] is not None and ent["baseline"] is not None:
        f.append(f"Mean attacker-entity coverage: chain narrator {pct(ent['facts'])}, baseline {pct(ent['baseline'])}.")
    if audit and not audit.get("refused"):
        f.append(f"Manual audit (single labeller): accepted sentences labelled S {ci(audit['precision_accepted_S'])}.")
    return f, head


def shows(tables, audit):
    f, _ = findings(tables, audit)
    S = ["## What these results do and do not show\n", "**What the numbers show (this synthetic setup, one run each):**\n"]
    S += [f"- {x}" for x in f]
    S.append("\n**What they do not show:**\n")
    S += ["- Performance on real logs, other log formats or other attack chains: all cases come from one generator whose attack storyline the rules were written against.",
          "- That one narrator or judge is better than another: the pairings were run once on two cases each, and differences between arms are within what run-to-run variation could produce.",
          "- That the verifier is complete: sentences with no checkable entity can pass, and the held-out misses listed above are real gaps.",
          "- Anything about human-level correctness beyond the single-labeller audit sample."]
    return "\n".join(S) + "\n"


LIMITS = """## Limits and threats to validity

- **One synthetic generator.** Every case, attack and benign look-alike comes from the same generator. The results do not show performance on real logs; the rules, parsers and verifier were developed against cases like these.
- **Small samples, one run per setting.** Four cases, two cases for each secondary arm, one run each. Differences are indicative only. The judge (llama3.1:8b) is not perfectly reproducible even at temperature 0 with a fixed seed.
- **Small local models.** Narrator and judge are 7B to 8B models. Larger models could behave quite differently.
- **Audit limits.** The human audit (if present) has a single labeller and no inter-annotator agreement. The LLM-labelled audit is not independent: the labeller is from the same model family as the narrator.
- **Facts mode is deliberately plain.** The facts-mode narrator mostly restates verified facts. Its higher supported rate partly reflects an easier task, not a better model.
- **Baseline cite ranges inflate loose coverage.** The chunked baseline tends to cite wide ranges of events; loose coverage (no cite cap) therefore overstates what its sentences actually show. Strict coverage caps cites at 8.
- **Held-out pool.** The held-out corruption pool was frozen (committed) before any evaluation run, but the verifier itself was designed knowing the original pool, and the held-out pool was written by the same author.
- **Coverage is citation-based.** A sentence "covers" a step if it cites that step's key evidence, not if it describes it well. Entity coverage is a string match.
"""


def gap_lines(tables, llm):
    g = []
    for m in (tables.get("corruption") or {}).get("missed") or []:
        added = m["corrupted_text"][len(m["original_text"]):].strip()
        g.append(f"  - Held-out corruption missed ({m['type']}, {m['case']}): the appended claim \"{added}\" was accepted by the judge.")
    if llm and not llm.get("refused"):
        acc = sum(llm["confusion_matrix"]["accepted"].values())
        ms = llm["verifier_misses"]
        ids = ", ".join(f"{m['item_id']} ({m['label']})" for m in ms)
        g.append(f"  - Accepted sentences that overstate: in the LLM-labelled audit {len(ms)} of {acc} accepted sentences were labelled P or U: {ids}. "
                 "They state more than the cited lines show: a boundary or aggregate claim (\"failed attempts ended at T\" when only one failed line is cited) "
                 "or a characterisation (\"events related to persistence\"). Counts, absence claims and similar statements are the typical weak spot; "
                 "the same audit also found sentences of that kind among the REJECTED ones, so the verifier does catch some of them.")
        for f in llm["false_rejections"]:
            if f["item_id"] == "A025":
                g.append("  - A025 (labelled S by the LLM labeller) ends in a cut-off backslash (\"... created the scheduled task \\\\\"). It passed every deterministic layer, "
                         "so there is no dangling-ending check for a trailing backslash; only the judge rejected it "
                         f"({f['failure_codes'].replace(';', ', ')}). It was REJECTED, so it did not reach the final narrative.")
    return g or ["  - See the missed corruptions listed under Table 5."]


def limits(tables, llm):
    return LIMITS.rstrip("\n") + "\n- **Known verifier gaps.**\n" + "\n".join(gap_lines(tables, llm)) + "\n"


def build(eval_dir, audit_override=None):
    eval_dir = Path(eval_dir)
    tables, prov = load(eval_dir / "tables.json"), load(eval_dir / "provenance.json")
    audit = audit_override if audit_override is not None else load(eval_dir / "audit" / "audit_scores.json")
    llm = load(eval_dir / "audit" / "audit_scores_llm.json")
    if tables is None:
        raise SystemExit("eval/tables.json missing: run the aggregate stage first")
    body = ["# EvidenceWeave - evaluation results\n",
            "Generated by `scripts/make_results.py` from `eval/results.json`, `eval/tables.json` and `eval/provenance.json`. Numbers are reported as they came out.\n",
            setup(prov, tables), t1(tables), t2(tables), t3(tables), t4(tables), t5(tables), t6(tables), t7(audit, llm), limits(tables, llm), shows(tables, audit)]
    return "\n".join(body), tables, audit


def demo_block(tables, audit):
    _, head = findings(tables, audit)
    rows = []
    for arm in ["facts", "baseline", "raw", "swap"]:
        ms = [m for m in tables["arms"][arm].values() if ok(m)]
        if not ms:
            rows.append([ARM_LABEL[arm], NR, NR, NR])
            continue
        var = "as_written" if arm == "baseline" else "llm"
        rows.append([ARM_LABEL[arm], f"{len(ms)} case(s)", pct(mean([m["coverage"][var]["coverage_strict"] for m in ms])),
                     "; ".join(f"{m['coverage'][var]['entities']['covered']}/{m['coverage'][var]['entities']['total']}" for m in ms)])
    out = [table(["arm", "runs", "mean strict step coverage", "attacker entities covered (per case)"], rows)]
    out += [f"{i}. {h} See docs/RESULTS.md." for i, h in enumerate(head[:3], 1)]
    return "\n".join(out)


def fill_demo(demo_path, block):
    p = Path(demo_path)
    s = p.read_text(encoding="utf-8")
    new = re.sub(r"(<!-- RESULTS:START -->).*?(<!-- RESULTS:END -->)", lambda m: f"{m.group(1)}\n{block}\n{m.group(2)}", s, flags=re.S)
    p.write_text(new, encoding="utf-8")


def ensure_readme_link(readme):
    p = Path(readme)
    s = p.read_text(encoding="utf-8")
    if "docs/RESULTS.md" not in s:
        p.write_text(s.rstrip() + "\n\nMeasured results: [docs/RESULTS.md](docs/RESULTS.md)\n", encoding="utf-8")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--eval-dir", default=str(ROOT / "eval"))
    ap.add_argument("--docs-dir", default=str(ROOT / "docs"))
    ap.add_argument("--readme", default=str(ROOT / "README.md"))
    a = ap.parse_args(argv)
    md, tables, audit = build(a.eval_dir)
    Path(a.docs_dir).mkdir(parents=True, exist_ok=True)
    (Path(a.docs_dir) / "RESULTS.md").write_text(md, encoding="utf-8")
    if (Path(a.docs_dir) / "DEMO.md").exists():
        fill_demo(Path(a.docs_dir) / "DEMO.md", demo_block(tables, audit))
    if Path(a.readme).exists():
        ensure_readme_link(a.readme)
    print(f"wrote {Path(a.docs_dir) / 'RESULTS.md'}")


if __name__ == "__main__":
    main()
