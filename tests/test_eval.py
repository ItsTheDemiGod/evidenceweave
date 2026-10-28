import csv
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import audit_sample  # noqa: E402
import audit_score  # noqa: E402
import evaluate_cases as EC  # noqa: E402
import make_results as MR  # noqa: E402
from stats import rate, wilson  # noqa: E402

from evidenceweave import schema as S  # noqa: E402
from evidenceweave.schema import Event  # noqa: E402


# ---------------- 4. Wilson ----------------
def test_wilson_known_values():
    lo, hi = wilson(0, 10)
    assert lo == 0.0 and hi == pytest.approx(0.2775, abs=1e-3)
    lo, hi = wilson(10, 10)
    assert hi == 1.0 and lo == pytest.approx(0.7225, abs=1e-3)
    lo, hi = wilson(5, 10)
    assert (lo, hi) == (pytest.approx(0.2366, abs=1e-3), pytest.approx(0.7634, abs=1e-3))
    assert wilson(0, 0) == (None, None)
    assert rate(3, 4)["rate"] == 0.75


# ---------------- 1-3 coverage / entities / false alarms ----------------
STEPS = {1: {"AUTH-L1", "AUTH-L2"}, 2: {"AUTH-L10"}, 3: {"NGX-L5"}}


def test_strict_vs_loose_step_coverage():
    wide = [{"text": "x", "cites": [f"AUTH-L{i}" for i in range(1, 41)]}]
    assert EC.covered_steps(wide, STEPS) == {1, 2}  # loose counts it
    assert EC.covered_steps(wide, STEPS, EC.MAX_CITES) == set()  # strict does not
    narrow = [{"text": "x", "cites": ["AUTH-L1", "AUTH-L3", "NGX-L5"]}]
    assert EC.covered_steps(narrow, STEPS) == EC.covered_steps(narrow, STEPS, EC.MAX_CITES) == {1, 3}


def test_fallback_sentences_only_in_separate_set():
    nv = {"executive_summary": [{"text": "a", "cites": ["AUTH-L1"], "source": "llm"}],
          "stages": [{"stage": "s", "sentences": [{"text": "b", "cites": ["AUTH-L10"], "source": "template_fallback"}]}],
          "attempts_only": [{"text": "c", "cites": ["NGX-L5"], "source": "template"}], "unprovable": []}
    llm, other = EC.chain_sentences(nv)
    cb = EC.coverage_block({"llm": llm, "all": llm + other}, STEPS, [], set(), {"x"})
    assert cb["llm"]["steps_covered_strict"] == [1]
    assert cb["all"]["steps_covered_strict"] == [1, 2, 3]


def test_entity_set_dedup_and_exact_tokens():
    key = {"attacker_ip": "203.0.113.45", "compromised_user": "deploy"}
    chain = {"attacker_entities": {"ips": ["203.0.113.45"], "users": ["deploy"], "associated_users": ["svc"], "hosts": ["web01"],
                                   "urls": ["http://203.0.113.45:8080/x.sh", "http://203.0.113.45:8080/b.sh"]}}
    ents = EC.entity_set(key, chain)
    assert ents == {"203.0.113.45", "deploy", "web01"}  # attacker as IP and payload host counts once
    assert EC.token_present("203.0.113.4", "from 203.0.113.45 port 1") is False
    assert EC.token_present("3.0.113.45", "from 203.0.113.45") is False
    assert EC.token_present("203.0.113.45", "from 203.0.113.45.") is True
    assert EC.token_present("deploy", "Deploy logged in") is False  # case-sensitive
    assert EC.token_present("web01", "on web01, then") is True
    cov = EC.entity_coverage(ents, "deploy came from 203.0.113.45")
    assert cov["covered"] == 2 and cov["total"] == 3 and cov["missing"] == ["web01"]
    assert EC.decoy_mentions(["198.51.100.23"], [{"text": "also 198.51.100.23 failed"}, {"text": "198.51.100.2 only"}])[0]["decoy"] == "198.51.100.23"
    assert len(EC.decoy_mentions(["198.51.100.23"], [{"text": "198.51.100.231"}])) == 0


def test_false_alarms_strict_only():
    benign = {"WIN-L9"}
    sents = [{"cites": ["WIN-L9"]}, {"cites": ["WIN-L9"] + [f"AUTH-L{i}" for i in range(20)]}, {"cites": ["AUTH-L1"]}]
    assert EC.false_alarms(sents, benign) == 1


# ---------------- 5. harness resume / crash / skip / not run ----------------
def opts(tmp, **kw):
    base = dict(resume=False, stages=[], skip=[], data_dir=str(tmp / "d"), output=str(tmp / "o"), output_raw=str(tmp / "or"),
                output_swap=str(tmp / "os"), eval_dir=str(tmp / "eval"))
    base.update(kw)
    return SimpleNamespace(**base)


def test_resume_crash_and_skip(tmp_path, monkeypatch):
    calls = []

    def fake(name):
        def f(o, case, res):
            calls.append((name, case))
            if name == "audit" and crash["on"]:
                raise RuntimeError("simulated crash")
            return {}
        return f

    crash = {"on": True}
    monkeypatch.setattr(EC, "STAGE_FUNCS", {s: fake(s) for s in EC.STAGES})
    o = opts(tmp_path, stages=["detect", "facts", "audit"])
    with pytest.raises(RuntimeError):
        EC.run(o)
    saved = json.loads((tmp_path / "eval" / "results.json").read_text())
    assert set(saved["stages"]) == {"detect", "facts"} and all(e["done"] for e in saved["stages"]["facts"].values())
    n = len(calls)
    crash["on"] = False
    EC.run(opts(tmp_path, stages=["detect", "facts", "audit"], resume=True))
    assert calls[n:] == [("audit", "_all")]  # finished entries were skipped
    calls.clear()
    EC.run(opts(tmp_path, skip=["raw", "swap", "detect", "facts", "audit", "baseline", "corruption", "aggregate"]))
    assert calls == []
    with pytest.raises(SystemExit):
        EC.parse(["--stages", "nonsense"])


def test_missing_arms_are_not_run_in_tables(tmp_path):
    o = opts(tmp_path)
    EC.stage_aggregate(o, "_all", {"stages": {}})
    t = json.loads((tmp_path / "eval" / "tables.json").read_text())
    assert t["arms"]["raw"]["eval_e1"]["status"] == "not run" and t["corruption"]["status"] == "not run"
    md, _, _ = MR.build(tmp_path / "eval")
    assert "not run" in md and "audit pending" in md


# ---------------- hand-built case for metrics ----------------
def build_mini(tmp, arm_dir="o"):
    case = "eval_e1"
    key = {"attacker_ip": "203.0.113.45", "compromised_user": "deploy", "decoy_ips": ["198.51.100.23"],
           "steps": [{"step_id": i, "name": f"s{i}", "evidence": [{"source_file": "linux_auth.log", "line_number": i}]} for i in range(1, 7)],
           "benign_but_suspicious_looking": [{"source_file": "windows_events.jsonl", "line_number": 9}]}
    d = tmp / "d" / case
    d.mkdir(parents=True)
    (d / "answer_key.json").write_text(json.dumps(key))
    o = tmp / "o" / case
    o.mkdir(parents=True)
    (o / "chain.json").write_text(json.dumps({"attacker_entities": {"ips": ["203.0.113.45"], "users": ["deploy"], "hosts": ["web01"], "urls": []}}))
    out = tmp / arm_dir / case
    out.mkdir(parents=True, exist_ok=True)
    sent = lambda t, c, src="llm": {"text": t, "cites": c, "source": src, "attempt": 0, "fact_ids": []}  # noqa: E731
    nv = {"executive_summary": [sent("deploy from 203.0.113.45", ["AUTH-L1", "AUTH-L2"])],
          "stages": [{"stage": "a", "sentences": [sent("benign touched", ["WIN-L9"]), sent("fb web01", ["AUTH-L3"], "template_fallback")]}],
          "attempts_only": [], "unprovable": [],
          "verification": {"accepted_total": 3, "dropped_total": 2, "fallback_units": ["a"], "narrator_model": "n", "judge_model": "j",
                           "judge_independent": True, "judge_double": True, "narration_mode": "facts"}}
    rep = {"total_seconds": 10.0, "summary": {"supported_rate": {"before_repair": {"rate": 0.4}, "after_repair": {"rate": 0.6}},
                                               "judge_agreement_rate": 0.9, "judge_error_count": 0, "repair_narrator_calls": 3,
                                               "repair_effectiveness": {"failing_at_attempt0": 5, "fixed_by_round": {"1": 2, "2": 1}}}}
    nar = {"total_seconds": 5.0, "stats": {"calls": 7, "total_tokens": 100}}
    for n, v in (("narrative_verified.json", nv), ("verification_report.json", rep), ("narrative.json", nar)):
        (out / n).write_text(json.dumps(v))
    return case


def test_arm_metrics_and_tables(tmp_path):
    build_mini(tmp_path)
    o = opts(tmp_path)
    m = EC.arm_metrics(o, "facts", "eval_e1")
    llm, allv = m["coverage"]["llm"], m["coverage"]["llm_plus_fallback_and_template"]
    assert llm["steps_covered_strict"] == [1, 2] and allv["steps_covered_strict"] == [1, 2, 3]
    assert llm["false_alarms"] == 1 and llm["entities"]["total"] == 3 and llm["entities"]["covered"] == 2
    assert allv["entities"]["covered"] == 3
    v = m["verification"]
    assert (v["accepted"], v["dropped"], v["fixed_round_1"], v["fixed_round_2"], v["total_seconds"], v["narrator_calls"]) == (3, 2, 2, 1, 15.0, 10)
    assert EC.arm_metrics(o, "raw", "eval_e1")["status"] == "not run"
    EC.stage_aggregate(o, "_all", {"stages": {}})
    md, tables, _ = MR.build(tmp_path / "eval")
    assert "Table 2" in md and "not run" in md


# ---------------- 6. audit sampler ----------------
def fake_outputs(tmp, cases, rejected_in=None):
    for ci_, c in enumerate(cases):
        d = tmp / c
        d.mkdir(parents=True)
        evs = [Event(f"AUTH-L{i}", datetime(2026, 10, 27, 2, 0, i, tzinfo=timezone.utc), datetime(2026, 10, 27, 2, 0, i, tzinfo=timezone.utc), False,
                     "web01", "deploy", None, None, "auth", S.SSH_LOGIN_FAILED, "f", i, f"raw line {i}", {}) for i in range(1, 31)]
        (d / "events.jsonl").write_text("\n".join(json.dumps(e.to_dict()) for e in evs) + "\n")
        vs = []
        for k in range(12):
            vs.append({"stage": f"st{k % 4}", "accepted": True, "source": "llm", "disposition": "kept", "attempt": 0, "text_normalized": f"{c} ok {k}",
                       "cites_final": [f"AUTH-L{j}" for j in range(1, 1 + (k % 3) * 8 + 1)], "layer_results": {"judge": {"reasons": []}},
                       "judge": {"verdict": "supported", "runs": [{"seed": 42, "derived": "supported"}]}})
        nrej = 0 if (rejected_in and c == rejected_in) else 4
        for k in range(nrej):
            vs.append({"stage": f"st{k}", "accepted": False, "source": "llm", "disposition": "dropped", "attempt": 1, "text_normalized": f"{c} bad {k}",
                       "cites_final": ["AUTH-L1"], "layer_results": {"entities": {"reasons": [{"code": "IP_NOT_GROUNDED"}]}}, "judge": None})
        (d / "verification_report.json").write_text(json.dumps({"verdicts": vs}))


CASES4 = ["c1", "c2", "c3", "c4"]


def test_audit_sampler(tmp_path):
    fake_outputs(tmp_path, CASES4, rejected_in="c3")
    items, keys = audit_sample.sample(tmp_path, CASES4, 42)
    assert len(items) == 32
    again, _ = audit_sample.sample(tmp_path, CASES4, 42)
    assert items == again
    assert [k["accepted"] for k in keys].count("true") == 24 and [k["accepted"] for k in keys].count("false") == 8
    for c in CASES4:
        assert sum(1 for k in keys if k["case"] == c and k["accepted"] == "true") == 6
        assert len({k["stage"] for k in keys if k["case"] == c and k["accepted"] == "true"}) == 4  # spread over stages
    assert [k["case"] for k in keys if k["accepted"] == "false"].count("c3") == 0  # topped up from other cases
    audit_sample.write(items, keys, tmp_path / "audit")
    raw = (tmp_path / "audit" / "audit_items.csv").read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")
    rows = list(csv.DictReader(open(tmp_path / "audit" / "audit_items.csv", encoding="utf-8-sig", newline="")))
    assert list(rows[0]) == ["item_id", "case", "sentence", "cited_events", "label", "notes"]
    blob = raw.decode("utf-8").lower()
    for w in ("accepted", "rejected", "ip_not_grounded", "supported", "judge", "template", "dropped", "failure"):
        assert w not in blob, w
    krows = list(csv.DictReader(open(tmp_path / "audit" / "audit_key.csv", encoding="utf-8-sig", newline="")))
    assert {"accepted", "stage", "source", "failure_codes", "judge_verdicts", "hidden_marker"} <= set(krows[0])
    big = next(r for r in rows if "more cited events not shown" in r["cited_events"])
    assert len(big["cited_events"].split(" || ")) == 13 and "AUTH-L1 |" in big["cited_events"] and "raw line" in big["cited_events"]
    assert any(k["failure_codes"] == "IP_NOT_GROUNDED" for k in krows)


# ---------------- 7. audit scorer ----------------
def write_csv(path, rows):
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def test_audit_scorer(tmp_path):
    items = [{"item_id": f"A{i:03d}", "case": "c", "sentence": f"s{i}", "cited_events": "", "label": l, "notes": ""}
             for i, l in enumerate(["S", "S", "S", "P", "U", "S", "U", "", ""], 1)]
    # accepted: 1-5 ; rejected: 6-9
    key = [{"item_id": it["item_id"], "case": "c", "stage": "st", "accepted": "true" if i <= 5 else "false", "source": "llm", "attempt": 0,
            "failure_codes": "JUDGE_PARTIAL", "judge_verdicts": "", "hidden_marker": ""} for i, it in enumerate(items, 1)]
    write_csv(tmp_path / "audit_items.csv", items)
    write_csv(tmp_path / "audit_key.csv", key)
    r = audit_score.score(audit_score.read(tmp_path / "audit_items.csv"), audit_score.read(tmp_path / "audit_key.csv"))
    assert r["refused"] and r["labelling_completeness"] == pytest.approx(7 / 9)  # 78% < 80%
    items2 = [dict(it, label=it["label"] or "U") for it in items]
    r = audit_score.score(items2, key)
    assert r["confusion_matrix"]["accepted"] == {"S": 3, "P": 1, "U": 1} and r["confusion_matrix"]["rejected"] == {"S": 1, "P": 0, "U": 3}
    assert r["precision_accepted_S"]["k"] == 3 and r["precision_accepted_S"]["n"] == 5
    assert r["precision_accepted_S"]["ci_lo"] == pytest.approx(wilson(3, 5)[0])
    assert r["precision_accepted_S_or_P"]["k"] == 4
    assert r["false_rejection_rate"]["k"] == 1 and r["false_rejection_rate"]["n"] == 4 and r["false_rejections"][0]["failure_codes"] == "JUDGE_PARTIAL"
    assert {m["item_id"] for m in r["verifier_misses"]} == {"A004", "A005"} and r["single_labeller"] is True
    few = [dict(it, label="") for it in items]
    few[0]["label"] = "S"
    refused = audit_score.score(few, key)
    assert refused["refused"] and "labelled" in refused["reason"]
    with pytest.raises(SystemExit):
        write_csv(tmp_path / "few.csv", few)
        audit_score.main(["--labels", str(tmp_path / "few.csv"), "--key", str(tmp_path / "audit_key.csv")])


# ---------------- 8. make_results ----------------
def test_make_results_idempotent_with_and_without_audit(tmp_path):
    build_mini(tmp_path)
    o = opts(tmp_path)
    EC.stage_aggregate(o, "_all", {"stages": {}})
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "DEMO.md").write_text("intro\n<!-- RESULTS:START -->\nplaceholder\n<!-- RESULTS:END -->\noutro\n")
    readme = tmp_path / "README.md"
    readme.write_text("hello\n")
    args = ["--eval-dir", str(tmp_path / "eval"), "--docs-dir", str(docs), "--readme", str(readme)]
    MR.main(args)
    a1, b1, c1 = (docs / "RESULTS.md").read_text(), (docs / "DEMO.md").read_text(), readme.read_text()
    assert "audit pending" in a1 and "placeholder" not in b1 and b1.startswith("intro") and b1.endswith("outro\n")
    MR.main(args)
    assert (docs / "RESULTS.md").read_text() == a1 and (docs / "DEMO.md").read_text() == b1 and readme.read_text() == c1
    assert c1.count("Measured results") == 1
    (tmp_path / "eval" / "audit").mkdir()
    (tmp_path / "eval" / "audit" / "audit_scores.json").write_text(json.dumps({
        "refused": False, "items_total": 32, "items_labelled": 32, "single_labeller": True,
        "confusion_matrix": {"accepted": {"S": 20, "P": 3, "U": 1}, "rejected": {"S": 1, "P": 2, "U": 5}},
        "precision_accepted_S": rate(20, 24), "precision_accepted_S_or_P": rate(23, 24), "false_rejection_rate": rate(1, 8),
        "false_rejections": [], "verifier_misses": [{"item_id": "A001", "label": "P", "case": "c", "stage": "s", "sentence": "x"}]}))
    MR.main(args)
    assert "Single labeller" in (docs / "RESULTS.md").read_text() or "single labeller" in (docs / "RESULTS.md").read_text()


# ---------------- 9. role swap bookkeeping ----------------
def test_role_swap_bookkeeping(tmp_path_factory, tmp_path):
    from test_phase5b import harness, make_case
    root = tmp_path_factory.mktemp("swap")
    make_case(root, "case01", "easy", 42)
    res, narr, jl, seq, data, _ = harness(root, tmp_path, narr_model="llama3.1:8b", judge_model="qwen2.5:7b-instruct")
    v = res["verified"]["verification"]
    assert v["narrator_model"] == "llama3.1:8b" and v["judge_model"] == "qwen2.5:7b-instruct" and v["judge_independent"] is True


# ---------------- 10. evaluate CLI delegates ----------------
def test_cli_evaluate_delegates(monkeypatch):
    from evidenceweave import cli
    seen = {}
    import subprocess
    monkeypatch.setattr(subprocess, "call", lambda cmd: seen.setdefault("cmd", cmd) and 7)
    with pytest.raises(SystemExit) as e:
        cli.main(["evaluate", "--resume", "--skip", "raw,swap"])
    assert e.value.code == 7
    assert seen["cmd"][1].endswith("evaluate_cases.py") and seen["cmd"][2:] == ["--resume", "--skip", "raw,swap"]


# ---------------- 11. static checks ----------------
def test_package_never_mentions_answer_key_or_imports_scripts():
    for p in (ROOT / "evidenceweave").rglob("*.py"):
        text = p.read_text(encoding="utf-8")
        if "generator" not in p.parts:  # the generator WRITES the key; nothing that analyses may read it
            assert "answer_key" not in text, p
        assert not re.search(r"^\s*(from|import)\s+scripts\b", text, re.M), p
    assert "answer_key" not in (ROOT / "evidenceweave" / "cli.py").read_text(encoding="utf-8")


def test_eval_seeds_are_new():
    seeds = {s for _, s in EC.CASES.values()}
    assert seeds == {101, 102, 201, 202} and not seeds & {1, 2, 3, 4, 7, 42}
    for p in (ROOT / "tests").glob("test_*.py"):
        if p.name != "test_eval.py":
            assert not re.search(r"seed\W+(101|102|201|202)", p.read_text(encoding="utf-8")), p


# ---------------- 12. docs hold no cross-arm numbers ----------------
def test_readme_and_demo_have_no_cross_arm_numbers():
    demo = (ROOT / "docs" / "DEMO.md").read_text(encoding="utf-8")
    assert "<!-- RESULTS:START -->" in demo and "<!-- RESULTS:END -->" in demo
    outside = re.sub(r"<!-- RESULTS:START -->.*?<!-- RESULTS:END -->", "", demo, flags=re.S)
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for text in (outside, readme):
        for line in text.splitlines():
            if re.search(r"baseline|raw mode|facts mode|chain narrator", line, re.I):
                assert not re.search(r"\d+(\.\d+)?%|\b\d+ of \d+\b|\b\d+/\d+\b|\b0\.\d+\b", line), line
