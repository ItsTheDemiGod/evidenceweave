"""Phase 6a: path grounding, default narration mode, format_ts, deterministic (--no-llm) narrative, HTML report, analyze/report commands.

No test calls real Ollama: clients are fakes (test_phase5b) and the Ollama metadata/tag lookups are stubbed.
"""
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import requests

from evidenceweave import analyze as A
from evidenceweave import cli, runmeta
from evidenceweave.generator.core import generate
from evidenceweave.narrator.llm import LLMError
from evidenceweave.narrator.narrate import NarratorConfig
from evidenceweave.report import build_report, render_html
from evidenceweave.report.build import build_data
from evidenceweave.schema import Event, format_ts
from evidenceweave.verifier import runner
from evidenceweave.verifier import verdicts as V
from evidenceweave.verifier.entities import build_pool, check_entities, extract_paths
from evidenceweave.verifier.judge import ClaimJudge

from test_phase5b import FactNarr, FClaimLLM, make_case

ROOT = Path(__file__).resolve().parent.parent
T0 = datetime(2026, 10, 27, 2, 15, 7, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Ollama metadata lookups fail fast; the model check is a no-op unless a test replaces it."""
    monkeypatch.setattr(runmeta.requests, "get", lambda *a, **k: (_ for _ in ()).throw(requests.ConnectionError("down")))
    monkeypatch.setattr(A, "check_models", lambda models, url=None: None)
    monkeypatch.setattr(A, "open_report", lambda p: None)


def ev(eid, text, host="web01", n=1, fname="linux_auth.log", action="ssh_login_success", src="auth", **kw):
    return Event(eid, kw.get("ts", T0), kw.get("raw_ts", kw.get("ts", T0)), False, host, kw.get("user"), kw.get("src_ip"), None, src,
                 action, fname, n, text, kw.get("extra", {}))


# ================= Part A: path grounding / defaults / format_ts =================
def codes(text, *events):
    return [r["code"] for r in check_entities(text, build_pool(list(events)))["reasons"]]


def test_path_in_cited_event_passes_and_invented_path_fails():
    e = ev("AUTH-L1", "sudo: deploy : COMMAND=/usr/bin/tar -czf /tmp/data.tar.gz /var/www", action="sudo_command")
    assert V.PATH_NOT_GROUNDED not in codes("It archived /var/www into /tmp/data.tar.gz.", e)
    assert codes("It archived /var/www into /tmp/other.tar.gz.", e) == [V.PATH_NOT_GROUNDED]
    assert V.PATH_NOT_GROUNDED in codes("It read /etc/shadow.", e)
    assert V.PATH_NOT_GROUNDED in codes("It ran evil.sh once.", e)  # bare file name with a known extension
    assert V.PATH_NOT_GROUNDED not in codes("It wrote data.tar.gz.", e)


def test_not_paths_and_nginx_and_windows_paths():
    e = ev("AUTH-L1", "x")
    for t in ("The and/or case happened on 10/27.", "It fetched http://203.0.113.45:8080/x.sh quickly.", "Requests to /login failed."):
        assert V.PATH_NOT_GROUNDED not in codes(t, ev("AUTH-L1", "http://203.0.113.45:8080/x.sh GET /login"))
    assert extract_paths("and/or on 10/27 at 2026/10") == []
    n = ev("NGX-L2", '203.0.113.45 - - "GET /login HTTP/1.1" 200 5', fname="nginx_access.log", src="nginx", action="web_request")
    assert V.PATH_NOT_GROUNDED not in codes("The attacker requested /login.php and /admin/config.", n.__class__(**{**n.__dict__, "raw_text": n.raw_text + " /login.php /admin/config"}))
    w = ev("WIN-L3", '{"Image": "C:\\\\Windows\\\\System32\\\\cmd.exe"}', fname="windows_events.jsonl", src="windows", action="win_process_created",
           extra={"Image": "C:\\Windows\\System32\\cmd.exe"})
    assert V.PATH_NOT_GROUNDED not in codes("It started C:\\Windows\\System32\\cmd.exe now.", w)
    assert codes("It started C:\\Temp\\evil.exe now.", w).count(V.PATH_NOT_GROUNDED) >= 1


def test_library_default_narration_mode_is_facts():
    assert NarratorConfig().mode == "facts"
    assert NarratorConfig(mode="raw").mode == "raw"


def test_format_ts():
    assert format_ts(T0) == "2026-10-27T02:15:07Z"
    assert format_ts(T0 + timedelta(milliseconds=510)) == "2026-10-27T02:15:07Z"  # whole seconds
    assert format_ts(datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone(timedelta(hours=2)))) == "2026-01-02T01:04:05Z"


# ================= hand-made case for the report builder =================
INJ = '</script><script>alert(1)</script><img src=x onerror=alert(2)><!-- evil -->'


def handmade(root: Path, inject: bool = False, no_llm: bool = False, narrative: bool = True, independent: bool = True) -> Path:
    out = root / "caseH"
    out.mkdir(parents=True)
    bad = INJ if inject else "ordinary"
    ts = lambda m, s=0: T0 + timedelta(minutes=m, seconds=s)
    events = [ev(f"AUTH-L{i}", f"line {i} {bad if i == 4 else 'text'}", n=i, ts=ts(i)) for i in range(1, 9)]
    events.append(ev("AUTH-L9", "Accepted password for deploy", n=9, ts=ts(10), raw_ts=ts(10, 90), user="deploy"))
    events.append(ev("NGX-L2", f'203.0.113.99 "GET /x HTTP/1.1" 404 {bad} http://evil.test/{bad}', host="web01", n=2,
                     fname="nginx_access.log", src="nginx", action="web_request", ts=ts(30)))
    (out / "events.jsonl").write_text("\n".join(json.dumps(e.to_dict()) for e in events) + "\n", encoding="utf-8")
    iso = lambda m: format_ts(ts(m)).replace("Z", "Z")
    ent = lambda **k: {"ips": [bad if inject else "203.0.113.45"], "users": ["deploy"], "hosts": ["web01"], "urls": [f"http://evil.test/{bad}"], **k}
    findings = [{"finding_id": "F-a-1", "rule": "initial_access", "entities": ent()}, {"finding_id": "F-b-1", "rule": "persistence", "entities": ent()}]
    stage = lambda name, st, a, b, ids, fid: {"stage": name, "status": st, "start_time": iso(a), "end_time": iso(b), "finding_ids": [fid],
                                              "evidence_event_ids": ids, "links": []}
    chain = {"case_name": "caseH", "generated_by_version": "1.0.0", "config": {"cross_host_tolerance_seconds": 300, "brute_force_min_failures": 8},
             "applied_clock_offsets": {"ws-fin01": 90}, "attacker_entities": {},
             # deliberately NOT in chronological order
             "stages": [stage("persistence", "partial", 20, 25, ["AUTH-L9"], "F-b-1"),
                        stage("brute_force", "confirmed", 1, 8, ["AUTH-L1", "AUTH-L4"], "F-a-1"),
                        stage("initial_access", "confirmed", 10, 10, ["AUTH-L9"], "F-a-1")],
             "attempts_only_actors": [{"ip": "198.51.100.23", "stages": ["web_recon"], "finding_ids": [], "evidence_event_ids": ["NGX-L2"],
                                       "first_seen": iso(30), "last_seen": iso(31), "statement": "No successful access from 198.51.100.23 was observed."}],
             "unprovable_items": [{"finding_id": "F-b-2", "affects_stage": "persistence", "summary": "Account svc_backup was never created in the logs.",
                                   "users": ["svc_backup"], "hosts": ["web01"], "evidence_event_ids": ["AUTH-L9", "AUTH-L3"]}],
             "unlinked_findings": [], "notes": [], "stats": {"events_read": 10, "findings_per_rule": {"initial_access": 1}}}
    (out / "chain.json").write_text(json.dumps(chain), encoding="utf-8")
    (out / "findings.json").write_text(json.dumps({"findings": findings}), encoding="utf-8")
    if narrative:
        src = "deterministic" if no_llm else "llm"
        fact = lambda st, c: [{"fact_id": f"{st}-F1", "text": f"Fact for {st} {bad}.", "cites": c, "kind": "time_window"}]
        sent = lambda text, c, s=src: {"text": text, "cites": c, "source": s, "attempt": 0, "fact_ids": []}
        nv = {"case_name": "caseH", "narration_mode": "facts",
              "executive_summary": [sent(f"Summary {bad}", ["AUTH-L9"])],
              "stages": [{"stage": "persistence", "facts": fact("persistence", ["AUTH-L9"]), "sentences": [sent("Persist sentence.", ["AUTH-L9"])]},
                         {"stage": "brute_force", "facts": fact("brute_force", ["AUTH-L1", "AUTH-L4"]),
                          "sentences": [sent(f"Brute {bad}", ["AUTH-L4"]), sent("Plain fact.", ["AUTH-L1"], "template_fallback" if not no_llm else "deterministic")]},
                         {"stage": "initial_access", "facts": fact("initial_access", ["AUTH-L9"]), "sentences": []}],
              "attempts_only": [sent("198.51.100.23 made 3 web requests; no successful access from this address was observed.", ["NGX-L2"], "template")],
              "unprovable": [sent("It could not be proven how this happened.", ["AUTH-L9", "AUTH-L3"], "template")],
              "verification": {"mode": "chain", "judge_model": None if no_llm else "judge-m", "narrator_model": None if no_llm else "narr-m",
                               "judge_independent": False if no_llm else independent, "judge_double": not no_llm, "no_llm": no_llm,
                               "accepted_total": 5, "dropped_total": 1, "fallback_units": []},
              "run_metadata": {"model_digests": {"narr-m": "abc123"}, "ollama_version": "0.9.9"}}
        (out / "narrative_verified.json").write_text(json.dumps(nv), encoding="utf-8")
        (out / "verification_report.json").write_text(json.dumps({"total_seconds": 1.0, "summary": {"judge_agreement_rate": 0.9, "repair_effectiveness": {
            "failing_at_attempt0": 2, "fixed_total": 1, "still_failing": 1}}}), encoding="utf-8")
    return out


def html_of(out):
    return render_html(build_data(out, None, "2026-10-28T00:00:00Z"))


def test_report_sections_order_and_status_labels(tmp_path):
    h = html_of(handmade(tmp_path))
    for sec in ("sec-header", "sec-summary", "sec-timeline", "sec-executive", "sec-stages", "sec-attempts", "sec-unprovable", "sec-method"):
        assert f'id="{sec}"' in h, sec
    order = [m for m in re.findall(r'id="stage-(\w+)"', h)]
    assert order == ["brute_force", "initial_access", "persistence"]  # chronological, not input order
    assert re.search(r'class="status confirmed">[^<]*confirmed', h) and re.search(r'class="status partial">[^<]*partial', h)
    assert "attempts only" in h and "Established facts (deterministic)" in h and "Narrative (verified sentences)" in h
    assert "Compromise confirmed: 2 of 3 stages established, 1 stage partially unprovable" in h
    assert "ws-fin01=90s" in h and "2026-10-27T02:16:07Z" in h  # applied offsets + format_ts display


def test_self_contained(tmp_path):
    h = html_of(handmade(tmp_path))
    assert not re.search(r'\b(?:src|href)\s*=\s*["\']?\s*(?:https?:)?//', h, re.I)
    assert "<link" not in h.lower() and "@import" not in h and "<iframe" not in h.lower()
    assert not re.search(r"url\(\s*[\"']?(?:https?:)?//", h)
    assert "<a " not in h and h.count("<script") == 2


def test_injection_is_inert(tmp_path):
    out = handmade(tmp_path, inject=True)
    h = html_of(out)
    for needle in ("<script>alert(1)", "<img", "<!-- evil", "</script><script"):
        assert needle not in h, needle
    assert h.count("<script") == 2 and h.count("</script") == 2 and "<!--" not in h
    assert "&lt;img src=x onerror=alert(2)&gt;" in h or "\\u003cimg" in h
    blob = re.search(r'<script type="application/json" id="ew-data">(.*?)</script>', h, re.S).group(1)
    assert "<" not in blob and ">" not in blob and "&" not in blob
    data = json.loads(blob)  # the escaped JSON still decodes to the exact hostile text
    assert INJ in data["evidence"]["AUTH-L4"]["text"]
    assert "innerHTML" not in h and "insertAdjacentHTML" not in h and "document.write" not in h
    assert 'href="http' not in h  # payload URLs are plain text


def test_evidence_index_resolves_and_context(tmp_path):
    out = handmade(tmp_path)
    h = html_of(out)
    data = json.loads(re.search(r'id="ew-data">(.*?)</script>', h, re.S).group(1))
    chips = set(re.findall(r'class="cite" data-id="([^"]+)"', h))
    assert chips and chips <= set(data["evidence"])
    for i, e in data["evidence"].items():
        assert e["file"] and e["line"] and e["text"]
        assert re.fullmatch(r"AUTH-L(\d+)|NGX-L(\d+)", i) and int(i.split("-L")[1]) == e["line"]
        assert len(e["context"]) <= 6
        for c in e["context"]:
            assert c["event_id"].split("-")[0] == i.split("-")[0] and c["rel"] != 0 and abs(c["rel"]) <= 3 and c["event_id"] != i
    l4 = data["evidence"]["AUTH-L4"]
    assert [c["rel"] for c in l4["context"]] == [-3, -2, -1, 1, 2, 3]
    assert data["evidence"]["AUTH-L9"]["raw_timestamp"] == "2026-10-27T02:26:37Z" and data["evidence"]["AUTH-L9"]["timestamp"] == "2026-10-27T02:25:07Z"
    # the drawer script marks the cited line and labels the others as context
    assert 'ctx" + (c.hit ? " hit"' in h and "cited ▶" in h and "context  " in h


def test_determinism(tmp_path):
    out = handmade(tmp_path)
    a, b = html_of(out), html_of(out)
    assert a == b and a.encode() == b.encode()
    p1 = build_report(out, None, "2026-10-28T00:00:00Z").read_bytes()
    assert p1 == build_report(out, None, "2026-10-28T00:00:00Z").read_bytes()


def test_badges_and_banners(tmp_path):
    h = html_of(handmade(tmp_path / "a"))
    assert 'class="badge"' in h and ">LLM + verified<" in h and ">deterministic<" in h and ">template<" in h
    assert "NOT independent" not in h and "WITHOUT the LLM" not in h and "narrative_verified.json was not found" not in h
    n = html_of(handmade(tmp_path / "b", no_llm=True))
    assert "WITHOUT the LLM and WITHOUT the independent judge" in n and ">LLM + verified<" not in n and ">deterministic<" in n
    same = html_of(handmade(tmp_path / "c", independent=False))
    assert "NOT independent" in same


def test_missing_narrative_notice(tmp_path, monkeypatch):
    root = tmp_path / "gen"
    make_case(root, "case01", "easy", 42)
    out = root / "out" / "case01"
    monkeypatch.setattr(A, "open_report", lambda p: None)
    cli.main(["report", "--case-dir", str(root / "cases" / "case01"), "--out", str(root / "out"), "--no-open"])
    h = (out / "report.html").read_text(encoding="utf-8")
    assert "narrative_verified.json was not found" in h and "No verified narrative available for this stage" in h
    assert 'class="cite"' in h  # facts still carry cite chips


# ================= generated cases: analyze / report =================
def fake_clients(seq=None, narr_model="narr-m", judge_model="judge-m"):
    made = {}

    def build(model, judge_name, num_ctx, no_judge, single):
        narr = FactNarr(None, model, seq)
        made["narr"], made["judge_llm"] = narr, FClaimLLM(None, judge_name, seq)
        return narr, ClaimJudge(made["judge_llm"], double=not single)

    return build, made


def run_analyze(tmp_path, case, diff, seed, extra=(), build=None, monkeypatch=None):
    cases = tmp_path / "cases"
    if not (cases / case).exists():
        generate(case, diff, seed, cases)
    argv = ["analyze", "--case-dir", str(cases / case), "--out", str(tmp_path / "out"), "--no-open", *extra]
    cli.main(argv)
    return tmp_path / "out" / case


@pytest.mark.parametrize("case,diff,seed", [("case01", "easy", 42), ("case02", "hard", 7)])
def test_analyze_with_fakes_end_to_end(tmp_path, monkeypatch, case, diff, seed):
    seq = []
    build, made = fake_clients(seq)
    monkeypatch.setattr(runner, "build_clients", build)
    out = run_analyze(tmp_path, case, diff, seed)
    for f in ("events.jsonl", "findings.json", "chain.json", "narrative.json", "narrative_verified.json", "verification_report.json", "report.html"):
        assert (out / f).exists(), f
    runs = [k for i, k in enumerate(seq) if i == 0 or seq[i - 1] != k]
    assert runs == ["narrator", "judge"]  # batched: all narrator calls, then all judge calls (faithful fake => no repair rounds)
    assert len(made["narr"].calls) == 7
    h = (out / "report.html").read_text(encoding="utf-8")
    assert ">LLM + verified<" in h and "WITHOUT the LLM" not in h
    ver = json.loads((out / "narrative_verified.json").read_text())["verification"]
    assert ver["judge_independent"] is True and ver["narrator_model"] == "qwen2.5:7b-instruct"


def test_analyze_repair_rounds_stay_batched(tmp_path, monkeypatch):
    seq = []
    n_calls = []

    def build(model, judge_name, num_ctx, no_judge, single):
        def handler(system, user, options, no):
            if "REPAIR:" not in user:
                from test_phase5b import bad_sentence, parse_facts
                if "STAGE: brute_force" in user:
                    return json.dumps({"sentences": [bad_sentence(user)]})
            return None
        return FactNarr(handler, model, seq), ClaimJudge(FClaimLLM(None, judge_name, seq))

    monkeypatch.setattr(runner, "build_clients", lambda m, j, c, nj, sj: build(m, j, c, nj, sj))
    run_analyze(tmp_path, "case01", "easy", 42)
    runs = [k for i, k in enumerate(seq) if i == 0 or seq[i - 1] != k]
    assert runs[:4] == ["narrator", "judge", "narrator", "judge"] and len(runs) <= 2 * 3  # <= round 0 + 2 repair rounds


def test_analyze_no_llm_makes_zero_llm_calls(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("an LLM client was constructed in --no-llm mode")

    monkeypatch.setattr(runner, "build_clients", boom)
    monkeypatch.setattr(A, "check_models", boom)
    monkeypatch.setattr("evidenceweave.narrator.llm.OllamaClient", boom)
    monkeypatch.setattr(runmeta, "collect", boom)
    out = run_analyze(tmp_path, "case02", "hard", 7, extra=("--no-llm",))
    h = (out / "report.html").read_text(encoding="utf-8")
    assert "WITHOUT the LLM and WITHOUT the independent judge" in h and ">LLM + verified<" not in h and ">template<" in h
    nv = json.loads((out / "narrative_verified.json").read_text())
    srcs = {s["source"] for st in nv["stages"] for s in st["sentences"]} | {s["source"] for s in nv["executive_summary"]}
    assert srcs == {"deterministic"} and nv["verification"]["no_llm"] and nv["verification"]["judge_model"] is None
    assert nv["verification"]["accepted_total"] > 0 and nv["verification"]["dropped_total"] == 0
    rep = json.loads((out / "verification_report.json").read_text())
    assert all(v["layer_results"]["judge"]["passed"] == "skipped" for v in rep["verdicts"])


def test_analyze_reuse(tmp_path, monkeypatch, capsys):
    seq = []
    build, made = fake_clients(seq)
    monkeypatch.setattr(runner, "build_clients", build)
    out = run_analyze(tmp_path, "case01", "easy", 42)
    n = len(seq)
    assert n > 0
    # chain.json older than the verified outputs -> skip narrate + verify
    old = out / "chain.json"
    for f in ("narrative_verified.json", "verification_report.json"):
        os.utime(out / f, (old.stat().st_mtime + 50,) * 2)
    run_analyze(tmp_path, "case01", "easy", 42, extra=("--reuse",))
    assert len(seq) == n and "--reuse applied" in capsys.readouterr().out
    # chain.json newer -> re-run
    os.utime(old, (old.stat().st_mtime + 500,) * 2)
    run_analyze(tmp_path, "case01", "easy", 42, extra=("--reuse",))
    assert len(seq) > n
    # without --reuse always re-runs
    m = len(seq)
    run_analyze(tmp_path, "case01", "easy", 42)
    assert len(seq) > m


def test_report_command_does_no_pipeline_work(tmp_path, monkeypatch):
    seq = []
    build, _ = fake_clients(seq)
    monkeypatch.setattr(runner, "build_clients", build)
    out = run_analyze(tmp_path, "case02", "hard", 7)
    n = len(seq)
    (out / "report.html").unlink()
    import evidenceweave.correlation.engine as eng
    import evidenceweave.parsers.pipeline as pp

    def boom(*a, **k):
        raise AssertionError("pipeline work in report command")

    for mod, name in ((eng, "correlate_case"), (pp, "parse_case"), (runner, "build_clients")):
        monkeypatch.setattr(mod, name, boom)
    cli.main(["report", "--case-dir", str(tmp_path / "cases" / "case02"), "--out", str(tmp_path / "out"), "--no-open"])
    assert (out / "report.html").exists() and len(seq) == n


def test_ollama_unreachable_gives_fix_and_no_llm_hint(tmp_path, monkeypatch):
    def down(models, url=None):
        raise LLMError("Ollama is not reachable at http://localhost:11434 (ConnectionError). Start it with: ollama serve")

    monkeypatch.setattr(A, "check_models", down)
    with pytest.raises(SystemExit) as e:
        run_analyze(tmp_path, "case01", "easy", 42)
    msg = str(e.value)
    assert "ollama serve" in msg and "--no-llm" in msg
    # a failure during the narrator call (server dies mid-run) gets the same treatment
    monkeypatch.setattr(A, "check_models", lambda m, url=None: None)

    class Dead(FactNarr):
        def complete(self, *a, **k):
            raise LLMError("Model 'x' is not installed. Run: ollama pull x")

    monkeypatch.setattr(runner, "build_clients", lambda m, j, c, nj, sj: (Dead(None, m), ClaimJudge(FClaimLLM(None, j))))
    with pytest.raises(SystemExit) as e2:
        run_analyze(tmp_path, "case01", "easy", 42)
    assert "ollama pull x" in str(e2.value) and "--no-llm" in str(e2.value)


def test_decoy_in_attempts_lane_and_unprovable_section(tmp_path):
    out = run_analyze(tmp_path, "case02", "hard", 7, extra=("--no-llm",))
    chain = json.loads((out / "chain.json").read_text())
    decoys = [a["ip"] for a in chain["attempts_only_actors"]]
    assert decoys  # derived from the chain, not from any key
    h = (out / "report.html").read_text(encoding="utf-8")
    data = json.loads(re.search(r'id="ew-data">(.*?)</script>', h, re.S).group(1))
    assert [a["ip"] for a in data["attempts_only"]] == decoys
    stage_names = {s["stage"] for s in data["stages"]}
    for ip in decoys:
        assert all(ip not in s["entities"]["ips"] for s in data["stages"])
        assert f'data-actor="{ip}"' in h and f'data-stage="{ip}"' not in h
    att = h.split('id="sec-attempts"')[1].split('id="sec-unprovable"')[0]
    assert all(ip in att for ip in decoys) and "no successful access" in att.lower()
    unp = h.split('id="sec-unprovable"')[1].split('id="sec-method"')[0]
    assert chain["unprovable_items"] and all(u["summary"].split()[1] in unp for u in chain["unprovable_items"])
    assert "svc_backup" in unp and "persistence" in stage_names


# ================= docs, static checks =================
def test_docs_exist():
    assert (ROOT / "README.md").exists() and (ROOT / "scripts" / "demo.ps1").exists()
    demo = (ROOT / "docs" / "DEMO.md").read_text(encoding="utf-8")
    for needle in ("Timed script", "Backup plan", "Pre-demo checklist", "Likely questions", "Results (filled in Phase 6b)"):
        assert needle in demo, needle
    assert len(re.findall(r"^\d+\. \*\*", demo.split("Likely questions")[1], re.M)) >= 12
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for needle in ("analyze", "report", "--no-llm", "Limitations"):
        assert needle in readme


def test_static_no_answer_key_and_no_generator_import():
    for p in (ROOT / "evidenceweave").rglob("*.py"):
        if "generator" in p.parts:
            continue
        txt = p.read_text(encoding="utf-8")
        assert "answer_key" not in txt, p
    for p in (ROOT / "evidenceweave" / "report").glob("*.*"):
        txt = p.read_text(encoding="utf-8")
        assert "evidenceweave.generator" not in txt and "from ..generator" not in txt and "answer_key" not in txt, p
    assert "answer_key" not in (ROOT / "evidenceweave" / "analyze.py").read_text(encoding="utf-8")
