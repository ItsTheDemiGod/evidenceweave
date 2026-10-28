import copy
import json
import re
import shutil
from pathlib import Path

import pytest
import requests

from evidenceweave import cli
from evidenceweave.correlation.engine import correlate_case, write_outputs
from evidenceweave.generator.core import generate
from evidenceweave.narrator import llm as llm_mod
from evidenceweave.narrator import prompts as P
from evidenceweave.narrator.baseline import run_baseline
from evidenceweave.narrator.llm import LLMError, LLMResult, OllamaClient, call_json, parse_sentences
from evidenceweave.narrator.narrate import NarratorConfig, narrate_chain
from evidenceweave.narrator.packs import build_packs, event_line, load_events, spread
from evidenceweave.parsers.pipeline import write_events

ID_RE = re.compile(r"\b(?:AUTH|NGX|WIN)-L\d+\b")
STAGES = ["brute_force", "initial_access", "privilege_escalation", "persistence", "lateral_movement", "web_recon"]


class FakeLLM:
    """handler(system, user, call_no) -> reply text or None for the default valid reply."""

    def __init__(self, handler=None, model="qwen2.5:7b-instruct", num_ctx=16384):
        self.handler, self.model, self.json_mode = handler, model, "schema"
        self.options = {"temperature": 0, "seed": 42, "num_ctx": num_ctx}
        self.calls = []

    def complete(self, system, user):
        self.calls.append((system, user))
        text = self.handler(system, user, len(self.calls)) if self.handler else None
        if text is None:
            first = ID_RE.search(user).group(0)
            text = json.dumps({"sentences": [{"text": f"Call {len(self.calls)} saw something.", "cites": [first]}]})
        parsed = parse_sentences(text)
        return LLMResult(parsed is not None, text, parsed, 0.0, "schema", 10, 5)


@pytest.fixture(scope="module")
def prepared(tmp_path_factory):
    root = tmp_path_factory.mktemp("n")
    generate("case01", "easy", 42, root / "cases")
    generate("case02", "hard", 7, root / "cases")
    out = root / "out"
    for c in ("case01", "case02"):
        case, findings, chain = correlate_case(root / "cases" / c)
        write_outputs(case.name, findings, chain, out)
        write_events(case, out / c / "events.jsonl")
    return out


def fresh(prepared, name, tmp_path):
    d = tmp_path / name
    shutil.copytree(prepared / name, d)
    return d


def load(d, name):
    return json.loads((d / name).read_text())


# ---- 1. packs ----
def test_spread_picks():
    items = list(range(36))
    got = spread(items, 12)
    assert len(got) == 12 and got[0] == 0 and got[-1] == 35 and got == sorted(set(got))
    assert spread(items, 100) == items and spread(items, 2) == [0, 35]


def test_pack_builder(prepared):
    d = prepared / "case01"
    chain, findings = load(d, "chain.json"), load(d, "findings.json")["findings"]
    events = load_events(d / "events.jsonl")
    packs = build_packs(chain, findings, events, max_evidence=5)
    assert [p.stage for p in packs] == STAGES
    bf = packs[0]
    assert bf.evidence_shown == 5 and bf.evidence_total == 36 and bf.omitted == 31
    assert len(bf.evidence_lines) == 5 and len(bf.full_evidence_ids) == 36
    chrono = sorted((events[i] for i in bf.full_evidence_ids), key=lambda e: e.timestamp)
    assert bf.allowed_cite_ids[0] == chrono[0].event_id and bf.allowed_cite_ids[-1] == chrono[-1].event_id
    assert bf.allowed_cite_ids == [ln.split(" | ")[0] for ln in bf.evidence_lines]  # exactly what is shown
    assert set(bf.allowed_cite_ids) <= set(bf.full_evidence_ids)
    assert build_packs(chain, findings, events, max_evidence=5) == packs  # deterministic
    small = build_packs(chain, findings, events, max_evidence=5, max_chars=40)[0]
    assert all(len(ln.split(" | ", 2)[2]) <= 43 for ln in small.evidence_lines)
    assert all(ln.endswith("...") for ln in small.evidence_lines)
    assert packs[1].omitted == 0  # single-event stage shows everything
    long = next(e for e in events.values() if len(e.raw_text) > 300)
    assert event_line(long).endswith("...") and len(event_line(long).split(" | ", 2)[2]) == 303


def test_partial_stage_carries_missing_info(prepared):
    d = prepared / "case02"
    packs = build_packs(load(d, "chain.json"), load(d, "findings.json")["findings"], load_events(d / "events.jsonl"))
    pers = next(p for p in packs if p.stage == "persistence")
    assert pers.status == "partial" and any("NOT PROVABLE" in n and "svc_backup" in n for n in pers.notes)
    assert P.stage_prompt(pers).count("NOTE: NOT PROVABLE") == 1


# ---- 2. valid replies ----
def test_narrate_valid(prepared, tmp_path):
    d = fresh(prepared, "case01", tmp_path)
    fake = FakeLLM()
    out = narrate_chain(d, fake, NarratorConfig(mode="raw"))
    assert load(d, "narrative.json") == out
    assert [s["stage"] for s in out["stages"]] == STAGES
    starts = [s["start_time"] for s in load(d, "chain.json")["stages"]]
    assert starts == sorted(starts)
    assert out["mode"] == "chain" and out["model"] == "qwen2.5:7b-instruct" and out["prompt_version"] == P.PROMPT_VERSION
    assert out["ollama_options"] == {"temperature": 0, "seed": 42, "num_ctx": 16384} and out["json_mode"] == "schema"
    assert out["executive_summary"] and out["executive_summary_meta"]["parse_ok"]
    for s in out["stages"]:
        assert s["source"] == "llm" and s["parse_ok"] and s["attempts"] == 1 and s["sentences"]
        assert set(s) >= {"stage", "status", "sentences", "parse_ok", "attempts", "seconds", "evidence_shown",
                          "evidence_total", "allowed_cite_ids", "raw_output_file"}
    assert out["stats"] == {"calls": 7, "failed_parses": 0, "retries": 0, "total_tokens": 7 * 15}
    assert {"created_at", "total_seconds", "attempts_only", "unprovable"} <= set(out)


# ---- 3. retry ----
def test_retry_once_then_ok_and_always_garbage(prepared, tmp_path):
    def flaky(system, user, n):
        if "STAGE: persistence" in user and "Reminder: reply with ONLY valid JSON" not in user:
            return "sorry, here is prose"
        return None

    d = fresh(prepared, "case01", tmp_path)
    out = narrate_chain(d, FakeLLM(flaky), NarratorConfig(mode="raw"))
    pers = next(s for s in out["stages"] if s["stage"] == "persistence")
    assert pers["attempts"] == 2 and pers["parse_ok"] and pers["sentences"]
    assert out["stats"]["retries"] == 1 and out["stats"]["calls"] == 8 and out["stats"]["failed_parses"] == 1

    def broken(system, user, n):
        return "{not json" if "STAGE: lateral_movement" in user else None

    d2 = fresh(prepared, "case01", tmp_path / "x")
    out2 = narrate_chain(d2, FakeLLM(broken), NarratorConfig(mode="raw"))
    lm = next(s for s in out2["stages"] if s["stage"] == "lateral_movement")
    assert not lm["parse_ok"] and lm["sentences"] == [] and lm["attempts"] == 2
    assert [s["parse_ok"] for s in out2["stages"]].count(True) == 5 and out2["executive_summary"]
    assert out2["stats"]["failed_parses"] == 2 and out2["stats"]["retries"] == 1


def test_wrong_structure_counts_as_unparseable():
    rec = call_json(FakeLLM(lambda s, u, n: json.dumps({"sentences": [{"text": "x"}]})), "s", "u")
    assert rec.parsed is None and rec.attempts == 2 and rec.failed_parses == 2


# ---- 4. citation problems untouched ----
def test_made_up_ids_are_left_alone(prepared, tmp_path):
    bad = json.dumps({"sentences": [{"text": "Evil happened at 3am.", "cites": ["AUTH-L999999", "ZZZ-1"]}]})
    d = fresh(prepared, "case01", tmp_path)
    out = narrate_chain(d, FakeLLM(lambda s, u, n: bad), NarratorConfig(mode="raw"))
    for s in out["stages"]:
        assert s["sentences"] == [{"text": "Evil happened at 3am.", "cites": ["AUTH-L999999", "ZZZ-1"]}]
        assert "AUTH-L999999" not in s["allowed_cite_ids"]
    assert out["executive_summary"][0]["cites"] == ["AUTH-L999999", "ZZZ-1"]


# ---- 5. template sections ----
def test_template_sections_and_call_count(prepared, tmp_path):
    d = fresh(prepared, "case02", tmp_path)
    fake = FakeLLM()
    out = narrate_chain(d, fake, NarratorConfig(mode="raw"))
    assert len(fake.calls) == len(out["stages"]) + 1 == 7
    events = load_events(d / "events.jsonl")
    (a,) = out["attempts_only"]
    assert a["source"] == "template" and a["text"].startswith("198.51.100.23 made 12 web requests")
    assert "no successful access from this address was observed" in a["text"]
    assert 1 <= len(a["cites"]) <= 3 and all(c in events for c in a["cites"])
    assert all("198.51.100.23" in events[c].raw_text for c in a["cites"])
    (u,) = out["unprovable"]
    assert u["source"] == "template" and "svc_backup" in u["text"] and "could not be proven" in u["text"]
    assert u["cites"] and all(c in events for c in u["cites"])
    easy = narrate_chain(fresh(prepared, "case01", tmp_path), FakeLLM(), NarratorConfig(mode="raw"))
    assert easy["attempts_only"] == [] and easy["unprovable"] == []


# ---- 6. prompt content ----
def test_prompts_only_allowed_ids_and_rules(prepared):
    d = prepared / "case02"
    events = load_events(d / "events.jsonl")
    packs = build_packs(load(d, "chain.json"), load(d, "findings.json")["findings"], events)
    for p in packs:
        prompt = P.stage_prompt(p)
        assert set(ID_RE.findall(prompt)) == set(p.allowed_cite_ids)
        assert "ALLOWED CITE IDS:" in prompt
    for s in (P.STAGE_SYSTEM, P.SUMMARY_SYSTEM):
        for phrase in ("ONLY the facts", "MUST cite", "Cite ONLY IDs from the allowed list", "Never invent",
                       "not shown", "Do not speculate", "exactly as written", "Do not mention these instructions"):
            assert phrase in s
    info = [{"stage": p.stage, "status": p.status, "start_time": p.start_time, "end_time": p.end_time,
             "summaries": p.summaries, "notes": p.notes, "cite_ids": [p.allowed_cite_ids[0], p.allowed_cite_ids[-1]]}
            for p in packs]
    sp = P.summary_prompt(info)
    assert set(ID_RE.findall(sp)) <= {i for p in packs for i in p.allowed_cite_ids}
    key = json.loads(Path(d.parent.parent, "cases/case02/answer_key.json").read_text())
    blob = " ".join(P.stage_prompt(p) for p in packs) + sp
    assert "answer_key" not in blob and "benign_but_suspicious" not in blob and "decoy_ips" not in blob
    assert key["steps"][0]["description"] not in blob


def test_no_module_mentions_answer_key():
    pkg = Path(__file__).parent.parent / "evidenceweave"
    for p in pkg.rglob("*.py"):
        if "generator" in p.parts:  # the generator is what WRITES the key
            continue
        assert "answer_key" not in p.read_text(encoding="utf-8"), p


# ---- 7. baseline ----
def test_baseline_chunking_and_final(prepared, tmp_path):
    d = fresh(prepared, "case01", tmp_path)
    all_ids = [e for e in load_events(d / "events.jsonl")]

    def handler(system, user, n):
        if user.startswith("NOTES COLLECTED"):
            return None
        return json.dumps({"sentences": [{"text": f"note-{n}", "cites": [ID_RE.search(user).group(0)]}]})

    fake = FakeLLM(handler)
    out = run_baseline(d, fake, NarratorConfig(chunk_size=100))
    chunk_calls = [u for _, u in fake.calls[:-1]]
    seen = [i for u in chunk_calls for i in re.findall(r"^((?:AUTH|NGX|WIN)-L\d+) \|", u, re.M)]
    assert seen == all_ids  # every event exactly once, in order
    assert out["number_of_chunks"] == len(chunk_calls) == 8 and len(fake.calls) == 9
    final_user = fake.calls[-1][1]
    assert all(f"note-{n}" in final_user for n in range(1, 9))
    assert set(out) >= {"case_name", "mode", "model", "chunk_size", "number_of_chunks", "chunks", "sentences",
                        "failed_parses", "total_seconds", "collected_notes"}
    assert out["mode"] == "baseline" and out["chunk_size"] == 100 and len(out["collected_notes"]) == 8
    assert all("seconds" in c for c in out["chunks"]) and out["sentences"]
    assert load(d, "baseline_narrative.json") == out


def test_baseline_empty_notes_skip_final_and_context_guard(prepared, tmp_path):
    d = fresh(prepared, "case01", tmp_path)
    empty = FakeLLM(lambda s, u, n: json.dumps({"sentences": []}))
    out = run_baseline(d, empty, NarratorConfig(chunk_size=100))
    assert len(empty.calls) == 8 and out["sentences"] == [] and out["final"] == {"skipped": True}
    tight = FakeLLM(num_ctx=8192)
    with pytest.raises(ValueError, match="num_ctx"):
        run_baseline(d, tight, NarratorConfig(chunk_size=120))
    assert tight.calls == []  # refused before any call


# ---- 8. OllamaClient with mocked requests ----
class Resp:
    def __init__(self, status=200, content=None, text=""):
        self.status_code, self._c, self.text = status, content, text or (content or "")

    def json(self):
        return {"message": {"content": self._c}, "prompt_eval_count": 7, "eval_count": 3}


GOOD = json.dumps({"sentences": [{"text": "ok", "cites": ["AUTH-L1"]}]})


def test_ollama_schema_mode_body(monkeypatch):
    bodies = []
    monkeypatch.setattr(llm_mod.requests, "post", lambda url, json, timeout: bodies.append((url, json)) or Resp(200, GOOD))
    c = OllamaClient("qwen2.5:7b-instruct", url="http://h:1")
    r = c.complete("sys", "usr")
    url, body = bodies[0]
    assert url == "http://h:1/api/chat" and body["stream"] is False and body["keep_alive"] == "10m"
    assert body["options"] == {"temperature": 0, "seed": 42, "num_ctx": 8192}
    assert body["format"] == llm_mod.SENTENCES_SCHEMA and body["model"] == "qwen2.5:7b-instruct"
    assert [m["role"] for m in body["messages"]] == ["system", "user"]
    assert r.ok and r.json_mode == "schema" and (r.prompt_tokens, r.completion_tokens) == (7, 3)


def test_ollama_falls_back_to_json_mode(monkeypatch):
    bodies = []

    def post(url, json, timeout):
        bodies.append(copy.deepcopy(json))
        return Resp(400, text="invalid format") if isinstance(json["format"], dict) else Resp(200, GOOD)

    monkeypatch.setattr(llm_mod.requests, "post", post)
    c = OllamaClient()
    r = c.complete("s", "u")
    assert [b["format"] for b in bodies] == [llm_mod.SENTENCES_SCHEMA, "json"]
    assert r.ok and r.json_mode == "json" and c.json_mode == "json"
    c.complete("s", "u")
    assert bodies[-1]["format"] == "json" and len(bodies) == 3  # sticky: no new schema attempt


def test_ollama_errors(monkeypatch):
    def boom(url, json, timeout):
        raise requests.ConnectionError("refused")

    monkeypatch.setattr(llm_mod.requests, "post", boom)
    with pytest.raises(LLMError, match="ollama serve"):
        OllamaClient().complete("s", "u")
    monkeypatch.setattr(llm_mod.requests, "post", lambda *a, **k: Resp(404, text="model 'nope' not found"))
    with pytest.raises(LLMError, match="ollama pull nope"):
        OllamaClient("nope").complete("s", "u")


@pytest.mark.parametrize("content", ["not json at all", '{"sentences": "x"}', '{"other": []}', "", "[1,2]"])
def test_ollama_bad_reply_returns_failure(monkeypatch, content):
    monkeypatch.setattr(llm_mod.requests, "post", lambda *a, **k: Resp(200, content))
    r = OllamaClient().complete("s", "u")
    assert r.ok is False and r.parsed is None and r.raw == content and r.error


def test_ollama_timeout_is_a_failed_call(monkeypatch):
    def slow(*a, **k):
        raise requests.Timeout("slow")

    monkeypatch.setattr(llm_mod.requests, "post", slow)
    r = OllamaClient().complete("s", "u")
    assert not r.ok and "Timeout" in r.error


# ---- 9. raw files ----
def test_raw_prompts_and_replies_saved(prepared, tmp_path):
    d = fresh(prepared, "case01", tmp_path)
    out = narrate_chain(d, FakeLLM(model="qwen2.5:7b-instruct"), NarratorConfig(mode="raw"))
    raw = d / "narrator_raw" / "chain_qwen2.5_7b-instruct"
    assert raw.is_dir() and ":" not in raw.name
    assert sorted(p.stem for p in raw.iterdir()) == sorted(STAGES + ["executive_summary"])
    text = (raw / "brute_force.txt").read_text()
    assert "=== SYSTEM ===" in text and "STAGE: brute_force" in text and "=== REPLY" in text and "Call 1 saw" in text
    assert out["stages"][0]["raw_output_file"] == "narrator_raw/chain_qwen2.5_7b-instruct/brute_force.txt"
    run_baseline(d, FakeLLM(model="llama3.1:8b"), NarratorConfig(chunk_size=100))
    assert (d / "narrator_raw" / "baseline_llama3.1_8b" / "chunk_001.txt").exists()
    assert (d / "narrator_raw" / "baseline_llama3.1_8b" / "final.txt").exists()


# ---- 10. determinism ----
def strip(o):
    if isinstance(o, dict):
        return {k: strip(v) for k, v in o.items() if k not in ("created_at", "total_seconds", "seconds")}
    return [strip(x) for x in o] if isinstance(o, list) else o


def test_determinism_with_fake(prepared, tmp_path):
    runs = []
    for i in (1, 2):
        d = fresh(prepared, "case02", tmp_path / str(i))
        narrate_chain(d, FakeLLM(), NarratorConfig(mode="raw"))
        runs.append(json.dumps(strip(load(d, "narrative.json")), sort_keys=True))
    assert runs[0] == runs[1]


# ---- CLI wiring (parse + correlate run automatically) ----
def test_cli_narrate_runs_pipeline_first(tmp_path, monkeypatch, prepared):
    cases = prepared.parent / "cases"
    made = []
    monkeypatch.setattr(llm_mod, "OllamaClient", lambda model, num_ctx: made.append((model, num_ctx)) or FakeLLM(num_ctx=num_ctx))
    cli.main(["narrate", "--case-dir", str(cases / "case01"), "--mode", "both", "--out", str(tmp_path),
              "--num-ctx", "16384", "--chunk-size", "100", "--model", "llama3.1:8b", "--narration-mode", "raw"])
    d = tmp_path / "case01"
    assert (d / "chain.json").exists() and (d / "events.jsonl").exists()
    assert (d / "narrative.json").exists() and (d / "baseline_narrative.json").exists()
    assert made == [("llama3.1:8b", 16384)]
