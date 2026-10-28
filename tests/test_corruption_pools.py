import json
import re

import pytest

from evidenceweave.verifier import corruption as C
from evidenceweave.verifier import corruption_pools as P
from evidenceweave.verifier.corruption import base_sentences, run_corruption
from evidenceweave.verifier.entities import extract
from evidenceweave.verifier.judge import ClaimJudge
from test_phase5b import FClaimLLM, harness, make_case


@pytest.fixture(scope="module")
def prepared(tmp_path_factory):
    root = tmp_path_factory.mktemp("pools")
    make_case(root, "case01", "easy", 42)
    return root


def test_sizes_and_kinds():
    assert len(P.HELDOUT_NO_ENTITY_CLAIMS) == 14 and len(P.HELDOUT_ENTITY_FABRICATIONS) == 10
    assert set(P.HELDOUT_ENTITY_KINDS) == set(P.HELDOUT_ENTITY_FABRICATIONS)
    assert len(set(P.HELDOUT_NO_ENTITY_CLAIMS)) == 14


def test_disjoint_from_original_pool():
    orig = set(C.FAKE_CLAIMS) | set(C.FAKE_ENTITY_CLAUSES)
    held = set(P.HELDOUT_NO_ENTITY_CLAIMS) | {e.strip(" ,") for e in P.HELDOUT_ENTITY_FABRICATIONS}
    assert not orig & held
    orig_ents = {m for t in C.FAKE_ENTITY_CLAUSES for m in re.findall(r"192\.0\.2\.99|malware\.example\.net|/var/tmp/\.cache_dump\.tar", t)}
    assert not any(o in e for o in orig_ents for e in P.HELDOUT_ENTITY_FABRICATIONS)


def test_no_entity_claims_have_no_entities():
    for s in P.HELDOUT_NO_ENTITY_CLAIMS:
        x = extract(s, ["web01", "ws-fin01"])
        assert not (x.urls or x.domains or x.ip_tokens or x.users or x.hosts or x.quoted or x.paths), s


def test_entity_clauses_do_carry_an_entity():
    for s in P.HELDOUT_ENTITY_FABRICATIONS:
        if P.HELDOUT_ENTITY_KINDS[s] in ("hostname", "domain"):
            continue  # the extractors do not model unknown hostnames/domains: a deliberate held-out probe
        x = extract(s, [])
        assert x.urls or x.domains or x.ip_tokens or x.users or x.hosts or x.quoted or x.paths, s


def test_selection_deterministic_and_each_entry_once(prepared, tmp_path):
    res, narr, jl, seq, data, _ = harness(prepared, tmp_path)
    cands = C.candidates(data, base_sentences(res["verified"]))
    def run():
        s = C.select(cands, 70)
        C.apply_heldout(s)
        return [(x["type"], x["text"]) for x in s]
    assert run() == run()
    s = C.select(cands, 70)
    C.apply_heldout(s)
    for t, n in (("fabricated_claim_no_entity", 14), ("fabricated_entity", 10)):
        used = [x["pool_entry"] for x in s if x["type"] == t]
        assert len(used) == len(set(used)) or len(used) > n  # no repeat before the list is exhausted
        assert len(set(used[:n])) == len(used[:n])
    assert all("entity_kind" in x for x in s if x["type"] == "fabricated_entity")


def test_report_records_pool_and_original_unchanged(prepared, tmp_path):
    res, narr, jl, seq, data, _ = harness(prepared, tmp_path)
    orig = run_corruption(data, res["verified"], ClaimJudge(FClaimLLM()), cap=40)
    again = run_corruption(data, res["verified"], ClaimJudge(FClaimLLM()), cap=40, pool="original")
    assert orig["pool"]["name"] == "original" and orig["pool"] == again["pool"]
    assert [s["text"] for s in orig["samples"]] == [s["text"] for s in again["samples"]]
    assert all(set(s["text"][len(s["original_text"]):].strip().split(". ")[0:1]) for s in orig["samples"])
    held = run_corruption(data, res["verified"], ClaimJudge(FClaimLLM()), cap=40, pool="heldout")
    assert held["pool"]["name"] == "heldout" and held["pool"]["sha256"] == P.pool_sha256(
        P.HELDOUT_NO_ENTITY_CLAIMS, P.HELDOUT_ENTITY_FABRICATIONS) != orig["pool"]["sha256"]
    assert held["seed"] == 42
    fe = [s for s in held["samples"] if s["type"] == "fabricated_entity"]
    assert fe and all(s["entity_kind"] in set(P.HELDOUT_ENTITY_KINDS.values()) for s in fe)
    for s in held["samples"]:
        if s["type"] not in ("fabricated_entity", "fabricated_claim_no_entity"):
            o = next(x for x in orig["samples"] if x["type"] == s["type"] and x["unit"] == s["unit"] and x["index"] == s["index"])
            assert o["text"] == s["text"]
    json.loads((data.out_dir / "corruption_report.json").read_text())
