import json
import re

import pytest

from evidenceweave.generator.core import generate
from evidenceweave.generator.formats import AUTH, NGINX, SOURCES, WIN

SYSLOG = re.compile(r"^[A-Z][a-z]{2} [ 0-3]\d \d\d:\d\d:\d\d web01 [\w.\-]+(\[\d+\])?: .+$")
COMBINED = re.compile(r'^\d+\.\d+\.\d+\.\d+ - - \[\d\d/[A-Z][a-z]{2}/\d{4}:\d\d:\d\d:\d\d \+0000\] '
                      r'"[A-Z]+ \S+ HTTP/1\.1" \d{3} \d+ "[^"]*" "[^"]*"$')


def logs(case_dir):
    return {s: (case_dir / "logs" / s).read_text(encoding="utf-8").split("\n")[:-1] for s in SOURCES}


@pytest.fixture(scope="module")
def cases(tmp_path_factory):
    root = tmp_path_factory.mktemp("cases")
    generate("easy", "easy", 42, root)
    generate("hard", "hard", 7, root)
    generate("easy_b", "easy", 43, root)
    generate("easy_again", "easy", 42, root)
    return root


def key(cases, name):
    return json.loads((cases / name / "answer_key.json").read_text(encoding="utf-8"))


def test_determinism(cases):
    for s in SOURCES:
        a = (cases / "easy" / "logs" / s).read_bytes()
        assert a == (cases / "easy_again" / "logs" / s).read_bytes()
        assert a != (cases / "easy_b" / "logs" / s).read_bytes()


@pytest.mark.parametrize("name", ["easy", "hard"])
def test_evidence_lines_match_markers(cases, name):
    files = logs(cases / name)
    for step in key(cases, name)["steps"]:
        assert step["evidence"]
        for ev in step["evidence"]:
            line = files[ev["source_file"]][ev["line_number"] - 1]
            assert ev["event_marker"] in line
            assert sum(ev["event_marker"] in l for l in files[ev["source_file"]]) == 1  # marker is unique
    for b in key(cases, name)["benign_but_suspicious_looking"]:
        assert b["event_marker"] in files[b["source_file"]][b["line_number"] - 1]


@pytest.mark.parametrize("name", ["easy", "hard"])
def test_six_ordered_steps_with_attacker_ip(cases, name):
    k = key(cases, name)
    steps = k["steps"]
    assert [s["step_id"] for s in steps] == [1, 2, 3, 4, 5, 6]
    starts = [s["start_time"] for s in steps]
    assert starts == sorted(starts) and len(set(starts)) == 6
    files = logs(cases / name)
    for s in steps:
        assert any(k["attacker_ip"] in files[e["source_file"]][e["line_number"] - 1] for e in s["evidence"])


def test_missing_evidence(cases):
    assert all(not s["evidence_missing"] for s in key(cases, "easy")["steps"])
    missing = [m for s in key(cases, "hard")["steps"] for m in s["evidence_missing"]]
    assert missing
    files = logs(cases / "hard")
    for m in missing:
        assert not any(m["event_marker"] in l for l in files[m["source_file"]])
    assert any("new user: name=svc_backup" in l for l in logs(cases / "easy")[AUTH])


def test_decoy_never_succeeds(cases):
    k = key(cases, "hard")
    files = logs(cases / "hard")
    for ip in k["decoy_ips"]:
        hits = [l for s in SOURCES for l in files[s] if ip in l]
        assert hits
        assert not any("Accepted" in l or '"EventID": 4624' in l for l in hits)
        assert not any(re.search(rf'{re.escape(ip)}.*" 200 ', l) for l in files[NGINX])


def test_hard_has_decoy_and_skew(cases):
    k = key(cases, "hard")
    assert k["decoy_ips"] == ["198.51.100.23"] and k["clock_skew_seconds"][WIN] == 90
    assert key(cases, "easy")["decoy_ips"] == []


@pytest.mark.parametrize("name", ["easy", "hard"])
def test_format_sanity(cases, name):
    files = logs(cases / name)
    for l in files[WIN]:
        obj = json.loads(l)
        assert {"TimeCreated", "EventID", "Computer", "Channel", "EventData"} <= obj.keys()
    assert all(SYSLOG.match(l) for l in files[AUTH])
    assert all(COMBINED.match(l) for l in files[NGINX])


def test_hard_is_bigger(cases):
    e, h = logs(cases / "easy"), logs(cases / "hard")
    assert sum(map(len, h.values())) > 3 * sum(map(len, e.values()))


# SHA-256 recorded BEFORE the Phase 4 answer-key fix: only answer_key.json may differ from these runs
PRE_FIX = {
    "case01/logs/linux_auth.log": "6e7d34ed0ae288b0a02903f960d1fdae6cc2f91a9882860e03561c2a189faa34",
    "case01/logs/nginx_access.log": "6b2b1bbefc8d6fc719d9965f92c44ba952a8d4fb1d7c4ed80795a88d41a1a9c6",
    "case01/logs/windows_events.jsonl": "725cd0b336ccb748bb882809c7c2369ad36a86f1e6bd2b9fb1a70f8f07d5b11a",
    "case01/manifest.json": "4ec2af9b3b5985d4442eaf79711159e0da64daf92ed378fb35247c1a155df4b7",
    "case01/hosts.json": "8011a4057e9122f585a2f53fe2262c7d3cb7bce6cd3bd0fe12cb81a330b1484b",
    "case02/logs/linux_auth.log": "5985f3949a9d4a48e5ddf78c9c1390d8247acf274fe792493b81ae923c5ae13c",
    "case02/logs/nginx_access.log": "b521a1ee2f53db675a5497b89c9ccab9a7f036c64c8442ada2e5f124d873271e",
    "case02/logs/windows_events.jsonl": "59227b7ca35b6beafb73c1bc9c1712ce24ae56af65b32f0747ccfa1548f1d3e6",
    "case02/manifest.json": "d9b3853ce5059d93e22e38d2b5b1b83d97ae0a27fe45a9028468d9f8a30d0d45",
    "case02/hosts.json": "8011a4057e9122f585a2f53fe2262c7d3cb7bce6cd3bd0fe12cb81a330b1484b",
}


@pytest.fixture(scope="module")
def fixed(tmp_path_factory):
    r = tmp_path_factory.mktemp("fixed")
    generate("case01", "easy", 42, r)
    generate("case02", "hard", 7, r)
    return r


def test_key_fix_leaves_logs_manifest_hosts_byte_identical(fixed):
    import hashlib
    for rel, digest in PRE_FIX.items():
        assert hashlib.sha256((fixed / rel).read_bytes()).hexdigest() == digest, rel


@pytest.mark.parametrize("name", ["case01", "case02"])
def test_cron_session_closed_lines_are_step4_evidence(fixed, name):
    k = json.loads((fixed / name / "answer_key.json").read_text())
    lines = (fixed / name / "logs" / AUTH).read_text().split("\n")
    closed = {i + 1 for i, line in enumerate(lines)
              if f"pam_unix(cron:session): session closed for user {k['created_user']}" in line}
    step4 = {e["line_number"] for e in k["steps"][3]["evidence"] if e["source_file"] == AUTH}
    assert len(closed) == 4 and closed <= step4
