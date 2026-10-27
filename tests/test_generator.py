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
