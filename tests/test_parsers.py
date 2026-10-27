import hashlib
import json
import re

import pytest

from evidenceweave import cli
from evidenceweave.generator.core import generate
from evidenceweave.parsers import auth_parser, nginx_parser, pipeline, windows_parser
from evidenceweave.parsers.pipeline import LOGS, parse_case, write_events
from evidenceweave.schema import ACTIONS, SOURCE_TYPES, Event, from_iso_z

# SHA-256 of generator output (answer_key hashes updated in Phase 4 for the cron session-closed tagging)
HASHES = {
    "case01/logs/linux_auth.log": "6E7D34ED0AE288B0A02903F960D1FDAE6CC2F91A9882860E03561C2A189FAA34",
    "case01/logs/nginx_access.log": "6B2B1BBEFC8D6FC719D9965F92C44BA952A8D4FB1D7C4ED80795A88D41A1A9C6",
    "case01/logs/windows_events.jsonl": "725CD0B336CCB748BB882809C7C2369AD36A86F1E6BD2B9FB1A70F8F07D5B11A",
    "case02/logs/linux_auth.log": "5985F3949A9D4A48E5DDF78C9C1390D8247ACF274FE792493B81AE923C5AE13C",
    "case02/logs/nginx_access.log": "B521A1EE2F53DB675A5497B89C9CCAB9A7F036C64C8442ADA2E5F124D873271E",
    "case02/logs/windows_events.jsonl": "59227B7CA35B6BEAFB73C1BC9C1712CE24AE56AF65B32F0747CCFA1548F1D3E6",
    "case01/answer_key.json": "07C5159E99A02ACB9E5ED94FA2998C3D506D678C67194B9CA392CE15D3EB9EC4",
    "case02/answer_key.json": "32493E7D2901E116019F65E9DA48ADC973592E0A9160DA6A996798F953AAD5F1",
    "case01/manifest.json": "4EC2AF9B3B5985D4442EAF79711159E0DA64DAF92ED378FB35247C1A155DF4B7",
    "case02/manifest.json": "D9B3853CE5059D93E22E38D2B5B1B83D97AE0A27FE45A9028468D9F8A30D0D45",
}
PREFIX = {"linux_auth.log": "AUTH", "nginx_access.log": "NGX", "windows_events.jsonl": "WIN"}
ID_RE = {"auth": r"AUTH-L\d+", "nginx": r"NGX-L\d+", "windows": r"WIN-L\d+"}


@pytest.fixture(scope="module")
def root(tmp_path_factory):
    r = tmp_path_factory.mktemp("cases")
    generate("case01", "easy", 42, r)
    generate("case02", "hard", 7, r)
    return r


@pytest.fixture(scope="module", params=["case01", "case02"])
def case_dir(root, request):
    return root / request.param


@pytest.fixture(scope="module")
def parsed(case_dir):
    return parse_case(case_dir)


@pytest.fixture(scope="module")
def hard(root):
    d = root / "case02"
    return d, json.loads((d / "answer_key.json").read_text()), parse_case(d)


def test_coverage_no_drops(parsed):
    assert parsed.stats.keys() == set(SOURCE_TYPES)
    for s, st in parsed.stats.items():
        assert st["events"] == st["lines"] - st["blank"] > 0, s
        assert st["unparsed"] == 0 and st["blank"] == 0, s
    assert len(parsed.events) == sum(st["events"] for st in parsed.stats.values())


def test_evidence_maps_to_events(case_dir, parsed):
    by_id = {e.event_id: e for e in parsed.events}
    key = json.loads((case_dir / "answer_key.json").read_text())
    n = 0
    for step in key["steps"]:
        for ev in step["evidence"]:
            e = by_id[f"{PREFIX[ev['source_file']]}-L{ev['line_number']}"]
            assert (e.raw_file, e.raw_line) == (ev["source_file"], ev["line_number"])
            assert ev["event_marker"] in e.raw_text
            n += 1
    assert n > 50


def test_ids_unique_and_formatted(parsed):
    assert len({e.event_id for e in parsed.events}) == len(parsed.events)
    for e in parsed.events:
        assert re.fullmatch(ID_RE[e.source_type], e.event_id)
        assert e.event_id.endswith(f"-L{e.raw_line}")


def test_round_trip(parsed):
    for s in SOURCE_TYPES:
        sample = [e for e in parsed.events if e.source_type == s][::37]
        assert sample
        for e in sample:
            assert Event.from_dict(json.loads(json.dumps(e.to_dict()))) == e
            assert e.to_dict()["timestamp"].endswith("Z")


def test_determinism(parsed, case_dir, tmp_path):
    write_events(parsed, tmp_path / "a.jsonl")
    write_events(parse_case(case_dir), tmp_path / "b.jsonl")
    assert (tmp_path / "a.jsonl").read_bytes() == (tmp_path / "b.jsonl").read_bytes()


def test_sorted(parsed, tmp_path):
    write_events(parsed, tmp_path / "e.jsonl")
    ts = [from_iso_z(json.loads(line)["timestamp"]) for line in (tmp_path / "e.jsonl").read_text().splitlines()]
    assert ts == sorted(ts) and len(ts) == len(parsed.events)


def step5_win(case, key, by_id=None):
    step = next(s for s in key["steps"] if s["step_id"] == 5)
    evs = {e.event_id: e for e in case.events}
    return step, [evs[f"WIN-L{x['line_number']}"] for x in step["evidence"]]


def test_clock_skew_not_applied_by_default(hard):
    d, key, case = hard
    step, evs = step5_win(case, key)
    start, end = from_iso_z(step["start_time"]), from_iso_z(step["end_time"])
    assert not any(e.clock_corrected for e in evs)
    assert all(e.timestamp == e.raw_timestamp for e in evs)
    assert abs((min(e.timestamp for e in evs) - start).total_seconds() - 90) < 1
    assert abs((max(e.timestamp for e in evs) - end).total_seconds() - 90) < 1


def test_clock_offset_corrects(hard):
    d, key, plain = hard
    case = parse_case(d, clock_offsets={"ws-fin01": 90})
    step, evs = step5_win(case, key)
    start, end = from_iso_z(step["start_time"]), from_iso_z(step["end_time"])
    assert all(e.clock_corrected for e in evs)
    assert abs((min(e.timestamp for e in evs) - start).total_seconds()) < 1
    assert abs((max(e.timestamp for e in evs) - end).total_seconds()) < 1
    raw = {e.event_id: e.raw_timestamp for e in plain.events}
    assert all(e.raw_timestamp == raw[e.event_id] for e in case.events)
    assert not any(e.clock_corrected for e in case.events if e.source_type != "windows")
    assert case.clock_offsets == {"ws-fin01": 90}


def test_decoy(hard):
    d, key, case = hard
    decoy = key["decoy_ips"][0]
    acts = {e.action for e in case.events if e.src_ip == decoy}
    assert {"ssh_invalid_user", "web_request"} <= acts or {"ssh_login_failed", "web_request"} <= acts
    assert "ssh_login_success" not in acts


def test_bad_input_never_raises(tmp_path):
    def write(name, lines):
        p = tmp_path / name
        p.write_bytes("\n".join(lines).encode() + b"\n")
        return p

    ok_auth = "Oct 27 00:00:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
    auth, st = auth_parser.parse(write("a", [
        "garbage", ok_auth, "", "Oct 27 00:00:00 web01 sshd[1]: something new", "Feb 30 00:00:00 web01 sudo: x",
        "   ", "\x00\xff binary"]), 2026)
    assert st == {"lines": 7, "events": 5, "unparsed": 4, "blank": 2}
    assert [e.action for e in auth].count("ssh_login_failed") == 1

    ok_ngx = '1.2.3.4 - - [27/Oct/2026:00:00:00 +0200] "GET / HTTP/1.1" 200 5 "-" "ua"'
    ngx, st = nginx_parser.parse(write("n", ["garbage", ok_ngx, "", '1.2.3.4 - - [bad] "GET /', '- - -']))
    assert st == {"lines": 5, "events": 4, "unparsed": 3, "blank": 1}
    assert ngx[1].timestamp.hour == 22 and ngx[1].timestamp.day == 26  # +0200 converted to UTC

    ok_win = json.dumps({"TimeCreated": "2026-10-27T00:00:00.000Z", "EventID": 4624, "Computer": "h",
                         "EventData": {"TargetUserName": "u", "IpAddress": "-"}})
    win, st = windows_parser.parse(write("w", [
        "not json", ok_win, '{"TimeCreated": "2026-10-27T00:', "",
        json.dumps({"TimeCreated": "2026-10-27T00:00:01.000Z", "EventID": 9999, "Computer": "h"}),
        "[1]", "null", json.dumps({"EventID": 4624})]))
    assert st == {"lines": 8, "events": 7, "unparsed": 6, "blank": 1}
    assert win[1].user == "u" and win[1].src_ip is None
    assert all(e.raw_text for e in win)

    assert {e.action for e in auth + ngx + win} <= ACTIONS


def test_missing_hosts_and_year(tmp_path):
    d = tmp_path / "bare"
    (d / "logs").mkdir(parents=True)
    (d / "logs" / LOGS["auth"]).write_text("Oct 27 00:00:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2\n")
    with pytest.raises(ValueError):
        parse_case(d)  # no manifest, no year
    c = parse_case(d, year=2026)
    assert c.hosts == {} and len(c.events) == 1 and c.events[0].timestamp.year == 2026


@pytest.mark.parametrize("bad", ["ws-fin01", "ws-fin01=abc", "=90", "ws-fin01=1.5", ""])
def test_malformed_clock_offset(bad, capsys, root):
    with pytest.raises(SystemExit) as e:
        cli.main(["parse", "--case-dir", str(root / "case01"), "--clock-offset", bad])
    assert e.value.code != 0
    assert "HOST=SECONDS" in capsys.readouterr().err


def test_cli_parse_writes_events(root, tmp_path, capsys):
    cli.main(["parse", "--case-dir", str(root / "case02"), "--clock-offset", "ws-fin01=+90", "--out", str(tmp_path)])
    assert (tmp_path / "case02" / "events.jsonl").exists()
    assert "ws-fin01=+90s" in capsys.readouterr().out


def test_hosts_json_and_generator_output_unchanged(root):
    for c in ("case01", "case02"):
        hosts = json.loads((root / c / "hosts.json").read_text())["hosts"]
        assert {h["name"]: (h["ip"], h["os"]) for h in hosts} == {
            "web01": ("10.0.0.5", "linux"), "ws-fin01": ("10.0.0.70", "windows")}
        assert pipeline.parse_case(root / c).hosts.keys() == {"web01", "ws-fin01"}
    for rel, digest in HASHES.items():
        assert hashlib.sha256((root / rel).read_bytes()).hexdigest().upper() == digest, rel
