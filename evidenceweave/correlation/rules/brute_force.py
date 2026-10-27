"""Rule 1: many failed logins from one source IP inside a sliding window."""
from __future__ import annotations

from collections import defaultdict

from ...schema import SSH_INVALID_USER, SSH_LOGIN_FAILED, SSH_LOGIN_SUCCESS, WIN_LOGON_FAILED, WIN_LOGON_SUCCESS
from .. import util as U

FAILS = {SSH_LOGIN_FAILED, SSH_INVALID_USER, WIN_LOGON_FAILED}
SUCCESS = {SSH_LOGIN_SUCCESS, WIN_LOGON_SUCCESS}
NAME = "brute_force"


def run(events, cfg, hosts, prior=()):
    fails, succ = defaultdict(list), defaultdict(list)
    for e in sorted(U.usable(events), key=U.order_key):
        if e.src_ip and e.action in FAILS:
            fails[e.src_ip].append(e)
        elif e.src_ip and e.action in SUCCESS:
            succ[e.src_ip].append(e)
    out = []
    for ip, fl in sorted(fails.items()):
        for i, j in U.burst_spans(fl, cfg.brute_force_window_seconds,
                                  lambda w: len(w) >= cfg.brute_force_min_failures):
            burst = fl[i:j + 1]
            start, end = burst[0].timestamp, burst[-1].timestamp
            hs = sorted({e.host for e in burst})
            wins = [s for s in succ[ip] if U.success_follows(start, end, hs, s, cfg)]
            names = sorted({e.user for e in burst if e.user})
            n = len(burst)
            tail = (f"a successful login as {wins[0].user} followed" if wins
                    else "no successful login followed")
            out.append(U.make(
                NAME, "brute_force", "confirmed" if wins else "attempts_only", burst,
                f"{n} failed logins from {ip} against {', '.join(hs)} over {U.secs(start, end)}s "
                f"trying {len(names)} distinct usernames; {tail}.",
                U.entities(ips=[ip], hosts=hs),
                {"failure_count": n, "distinct_usernames": len(names), "usernames": names[:25],
                 "succeeded": bool(wins), "success_event_ids": U.ids(wins),
                 "thresholds": {"min_failures": cfg.brute_force_min_failures,
                                "window_seconds": cfg.brute_force_window_seconds},
                 "duration_seconds": U.secs(start, end)}))
    return U.number(NAME, out)
