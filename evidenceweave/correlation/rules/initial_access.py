"""Rule 2: a successful login from an IP that just brute-forced."""
from __future__ import annotations

from ...schema import SSH_LOGIN_SUCCESS, WIN_LOGON_SUCCESS
from .. import util as U

NAME = "initial_access"


def run(events, cfg, hosts, prior=()):
    bfs = [f for f in prior if f.rule == "brute_force"]
    inventory = U.inventory_ips(hosts)
    out = []
    for e in sorted(U.usable(events), key=U.order_key):
        if not e.src_ip:
            continue
        # windows logons only count from outside the inventory (inside = lateral movement territory)
        if e.action != SSH_LOGIN_SUCCESS and not (e.action == WIN_LOGON_SUCCESS and e.src_ip not in inventory):
            continue
        links = [f for f in bfs if e.src_ip in f.entities["ips"]
                 and U.success_follows(f.start_time, f.end_time, f.hosts, e, cfg)]
        if not links:
            continue
        bf = max(links, key=lambda f: f.end_time)
        gap = max(0, U.secs(bf.end_time, e.timestamp))
        method = e.extra.get("method", "logon")
        out.append(U.make(
            NAME, "initial_access", "confirmed", [e],
            f"Successful {method} login as {e.user} on {e.host} from {e.src_ip}, {gap}s after "
            f"{bf.details['failure_count']} failed attempts from the same IP.",
            U.entities(ips=[e.src_ip], users=[e.user], hosts=[e.host]),
            {"linked_brute_force": bf.finding_id, "seconds_after_failures": gap, "method": method,
             "window_seconds": cfg.access_after_failures_window_seconds}))
    return U.number(NAME, out)
