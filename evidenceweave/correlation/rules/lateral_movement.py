"""Rule 5: network logon on another host from an already-compromised (pivot) host, plus what followed."""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from ...schema import WIN_LOGON_FAILED, WIN_LOGON_SUCCESS, WIN_PROCESS_CREATED, WIN_SPECIAL_PRIVILEGES, WIN_TASK_CREATED
from .. import util as U

NAME = "lateral_movement"
NOTE = ("host inventory (hosts.json) is absent: the logon source IP could not be mapped to a compromised host, "
        "so this is a candidate that cannot be linked to the attack chain")


def run(events, cfg, hosts, prior=()):
    evs = sorted(U.usable(events), key=U.order_key)
    compromise = [f for f in prior if f.stage in ("initial_access", "privilege_escalation")]
    pivots = {ip: name for ip, name in U.inventory_ips(hosts).items() if any(name in f.hosts for f in compromise)}
    window = timedelta(seconds=cfg.lateral_window_seconds)
    windows_by_host = defaultdict(list)
    for e in evs:
        if e.source_type == "windows":
            windows_by_host[e.host].append(e)
    out = []
    for e in evs:
        if (e.action != WIN_LOGON_SUCCESS or not e.src_ip
                or str(e.extra.get("LogonType")) not in ("3", "10")):
            continue
        pivot = pivots.get(e.src_ip)
        if hosts and pivot is None:
            continue
        if pivot:  # cross-host time check against the pivot's earliest compromise finding
            first = min(f.start_time for f in compromise if pivot in f.hosts)
            if e.timestamp < first - timedelta(seconds=cfg.cross_host_tolerance_seconds):
                continue
        same = windows_by_host[e.host]
        failed = [x for x in same if x.action == WIN_LOGON_FAILED and x.src_ip == e.src_ip
                  and e.timestamp - window <= x.timestamp < e.timestamp]
        later = [x for x in same if x is not e and x.user == e.user
                 and e.timestamp <= x.timestamp <= e.timestamp + window]
        privs = [x for x in later if x.action == WIN_SPECIAL_PRIVILEGES]
        procs = [x for x in later if x.action == WIN_PROCESS_CREATED
                 and U.matched(cfg, x.extra.get("CommandLine", ""))]
        tasks = [x for x in later if x.action == WIN_TASK_CREATED]
        if not pivot and not procs:  # without an inventory demand independent evidence of malice
            continue
        urls = sorted({u for x in procs + tasks
                       for u in U.urls_in(x.extra.get("CommandLine", "") + " " + x.extra.get("TaskContent", ""))})
        evidence = failed + [e] + privs + procs + tasks
        who = f"from {pivot} ({e.src_ip})" if pivot else f"from {e.src_ip}"
        details = {"pivot_host": pivot, "pivot_ip": e.src_ip if pivot else None, "target_host": e.host,
                   "logon_type": str(e.extra.get("LogonType")), "failed_logons_before": len(failed),
                   "special_privilege_events": len(privs), "suspicious_processes": len(procs),
                   "scheduled_tasks": [x.extra.get("TaskName") for x in tasks],
                   "window_seconds": cfg.lateral_window_seconds}
        if not hosts:
            details["note"] = NOTE
        out.append(U.make(
            NAME, "lateral_movement", "confirmed" if pivot else "partial", evidence,
            f"Network logon to {e.host} as {e.user} {who} after {len(failed)} failed attempts, followed by "
            f"{len(privs)} privileged-logon, {len(procs)} suspicious-process and {len(tasks)} scheduled-task events.",
            U.entities(ips=[e.src_ip] + [U.url_ip(u) for u in urls], users=[e.user],
                       hosts=[e.host] + ([pivot] if pivot else []), urls=urls),
            details))
    return U.number(NAME, out)
