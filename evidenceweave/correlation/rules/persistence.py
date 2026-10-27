"""Rule 4: new accounts after a compromise, suspicious cron jobs, suspicious scheduled tasks, and gaps."""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from ...schema import (CRON_COMMAND, CRON_SESSION_CLOSED, CRON_SESSION_OPENED, USER_CREATED, WIN_TASK_CREATED,
                       WIN_USER_CREATED)
from .. import util as U

NAME = "persistence"


def run(events, cfg, hosts, prior=()):
    evs = sorted(U.usable(events), key=U.order_key)
    tol = cfg.cross_host_tolerance_seconds
    access = [f for f in prior if f.stage == "initial_access"]
    lateral_ids = {i for f in prior if f.rule == "lateral_movement" for i in f.evidence_event_ids}
    out = []

    # (a) account created after a compromise
    created = set()
    for e in evs:
        if e.action not in (USER_CREATED, WIN_USER_CREATED):
            continue
        new = e.user or e.extra.get("new_user")
        created.add(new)
        anchors = [f for f in access if U.after(f.start_time, f.hosts, e.timestamp, [e.host], tol)]
        if not anchors:
            continue
        a = min(anchors, key=lambda f: f.start_time)
        out.append(U.make(NAME, "persistence", "confirmed", [e],
                          f"Account {new} was created on {e.host} {U.secs(a.start_time, e.timestamp)}s after initial access.",
                          U.entities(users=[new], hosts=[e.host]),
                          {"kind": "user_created", "new_user": new, "created_by": e.extra.get("SubjectUserName"),
                           "linked_initial_access": a.finding_id}))

    # (b) suspicious cron jobs, one finding per (host, user, command) with the execution count
    groups = defaultdict(list)
    for e in evs:
        if e.action == CRON_COMMAND:
            cmd = e.extra.get("command", "")
            if U.matched(cfg, cmd) or U.urls_in(cmd):
                groups[(e.host, e.user, cmd)].append(e)
    sessions = defaultdict(list)
    for e in evs:
        if e.action in (CRON_SESSION_OPENED, CRON_SESSION_CLOSED):
            sessions[(e.host, e.user, e.extra.get("pid"))].append(e)
    first_seen = {}
    for e in evs:
        if e.user:
            first_seen.setdefault(e.user, e.timestamp)
    match = timedelta(seconds=cfg.cron_session_match_seconds)
    for (host, user, cmd), runs in sorted(groups.items()):
        support = {s.event_id: s for c in runs for s in sessions[(host, user, c.extra.get("pid"))]
                   if abs(s.timestamp - c.timestamp) <= match}
        urls = U.urls_in(cmd)
        ents = U.entities(ips=[U.url_ip(u) for u in urls], users=[user], hosts=[host], urls=urls)
        out.append(U.make(
            NAME, "persistence", "confirmed", runs + list(support.values()),
            f"Cron job for {user} on {host} ran a suspicious command {len(runs)} times "
            f"({runs[0].timestamp:%H:%M:%S} to {runs[-1].timestamp:%H:%M:%S} UTC): {cmd[:120]}",
            ents, {"kind": "cron", "command": cmd, "executions": len(runs), "matched_patterns": U.matched(cfg, cmd),
                   "supporting_session_events": len(support)}))
        # the account behind the cron job appeared only after the compromise but its creation is not logged
        if access and user not in created:
            a = min(access, key=lambda f: f.start_time)
            if U.after(a.start_time, a.hosts, first_seen[user], [host], tol):
                out.append(U.make(
                    NAME, "missing_evidence", "unprovable", runs + list(support.values()),
                    f"Account {user} runs cron jobs on {host} but no event creating it appears in the logs "
                    f"(deleted, never logged, or outside the collected logs).",
                    ents, {"kind": "missing_account_creation", "missing_user": user, "affects_stage": "persistence",
                           "account_first_seen": first_seen[user].isoformat().replace("+00:00", "Z")}))

    # (c) suspicious scheduled tasks not already explained by a lateral-movement finding
    for e in evs:
        if e.action != WIN_TASK_CREATED or e.event_id in lateral_ids:
            continue
        text = e.extra.get("TaskContent", "")
        urls = U.urls_in(text)
        pats = U.matched(cfg, text)
        if not (pats or urls):
            continue
        user = e.user
        out.append(U.make(NAME, "persistence", "confirmed", [e],
                          f"Scheduled task {e.extra.get('TaskName')} created on {e.host} by {user} runs a suspicious command.",
                          U.entities(ips=[U.url_ip(u) for u in urls], users=[user], hosts=[e.host], urls=urls),
                          {"kind": "scheduled_task", "task_name": e.extra.get("TaskName"), "matched_patterns": pats}))
    return U.number(NAME, out)
