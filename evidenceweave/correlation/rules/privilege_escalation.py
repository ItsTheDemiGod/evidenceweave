"""Rule 3: sudo that runs a suspicious/remote-fetched command, or any sudo soon after a compromise."""
from __future__ import annotations

from ...schema import SUDO_COMMAND
from .. import util as U

NAME = "privilege_escalation"


def run(events, cfg, hosts, prior=()):
    access = [f for f in prior if f.stage == "initial_access"]
    out = []
    for e in sorted(U.usable(events), key=U.order_key):
        if e.action != SUDO_COMMAND:
            continue
        cmd = e.extra.get("command", "")
        pats, urls = U.matched(cfg, cmd), U.urls_in(cmd)
        mine = [f for f in access if e.user in f.entities["users"]
                and U.after(f.start_time, f.hosts, e.timestamp, [e.host], cfg.cross_host_tolerance_seconds)]
        reasons = []
        if pats and (mine or urls):
            reasons.append("suspicious_command")
        if mine and U.secs(min(f.start_time for f in mine), e.timestamp) <= cfg.sudo_after_access_window_seconds:
            reasons.append("sudo_shortly_after_access")
        if not reasons:
            continue
        out.append(U.make(
            NAME, "privilege_escalation", "confirmed" if pats else "partial", [e],
            f"{e.user} ran sudo on {e.host}: {cmd[:120]}" + (" (suspicious command)" if pats else ""),
            U.entities(ips=[U.url_ip(u) for u in urls], users=[e.user], hosts=[e.host], urls=urls),
            {"command": cmd, "reasons": reasons, "matched_patterns": pats,
             "linked_initial_access": sorted(f.finding_id for f in mine)}))
    return U.number(NAME, out)
