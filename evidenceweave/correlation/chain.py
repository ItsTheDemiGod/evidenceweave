"""Chain builder: grow an attacker entity set from successful accesses and link findings through it."""
from __future__ import annotations

from dataclasses import replace

from ..schema import iso_z
from . import util as U

VERSION = "1.0.0"
POST_ACCESS = {"privilege_escalation", "persistence", "lateral_movement", "missing_evidence"}


def build_chain(findings, hosts, cfg, case_name, clock_offsets, stats):
    """Return (chain dict, findings with chain-attributed statuses). Never reads anything but its arguments."""
    fs = {f.finding_id: replace(f, details=dict(f.details)) for f in findings}
    order = sorted(fs.values(), key=lambda f: (f.start_time, f.finding_id))
    host_ip = {n: h.get("ip") for n, h in hosts.items()}
    inventory = set(U.inventory_ips(hosts))
    tol = cfg.cross_host_tolerance_seconds
    ents = {"ips": set(), "users": set(), "assoc_users": set(), "hosts": set(), "urls": set(), "origins": set()}
    links: dict[str, list[str]] = {}
    refused: dict[str, str] = {}
    anchors = [f for f in order if f.stage == "initial_access"]
    first = min(anchors, key=lambda f: f.start_time) if anchors else None

    def grow(f, seed=False):
        ents["ips"] |= {i for i in f.entities["ips"] if i not in inventory}
        ents["users" if seed else "assoc_users"] |= set(f.entities["users"])
        ents["hosts"] |= set(f.hosts)
        ents["urls"] |= set(f.entities["urls"])
        ents["origins"] |= {U.origin(u) for u in f.entities["urls"]}

    for f in anchors:
        links[f.finding_id] = [f"initial access as {'/'.join(f.entities['users'])} from IP "
                               f"{'/'.join(f.entities['ips'])} following brute force {f.details['linked_brute_force']}"]
        grow(f, seed=True)

    def shared(f):
        why = [f"shares payload server {U.origin(u)}" for u in f.entities["urls"] if U.origin(u) in ents["origins"]]
        why += [f"shares IP {i}" for i in f.entities["ips"] if i in ents["ips"]]
        pivots = {host_ip[n]: n for n in ents["hosts"] if host_ip.get(n)}
        why += [f"pivot host {pivots[i]} = {i}" for i in f.entities["ips"] if i in pivots]
        known = ents["users"] | ents["assoc_users"]
        why += [f"shares user {u}" for u in f.entities["users"] if u in known]
        return why

    changed = bool(anchors)
    while changed:
        changed = False
        for f in order:
            if f.finding_id in links or f.finding_id in refused or not (why := shared(f)):
                continue
            stage = f.stage
            if stage == "lateral_movement" and not f.details.get("pivot_host"):
                refused[f.finding_id] = "no host inventory: the pivot host link cannot be established"
                continue
            if stage in POST_ACCESS:
                if not U.after(first.start_time, first.hosts, f.start_time, f.hosts, tol):
                    refused[f.finding_id] = (f"shares an entity but starts before initial access "
                                             f"{first.finding_id} (tolerance {tol}s)")
                    continue
                cross = U.slack(first.hosts, f.hosts, tol) > 0
                why.append(f"starts {U.secs(first.start_time, f.start_time)}s after initial access {first.finding_id}"
                           + (f" (cross-host, tolerance {tol}s)" if cross else ""))
            links[f.finding_id] = why
            grow(f)
            changed = True

    # attribution upgrades
    for fid in links:
        f = fs[fid]
        if f.status == "attempts_only":
            f.status, f.details["upgraded_by_chain"] = "confirmed", True

    def stage_of(f):
        return f.details.get("affects_stage", "persistence") if f.stage == "missing_evidence" else f.stage

    by_stage: dict[str, list] = {}
    for fid in links:
        by_stage.setdefault(stage_of(fs[fid]), []).append(fs[fid])
    stages = []
    for name, members in by_stage.items():
        members.sort(key=lambda f: (f.start_time, f.finding_id))
        stages.append({
            "stage": name,
            "status": "confirmed" if all(f.status == "confirmed" for f in members) else "partial",
            "start_time": iso_z(min(f.start_time for f in members)),
            "end_time": iso_z(max(f.end_time for f in members)),
            "finding_ids": [f.finding_id for f in members],
            "evidence_event_ids": sorted({i for f in members for i in f.evidence_event_ids}, key=U.id_key),
            "links": [{"finding_id": f.finding_id, "reasons": links[f.finding_id]} for f in members]})
    stages.sort(key=lambda s: (s["start_time"], s["stage"]))

    outside = [f for f in order if f.finding_id not in links]
    actors: dict[str, list] = {}
    unlinked = []
    for f in outside:
        if f.stage in ("brute_force", "web_recon") and f.entities["ips"]:
            for ip in f.entities["ips"]:
                actors.setdefault(ip, []).append(f)
        elif f.stage != "missing_evidence":
            unlinked.append({"finding_id": f.finding_id, "stage": f.stage, "summary": f.summary,
                             "reason": refused.get(f.finding_id, "shares no entity with the attacker set")})
    actor_list = [{
        "ip": ip, "stages": sorted({f.stage for f in v}), "finding_ids": [f.finding_id for f in v],
        "evidence_event_ids": sorted({i for f in v for i in f.evidence_event_ids}, key=U.id_key),
        "first_seen": iso_z(min(f.start_time for f in v)), "last_seen": iso_z(max(f.end_time for f in v)),
        "statement": f"No successful access from {ip} was observed in the logs; activity is attempts only."}
        for ip, v in sorted(actors.items())]

    unprovable = [{"finding_id": f.finding_id, "affects_stage": stage_of(f), "summary": f.summary,
                   "users": f.entities["users"], "hosts": f.hosts, "evidence_event_ids": f.evidence_event_ids,
                   "attached_to_chain": f.finding_id in links}
                  for f in order if f.status == "unprovable"]
    notes = []
    if not hosts:
        notes.append("host inventory (hosts.json) absent: lateral movement cannot be linked to a pivot host")
    chain = {
        "case_name": case_name, "generated_by_version": VERSION, "config": cfg.to_dict(),
        "applied_clock_offsets": dict(clock_offsets or {}),
        "attacker_entities": {"ips": sorted(ents["ips"]), "users": sorted(ents["users"]),
                              "associated_users": sorted(ents["assoc_users"] - ents["users"]),
                              "hosts": sorted(ents["hosts"]), "urls": sorted(ents["urls"])},
        "stages": stages, "attempts_only_actors": actor_list, "unlinked_findings": unlinked,
        "unprovable_items": unprovable, "notes": notes, "stats": stats}
    return chain, sorted(fs.values(), key=lambda f: (f.rule, int(f.finding_id.rsplit("-", 1)[1])))
