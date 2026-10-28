"""Deterministic atomic facts per chain stage: what the LLM is allowed to say, with the events that prove each claim.

Every fact is a template sentence about one checkable thing and cites the events that show it BY THEMSELVES.
Facts are built from finding details, entities and chain links only (no LLM, nothing case specific). A fact that
fails the deterministic verifier layers is a bug in this builder (tests build facts for several seeds).
"""
from __future__ import annotations

from collections import defaultdict

from .. import schema as S
from ..schema import SOURCE_TYPES, iso_z
from .packs import spread

PRIORITY = {"time_window": 0, "actor": 1, "key_action": 2, "count": 3, "link": 4, "status": 5}
_ORDER = {s: i for i, s in enumerate(SOURCE_TYPES)}
CMD_PREFIX_CHARS = 60


def _t(e) -> str:
    return iso_z(e.timestamp).split(".")[0].rstrip("Z") + "Z"  # whole seconds, e.g. 2026-10-27T02:10:43Z


def linked_ids(f: dict) -> list[str]:
    """Finding ids a finding points to through its details (brute force it followed, accesses it builds on)."""
    out = []
    for k, v in f["details"].items():
        if k.startswith("linked_"):
            out += v if isinstance(v, list) else [v]
    return [i for i in out if isinstance(i, str) and i.startswith("F-")]


class _Ctx:
    def __init__(self, events: dict, findings: list[dict]):
        self.events, self.by_id = events, {f["finding_id"]: f for f in findings}
        self.findings = findings

    def chrono(self, ids):
        ev = [self.events[i] for i in dict.fromkeys(ids) if i in self.events]
        return sorted(ev, key=lambda e: (e.timestamp, _ORDER[e.source_type], e.raw_line))

    def evidence(self, f, action=None):
        ev = self.chrono(f["evidence_event_ids"])
        return [e for e in ev if action is None or e.action == action]


def _fact(kind, text, cites):
    return {"kind": kind, "text": text[:1].upper() + text[1:], "cites": [e.event_id if hasattr(e, "event_id") else e for e in cites]}


def _ends(ev):
    return [ev[0], ev[-1]] if len(ev) > 1 else list(ev)


# ---------------- per-rule generators ----------------
# A fact must be provable from its OWN cites by a reader who sees only those log lines. Aggregate numbers are therefore
# stated exactly only when every counted event is cited (at most FACT_CITE_CAP); otherwise the fact says "at least k",
# with k the number of cited events.
FACT_CITE_CAP = 8


def _sample(ev):
    """(cited events, 'N' | 'at least k'): all events when they fit under the cap, else an evenly spaced sample."""
    if len(ev) <= FACT_CITE_CAP:
        return list(ev), str(len(ev))
    picked = spread(ev, FACT_CITE_CAP)
    return picked, f"at least {len(picked)}"


def brute_force(c: _Ctx, f: dict):
    ev = c.evidence(f)
    if not ev:
        return []
    d, ip, host = f["details"], (f["entities"]["ips"] or [None])[0], (f["hosts"] or [ev[0].host])[0]
    cited, claim = _sample(ev)
    out = [_fact("actor", f"{ip} made {claim} failed login attempts against {host}.", cited)]
    by_user = {}
    for e in cited:  # distinct usernames visible in the cited lines
        by_user.setdefault(e.user, e)
    if len(by_user) > 1:
        out.append(_fact("count", f"The attempts used at least {len(by_user)} distinct usernames.", list(by_user.values())))
    for sid in d.get("success_event_ids", [])[:1]:
        s = c.events.get(sid)
        if s is not None:
            out.append(_fact("link", f"A successful login as {s.user} from {s.src_ip} was recorded.", [s]))
    return out


def initial_access(c: _Ctx, f: dict):
    ev = c.evidence(f)
    if not ev:
        return []
    e, d = ev[0], f["details"]
    method = d.get("method", "an unknown method")
    how = f"{method} authentication" if method not in ("logon",) else "an unspecified method"
    out = [_fact("key_action", f"At {_t(e)}, {e.user} logged in to {e.host} from {e.src_ip} using {how}.", [e])]
    for lid in linked_ids(f):
        lf = c.by_id.get(lid)
        lev = c.evidence(lf) if lf else []
        if lf and lev and lev[-1].timestamp <= e.timestamp:
            out.append(_fact("link", f"Failed login attempts from {lev[-1].src_ip} ended at {_t(lev[-1])}, before the login at {_t(e)}.",
                             [lev[-1], e]))
            break
    return out


def privilege_escalation(c: _Ctx, f: dict):
    ev = c.evidence(f)
    if not ev:
        return []
    e = ev[0]
    cmd = e.extra.get("command", "")
    quoted = f": `{cmd}`" if cmd and "`" not in cmd else "."
    out = [_fact("key_action", f"At {_t(e)}, {e.user} ran a sudo command on {e.host}{quoted}", [e])]
    for lid in linked_ids(f):
        lf = c.by_id.get(lid)
        lev = c.evidence(lf) if lf else []
        if lf and lf["stage"] == "initial_access" and lev and lev[0].timestamp <= e.timestamp:
            a = lev[0]
            out.append(_fact("link", f"The login by {a.user} from {a.src_ip} at {_t(a)} preceded the sudo command at {_t(e)}.", [a, e]))
            break
    return out


def persistence(c: _Ctx, f: dict):
    ev, d = c.evidence(f), f["details"]
    if not ev:
        return []
    kind = d.get("kind")
    if kind == "user_created":
        e = ev[0]
        out = [_fact("key_action", f"At {_t(e)}, the account {d['new_user']} was created on {e.host}.", [e])]
        for lid in linked_ids(f):
            lf = c.by_id.get(lid)
            lev = c.evidence(lf) if lf else []
            if lf and lev and lev[0].timestamp <= e.timestamp:
                out.append(_fact("link", f"The account {d['new_user']} was created at {_t(e)}, after the initial login at {_t(lev[0])}.",
                                 [lev[0], e]))
                break
        return out
    if kind == "cron":
        cmds = c.evidence(f, S.CRON_COMMAND)
        if not cmds:
            return []
        first, user, host = cmds[0], cmds[0].user, cmds[0].host
        cmd = d.get("command", "")
        quoted = f" `{cmd}`" if cmd and "`" not in cmd else " a command"
        cited, claim = _sample(cmds)
        return [_fact("key_action", f"A cron job for {user} on {host} ran{quoted}.", [first]),
                _fact("count", f"The cron job ran {claim} times between {_t(cited[0])} and {_t(cited[-1])}.", cited)]
    if kind == "scheduled_task":
        e = ev[0]
        return [_fact("key_action", f"At {_t(e)}, {e.user} created the scheduled task {d.get('task_name')} on {e.host}.", [e])]
    if kind == "missing_account_creation":
        return [_fact("status", f"No log event creating the account {d['missing_user']} was found, although its cron jobs on "
                                f"{ev[0].host} show it was active.", _ends(ev))]
    return []


def lateral_movement(c: _Ctx, f: dict):
    d = f["details"]
    logons = c.evidence(f, S.WIN_LOGON_SUCCESS)
    if not logons:
        return []
    lg = logons[0]
    pip, target = d.get("pivot_ip"), d.get("target_host") or lg.host
    out = [_fact("key_action", f"At {_t(lg)}, {lg.user} logged on to {target} over the network"
                               + (f" from {pip}." if pip else "."), [lg])]
    fails = c.evidence(f, S.WIN_LOGON_FAILED)
    if fails:
        cited, claim = _sample(fails)
        out.append(_fact("count", f"There were {claim} failed logons for {lg.user}" + (f" from {pip}" if pip else "") + ".", cited))
    ws = lg.extra.get("WorkstationName")
    if d.get("pivot_host") and pip and ws == d["pivot_host"]:  # only when the logon event itself names the source host
        out.append(_fact("link", f"The logon event names {ws} as the source workstation and {pip} as the source address.", [lg]))
    priv = c.evidence(f, S.WIN_SPECIAL_PRIVILEGES)
    if priv:
        out.append(_fact("key_action", f"A special-privileges event for {priv[0].user} was recorded at {_t(priv[0])}.", [priv[0]]))
    procs = c.evidence(f, S.WIN_PROCESS_CREATED)
    if procs:
        cl = procs[0].extra.get("CommandLine", "")
        prefix = " ".join(cl.split()[:4])[:CMD_PREFIX_CHARS].strip()
        tail = f" whose command line begins with `{prefix}`." if prefix and "`" not in prefix else "."
        out.append(_fact("key_action", f"At {_t(procs[0])}, {procs[0].user} started a process on {procs[0].host}{tail}", [procs[0]]))
    tasks = c.evidence(f, S.WIN_TASK_CREATED)
    if tasks:
        tk = tasks[0]
        out.append(_fact("key_action", f"At {_t(tk)}, {tk.user} created the scheduled task {tk.extra.get('TaskName')} on {tk.host}.", [tk]))
        for url in f["entities"]["urls"][:1]:
            if url in str(tk.extra.get("TaskContent", "")):
                out.append(_fact("link", f"The task content refers to {url}.", [tk]))
    return out


def web_recon(c: _Ctx, f: dict):
    reqs = c.evidence(f, S.WEB_REQUEST)
    if not reqs:
        return []
    d, ip, host = f["details"], (f["entities"]["ips"] or [None])[0], (f["hosts"] or [reqs[0].host])[0]
    cited, claim = _sample(reqs)
    out = [_fact("actor", f"{ip} made {claim} web requests to {host}.", cited)]
    errs = [e for e in reqs if e.extra.get("status") in (403, 404)]
    if errs:
        cited_e, claim_e = _sample(errs)
        out.append(_fact("count", f"{claim_e} of the requests returned HTTP status 403 or 404.", cited_e))
    picked, cites = [], []
    for p in d.get("sensitive_paths", []):
        e = next((x for x in reqs if x.extra.get("path", "").split("?")[0].lower() == p), None)
        if e is not None and len(picked) < 3:
            picked.append(e.extra["path"].split("?")[0])
            cites.append(e)
    if picked:
        names = [f"`{p}`" for p in picked]
        out.append(_fact("key_action", "The requested paths included " + (", ".join(names[:-1]) + " and " + names[-1] if len(names) > 1 else names[0]) + ".",
                         cites))
    return out


GENERATORS = {"brute_force": brute_force, "initial_access": initial_access, "privilege_escalation": privilege_escalation,
              "persistence": persistence, "lateral_movement": lateral_movement, "web_recon": web_recon}


def stage_facts(c: _Ctx, stage_entry: dict, max_facts: int) -> list[dict]:
    members = sorted((c.by_id[i] for i in stage_entry["finding_ids"]), key=lambda f: (f["start_time"], f["finding_id"]))
    ev = c.chrono(stage_entry["evidence_event_ids"])
    cands = []
    if ev:
        if ev[0].timestamp == ev[-1].timestamp or len(ev) == 1:
            cands.append(_fact("time_window", f"An event in this stage was logged at {_t(ev[0])}.", [ev[0]]))
        else:
            cands.append(_fact("time_window", f"Events in this stage were logged from {_t(ev[0])} to {_t(ev[-1])}.", [ev[0], ev[-1]]))
    for f in members:
        gen = GENERATORS.get(f["rule"])
        if gen:
            cands += gen(c, f)
    order = {id(x): i for i, x in enumerate(cands)}
    chosen = sorted(cands, key=lambda x: (PRIORITY[x["kind"]], order[id(x)]))[:max_facts]

    def first_time(x):
        evs = c.chrono(x["cites"])
        return (evs[0].timestamp if evs else ev[0].timestamp, order[id(x)])

    chosen.sort(key=first_time)  # selected by priority, presented chronologically
    for n, x in enumerate(chosen, 1):
        x["fact_id"] = f"{stage_entry['stage']}-F{n}"
        x["cites"] = [e.event_id for e in c.chrono(x["cites"])]
    return [{"fact_id": x["fact_id"], "text": x["text"], "cites": x["cites"], "kind": x["kind"]} for x in chosen]


def build_facts(chain: dict, findings: list[dict], events: dict, max_facts: int = 8) -> dict[str, list[dict]]:
    """stage name -> facts (chronological, at most max_facts, chosen by kind priority)."""
    from ..schema import from_iso_z
    fs = [{**f, "start_time_dt": from_iso_z(f["start_time"])} for f in findings]
    c = _Ctx(events, fs)
    return {st["stage"]: stage_facts(c, st, max_facts) for st in chain["stages"]}


def allowed_ids(facts: list[dict], events: dict) -> list[str]:
    """The stage's allowed cite list = the union of its facts' cites (includes linked-finding events), chronological."""
    ids = {i for f in facts for i in f["cites"]}
    return [e.event_id for e in sorted((events[i] for i in ids if i in events),
                                       key=lambda e: (e.timestamp, _ORDER[e.source_type], e.raw_line))]
