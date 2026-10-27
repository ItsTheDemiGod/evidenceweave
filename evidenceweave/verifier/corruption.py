"""The verifier's own scoreboard: inject known corruptions into accepted sentences and see what is caught."""
from __future__ import annotations

import random
import re
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta

from ..narrator.narrate import now_iso, write_json
from .entities import HMS_RE, ISO_RE, build_pool, extract, norm_iso
from .structure import id_key
from .verify import UnitCtx, Verifier, needs_judge, CaseData

SEED = 42
CAP = 70
TYPES = ["ip_digit_drop", "ip_swap", "time_shift", "number_change", "username_swap", "cite_nonexistent",
         "cite_foreign_stage", "cite_wrong_event", "fabricated_entity", "fabricated_claim_no_entity", "cite_padding"]
FAKE_NAMES = ["mallory", "oscar", "trent", "victor", "wendy", "peggy"]
FAKE_ENTITY_CLAUSES = ["The attacker also sent data to 192.0.2.99.",
                       "The host then downloaded a tool from http://malware.example.net/tool.bin.",
                       "The attacker then stored a copy in /var/tmp/.cache_dump.tar."]
FAKE_CLAIMS = ["The attacker then deleted the audit logs.", "The attacker disabled the endpoint antivirus.",
               "The attacker then cleared the shell history."]


@dataclass
class Base:
    unit: str
    index: int
    text: str
    cites: list


@dataclass
class Env:
    data: CaseData
    ctx: UnitCtx
    pool: object  # grounding Pool for the base sentence

    @property
    def events(self):
        return self.data.events


def base_sentences(verified: dict) -> list[Base]:
    out = []
    for st in verified["stages"]:
        for i, s in enumerate(x for x in st["sentences"] if x["source"] == "llm"):
            out.append(Base(st["stage"], i, s["text"], list(s["cites"])))
    for i, s in enumerate(x for x in verified["executive_summary"] if x["source"] == "llm"):
        out.append(Base("executive_summary", i, s["text"], list(s["cites"])))
    return out


# ---- generators: (base, env, rng) -> (text, cites) or None when not applicable ----
def c_ip_digit_drop(b, env, rng):
    ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", b.text)
    if not ips:
        return None
    ip = ips[0]
    if rng.random() < 0.5:
        k = rng.choice([i for i, c in enumerate(ip) if c == "."])
        bad = ip[:k] + ip[k + 1:]
    else:
        octs = ip.split(".")
        cand = [j for j, o in enumerate(octs) if len(o) >= 2]
        if not cand:
            return None
        j = rng.choice(cand)
        d = rng.randrange(len(octs[j]))
        octs[j] = octs[j][:d] + octs[j][d + 1:]
        bad = ".".join(octs)
    return (b.text.replace(ip, bad, 1), b.cites) if bad not in env.pool.text else None


def c_ip_swap(b, env, rng):
    ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", b.text)
    if not ips:
        return None
    for _ in range(50):
        new = f"192.0.2.{rng.randint(2, 250)}"
        if new not in env.pool.text and new not in b.text:
            return b.text.replace(ips[0], new), b.cites
    return None


def c_time_shift(b, env, rng):
    m = ISO_RE.search(b.text)
    if m:
        dt = datetime.fromisoformat(norm_iso(m.group(0)))
        for mins in rng.sample([17, 43, 71, 127, 211], 5):
            new = (dt + timedelta(minutes=mins)).strftime("%Y-%m-%dT%H:%M:%S") + ("Z" if m.group(0).endswith("Z") else "")
            if norm_iso(new) not in env.pool.iso:
                return b.text.replace(m.group(0), new, 1), b.cites
        return None
    m = HMS_RE.search(b.text)
    if m:
        dt = datetime.strptime(m.group(0).split(".")[0], "%H:%M:%S")
        for mins in rng.sample([17, 43, 71, 127, 211], 5):
            new = (dt + timedelta(minutes=mins)).strftime("%H:%M:%S")
            if new not in env.pool.hms:
                return b.text.replace(m.group(0), new, 1), b.cites
    return None


def c_number_change(b, env, rng):
    for n in extract(b.text, env.data.host_names).numbers:
        if not n.isdigit() or n in ("0", "1"):
            continue
        pat = re.compile(rf"(?<![\w.:\-]){n}(?![\w.:\-])")
        if not pat.search(b.text):
            continue
        for add in rng.sample([2, 3, 5, 7, 11, 13, 17], 7):
            if str(int(n) + add) not in env.pool.numbers:
                return pat.sub(str(int(n) + add), b.text, count=1), b.cites
    return None


def c_username_swap(b, env, rng):
    users = extract(b.text, env.data.host_names).users
    if not users:
        return None
    for new in rng.sample(FAKE_NAMES, len(FAKE_NAMES)):
        if new not in env.pool.text.lower():
            return re.sub(rf"\b{re.escape(users[0])}\b", new, b.text), b.cites
    return None


def c_cite_nonexistent(b, env, rng):
    if not b.cites:
        return None
    k = rng.randrange(len(b.cites))
    prefix = b.cites[k].rpartition("-L")[0]
    top = max(id_key(i)[1] for i in env.events if i.startswith(prefix))
    cites = list(b.cites)
    cites[k] = f"{prefix}-L{top + 1000 + rng.randint(0, 99)}"
    return b.text, cites


def c_cite_foreign_stage(b, env, rng):
    own = env.ctx.allowed or set()
    other = sorted({i for p in env.data.packs if p.stage != b.unit for i in p.allowed_cite_ids} - own, key=id_key)
    if not other:
        return None
    return b.text, sorted(rng.sample(other, min(max(len(b.cites), 1), len(other))), key=id_key)


def c_cite_wrong_event(b, env, rng):
    used = {env.events[c].action for c in b.cites if c in env.events}
    cand = [i for i in sorted(env.ctx.allowed or [], key=id_key) if i in env.events and env.events[i].action not in used]
    if not cand:
        return None
    return b.text, sorted(rng.sample(cand, min(max(len(b.cites), 1), len(cand))), key=id_key)


def c_fabricated_entity(b, env, rng):
    return f"{b.text.rstrip()} {rng.choice(FAKE_ENTITY_CLAUSES)}", b.cites


def c_fabricated_claim(b, env, rng):
    return f"{b.text.rstrip()} {rng.choice(FAKE_CLAIMS)}", b.cites


def c_cite_padding(b, env, rng):
    spare = sorted(set(env.ctx.allowed or []) - set(b.cites), key=id_key)
    if len(spare) < 7:
        return None
    return b.text, sorted(set(b.cites) | set(rng.sample(spare, 7)), key=id_key)


GENERATORS = dict(zip(TYPES, [c_ip_digit_drop, c_ip_swap, c_time_shift, c_number_change, c_username_swap,
                              c_cite_nonexistent, c_cite_foreign_stage, c_cite_wrong_event, c_fabricated_entity,
                              c_fabricated_claim, c_cite_padding]))


def make_env(data: CaseData, b: Base) -> Env:
    ctx = data.ctxs[b.unit]
    ev = [data.events[c] for c in b.cites if c in data.events]
    facts = type(ctx.facts)(ctx.facts.times, ctx.facts.numbers | {str(len(b.cites))}, ctx.facts.text)
    return Env(data, ctx, build_pool(ev, facts))


def candidates(data: CaseData, bases: list[Base], seed: int = SEED) -> dict[str, list[dict]]:
    out = {t: [] for t in TYPES}
    for t, gen in GENERATORS.items():
        for b in bases:
            rng = random.Random(f"{seed}/{t}/{b.unit}/{b.index}")
            r = gen(b, make_env(data, b), rng)
            if r and (r[0] != b.text or r[1] != b.cites):
                out[t].append({"type": t, "unit": b.unit, "index": b.index, "original_text": b.text,
                               "original_cites": b.cites, "text": r[0], "cites": r[1]})
    return out


def select(cands: dict[str, list[dict]], cap: int = CAP, seed: int = SEED) -> list[dict]:
    """Round-robin over the types so the cap is spread as evenly as the applicable candidates allow."""
    pools = {}
    for t in TYPES:
        items = list(cands[t])
        random.Random(f"{seed}/select/{t}").shuffle(items)
        pools[t] = items
    picked = []
    while len(picked) < cap and any(pools.values()):
        for t in TYPES:
            if pools[t] and len(picked) < cap:
                picked.append(pools[t].pop(0))
    return sorted(picked, key=lambda s: (TYPES.index(s["type"]), s["unit"], s["index"]))


def classify(v) -> str:
    if v.accepted:
        return "missed"
    if not v.det_passed():
        return "deterministic"
    verdict = (v.judge or {}).get("verdict")
    return "judge_error" if verdict == "judge_error" else "judge"


def run_corruption(data: CaseData, verified: dict, judge, max_cites: int = 8, cap: int = CAP, progress=None) -> dict:
    t0 = time.time()
    use_judge = judge is not None
    verifier = Verifier(data.events, data.host_names, max_cites)
    bases = base_sentences(verified)
    cands = candidates(data, bases)
    samples = select(cands, cap)
    jobs = [("corrupt", s) for s in samples] + [("control", {"type": "control", "unit": b.unit, "index": b.index,
                                                            "original_text": b.text, "original_cites": b.cites,
                                                            "text": b.text, "cites": b.cites}) for b in bases]
    results = []
    for kind, s in jobs:
        ctx = data.ctxs[s["unit"]]
        v = verifier.det(ctx, s["text"], s["cites"], s["index"], 0, "llm", use_judge)
        results.append((kind, s, ctx, v))
    n = 0
    if use_judge:
        for _, _, ctx, v in results:
            if needs_judge(v):
                verifier.apply_judge(judge, ctx, v)
                n += 1
    if progress:
        progress(f"  corruption: {len(samples)} corrupted + {len(bases)} control sentences, {n} judge calls, "
                 f"{time.time() - t0:.1f}s")
    per = {t: {"applicable_base_sentences": len(cands[t]), "injected": 0, "caught_deterministic": 0,
               "caught_judge_only": 0, "caught_judge_error": 0, "missed": 0} for t in TYPES}
    missed, sample_out, controls = [], [], []
    for kind, s, ctx, v in results:
        how = classify(v)
        rec = {**s, "rejected": not v.accepted, "caught_by": how, "codes": v.codes(), "judge": v.judge}
        if kind == "corrupt":
            p = per[s["type"]]
            p["injected"] += 1
            p[{"deterministic": "caught_deterministic", "judge": "caught_judge_only", "judge_error": "caught_judge_error",
               "missed": "missed"}[how]] += 1
            sample_out.append(rec)
            if how == "missed":
                missed.append({"type": s["type"], "unit": s["unit"], "original_text": s["original_text"],
                               "corrupted_text": s["text"], "original_cites": s["original_cites"],
                               "corrupted_cites": s["cites"], "judge": v.judge})
        else:
            controls.append(rec)
    for p in per.values():
        caught = p["caught_deterministic"] + p["caught_judge_only"] + p["caught_judge_error"]
        p["catch_rate"] = round(caught / p["injected"], 4) if p["injected"] else None
    inj = sum(p["injected"] for p in per.values())
    caught = sum(p["caught_deterministic"] + p["caught_judge_only"] + p["caught_judge_error"] for p in per.values())
    rej = [c for c in controls if c["rejected"]]
    report = {
        "case_name": data.name, "mode": "corruption", "created_at": now_iso(), "seed": SEED, "cap": cap,
        "judge_mode": "with_judge" if use_judge else "deterministic_only (--no-judge)",
        "judge_model": judge.model if use_judge else None, "max_cites": max_cites,
        "base_sentences": len(bases), "per_type": per,
        "overall": {"injected": inj, "caught": caught, "catch_rate": round(caught / inj, 4) if inj else None,
                    "caught_deterministic": sum(p["caught_deterministic"] for p in per.values()),
                    "caught_judge_only": sum(p["caught_judge_only"] for p in per.values()),
                    "missed": inj - caught},
        "control": {"count": len(controls), "rejected": len(rej),
                    "false_rejection_rate": round(len(rej) / len(controls), 4) if controls else None,
                    "rejected_sentences": rej},
        "missed": missed, "samples": sample_out, "controls": controls,
        "total_seconds": round(time.time() - t0, 2)}
    write_json(data.out_dir / "corruption_report.json", report)
    return report
