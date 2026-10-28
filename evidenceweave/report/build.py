"""Collects everything the HTML report shows into one JSON-serialisable dict. Reads only the pipeline outputs;
manifest.json is read for one generic flag (synthetic data) and never the answer key."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ..narrator import facts as F
from ..narrator.packs import load_events
from ..schema import format_ts, from_iso_z

LIMITS = [
    "Validated on synthetic cases with planted attacks and known ground truth only; the rules were not tested on real-world logs.",
    "The LLM narrator can only restate verified deterministic facts, so the narrative is deliberately plain.",
    "The local judge model is imperfect. Its verdicts are cross-checked by exact quote matching, double judging and the deterministic "
    "layers, but a sentence with no checkable entity may still pass if it is phrased unusually.",
    "Time correlation across hosts uses a tolerance and does not estimate clock skew.",
    "Absence of evidence in the logs is not proof of absence.",
]
PIPELINE = [
    "1. Parse: auth.log, nginx and Windows JSON logs become one normalized event schema (every line kept, unparsed lines counted).",
    "2. Correlate: deterministic rules produce findings (brute force, access, privilege escalation, persistence, lateral movement, web recon).",
    "3. Chain: findings that share an attacker entity and fit the time order are linked into an attack chain; the rest stay separate.",
    "4. Facts + narrate: atomic facts are computed from the events; a local LLM may only rewrite them (or, with --no-llm, they are shown verbatim).",
    "5. Verify: structure, fact references, entity grounding (IPs, times, numbers, users, paths, commands), claim semantics, then an independent judge.",
]
BADGES = {
    "llm": ("LLM + verified", "Written by the local LLM from deterministic facts. Accepted only after: citation structure, fact references, "
            "entity grounding, claim semantics{judge}."),
    "deterministic": ("deterministic", "A deterministic fact shown verbatim (no LLM wording). Checked by: citation structure, fact references, "
                      "entity grounding and claim semantics. Never judged by a model."),
    "template": ("template", "Fixed-wording template for attempts-only or unprovable items (no LLM). Checked by: citation structure and "
                 "entity grounding."),
}


def _load(p: Path):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def _synthetic(case_dir) -> bool:
    """Generic flag only: the manifest of a generated case says so. Nothing else is read from it."""
    try:
        m = _load(Path(case_dir) / "manifest.json")
        return bool(m.get("synthetic") or "generator_version" in m)
    except Exception:
        return False


def _git() -> str | None:
    from .. import runmeta
    c = runmeta._git().get("git_commit")
    return c[:10] if c else None


def _badge(source: str, judge_used: bool) -> dict:
    key = "llm" if source == "llm" else ("template" if source == "template" else "deterministic")
    label, tip = BADGES[key]
    return {"badge": label, "badge_kind": key,
            "tip": tip.format(judge=" and the independent double judge" if judge_used else " (judge not used in this run)")}


def _sent(s: dict, judge_used: bool) -> dict:
    return {"text": s["text"], "cites": list(s.get("cites", [])), "fact_ids": list(s.get("fact_ids", [])),
            "source": s.get("source", "llm"), **_badge(s.get("source", "llm"), judge_used)}


def verdict_line(stages: list, attempts: list) -> str:
    n = len(stages)
    if not n:
        return "No attack chain established from the logs."
    est = sum(s["status"] == "confirmed" for s in stages)
    part = sum(s["status"] in ("partial", "unprovable") for s in stages)
    head = ("Compromise confirmed" if any(s["stage"] == "initial_access" and s["status"] == "confirmed" for s in stages)
            else "Possible compromise (no confirmed initial access)")
    txt = f"{head}: {est} of {n} stages established"
    if part:
        txt += f", {part} stage{'s' if part != 1 else ''} partially unprovable"
    if attempts:
        txt += f"; {len(attempts)} actor{'s' if len(attempts) != 1 else ''} with attempts only and no successful access"
    return txt + "."


def build_data(out_dir, case_dir=None, generated_at: str | None = None) -> dict:
    out = Path(out_dir)
    chain, findings = _load(out / "chain.json"), _load(out / "findings.json")["findings"]
    events = load_events(out / "events.jsonl")
    nv = _load(out / "narrative_verified.json") if (out / "narrative_verified.json").exists() else None
    rep = _load(out / "verification_report.json") if (out / "verification_report.json").exists() else None
    ver = (nv or {}).get("verification", {})
    no_llm = bool(ver.get("no_llm"))
    judge_used = bool(nv) and not no_llm and ver.get("judge_model") is not None
    rm = (nv or {}).get("run_metadata") or {}
    by_f = {f["finding_id"]: f for f in findings}
    banners = []
    if nv is None:
        banners.append({"level": "warn", "text": "narrative_verified.json was not found: only the deterministic chain and facts are shown "
                                                 "(no narrative). Run `analyze` to create it."})
    elif no_llm:
        banners.append({"level": "warn", "text": "Built WITHOUT the LLM and WITHOUT the independent judge (--no-llm). Sentences are the "
                                                 "deterministic facts verbatim, checked by structure, entity and semantic layers only."})
    elif not judge_used:
        banners.append({"level": "warn", "text": "The independent judge was NOT used in this run (deterministic layers only)."})
    elif ver.get("judge_independent") is False:
        banners.append({"level": "warn", "text": f"WARNING: the judge model ({ver.get('judge_model')}) is the same as the narrator model; "
                                                 "the judge is NOT independent."})
    nstage = {s["stage"]: s for s in (nv or {}).get("stages", [])}
    rebuilt = None
    if any("facts" not in nstage.get(s["stage"], {}) for s in chain["stages"]):
        rebuilt = F.build_facts(chain, findings, events, 8)
    stages = []
    for st in sorted(chain["stages"], key=lambda s: (from_iso_z(s["start_time"]), s["stage"])):
        ns = nstage.get(st["stage"], {})
        ents = {k: [] for k in ("ips", "users", "hosts", "urls")}
        for fid in st["finding_ids"]:
            for k in ents:
                for v in by_f.get(fid, {}).get("entities", {}).get(k, []):
                    if v not in ents[k]:
                        ents[k].append(v)
        stages.append({
            "stage": st["stage"], "status": st["status"], "start": format_ts(from_iso_z(st["start_time"])),
            "end": format_ts(from_iso_z(st["end_time"])), "start_raw": st["start_time"], "end_raw": st["end_time"],
            "finding_ids": st["finding_ids"], "evidence_total": len(st["evidence_event_ids"]), "entities": ents,
            "facts": ns.get("facts") or (rebuilt or {}).get(st["stage"], []),
            "sentences": [_sent(s, judge_used) for s in ns.get("sentences", [])]})
    exec_s = [_sent(s, judge_used) for s in (nv or {}).get("executive_summary", [])]
    ts = (nv or {}).get("attempts_only", [])
    actors = []
    for i, a in enumerate(chain["attempts_only_actors"]):
        actors.append({"ip": a["ip"], "stages": a["stages"], "first": format_ts(from_iso_z(a["first_seen"])),
                       "last": format_ts(from_iso_z(a["last_seen"])), "first_raw": a["first_seen"], "last_raw": a["last_seen"],
                       "evidence_count": len(a["evidence_event_ids"]), "statement": a["statement"],
                       "sentences": [_sent(ts[i], judge_used)] if i < len(ts) else []})
    tu = (nv or {}).get("unprovable", [])
    unprov = []
    for i, u in enumerate(chain["unprovable_items"]):
        unprov.append({"finding_id": u["finding_id"], "affects_stage": u["affects_stage"], "summary": u["summary"],
                       "users": u["users"], "hosts": u["hosts"], "evidence_count": len(u["evidence_event_ids"]),
                       "sentences": [_sent(tu[i], judge_used)] if i < len(tu) else []})
    # ---- evidence index: every id referenced anywhere on the page ----
    ids = []
    for blk in stages:
        for x in blk["facts"] + blk["sentences"]:
            ids += x["cites"]
    for grp in (exec_s, *[a["sentences"] for a in actors], *[u["sentences"] for u in unprov]):
        for x in grp:
            ids += x["cites"]
    byfile = {}
    for e in events.values():
        byfile.setdefault(e.raw_file, []).append(e)
    for v in byfile.values():
        v.sort(key=lambda e: e.raw_line)
    evidence = {}
    for i in sorted(set(ids)):
        e = events.get(i)
        if e is None:
            evidence[i] = {"missing": True, "file": None, "line": None, "text": "(event not found in events.jsonl)", "context": []}
            continue
        seq = byfile[e.raw_file]
        k = seq.index(e)
        ctx = [{"event_id": c.event_id, "line": c.raw_line, "text": c.raw_text, "rel": j - k}
               for j, c in enumerate(seq) if k - 3 <= j <= k + 3 and j != k]
        evidence[i] = {"file": Path(e.raw_file).name, "line": e.raw_line, "timestamp": format_ts(e.timestamp),
                       "raw_timestamp": format_ts(e.raw_timestamp) if e.raw_timestamp != e.timestamp else None,
                       "host": e.host, "user": e.user, "src_ip": e.src_ip, "action": e.action, "text": e.raw_text, "context": ctx}
    src = {}
    for e in events.values():
        src[e.source_type] = src.get(e.source_type, 0) + 1
    summ = (rep or {}).get("summary", {})
    eff = summ.get("repair_effectiveness", {})
    cfg = chain.get("config", {})
    n_sent = (len(exec_s) + sum(len(s["sentences"]) for s in stages) + sum(len(a["sentences"]) for a in actors)
              + sum(len(u["sentences"]) for u in unprov))
    mode = "no-llm" if no_llm else ("no-narrative" if nv is None else "llm")
    return {
        "case": {"name": chain["case_name"], "generated_at": generated_at or format_ts(datetime.now(timezone.utc)), "mode": mode,
                 "narration_mode": (nv or {}).get("narration_mode") or "facts",
                 "narrator_model": ver.get("narrator_model"), "judge_model": ver.get("judge_model"),
                 "model_digests": rm.get("model_digests") or {}, "ollama_version": rm.get("ollama_version"),
                 "clock_offsets": chain.get("applied_clock_offsets") or {}, "tolerance_seconds": cfg.get("cross_host_tolerance_seconds"),
                 "thresholds": {k: v for k, v in cfg.items() if isinstance(v, (int, float)) and not isinstance(v, bool)},
                 "synthetic": _synthetic(case_dir) if case_dir else False,
                 "tool_version": chain.get("generated_by_version"), "git_commit": _git()},
        "banners": banners, "verdict": verdict_line(stages, actors),
        "summary": {"events": chain["stats"]["events_read"], "findings": len(findings), "stages": len(stages),
                    "attempts_only": len(actors), "unprovable": len(unprov), "sentences": n_sent},
        "stages": stages, "executive_summary": exec_s, "attempts_only": actors, "unprovable": unprov,
        "unlinked": chain.get("unlinked_findings", []), "evidence": evidence, "limits": LIMITS, "pipeline": PIPELINE,
        "stats": {"events_by_source": src, "unparsed": sum(e.action == "unparsed" for e in events.values()),
                  "findings_per_rule": chain["stats"].get("findings_per_rule", {}),
                  "verification": ({
                      "accepted": ver.get("accepted_total"), "dropped": ver.get("dropped_total"),
                      "fallback_units": ver.get("fallback_units", []), "judge_model": ver.get("judge_model"),
                      "judge_independent": ver.get("judge_independent"), "judge_double": ver.get("judge_double"),
                      "judge_agreement_rate": summ.get("judge_agreement_rate"),
                      "repair": {k: eff.get(k) for k in ("failing_at_attempt0", "fixed_total", "still_failing")},
                      "total_seconds": (rep or {}).get("total_seconds")} if nv else None)}}
