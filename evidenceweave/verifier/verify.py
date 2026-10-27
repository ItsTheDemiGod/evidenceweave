"""Per-sentence verification: grounding contexts, the deterministic layers, judge hookup, feedback text."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..narrator.packs import build_packs, load_events
from ..schema import from_iso_z
from .entities import Facts, build_pool, check_entities, fact_numbers, norm_num
from .semantics import check_semantics
from .structure import check_structure
from .verdicts import (JUDGE_ERROR, JUDGE_PARTIAL, JUDGE_UNSUPPORTED, TOO_MANY_CITES, WORDS, SentenceVerdict, layer,
                       reason, skipped)


@dataclass
class UnitCtx:
    name: str  # stage name | executive_summary | template item name
    section: str
    allowed: set | None  # None = any existing event (baseline)
    facts: Facts = field(default_factory=Facts)
    pool_events: list = field(default_factory=list)  # IDs always in the grounding pool (templates, fallbacks)
    summaries: list = field(default_factory=list)  # extra ground truth shown to the judge (executive summary)
    skip_semantics: bool = False
    template: bool = False  # template/fallback: layers 1 and 2 only, never judged


def _ints(d: dict) -> set:
    out = set()
    for v in d.values():
        if isinstance(v, dict):
            out |= _ints(v)
        elif isinstance(v, (int, float)) and not isinstance(v, bool):
            out.add(norm_num(str(v)))
    return out


def facts_for(start: str, end: str, findings: list[dict], extra_numbers=(), text: str = "") -> Facts:
    nums = set()
    for f in findings:
        nums |= _ints(f["details"])
        nums |= fact_numbers(f["summary"])
    nums |= {norm_num(str(n)) for n in extra_numbers}
    dur = int((from_iso_z(end) - from_iso_z(start)).total_seconds())
    nums |= {str(dur), str(round(dur / 60))}
    nums |= {str(round(int(n) / 60)) for n in list(nums) if n.isdigit() and int(n) >= 60}  # seconds -> minutes
    return Facts({start, end}, nums, text)


@dataclass
class CaseData:
    name: str
    chain: dict
    findings: list
    events: dict
    hosts: dict
    narrative: dict | None
    packs: list
    ctxs: dict  # unit name -> UnitCtx (stages + executive_summary)
    out_dir: Path

    @property
    def host_names(self) -> list[str]:
        return list(self.hosts)

    def pack(self, stage: str):
        return next(p for p in self.packs if p.stage == stage)


def load_case_data(out_dir, hosts: dict, narrative: dict | None = None, max_evidence: int = 12) -> CaseData:
    d = Path(out_dir)
    chain = json.loads((d / "chain.json").read_text(encoding="utf-8"))
    findings = json.loads((d / "findings.json").read_text(encoding="utf-8"))["findings"]
    events = load_events(d / "events.jsonl")
    if narrative is None and (d / "narrative.json").exists():
        narrative = json.loads((d / "narrative.json").read_text(encoding="utf-8"))
    if narrative:
        max_evidence = narrative.get("max_evidence_per_stage", max_evidence)
    packs = build_packs(chain, findings, events, max_evidence)
    by_id = {f["finding_id"]: f for f in findings}
    ctxs, all_facts = {}, Facts()
    ent_lines = []
    for p, st in zip(packs, chain["stages"]):
        members = [by_id[i] for i in st["finding_ids"]]
        fx = facts_for(p.start_time, p.end_time, members, [p.evidence_shown, p.evidence_total])
        ctxs[p.stage] = UnitCtx(p.stage, "stage", set(p.allowed_cite_ids), fx)
        all_facts.times |= fx.times
        all_facts.numbers |= fx.numbers
        ent_lines.append(" ".join(v for vals in p.entities.values() for v in vals))
    ent_lines.append(" ".join(hosts))
    all_facts.text = "\n".join(ent_lines)
    ex_allowed = set((narrative or {}).get("executive_summary_meta", {}).get("allowed_cite_ids", []))
    ctxs["executive_summary"] = UnitCtx(
        "executive_summary", "executive_summary", ex_allowed, all_facts,
        summaries=[f"{p.stage}: {' '.join(p.summaries)}" for p in packs])
    return CaseData(d.name, chain, findings, events, hosts, narrative, packs, ctxs, d)


def template_ctx(data: CaseData, kind: str, index: int, cites: list) -> UnitCtx:
    """Context for a deterministic template sentence: grounded in ALL evidence of the item it came from."""
    by_id = {f["finding_id"]: f for f in data.findings}
    if kind == "attempts_only":
        item = data.chain["attempts_only_actors"][index]
        start, end = item["first_seen"], item["last_seen"]
        text = item["ip"]
    else:
        item = data.chain["unprovable_items"][index]
        fs = [by_id[item["finding_id"]]]
        start, end = fs[0]["start_time"], fs[0]["end_time"]
        text = item["summary"] + " " + " ".join(item["users"] + item["hosts"])
    members = [by_id[i] for i in item.get("finding_ids", [item.get("finding_id")]) if i in by_id]
    fx = facts_for(start, end, members, [len(item["evidence_event_ids"])], text)
    return UnitCtx(kind, kind, set(cites), fx, list(item["evidence_event_ids"]), skip_semantics=True, template=True)


def fallback_ctx(data: CaseData, unit: str, allowed: list) -> UnitCtx:
    """Context for the deterministic fallback of a unit (stage or executive summary)."""
    base = data.ctxs[unit]
    pool = (list(data.pack(unit).full_evidence_ids) if unit != "executive_summary"
            else [i for p in data.packs for i in p.full_evidence_ids])
    return UnitCtx(unit, base.section, set(allowed), base.facts, pool, base.summaries, skip_semantics=True, template=True)


class Verifier:
    def __init__(self, events: dict, host_names, max_cites: int = 8):
        self.events, self.host_names, self.max_cites = events, list(host_names), max_cites

    def det(self, ctx: UnitCtx, text: str, cites: list, index: int, attempt: int, source: str = "llm",
            use_judge: bool = True) -> SentenceVerdict:
        norm, final, st = check_structure(text, cites, ctx.allowed, self.events, self.max_cites)
        v = SentenceVerdict(index, ctx.name, ctx.section, source, attempt, text, norm, list(cites or []), final)
        v.layer_results["structure"] = st
        cited = [self.events[c] for c in final if c in self.events]
        pool_ev = cited + [self.events[i] for i in ctx.pool_events if i in self.events]
        if pool_ev or ctx.facts.text:
            facts = Facts(ctx.facts.times, ctx.facts.numbers | {str(len(final))}, ctx.facts.text)
            v.layer_results["entities"] = check_entities(norm, build_pool(pool_ev, facts), self.host_names)
        else:
            v.layer_results["entities"] = skipped("no existing cited events to ground against")
        if ctx.skip_semantics:
            v.layer_results["semantics"] = skipped("not applied to template sentences")
        elif cited:
            v.layer_results["semantics"] = check_semantics(norm, {e.action for e in cited})
        else:
            v.layer_results["semantics"] = skipped("no existing cited events")
        if ctx.template or not use_judge:
            v.layer_results["judge"] = skipped("template sentence" if ctx.template else "judge disabled (--no-judge)")
            v.accepted = v.det_passed()
        else:
            v.layer_results["judge"] = skipped("deterministic layers failed" if not v.det_passed() else "pending")
            v.accepted = False
        return v

    def apply_judge(self, judge, ctx: UnitCtx, v: SentenceVerdict) -> None:
        cited = [self.events[c] for c in v.cites_final if c in self.events]
        res = judge.judge(v.text_normalized, cited, ctx.summaries or None)
        v.judge = {k: res[k] for k in ("model", "verdict", "reason", "seconds")}
        code = {"supported": None, "partial": JUDGE_PARTIAL, "unsupported": JUDGE_UNSUPPORTED}.get(res["verdict"], JUDGE_ERROR)
        v.layer_results["judge"] = layer([reason(code, res["reason"])] if code else [])
        v.accepted = res["verdict"] == "supported"


def needs_judge(v: SentenceVerdict) -> bool:
    return v.det_passed() and v.layer_results["judge"].get("note") == "pending"


def feedback_text(verdicts: list[SentenceVerdict]) -> str:
    """Plain-words list of the previous sentences that failed and why."""
    lines = []
    for v in verdicts:
        if v.accepted:
            continue
        probs = []
        for r in v.failures():
            probs.append(f"{WORDS.get(r['code'], r['code'])} [{r['code']}: {r['detail']}]")
        lines.append(f"- Sentence: \"{v.text_normalized or v.text_original}\" (cited {', '.join(v.cites_final) or 'nothing'}) "
                     f"-> " + ("; ".join(probs) or "it was not accepted"))
    return "\n".join(lines) or "- The previous answer contained no usable sentences; produce 2 to 5 cited sentences."


def only_cap_failure(v: SentenceVerdict) -> bool:
    return not v.accepted and set(v.codes()) == {TOO_MANY_CITES}


def rates(verdicts: list[SentenceVerdict]) -> dict:
    total = len(verdicts)
    acc = sum(v.accepted for v in verdicts)
    cap = sum(only_cap_failure(v) for v in verdicts)
    return {"total": total, "accepted": acc, "rate": round(acc / total, 4) if total else None,
            "cap_only_failures": cap,
            "rate_excluding_cap_only": round(acc / (total - cap), 4) if total - cap else None}


def entity_coverage(chain: dict, findings: list[dict], hosts: dict, text: str) -> dict:
    """Which of the chain's attacker entities appear in a narrative text (derived from chain/findings only)."""
    from urllib.parse import urlsplit
    ae = chain["attacker_entities"]
    items = [("attacker_ip", i) for i in ae["ips"]] + [("compromised_user", u) for u in ae["users"]]
    items += [("payload_host", urlsplit(u).hostname) for u in ae["urls"][:1] if urlsplit(u).hostname]
    items += [("pivot_host", f["details"]["pivot_host"]) for f in findings[:]
              if f["stage"] == "lateral_movement" and f["details"].get("pivot_host")][:1]
    low = text.lower()
    out = [{"kind": k, "value": v, "present": re.search(rf"(?<![\w.\-]){re.escape(v.lower())}(?![\w\-]|\.\d)", low) is not None}
           for k, v in items]
    return {"items": out, "present": sum(i["present"] for i in out), "total": len(out)}
