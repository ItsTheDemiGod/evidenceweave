"""Chain narrator: one LLM call per stage + an executive summary; accountability sections are templates."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import prompts as P
from .llm import LLMClient, call_json, safe_name
from .packs import MAX_RAW_CHARS, build_packs, load_events


@dataclass
class NarratorConfig:
    max_evidence_per_stage: int = 12
    max_raw_chars: int = MAX_RAW_CHARS
    chunk_size: int = 120  # baseline only


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def save_raw(case_dir: Path, mode: str, model: str, name: str, text: str) -> str:
    rel = Path("narrator_raw") / f"{mode}_{safe_name(model)}" / f"{name}.txt"
    (case_dir / rel).parent.mkdir(parents=True, exist_ok=True)
    (case_dir / rel).write_text(text, encoding="utf-8", newline="\n")
    return rel.as_posix()


def write_json(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8", newline="\n")


def _pick(ids: list, n: int) -> list:
    """First, middle and last (n=3) / first few, de-duplicated, order kept."""
    if n == 3 and len(ids) > 2:
        ids = [ids[0], ids[len(ids) // 2], ids[-1]]
    return list(dict.fromkeys(ids[:n] if n != 3 else ids))


def template_sections(chain: dict, findings: list[dict], events: dict) -> tuple[list, list]:
    """Deterministic accountability sentences (never written by the LLM)."""
    by_id = {f["finding_id"]: f for f in findings}
    chrono = lambda ids: sorted((i for i in ids if i in events), key=lambda i: (events[i].timestamp, i))
    attempts = []
    for a in chain["attempts_only_actors"]:
        parts = []
        for fid in a["finding_ids"]:
            d = by_id[fid]["details"]
            if "failure_count" in d:
                parts.append(f"{d['failure_count']} failed login attempts")
            elif "request_count" in d:
                parts.append(f"{d['request_count']} web requests")
            else:
                parts.append(f"{len(by_id[fid]['evidence_event_ids'])} events")
        attempts.append({
            "text": f"{a['ip']} made {' and '.join(parts)} between {a['first_seen']} and {a['last_seen']}; "
                    f"no successful access from this address was observed.",
            "cites": _pick(chrono(a["evidence_event_ids"]), 3), "source": "template"})
    unprovable = []
    for u in chain["unprovable_items"]:
        unprovable.append({
            "text": f"It could not be proven how this happened: {u['summary']} Only indirect evidence exists: "
                    f"{len(u['evidence_event_ids'])} related events involving {', '.join(u['users'])} on "
                    f"{', '.join(u['hosts'])}.",
            "cites": _pick(chrono(u["evidence_event_ids"]), 4), "source": "template"})
    return attempts, unprovable


FEEDBACK_HEADER = "\n\nREPAIR FEEDBACK - your previous answer had problems:\n"
FEEDBACK_FOOTER = ("\nRewrite the answer using ONLY the evidence lines and the allowed IDs above. Fix every problem listed, "
                   "keep the facts that were fine, and reply with the JSON object only.")


def with_feedback(user: str, feedback: str | None) -> str:
    """Phase 5 repair rounds append the verifier's feedback; the first attempt is byte-identical to Phase 4."""
    return user if not feedback else user + FEEDBACK_HEADER + feedback + FEEDBACK_FOOTER


def narrate_stage(client: LLMClient, pack, feedback: str | None = None):
    return call_json(client, P.STAGE_SYSTEM, with_feedback(P.stage_prompt(pack), feedback))


def summary_info(packs) -> list[dict]:
    return [{"stage": p.stage, "status": p.status, "start_time": p.start_time, "end_time": p.end_time,
             "summaries": p.summaries, "notes": p.notes,
             "cite_ids": list(dict.fromkeys([p.allowed_cite_ids[0], p.allowed_cite_ids[-1]]))} for p in packs]


def narrate_summary(client: LLMClient, info: list[dict], feedback: str | None = None):
    return call_json(client, P.SUMMARY_SYSTEM, with_feedback(P.summary_prompt(info), feedback))


def _progress(cb, msg: str) -> None:
    if cb:
        cb(msg)


def narrate_chain(case_output_dir, client: LLMClient, config: NarratorConfig | None = None, progress=None) -> dict:
    cfg = config or NarratorConfig()
    d = Path(case_output_dir)
    chain = json.loads((d / "chain.json").read_text(encoding="utf-8"))
    findings = json.loads((d / "findings.json").read_text(encoding="utf-8"))["findings"]
    events = load_events(d / "events.jsonl")
    packs = build_packs(chain, findings, events, cfg.max_evidence_per_stage, cfg.max_raw_chars)
    t_all, stats = time.time(), {"calls": 0, "failed_parses": 0, "retries": 0, "tokens": None}

    def run(name: str, call) -> tuple:
        rec = call()
        stats["calls"] += rec.attempts
        stats["failed_parses"] += rec.failed_parses
        stats["retries"] += rec.retries
        if rec.tokens is not None:
            stats["tokens"] = (stats["tokens"] or 0) + rec.tokens
        raw = save_raw(d, "chain", client.model, name, rec.transcript)
        _progress(progress, f"  {name}: {rec.seconds:.1f}s, attempts={rec.attempts}, parse_ok={rec.parsed is not None}")
        return rec, raw

    stage_out = []
    for p in packs:
        rec, raw = run(p.stage, lambda p=p: narrate_stage(client, p))
        stage_out.append({
            "stage": p.stage, "status": p.status, "source": "llm",
            "sentences": rec.parsed["sentences"] if rec.parsed else [], "parse_ok": rec.parsed is not None,
            "attempts": rec.attempts, "seconds": round(rec.seconds, 2), "evidence_shown": p.evidence_shown,
            "evidence_total": p.evidence_total, "allowed_cite_ids": p.allowed_cite_ids, "raw_output_file": raw})
    info = summary_info(packs)
    rec, raw = run("executive_summary", lambda: narrate_summary(client, info))
    allowed = list(dict.fromkeys(i for s in info for i in s["cite_ids"]))
    attempts_only, unprovable = template_sections(chain, findings, events)
    out = {
        "case_name": chain["case_name"], "mode": "chain", "model": client.model, "prompt_version": P.PROMPT_VERSION,
        "ollama_options": client.options, "json_mode": client.json_mode,
        "total_seconds": round(time.time() - t_all, 2), "created_at": now_iso(),
        "max_evidence_per_stage": cfg.max_evidence_per_stage,
        "executive_summary": rec.parsed["sentences"] if rec.parsed else [],
        "executive_summary_meta": {"parse_ok": rec.parsed is not None, "attempts": rec.attempts,
                                   "seconds": round(rec.seconds, 2), "allowed_cite_ids": allowed,
                                   "raw_output_file": raw},
        "stages": stage_out, "attempts_only": attempts_only, "unprovable": unprovable,
        "stats": {"calls": stats["calls"], "failed_parses": stats["failed_parses"], "retries": stats["retries"],
                  "total_tokens": stats["tokens"]}}
    write_json(d / "narrative.json", out)
    return out
