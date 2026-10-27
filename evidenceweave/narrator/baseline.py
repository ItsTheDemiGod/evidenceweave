"""Naive baseline: raw events in chunks -> LLM notes -> one LLM narrative. No rules, no chain, no key."""
from __future__ import annotations

import time
from pathlib import Path

from . import prompts as P
from .llm import LLMClient, call_json
from .narrate import NarratorConfig, now_iso, save_raw, write_json, _progress
from .packs import event_line, load_events


def chunks(items: list, size: int) -> list[list]:
    return [items[i:i + size] for i in range(0, len(items), size)]


def check_fits(lines: list[str], num_ctx: int, size: int) -> None:
    est = sum(len(x) for x in lines) / 3 + 700  # ~3 chars per token for logs, + prompt overhead
    if est > num_ctx * 0.85:
        raise ValueError(f"chunk of {size} events needs ~{int(est)} tokens but num_ctx is {num_ctx}: "
                         f"lower --chunk-size or raise --num-ctx")


def run_baseline(case_output_dir, client: LLMClient, config: NarratorConfig | None = None, progress=None) -> dict:
    cfg = config or NarratorConfig()
    d = Path(case_output_dir)
    events = list(load_events(d / "events.jsonl").values())  # dicts keep file (= sorted) order
    t_all = time.time()
    stats = {"calls": 0, "failed_parses": 0, "retries": 0, "tokens": None}

    def run(name: str, system: str, user: str):
        rec = call_json(client, system, user)
        stats["calls"] += rec.attempts
        stats["failed_parses"] += rec.failed_parses
        stats["retries"] += rec.retries
        if rec.tokens is not None:
            stats["tokens"] = (stats["tokens"] or 0) + rec.tokens
        raw = save_raw(d, "baseline", client.model, name, rec.transcript)
        _progress(progress, f"  {name}: {rec.seconds:.1f}s, attempts={rec.attempts}, parse_ok={rec.parsed is not None}")
        return rec, raw

    parts = chunks(events, cfg.chunk_size)
    num_ctx = client.options.get("num_ctx", 8192)
    notes, chunk_out = [], []
    all_lines = [[event_line(e, cfg.max_raw_chars) for e in part] for part in parts]
    for lines in all_lines:  # fail before the first LLM call, not halfway through
        check_fits(lines, num_ctx, len(lines))
    for n, (part, lines) in enumerate(zip(parts, all_lines), 1):
        rec, raw = run(f"chunk_{n:03d}", P.BASELINE_CHUNK_SYSTEM, P.baseline_chunk_prompt(lines))
        sents = rec.parsed["sentences"] if rec.parsed else []
        notes += sents
        chunk_out.append({"index": n, "first_event": part[0].event_id, "last_event": part[-1].event_id,
                          "events": len(part), "seconds": round(rec.seconds, 2), "parse_ok": rec.parsed is not None,
                          "attempts": rec.attempts, "notes": len(sents), "raw_output_file": raw})
    final_sents, final_meta = [], {"skipped": True}
    if notes:
        rec, raw = run("final", P.BASELINE_FINAL_SYSTEM, P.baseline_final_prompt(notes))
        final_sents = rec.parsed["sentences"] if rec.parsed else []
        final_meta = {"parse_ok": rec.parsed is not None, "attempts": rec.attempts,
                      "seconds": round(rec.seconds, 2), "raw_output_file": raw}
    out = {
        "case_name": d.name, "mode": "baseline", "model": client.model, "prompt_version": P.PROMPT_VERSION,
        "ollama_options": client.options, "json_mode": client.json_mode, "chunk_size": cfg.chunk_size,
        "number_of_chunks": len(parts), "chunks": chunk_out, "collected_notes": notes, "final": final_meta,
        "sentences": final_sents, "failed_parses": stats["failed_parses"], "retries": stats["retries"],
        "total_seconds": round(time.time() - t_all, 2), "created_at": now_iso(),
        "stats": {"calls": stats["calls"], "failed_parses": stats["failed_parses"], "retries": stats["retries"],
                  "total_tokens": stats["tokens"]}}
    write_json(d / "baseline_narrative.json", out)
    return out
