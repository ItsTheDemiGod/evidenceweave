"""Orchestration: build entries, merge/sort/delete, write files, THEN compute line numbers."""
from __future__ import annotations

import json
import random
from pathlib import Path

from . import attack, noise
from .formats import AUTH, NGINX, SOURCES, WIN, Entry
from .key import build_key, build_manifest

WIN_SKEW_HARD = 90


def generate(case: str, difficulty: str, seed: int, out_dir: Path) -> dict:
    if difficulty not in ("easy", "hard"):
        raise ValueError("difficulty must be easy or hard")
    hard = difficulty == "hard"
    scale = 5 if hard else 1
    skew = {s: 0 for s in SOURCES}
    skew[WIN] = WIN_SKEW_HARD if hard else 0
    rng = lambda part: random.Random(f"{seed}/{part}")  # independent deterministic streams

    entries = attack.build(rng("attack"), hard, skew[WIN])
    nr = rng("noise")
    entries += noise.ssh_sessions(nr, 20 * scale) + noise.sudo_usage(nr, 10 * scale)
    entries += noise.cron_jobs(nr, hard) + noise.web_traffic(nr, 400 * scale)
    entries += noise.windows_noise(nr, skew[WIN], scale)
    if hard:  # extra benign chatter interleaved with the attack window
        a, b = attack.DAY.replace(hour=2), attack.DAY.replace(hour=3, minute=30)
        entries += noise.ssh_sessions(nr, 40, a, b) + noise.sudo_usage(nr, 20, a, b)
        entries += noise.web_traffic(nr, 300, a, b) + noise.decoy(rng("decoy"), skew[WIN])

    placed: dict[str, list[Entry]] = {}
    dropped = [e for e in entries if e.missing]
    for src in SOURCES:
        mine = [e for e in entries if e.source == src and not e.missing]
        placed[src] = sorted(mine, key=lambda e: e.ts)  # stable: ties keep insertion order

    logs = out_dir / case / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    for src, es in placed.items():
        (logs / src).write_text("".join(e.text + "\n" for e in es), encoding="utf-8", newline="\n")

    counts = {s: len(placed[s]) for s in SOURCES}
    key = build_key(case, seed, difficulty, skew, placed, dropped)
    for name, obj in (("answer_key.json", key),
                      ("manifest.json", build_manifest(case, seed, difficulty, skew, counts))):
        (out_dir / case / name).write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8", newline="\n")
    return {"counts": counts, "evidence": sum(len(s["evidence"]) for s in key["steps"]),
            "missing": sum(len(s["evidence_missing"]) for s in key["steps"]), "path": out_dir / case}
