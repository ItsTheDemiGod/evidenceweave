"""Answer key + manifest, computed from the FINAL written line order."""
from __future__ import annotations

from .attack import ATTACKER, NEW_USER, STEPS, VICTIM
from .formats import SOURCES, Entry
from .noise import DECOY

VERSION = "1.0.0"
SYSLOG_YEAR = 2026


def iso(ts) -> str:
    return f"{ts:%Y-%m-%dT%H:%M:%S}Z"


def build_key(case: str, seed: int, difficulty: str, skew: dict[str, int],
              placed: dict[str, list[Entry]], dropped: list[Entry]) -> dict:
    """placed[source] is the final, written, ordered list: index+1 == line number."""
    steps = {i: {"step_id": i, "name": n, "description": d, "evidence": [], "evidence_missing": []}
             for i, (n, d) in STEPS.items()}
    times: dict[int, list] = {i: [] for i in steps}
    benign = []
    for src in SOURCES:
        for line_no, e in enumerate(placed[src], start=1):
            ref = {"source_file": src, "line_number": line_no, "event_marker": e.marker}
            if e.step:
                steps[e.step]["evidence"].append(ref)
            if e.benign_note:
                benign.append({**ref, "reason": e.benign_note})
    for e in dropped:
        steps[e.step]["evidence_missing"].append(
            {"description": e.missing, "source_file": e.source, "event_marker": e.marker})
    for e in [*dropped, *(x for v in placed.values() for x in v)]:
        if e.step:
            times[e.step].append(e.true_ts)
    for i, s in steps.items():
        s["start_time"], s["end_time"] = iso(min(times[i])), iso(max(times[i]))
        s["status"] = "partially_unprovable" if s["evidence_missing"] else "complete"
    return {"case_name": case, "seed": seed, "difficulty": difficulty, "attacker_ip": ATTACKER,
            "decoy_ips": [DECOY] if difficulty == "hard" else [], "compromised_user": VICTIM,
            "created_user": NEW_USER, "clock_skew_seconds": skew,
            "time_note": "step times are true UTC; windows_events.jsonl timestamps = true time + skew",
            "steps": list(steps.values()), "benign_but_suspicious_looking": benign}


def build_manifest(case: str, seed: int, difficulty: str, skew: dict[str, int], counts: dict[str, int]) -> dict:
    return {"case_name": case, "seed": seed, "difficulty": difficulty, "generator_version": VERSION,
            "assumed_syslog_year": SYSLOG_YEAR, "line_counts": counts, "clock_skew_seconds": skew}
