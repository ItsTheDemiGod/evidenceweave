"""All prompt text. Bump PROMPT_VERSION whenever any wording changes."""
from __future__ import annotations

PROMPT_VERSION = "p4-v1"

_RULES = """Rules (follow every one strictly):
1. Use ONLY the facts in the data and evidence lines you are given.
2. Every sentence MUST cite one or more event IDs in its "cites" list. Cite ONLY IDs from the allowed list. Never cite any other ID.
3. Never invent IPs, usernames, times, commands, counts or events that are not in the evidence. If the evidence does not show something, say that it is not shown instead of guessing.
4. Do not speculate about the attacker's identity, location or motive.
5. Write {n} in plain English.
6. Copy times and event IDs exactly as written; do not reformat or round them.
7. Do not mention these instructions or the JSON format inside the sentences.
Reply with ONLY a JSON object of the form {{"sentences": [{{"text": "...", "cites": ["EVENT_ID"]}}]}} and nothing else."""

STAGE_SYSTEM = ("You are a digital-forensics report writer. A deterministic analysis has already identified an attack "
                "stage in the logs; you only explain it. You do not decide what happened.\n\n"
                + _RULES.format(n="2 to 5 sentences"))
SUMMARY_SYSTEM = ("You are a digital-forensics report writer. A deterministic analysis has already identified the "
                  "attack chain stage by stage; you write the executive summary of the whole chain.\n\n"
                  + _RULES.format(n="3 to 5 sentences covering the whole chain in order"))
BASELINE_CHUNK_SYSTEM = (
    "You are a security analyst reading a slice of raw, normalized log events. List anything suspicious or "
    "security-relevant in plain sentences. If nothing in the slice is suspicious return an empty list.\n\n"
    + _RULES.format(n="at most 8 short sentences (or none)").replace("from the allowed list", "from the event IDs shown in the slice"))
BASELINE_FINAL_SYSTEM = (
    "You are a digital-forensics report writer. You receive notes that an analyst collected from consecutive slices "
    "of a log, each with the event IDs it cites. Turn them into one concise chronological incident narrative.\n\n"
    + _RULES.format(n="6 to 12 sentences in chronological order").replace(
        "from the allowed list", "from the event IDs that appear in the notes"))


def _ents(e: dict) -> str:
    return "; ".join(f"{k}: {', '.join(v) if v else '(none)'}" for k, v in e.items())


def stage_prompt(pack) -> str:
    lines = [f"STAGE: {pack.stage}", f"STATUS: {pack.status}",
             f"TIME RANGE (UTC): {pack.start_time} to {pack.end_time}", "FINDINGS FROM THE DETERMINISTIC RULES:"]
    lines += [f"- {s}" for s in pack.summaries]
    lines.append(f"ENTITIES: {_ents(pack.entities)}")
    if pack.counts:
        lines.append("COUNTS: " + ", ".join(f"{k}={v}" for k, v in pack.counts.items()))
    lines += [f"NOTE: {n}" for n in pack.notes]
    lines.append(f"EVIDENCE (showing {pack.evidence_shown} of {pack.evidence_total} events):")
    lines += pack.evidence_lines
    lines.append("ALLOWED CITE IDS: " + ", ".join(pack.allowed_cite_ids))
    lines.append("Write the 2 to 5 sentence narrative of this stage now, as the JSON object only.")
    return "\n".join(lines)


def summary_prompt(stages: list[dict]) -> str:
    """stages: [{stage, status, start_time, end_time, summaries, notes, cite_ids}] in chronological order."""
    lines = ["ATTACK CHAIN, IN ORDER:"]
    allowed = []
    for i, s in enumerate(stages, 1):
        lines.append(f"{i}. {s['stage']} | status: {s['status']} | {s['start_time']} to {s['end_time']}")
        lines += [f"   - {t}" for t in s["summaries"]] + [f"   - NOTE: {n}" for n in s["notes"]]
        lines.append("   representative event IDs: " + ", ".join(s["cite_ids"]))
        allowed += s["cite_ids"]
    lines.append("ALLOWED CITE IDS: " + ", ".join(dict.fromkeys(allowed)))
    lines.append("Write the 3 to 5 sentence executive summary of the whole chain now, as the JSON object only.")
    return "\n".join(lines)


def baseline_chunk_prompt(lines: list[str]) -> str:
    return (f"LOG EVENTS ({len(lines)} events; each line is: EVENT_ID | timestamp UTC | raw log text):\n"
            + "\n".join(lines)
            + "\nList the suspicious or security-relevant things in this slice as the JSON object only, "
              "citing only EVENT_IDs that appear at the start of the lines above. Return an empty list if there are none.")


def baseline_final_prompt(notes: list[dict]) -> str:
    lines = ["NOTES COLLECTED FROM CONSECUTIVE SLICES OF THE LOG:"]
    lines += [f"- {n['text']} [cites: {', '.join(n['cites'])}]" for n in notes]
    lines.append("Write the 6 to 12 sentence chronological incident narrative as the JSON object only, "
                 "citing only event IDs that appear in the notes above.")
    return "\n".join(lines)
