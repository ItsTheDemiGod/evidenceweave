"""Layer 3b: an independent LLM (a different model from the narrator) judges one sentence against its cited lines."""
from __future__ import annotations

import json
import time

from ..narrator.packs import event_line, spread

VERDICTS = ("supported", "partial", "unsupported")
VERDICT_SCHEMA = {"type": "object",
                  "properties": {"verdict": {"type": "string", "enum": list(VERDICTS)}, "reason": {"type": "string"}},
                  "required": ["verdict", "reason"]}
JUDGE_REMINDER = '\n\nReminder: reply with ONLY valid JSON: {"verdict": "supported|partial|unsupported", "reason": "..."}.'

JUDGE_SYSTEM = """You are a strict evidence checker. You are given ONE sentence from an incident report and the exact log lines it cites.
Decide whether the sentence is fully supported by those log lines alone.
- supported: every factual claim in the sentence is shown in the lines.
- partial: some claims are shown and some are not, or the sentence goes beyond what the lines show.
- unsupported: the sentence is contradicted by the lines or is not shown by them.
Do not use outside knowledge or assumptions; judge only what the lines say. Pay attention to IP addresses, user names, times, counts, commands and the kind of event (a plain logon is not a privileged logon).
Reply with ONLY a JSON object: {"verdict": "supported" | "partial" | "unsupported", "reason": "<one short sentence>"}."""


def parse_verdict(text: str) -> dict | None:
    try:
        obj = json.loads(text)
        if obj["verdict"] in VERDICTS and isinstance(obj["reason"], str):
            return obj
    except (ValueError, KeyError, TypeError):
        pass
    return None


def judge_prompt(sentence: str, cited_events: list, summaries: list[str] | None = None, max_events: int = 12) -> str:
    shown = spread(cited_events, max_events) if len(cited_events) > max_events else list(cited_events)
    lines = [f"SENTENCE: {sentence}", ""]
    head = f"LOG LINES ({len(shown)} shown"
    head += f", {len(cited_events) - len(shown)} more cited lines omitted):" if len(shown) < len(cited_events) else "):"
    lines.append(head)
    lines += [event_line(e) for e in shown]
    if summaries:
        lines += ["", "GROUND TRUTH SUMMARIES OF THE ATTACK STAGES (from deterministic analysis):"]
        lines += [f"- {s}" for s in summaries]
    lines += ["", "Is the sentence fully supported by the information above? Reply with the JSON object only."]
    return "\n".join(lines)


class Judge:
    def __init__(self, client, max_events: int = 12):
        self.client, self.max_events = client, max_events

    @property
    def model(self) -> str:
        return self.client.model

    def judge(self, sentence: str, cited_events: list, summaries: list[str] | None = None) -> dict:
        """Never raises on a bad reply: unparseable twice -> verdict judge_error."""
        user = judge_prompt(sentence, cited_events, summaries, self.max_events)
        t0, last = time.time(), None
        for attempt in (1, 2):
            res = self.client.complete(JUDGE_SYSTEM, user if attempt == 1 else user + JUDGE_REMINDER)
            obj = res.parsed if isinstance(res.parsed, dict) and "verdict" in res.parsed else parse_verdict(res.raw)
            if obj is not None and obj.get("verdict") in VERDICTS:
                return {"model": self.model, "verdict": obj["verdict"], "reason": obj.get("reason", ""),
                        "seconds": round(time.time() - t0, 2), "attempts": attempt}
            last = res
        return {"model": self.model, "verdict": "judge_error",
                "reason": f"unparseable judge reply twice: {(last.raw if last else '')[:120]!r}",
                "seconds": round(time.time() - t0, 2), "attempts": 2}
