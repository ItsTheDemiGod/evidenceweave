"""Layer 3b: an independent LLM (a different model from the narrator) judges one sentence against its cited lines."""
from __future__ import annotations

import json
import re
import time

from ..narrator.packs import event_line, spread
from ..schema import iso_z
from .verdicts import JUDGE_DISAGREE, JUDGE_ERROR, JUDGE_PARTIAL, JUDGE_QUOTE_INVALID, JUDGE_UNSUPPORTED

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


def judge_prompt(sentence: str, cited_events: list, summaries: list[str] | None = None, max_events: int = 12,
                 closing: str = "Is the sentence fully supported by the information above? Reply with the JSON object only.") -> str:
    shown = spread(cited_events, max_events) if len(cited_events) > max_events else list(cited_events)
    lines = [f"SENTENCE: {sentence}", ""]
    head = f"LOG LINES ({len(shown)} shown"
    head += f", {len(cited_events) - len(shown)} more cited lines omitted):" if len(shown) < len(cited_events) else "):"
    lines.append(head)
    lines += [event_line(e) for e in shown]
    if summaries:
        lines += ["", "GROUND TRUTH SUMMARIES OF THE ATTACK STAGES (from deterministic analysis):"]
        lines += [f"- {s}" for s in summaries]
    lines += ["", closing]
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


# ---------------- hardened judge (Phase 5b): claims + exact quotes, verdict derived in code, judged twice ----------------
CLAIMS_SCHEMA = {
    "type": "object",
    "properties": {
        "claims": {"type": "array", "items": {"type": "object", "properties": {
            "claim": {"type": "string"}, "supported": {"type": "boolean"}, "quote": {"type": "string"}},
            "required": ["claim", "supported", "quote"]}},
        "verdict": {"type": "string", "enum": list(VERDICTS)}, "reason": {"type": "string"}},
    "required": ["claims", "verdict", "reason"]}

CLAIMS_SYSTEM = """You are a strict evidence checker. You are given ONE sentence from an incident report and the exact log lines it cites.
Step 1: split the sentence into its distinct factual claims (who, what, when, where, how many, with what).
Each log line has the form: EVENT_ID | timestamp (UTC) | raw log text. A quote may come from the timestamp or from the raw log text; never include the 'EVENT_ID |' prefix, '|' separators or '...' in a quote.
Standard Windows Security EventIDs you may rely on: 4624 successful logon, 4625 failed logon, 4672 special privileges assigned, 4688 process created, 4698 scheduled task created, 4720 user account created. Nothing else is assumed.
Step 2: for each claim decide whether the log lines show it. If they do, copy ONE exact quote from a single log line that shows it (character for character, no changes). If they do not, set supported to false and leave quote empty.
Rules: never quote text that is not in the lines; use no outside knowledge; a claim about something the lines do not show (an action, cause, tool, intent, or event that is not in the lines) is unsupported; a plain logon is not a privileged logon; counts, times, names and addresses must match the lines exactly.
Finally give an overall verdict (supported / partial / unsupported) and a one-sentence reason.
Reply with ONLY a JSON object: {"claims": [{"claim": "...", "supported": true, "quote": "..."}], "verdict": "supported|partial|unsupported", "reason": "..."}."""
CLAIMS_CLOSING = "List the claims with their exact quotes. Reply with the JSON object only."
CLAIMS_REMINDER = ('\n\nReminder: reply with ONLY valid JSON: {"claims": [{"claim": "", "supported": true, "quote": ""}], '
                   '"verdict": "supported|partial|unsupported", "reason": ""}.')


def parse_claims(text: str) -> dict | None:
    try:
        obj = json.loads(text)
        if (obj["verdict"] in VERDICTS and isinstance(obj["reason"], str) and isinstance(obj["claims"], list)
                and all(isinstance(c, dict) and isinstance(c.get("claim"), str) and isinstance(c.get("supported"), bool)
                        and isinstance(c.get("quote"), str) for c in obj["claims"])):
            return obj
    except (ValueError, KeyError, TypeError):
        pass
    return None


def _squash(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


class ClaimJudge:
    """Same interface as Judge. Each sentence is judged twice (run 2 uses seed 43); accepted only if both DERIVED
    verdicts are 'supported'. A claim only counts if supported is true AND its quote is found in a shown log line."""

    def __init__(self, client, max_events: int = 12, double: bool = True, second_seed: int = 43):
        self.client, self.max_events, self.double, self.second_seed = client, max_events, double, second_seed

    @property
    def model(self) -> str:
        return self.client.model

    def _run(self, user: str, shown: list, options: dict | None) -> dict:
        extra = {"options": options} if options else {}
        # a quote is valid inside a shown event's raw text OR its timestamp field (both are in the line the judge sees)
        texts = [_squash(e.raw_text) for e in shown] + [iso_z(e.timestamp) for e in shown]
        obj, attempts = None, 0
        for attempts in (1, 2):
            res = self.client.complete(CLAIMS_SYSTEM, user if attempts == 1 else user + CLAIMS_REMINDER, **extra)
            obj = res.parsed if isinstance(res.parsed, dict) and "claims" in res.parsed else parse_claims(res.raw)
            if obj is not None:
                break
        seed = (options or {}).get("seed", getattr(self.client, "options", {}).get("seed"))
        if obj is None:
            return {"seed": seed, "derived": "judge_error", "own_verdict": None, "own_reason": "unparseable twice",
                    "claims": [], "invalid_quotes": 0, "attempts": 2}
        claims = []
        for c in obj["claims"]:
            q = _squash(c["quote"])
            valid = bool(c["supported"]) and bool(q) and any(q in t for t in texts)
            claims.append({"claim": c["claim"], "supported": c["supported"], "quote": c["quote"], "valid": valid,
                           "invalid_quote": bool(c["supported"]) and not valid})
        n_valid = sum(c["valid"] for c in claims)
        derived = "supported" if claims and n_valid == len(claims) else ("partial" if n_valid else "unsupported")
        return {"seed": seed, "derived": derived, "own_verdict": obj["verdict"], "own_reason": obj["reason"],
                "claims": claims, "invalid_quotes": sum(c["invalid_quote"] for c in claims), "attempts": attempts}

    def judge(self, sentence: str, cited_events: list, summaries: list[str] | None = None) -> dict:
        t0 = time.time()
        shown = spread(cited_events, self.max_events) if len(cited_events) > self.max_events else list(cited_events)
        user = judge_prompt(sentence, cited_events, summaries, self.max_events, CLAIMS_CLOSING)
        runs = [self._run(user, shown, None)]
        if self.double:
            runs.append(self._run(user, shown, {"seed": self.second_seed}))
        derived = [r["derived"] for r in runs]
        agreement = len(set(derived)) == 1
        disagreements = sum(1 for r in runs if r["own_verdict"] is not None and r["own_verdict"] != r["derived"])
        codes, bad_quotes = [], sum(r["invalid_quotes"] for r in runs)
        if "judge_error" in derived:
            verdict, reason = "judge_error", runs[derived.index("judge_error")]["own_reason"]
            codes.append((JUDGE_ERROR, reason))
        else:
            if bad_quotes:
                codes.append((JUDGE_QUOTE_INVALID, f"{bad_quotes} supported claim(s) quoted text that is not in the cited lines"))
            if not agreement:
                verdict, reason = "disagree", f"the two judge runs derived {derived}"
                codes.append((JUDGE_DISAGREE, reason))
            else:
                verdict = derived[0]
                weak = [c["claim"] for c in runs[0]["claims"] if not c["valid"]]
                reason = (f"all {len(runs[0]['claims'])} claims quoted from the lines" if verdict == "supported"
                          else "; ".join(f"not shown: {w}" for w in weak[:3]) or runs[0]["own_reason"])
                if verdict == "partial":
                    codes.append((JUDGE_PARTIAL, reason))
                elif verdict == "unsupported":
                    codes.append((JUDGE_UNSUPPORTED, reason))
        return {"model": self.model, "verdict": verdict, "reason": reason, "seconds": round(time.time() - t0, 2),
                "runs": [{k: r[k] for k in ("seed", "own_verdict", "own_reason", "derived", "claims", "invalid_quotes", "attempts")}
                         for r in runs],
                "agreement": agreement, "own_vs_derived_disagreements": disagreements, "codes": codes}

JUDGE_PROMPT_VERSION = "p5b-claims-v2"
