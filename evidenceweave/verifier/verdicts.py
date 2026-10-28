"""Failure codes and the per-sentence verdict record."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

EMPTY_TEXT, NO_CITES, CITE_NOT_ALLOWED, CITE_UNKNOWN_ID = "EMPTY_TEXT", "NO_CITES", "CITE_NOT_ALLOWED", "CITE_UNKNOWN_ID"
TOO_MANY_CITES, INLINE_ID_NOT_ALLOWED = "TOO_MANY_CITES", "INLINE_ID_NOT_ALLOWED"
MALFORMED_IP, IP_NOT_GROUNDED, TIME_NOT_GROUNDED = "MALFORMED_IP", "IP_NOT_GROUNDED", "TIME_NOT_GROUNDED"
NUMBER_NOT_GROUNDED, URL_NOT_GROUNDED, USER_NOT_GROUNDED = "NUMBER_NOT_GROUNDED", "URL_NOT_GROUNDED", "USER_NOT_GROUNDED"
HOST_NOT_GROUNDED, COMMAND_NOT_GROUNDED, SEMANTIC_MISMATCH = "HOST_NOT_GROUNDED", "COMMAND_NOT_GROUNDED", "SEMANTIC_MISMATCH"
JUDGE_UNSUPPORTED, JUDGE_PARTIAL, JUDGE_ERROR = "JUDGE_UNSUPPORTED", "JUDGE_PARTIAL", "JUDGE_ERROR"
DANGLING_ENDING = "DANGLING_ENDING"
FACT_ID_UNKNOWN, CITES_NOT_FROM_FACTS, NO_FACT_REFERENCE = "FACT_ID_UNKNOWN", "CITES_NOT_FROM_FACTS", "NO_FACT_REFERENCE"
JUDGE_QUOTE_INVALID, JUDGE_DISAGREE = "JUDGE_QUOTE_INVALID", "JUDGE_DISAGREE"
NORMALIZED = "NORMALIZED"  # informational only, never a failure

LAYERS = ("structure", "facts", "entities", "semantics", "judge")
DET_LAYERS = ("structure", "facts", "entities", "semantics")

WORDS = {
    EMPTY_TEXT: "the sentence was empty",
    NO_CITES: "the sentence cited no event IDs",
    CITE_NOT_ALLOWED: "it cited an event ID that is not in the allowed list",
    CITE_UNKNOWN_ID: "it cited an event ID that does not exist",
    TOO_MANY_CITES: "it cited too many event IDs; cite only the few that directly support it",
    INLINE_ID_NOT_ALLOWED: "it wrote an event ID in the text that is not in the allowed list",
    MALFORMED_IP: "it contains an IP address that is not a valid IPv4 address (copy IPs exactly)",
    IP_NOT_GROUNDED: "it mentions an IP address that is not in the cited events",
    TIME_NOT_GROUNDED: "it mentions a time that does not match the cited events",
    NUMBER_NOT_GROUNDED: "it states a number that is not shown in the cited events or the stage data",
    URL_NOT_GROUNDED: "it mentions a URL or domain that is not in the cited events",
    USER_NOT_GROUNDED: "it names a user or account that is not in the cited events",
    HOST_NOT_GROUNDED: "it names a host that is not in the cited events",
    COMMAND_NOT_GROUNDED: "it quotes a command or string that is not in the cited events",
    SEMANTIC_MISMATCH: "the claim is not what the cited events show (cite an event of the matching kind)",
    JUDGE_UNSUPPORTED: "an independent checker found it contradicted or not shown by the cited log lines",
    JUDGE_PARTIAL: "an independent checker found part of it unsupported by the cited log lines",
    JUDGE_ERROR: "the independent checker could not evaluate it",
    DANGLING_ENDING: "the sentence ends in a connector word or opening bracket (it looks cut off)",
    FACT_ID_UNKNOWN: "it references a fact_id that is not one of this stage's facts",
    CITES_NOT_FROM_FACTS: "its cites are not a subset of the cites of the facts it references (copy the facts' cites)",
    NO_FACT_REFERENCE: "it lists no fact_ids (every sentence must say which facts it is based on)",
    JUDGE_QUOTE_INVALID: "the checker's supporting quote for a claim does not appear in the cited log lines",
    JUDGE_DISAGREE: "two independent checks of the sentence reached different verdicts",
}


@dataclass
class SentenceVerdict:
    sentence_index: int
    stage: str
    section: str  # stage | executive_summary | attempts_only | unprovable | baseline
    source: str  # llm | template | template_fallback
    attempt: int  # 0 = original, 1..n = repair rounds
    text_original: str
    text_normalized: str
    cites_original: list
    cites_final: list
    fact_ids: list = field(default_factory=list)
    layer_results: dict = field(default_factory=dict)  # layer -> {passed: true|false|"skipped", reasons: [{code, detail}]}
    judge: dict | None = None  # {model, verdict, reason, seconds}
    accepted: bool = False
    disposition: str = "kept"  # kept | dropped | replaced_by_fallback

    def to_dict(self) -> dict:
        return asdict(self)

    def failures(self) -> list[dict]:
        """Real failures only (informational NORMALIZED notes are excluded)."""
        return [r for lr in self.layer_results.values() for r in lr.get("reasons", []) if r["code"] != NORMALIZED]

    def codes(self) -> list[str]:
        return [r["code"] for r in self.failures()]

    def det_passed(self) -> bool:
        return all(self.layer_results.get(l, {}).get("passed") is not False for l in DET_LAYERS)


def layer(reasons: list[dict]) -> dict:
    passed = not any(r["code"] != NORMALIZED for r in reasons)
    return {"passed": passed, "reasons": reasons}


def skipped(why: str) -> dict:
    return {"passed": "skipped", "reasons": [], "note": why}


def reason(code: str, detail: str) -> dict:
    return {"code": code, "detail": detail}
