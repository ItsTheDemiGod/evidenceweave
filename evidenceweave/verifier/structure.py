"""Layer 1: text normalization, inline-ID handling and citation structure."""
from __future__ import annotations

import re

from .verdicts import (CITE_NOT_ALLOWED, CITE_UNKNOWN_ID, DANGLING_ENDING, EMPTY_TEXT, INLINE_ID_NOT_ALLOWED, NO_CITES,
                       NORMALIZED, TOO_MANY_CITES, layer, reason)

IDS = r"(?:AUTH|NGX|WIN)-L\d+"
ID_RE = re.compile(rf"\b{IDS}\b")
_LIST = rf"{IDS}(?:\s*(?:,|;|&|\band\b|\bto\b|-|–)\s*{IDS})*"
_LABEL = r"(?:cites?|citing|cited|event\s+ids?|events?|ids?|see)"
GROUP_RE = re.compile(rf"\s*[(\[]\s*(?:{_LABEL}\s*:?\s*)?{_LIST}\s*[)\]]", re.I)
LEAD_RE = re.compile(rf"\s*\b(?:cites?|citing|cited|event\s+ids?)\s*:?\s*{_LIST}", re.I)
BARE_RE = re.compile(rf"\s*{IDS}(?:\s*(?:,|;|&|\band\b)\s*{IDS})*")


def id_key(event_id: str):
    prefix, _, n = event_id.rpartition("-L")
    return (prefix, int(n))


QUOTES = "'\"`"


def _excess(t: str, q: str) -> int:
    """closers minus openers of quote char q (apostrophes inside words are ignored)."""
    opens = closes = 0
    last = None
    for i, ch in enumerate(t):
        if ch != q:
            continue
        prev = t[i - 1] if i else " "
        nxt = t[i + 1] if i + 1 < len(t) else " "
        if prev == q:
            cls = last  # a run inherits the class of its first quote
        elif prev.isalnum() and nxt.isalnum():
            last = None
            continue
        else:
            cls = "o" if (i == 0 or prev in " \t([{") else "c"
        last = cls
        opens += cls == "o"
        closes += cls == "c"
    return closes - opens


def normalize(text: str) -> str:
    """Strip markdown, junk and stray quote runs; collapse whitespace.

    A quote character is only removed when it is in EXCESS (more closers than openers), so the closing quote
    of a quoted phrase or command is never deleted.
    """
    t = re.sub(r"\*+", "", text or "")
    t = re.sub(r"^\s*(?:[-\u2022]|\d+[.)])\s+", "", t)
    t = re.sub(r"\s+", " ", t).strip()
    t = re.sub(r"^[\s,;:\-]+", "", t)
    for q in QUOTES:  # leading quotes only while openers are in excess
        extra = -_excess(t, q)
        while extra > 0 and t.startswith(q):
            t, extra = t[1:], extra - 1
    t = t.lstrip()
    m = re.search(r"[\s.!?,;:'\"`]*$", t)
    body, tail = t[:m.start()], list(t[m.start():])
    for q in QUOTES:  # excess closing quotes are junk: remove them from the right end of the tail
        extra = min(_excess(t, q), tail.count(q))
        for i in range(len(tail) - 1, -1, -1):
            if extra <= 0:
                break
            if tail[i] == q:
                del tail[i]
                extra -= 1
    t = body + re.sub(r"[\s,;:]+$", "", "".join(tail))
    t = re.sub(r"\s+([,.;:!?])", r"\1", t)
    t = re.sub(r"([.!?])[.!?]+$", r"\1", t)  # a quote run after a full stop leaves a doubled stop
    return re.sub(r"\s+", " ", t).strip()


# ---- dangling endings ("... as shown by.") ----
CONNECTORS = set("by as in with of and or the an to from via see cited shown per on at for that which than into onto "
                 "between through during under over about after before because while".split())
_SHOWN = r"(?:shown|seen|evidenced|confirmed|recorded|documented|noted|cited|listed|indicated|visible)"
DANGLING_PHRASES = [
    re.compile(rf"(?:,\s*)?\b(?:as\s+)?{_SHOWN}\s+(?:by|in|at|from|on)\s*$", re.I),
    re.compile(r"(?:,\s*)?\b(?:see(?:\s+also)?|cited\s+(?:in|by)|according\s+to|per|refer(?:ring)?\s+to)\s*$", re.I),
]
PARTICLE_OK = re.compile(r"\b(?:log(?:ged|ging)?|sign(?:ed|ing)?|check(?:ed)?|came?|come|break|broke|plug(?:ged)?)\s+(?:in|on)$",
                         re.I)


def fix_dangling(text: str):
    """Returns (text, removed_phrase, still_dangling). Removes 'as shown by'-style tails and empty brackets."""
    t, removed = text, False
    for _ in range(3):
        m = re.search(r"[.!?]*$", t)
        core, end = t[:m.start()].rstrip(), m.group(0)
        c2 = re.sub(r"\s*[(\[]\s*[)\]]", "", core)
        for pat in DANGLING_PHRASES:
            c2 = pat.sub("", c2).rstrip(" ,;:")
        if c2 == core:
            break
        removed, t = True, c2 + end
    if removed and not re.sub(r"[.!?\s]", "", t):
        return "", True, False
    core = re.sub(r"[.!?]+$", "", t).rstrip()
    words = re.findall(r"[A-Za-z']+$", core)
    last = words[0] if words else ""
    ends_on_connector = (last.lower() in CONNECTORS or last == "a") and not PARTICLE_OK.search(core)
    opens_quote = core[-1:] in tuple(QUOTES) and len(core) > 1 and core[-2] == " "
    dangling = bool(core) and (core[-1] in "([{" or ends_on_connector or opens_quote)
    return t, removed, dangling


def strip_ids(text: str) -> str:
    for pat in (GROUP_RE, LEAD_RE, BARE_RE):
        text = pat.sub("", text)
    text = re.sub(r"\(\s*\)|\[\s*\]", "", text)
    text = re.sub(r"([,;:])\s*(?=[,.;:])", "", text)
    text = re.sub(r"\s+([,.;:!?])", r"\1", text)
    return re.sub(r"\s+", " ", text).strip()


def check_structure(text: str, cites: list, allowed, events: dict, max_cites: int):
    """Returns (normalized text, final cites, layer result). allowed=None means any existing event."""
    reasons = []
    norm = normalize(text)
    if norm != re.sub(r"\s+", " ", text or "").strip():
        reasons.append(reason(NORMALIZED, "stripped junk characters / markdown"))
    inline = list(dict.fromkeys(ID_RE.findall(norm)))
    bad_inline = False
    for i in inline:
        if i not in events:
            reasons.append(reason(CITE_UNKNOWN_ID, f"inline {i} does not exist"))
            bad_inline = True
        elif allowed is not None and i not in allowed:
            reasons.append(reason(INLINE_ID_NOT_ALLOWED, f"inline {i}"))
            bad_inline = True
    moved = []
    if inline and not bad_inline:
        norm, moved = strip_ids(norm), inline
        reasons.append(reason(NORMALIZED, f"moved inline IDs into cites: {', '.join(inline)}"))
    norm, removed, dangling = fix_dangling(norm)
    if removed:
        reasons.append(reason(NORMALIZED, "removed a dangling phrase such as 'as shown by'"))
    final = sorted(set(cites or []) | set(moved), key=id_key)
    if not norm:
        reasons.append(reason(EMPTY_TEXT, "no text left after normalization"))
    elif dangling:
        reasons.append(reason(DANGLING_ENDING, f"the sentence ends in a connector or opening bracket: ...{norm[-30:]!r}"))
    for c in final:
        if c not in events:
            reasons.append(reason(CITE_UNKNOWN_ID, f"{c} does not exist in the events"))
        elif allowed is not None and c not in allowed:
            reasons.append(reason(CITE_NOT_ALLOWED, f"{c} is not in the allowed list"))
    if not final:
        reasons.append(reason(NO_CITES, "no event IDs cited"))
    if len(final) > max_cites:
        reasons.append(reason(TOO_MANY_CITES, f"{len(final)} cites, maximum is {max_cites}"))
    return norm, final, layer(reasons)
