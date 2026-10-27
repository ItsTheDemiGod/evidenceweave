"""Layer 1: text normalization, inline-ID handling and citation structure."""
from __future__ import annotations

import re

from .verdicts import (CITE_NOT_ALLOWED, CITE_UNKNOWN_ID, EMPTY_TEXT, INLINE_ID_NOT_ALLOWED, NO_CITES, NORMALIZED,
                       TOO_MANY_CITES, layer, reason)

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


def normalize(text: str) -> str:
    """Strip markdown, leading/trailing junk and stray quote runs; collapse whitespace."""
    t = re.sub(r"\*+", "", text or "")
    t = re.sub(r"^\s*(?:[-•]|\d+[.)])\s+", "", t)
    t = re.sub(r"\s+", " ", t).strip()
    t = re.sub(r"^[\s'\"`,;:\-]+", "", t)
    m = re.search(r"(['\"`]{2,})?\s*([.!?]?)[\s,;:]*$", t)  # quote run + trailing junk, keep the final punctuation
    if m:
        t = t[:m.start()] + m.group(2)
    m = re.search(r"([.!?]?)(['\"`])$", t)  # a lone dangling quote (odd count)
    if m and t.count(m.group(2)) % 2 == 1:
        t = t[:m.start()] + m.group(1)
    t = re.sub(r"\s+([,.;:!?])", r"\1", t)
    t = re.sub(r"([.!?])[.!?]+$", r"\1", t)  # a quote run after a full stop leaves a doubled stop
    return re.sub(r"\s+", " ", t).strip()


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
    final = sorted(set(cites or []) | set(moved), key=id_key)
    if not norm:
        reasons.append(reason(EMPTY_TEXT, "no text left after normalization"))
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
