"""Helpers shared by the rules and the chain builder."""
from __future__ import annotations

import re
from datetime import timedelta
from urllib.parse import urlsplit

from ..schema import SOURCE_TYPES, UNPARSED
from .findings import Finding

URL_RE = re.compile(r"https?://[^\s'\"|)<>\\]+")
IPV4 = re.compile(r"\d{1,3}(\.\d{1,3}){3}")
_ORDER = {s: i for i, s in enumerate(SOURCE_TYPES)}


def order_key(e):
    return (e.timestamp, _ORDER[e.source_type], e.raw_line)


def id_key(event_id: str):
    prefix, _, n = event_id.rpartition("-L")
    return (prefix, int(n))


def usable(events):
    """Unparsed events carry no facts; every rule skips them."""
    return [e for e in events if e.action != UNPARSED]


def ids(evs) -> list[str]:
    return sorted({e.event_id for e in evs}, key=id_key)


def urls_in(text) -> list[str]:
    return sorted({u.rstrip(".,;") for u in URL_RE.findall(text or "")})


def url_ip(url: str):
    host = urlsplit(url).hostname or ""
    return host if IPV4.fullmatch(host) else None


def origin(url: str) -> str:
    s = urlsplit(url)
    return f"{s.scheme}://{s.netloc}"


def matched(cfg, text) -> list[str]:
    return [p.pattern for p in cfg.suspicious_patterns if p.search(text or "")]


def inventory_ips(hosts: dict) -> dict:
    """ip -> host name for every inventory host that has an ip."""
    return {h["ip"]: name for name, h in hosts.items() if h.get("ip")}


def slack(a_hosts, b_hosts, tolerance: int) -> int:
    """Seconds of clock disagreement to allow when comparing times across different hosts."""
    return 0 if b_hosts and set(b_hosts) <= set(a_hosts) else tolerance


def after(a_start, a_hosts, b_start, b_hosts, tolerance: int) -> bool:
    """b happens after a; across hosts accept b >= a - tolerance."""
    return b_start >= a_start - timedelta(seconds=slack(a_hosts, b_hosts, tolerance))


def success_follows(bf_start, bf_end, bf_hosts, success, cfg) -> bool:
    tol = slack(bf_hosts, [success.host], cfg.cross_host_tolerance_seconds)
    return (bf_start - timedelta(seconds=tol) <= success.timestamp
            <= bf_end + timedelta(seconds=cfg.access_after_failures_window_seconds + tol))


def burst_spans(items, window_seconds, ok):
    """Merged [i, j] index spans of maximal <=window windows over time-sorted items where ok(window) holds.

    ponytail: ok() is only tested on the maximal window starting at each item, so a non-monotone test
    (error ratio) can miss a sub-window; upgrade to full sub-window search if that ever matters.
    """
    spans, j = [], 0
    for i in range(len(items)):
        j = max(j, i)
        while j + 1 < len(items) and (items[j + 1].timestamp - items[i].timestamp).total_seconds() <= window_seconds:
            j += 1
        if ok(items[i:j + 1]):
            if spans and i <= spans[-1][1]:
                spans[-1][1] = max(spans[-1][1], j)
            else:
                spans.append([i, j])
    return spans


def entities(ips=(), users=(), hosts=(), urls=()) -> dict:
    return {"ips": sorted({x for x in ips if x}), "users": sorted({x for x in users if x}),
            "hosts": sorted({x for x in hosts if x}), "urls": sorted({x for x in urls if x})}


def make(rule, stage, status, evs, summary, ents, details) -> Finding:
    return Finding("", rule, stage, status, min(e.timestamp for e in evs), max(e.timestamp for e in evs),
                   list(ents["hosts"]), ents, ids(evs), summary, details)


def number(rule, findings) -> list[Finding]:
    findings = sorted(findings, key=lambda f: (f.start_time, id_key(f.evidence_event_ids[0])))
    for n, f in enumerate(findings, 1):
        f.finding_id = f"F-{rule}-{n}"
    return findings


def secs(a, b) -> int:
    return int((b - a).total_seconds())
