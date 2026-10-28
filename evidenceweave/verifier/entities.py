"""Layer 2: deterministic entity grounding. Every IP, time, number, URL, user, host and quoted command in a
sentence must be present in the pool of facts it is allowed to rely on."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from ..schema import iso_z
from .structure import ID_RE
from .verdicts import (COMMAND_NOT_GROUNDED, HOST_NOT_GROUNDED, IP_NOT_GROUNDED, MALFORMED_IP, NUMBER_NOT_GROUNDED,
                       PATH_NOT_GROUNDED, TIME_NOT_GROUNDED, URL_NOT_GROUNDED, USER_NOT_GROUNDED, layer, reason)

URL_RE = re.compile(r"https?://[^\s'\"`)>\]]+")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|dev|app|co|uk|de|local|internal)\b", re.I)
ISO_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?")
HMS_RE = re.compile(r"(?<![\d:])\d{1,2}:\d{2}:\d{2}(?:\.\d+)?(?![\d:])")
IPLIKE_RE = re.compile(r"\b\d{1,3}(?:[ ]?\.\d+){2,4}\b")  # >= 3 dotted groups (2 groups are decimals, not IPs)
QUOTED_RE = re.compile(r"`([^`]+)`|\"([^\"]+)\"")
NUM_RE = re.compile(r"\b\d+\.\d+\b|\b\d{1,3}(?:,\d{3})+\b|\b\d+\b")
FACT_ID_RE = re.compile(r"\b[a-z_]+-F\d+\b")
FILE_EXTS = "tar|gz|zip|sh|py|exe|dll|ps1|bat|txt|log|conf|cfg|db|sql|php|bak|key|pem|json|xml"
# POSIX: leading slash at text start / after whitespace, quote, bracket or ~ (so and/or and dates like 10/27 never match);
# >= 2 segments, or 1 segment with a file extension. Windows: drive letter + backslash segments. Bare names: known extensions.
POSIX_PATH_RE = re.compile(r"(?:(?<=^)|(?<=[\s'\"`(\[{~]))(/[\w.\-@+%]+(?:/[\w.\-@+%]+)*)")
WIN_PATH_RE = re.compile(r"\b[A-Za-z]:\\(?:[\w.\-~$]*[\w.\-~$]\\?)+")
BARE_FILE_RE = re.compile(rf"(?<![\w/\.\-])[\w\-]+(?:\.[\w\-]+)*\.(?:{FILE_EXTS})\b", re.I)
USER_PATTERNS = [  # group q = opening quote (quoted names are always checked), group n = the candidate name
    re.compile(r"\b(?:user(?:name)?s?|account)\s+(?:named\s+|called\s+)?(?P<q>[`'\"“]?)(?P<n>[A-Za-z_][\w.\-]*)", re.I),
    re.compile(r"\buser\s*\(\s*(?P<q>['\"`]?)(?P<n>[A-Za-z_][\w.\-]*)['\"`]?\s*\)", re.I),
    re.compile(r"\bas\s+(?:the\s+user\s+)?(?P<q>[`'\"“]?)(?P<n>[A-Za-z_][\w.\-]*)", re.I),
]
# an unquoted word like "recorded"/"suggesting"/"quickly" after "user"/"as" is prose, not a name
PROSE_SUFFIX = re.compile(r"(?:ed|ing|ly)$", re.I)
# words that follow "user"/"account"/"as" in ordinary prose and are not names
STOPWORDS = set("""a an the this that these those it its he she they them who which what whose whom with without on in at
from via to into onto of for by and or but then also later earlier first last next same other another one two three
was were is are be been being has have had having did does do done not no never none logged logging log login logon
logons created creating create ran run runs running executed executing execute performed made make using used use
accessed access connected attempted attempting attempts attempt successfully successful failed failing failure
shown part well such result results follows follow expected evidence indicated indicating suggests suggesting soon
possible potential privileges privilege privileged elevated root-level unknown user users account accounts name named
called new existing legitimate normal valid invalid suspicious malicious unauthorized authorized active remote local
well-known if when while after before during since because both either each every all any some many multiple several
few more most less least only just still already again once twice per over under between among through across
suggest suggests show shows indicate indicates appear appears appeared perform performs reveal reveals
confirm confirms demonstrate demonstrates imply implies involve involves represent represents contain contains""".split())


# ---------------- extraction ----------------
@dataclass
class Extracted:
    urls: list = field(default_factory=list)
    domains: list = field(default_factory=list)
    iso: list = field(default_factory=list)
    hms: list = field(default_factory=list)
    ip_tokens: list = field(default_factory=list)
    users: list = field(default_factory=list)
    hosts: list = field(default_factory=list)
    quoted: list = field(default_factory=list)
    paths: list = field(default_factory=list)
    numbers: list = field(default_factory=list)


def extract_paths(t: str) -> list[str]:
    """File paths in text that has already had URLs, IPs, times and event IDs removed."""
    t = FACT_ID_RE.sub(" ", t)
    found = []
    for m in WIN_PATH_RE.finditer(t):
        found.append(m.group(0))
    t = WIN_PATH_RE.sub(" ", t)
    for m in POSIX_PATH_RE.finditer(t):
        p = m.group(1).rstrip(".,;:!?")
        if p.count("/") >= 2 or re.search(rf"\.(?:{FILE_EXTS})$", p, re.I):
            found.append(p)
    t = POSIX_PATH_RE.sub(" ", t)
    found += [m.group(0) for m in BARE_FILE_RE.finditer(t)]
    return list(dict.fromkeys(p.rstrip(".,;:") for p in found))


def _take(pat, text):
    found = [m.group(0) for m in pat.finditer(text)]
    return found, pat.sub(" ", text)


def valid_ip(token: str) -> bool:
    try:
        ipaddress.IPv4Address(token.replace(" ", ""))
        return True
    except ValueError:
        return False


def norm_iso(s: str) -> str:
    return s.replace(" ", "T").rstrip("Z")[:19]


def norm_hms(s: str) -> str:
    h, m, sec = s.split(":")
    return f"{int(h):02d}:{m}:{sec.split('.')[0]}"


def norm_num(s: str) -> str:
    s = s.replace(",", "")
    return s if "." in s else str(int(s))


def fact_numbers(text: str) -> set:
    """Numbers stated in a deterministic summary (units glued on, like '1205s', are fine); IPs/URLs/times excluded."""
    t = ID_RE.sub(" ", text)
    for pat in (URL_RE, ISO_RE, HMS_RE, IPLIKE_RE):
        t = pat.sub(" ", t)
    return {norm_num(n) for n in re.findall(r"\b\d+(?:\.\d+)?", t)}


def extract(text: str, host_names=()) -> Extracted:
    ex = Extracted()
    ex.quoted = [a or b for a, b in QUOTED_RE.findall(text)]
    t = ID_RE.sub(" ", text)
    ex.urls, t = _take(URL_RE, t)
    ex.domains, t = _take(DOMAIN_RE, t)
    ex.iso, t = _take(ISO_RE, t)
    ex.hms, t = _take(HMS_RE, t)
    ex.ip_tokens, t = _take(IPLIKE_RE, t)
    ex.paths = extract_paths(t)
    for pat in USER_PATTERNS:
        for m in pat.finditer(t):
            name, quoted = m.group("n").rstrip(".-"), bool(m.group("q"))
            if len(name) < 2 or name.lower() in STOPWORDS:
                continue
            if not quoted and len(name) >= 5 and PROSE_SUFFIX.search(name):
                continue
            ex.users.append(name)
    ex.users = list(dict.fromkeys(ex.users))
    ex.hosts = [h for h in host_names if re.search(rf"(?<![\w-]){re.escape(h)}(?![\w-])", t, re.I)]
    t = QUOTED_RE.sub(" ", t)
    ex.numbers = [norm_num(n) for n in NUM_RE.findall(t)]
    return ex


# ---------------- pool ----------------
@dataclass
class Facts:
    """Stage-level facts that may ground TIMES and NUMBERS (and, for summaries/templates, entity text)."""
    times: set = field(default_factory=set)  # ISO or HH:MM:SS strings, any form
    numbers: set = field(default_factory=set)
    text: str = ""


@dataclass
class Pool:
    text: str
    iso: set
    hms: set
    numbers: set
    path_text: str = ""  # pool text plus the source file names of the events


def event_parts(e) -> list[str]:
    parts = [e.raw_text, e.host, e.user or "", e.src_ip or "", e.dst_ip or "", iso_z(e.timestamp), iso_z(e.raw_timestamp)]
    parts += [str(v) for v in e.extra.values()]
    return parts


def squash(s: str) -> str:
    return re.sub(r"\s+", " ", s)


def build_pool(events, facts: Facts | None = None) -> Pool:
    facts = facts or Facts()
    chunks = [p for e in events for p in event_parts(e)] + [facts.text]
    text = squash("\n".join(chunks))
    iso, hms = set(), set()
    for e in events:
        for dt in (e.timestamp, e.raw_timestamp):
            iso.add(dt.strftime("%Y-%m-%dT%H:%M:%S"))
            hms.add(dt.strftime("%H:%M:%S"))
    for t in facts.times:
        iso.update(norm_iso(x) for x in ISO_RE.findall(t))
        hms.update(norm_hms(x) for x in HMS_RE.findall(t))
        hms.update(norm_iso(x)[11:] for x in ISO_RE.findall(t))
    iso.update(norm_iso(x) for x in ISO_RE.findall(text))
    hms.update(norm_hms(x) for x in HMS_RE.findall(text))
    hms.update(norm_iso(x)[11:] for x in ISO_RE.findall(text))
    nums = {norm_num(n) for n in NUM_RE.findall(text)}
    nums |= {norm_num(d) for s in iso for d in re.findall(r"\d+", s)}
    nums |= {str(n) for n in facts.numbers}
    return Pool(text, iso, hms, nums, squash(text + "\n" + "\n".join(e.raw_file for e in events)))


def _in_text(token: str, text: str, ip: bool = False) -> bool:
    if ip:
        return re.search(rf"(?<![\d.]){re.escape(token)}(?!\d|\.\d)", text) is not None
    return token in text


def check_entities(text: str, pool: Pool, host_names=()) -> dict:
    ex = extract(text, host_names)
    out = []
    for tok in ex.ip_tokens:
        if not valid_ip(tok):
            out.append(reason(MALFORMED_IP, f"'{tok}' is not a valid IPv4 address"))
        elif not _in_text(tok, pool.text, ip=True):
            out.append(reason(IP_NOT_GROUNDED, f"{tok} is not in the cited events"))
    for t in ex.iso:
        if norm_iso(t) not in pool.iso:
            out.append(reason(TIME_NOT_GROUNDED, f"{t} does not match any cited event or the stage range"))
    for t in ex.hms:
        if norm_hms(t) not in pool.hms:
            out.append(reason(TIME_NOT_GROUNDED, f"{t} does not match any cited event or the stage range"))
    for n in dict.fromkeys(ex.numbers):
        if n not in ("0", "1") and n not in pool.numbers:
            out.append(reason(NUMBER_NOT_GROUNDED, f"{n} is not shown in the cited events or stage facts"))
    for u in ex.urls:
        u = u.rstrip(".,;")
        if u not in pool.text:
            out.append(reason(URL_NOT_GROUNDED, f"{u} is not in the cited events"))
    for d in ex.domains:
        if d.lower() not in pool.text.lower():
            out.append(reason(URL_NOT_GROUNDED, f"domain {d} is not in the cited events"))
    for pth in ex.paths:
        if pth not in pool.path_text:
            out.append(reason(PATH_NOT_GROUNDED, f"path {pth} is not in the cited events"))
    low = pool.text.lower()
    for u in ex.users:
        if not re.search(rf"(?<![\w.\-]){re.escape(u.lower())}(?![\w\-])", low):
            out.append(reason(USER_NOT_GROUNDED, f"user/account '{u}' is not in the cited events"))
    for h in ex.hosts:
        if h.lower() not in low:
            out.append(reason(HOST_NOT_GROUNDED, f"host {h} is not in the cited events"))
    for q in ex.quoted:
        q = squash(q.strip().rstrip(".,;"))
        if len(q) > 6 and q not in pool.text:
            out.append(reason(COMMAND_NOT_GROUNDED, f"\"{q}\" does not appear in the cited events"))
    return layer(out)
