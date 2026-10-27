"""Layer 3a: claim phrase -> event actions that can support it. Extend CLAIM_TABLE to add claims."""
from __future__ import annotations

import re

from .. import schema as S
from .entities import QUOTED_RE, URL_RE
from .verdicts import SEMANTIC_MISMATCH, layer, reason

_I = re.IGNORECASE
# (name, regex, actions that can support the phrase)
CLAIM_TABLE = [
    ("privileged", re.compile(r"privileg|special privileges|elevated|administrator rights|admin rights", _I),
     frozenset({S.WIN_SPECIAL_PRIVILEGES, S.SUDO_COMMAND})),
    ("failed login", re.compile(r"failed (?:log ?in|logon|password|attempts?|authentication)|invalid user|"
                                r"brute[- ]?force|password guess", _I),
     frozenset({S.SSH_LOGIN_FAILED, S.SSH_INVALID_USER, S.WIN_LOGON_FAILED})),
    ("successful login", re.compile(r"successful\w*\s+(?:\w+\s+)?(?:log ?in|logon)|logged in|gained access|"
                                    r"\baccepted\b", _I),
     frozenset({S.SSH_LOGIN_SUCCESS, S.WIN_LOGON_SUCCESS})),
    ("account created", re.compile(r"creat\w*\s+(?:an?\s+|the\s+)?(?:new\s+)?(?:user\s+)?account|new user|added a user|"
                                   r"(?:user|account)\b[^.]{0,40}\b(?:was|were)\s+created", _I),
     frozenset({S.USER_CREATED, S.WIN_USER_CREATED})),
    ("scheduled task", re.compile(r"scheduled task", _I), frozenset({S.WIN_TASK_CREATED})),
    ("cron", re.compile(r"\bcron\b", _I),
     frozenset({S.CRON_COMMAND, S.CRON_SESSION_OPENED, S.CRON_SESSION_CLOSED})),
    ("sudo", re.compile(r"\bsudo\b", _I), frozenset({S.SUDO_COMMAND})),
    ("process/command", re.compile(r"powershell|\bprocess(?:es)?\b|executed|ran a command|runs? (?:a )?command", _I),
     frozenset({S.WIN_PROCESS_CREATED, S.SUDO_COMMAND, S.CRON_COMMAND})),
    ("web request", re.compile(r"web request|scann|probe|probing|\b404\b|\b403\b|\bHTTP\b", _I),
     frozenset({S.WEB_REQUEST})),
    ("session", re.compile(r"session (?:opened|closed)|opened a session|closed the session", _I),
     frozenset({S.SESSION_OPENED, S.SESSION_CLOSED, S.CRON_SESSION_OPENED, S.CRON_SESSION_CLOSED})),
]
NEGATIONS = {"no", "not", "never", "without", "none"}


def _negated(text: str, start: int) -> bool:
    words = re.findall(r"[\w']+", text[:start].lower())[-3:]
    return any(w in NEGATIONS or w.endswith("n't") for w in words)


def check_semantics(text: str, cited_actions) -> dict:
    cited = set(cited_actions)
    text = QUOTED_RE.sub(" ", URL_RE.sub(" ", text))  # a URL scheme or a quoted command is not a claim about the event
    out = []
    for name, pat, actions in CLAIM_TABLE:
        hits = [m for m in pat.finditer(text) if not _negated(text, m.start())]
        if hits and not (cited & actions):
            out.append(reason(SEMANTIC_MISMATCH, f"phrase '{hits[0].group(0)}' ({name}) needs one of "
                                                 f"{sorted(actions)} but the cited actions are {sorted(cited)}"))
    return layer(out)
