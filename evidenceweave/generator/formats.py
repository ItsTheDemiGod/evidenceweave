"""Log line formatters. Each returns an Entry: (source, logged ts, text, tags)."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta

AUTH, NGINX, WIN = "linux_auth.log", "nginx_access.log", "windows_events.jsonl"
SOURCES = (AUTH, NGINX, WIN)
HOST_LINUX, HOST_WIN = "web01", "ws-fin01"
# ws-fin01 never appears with an IP in the logs; 10.0.0.70 sits outside the noise range (10.0.0.10-60)
HOSTS = [{"name": HOST_LINUX, "ip": "10.0.0.5", "os": "linux", "role": "web"},
         {"name": HOST_WIN, "ip": "10.0.0.70", "os": "windows", "role": "workstation"}]


@dataclass
class Entry:
    source: str
    ts: datetime  # as written in the log (includes clock skew)
    text: str
    true_ts: datetime | None = None  # real UTC time; defaults to ts
    step: int | None = None  # attack step this line is evidence for
    marker: str | None = None  # unique substring of text
    benign_note: str | None = None  # benign-but-suspicious-looking reason
    missing: str | None = None  # set => line is deleted; describes what vanished

    def __post_init__(self) -> None:
        if self.true_ts is None:
            self.true_ts = self.ts


def auth(ts: datetime, tag: str, msg: str, **kw) -> Entry:
    """tag is e.g. 'sshd[1234]' or 'sudo'."""
    text = f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S} {HOST_LINUX} {tag}: {msg}"
    return Entry(AUTH, ts, text, **kw)


def nginx(ts: datetime, ip: str, method: str, path: str, status: int, size: int,
          ref: str, ua: str, **kw) -> Entry:
    stamp = f"{ts:%d/%b/%Y:%H:%M:%S} +0000"
    text = f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}"'
    kw.setdefault("marker", f'{ip} - - [{stamp}] "{method} {path}')
    return Entry(NGINX, ts, text, **kw)


def win_stamp(ts: datetime) -> str:
    return f"{ts:%Y-%m-%dT%H:%M:%S}.{ts.microsecond // 1000:03d}Z"


def win(true_ts: datetime, skew: int, event_id: int, data: dict, **kw) -> Entry:
    ts = true_ts + timedelta(seconds=skew)
    obj = {"TimeCreated": win_stamp(ts), "EventID": event_id, "Computer": HOST_WIN,
           "Channel": "Security", "EventData": data}
    kw.setdefault("marker", f'"TimeCreated": "{win_stamp(ts)}"')
    return Entry(WIN, ts, json.dumps(obj), true_ts=true_ts, **kw)
