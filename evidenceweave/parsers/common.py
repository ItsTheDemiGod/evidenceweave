"""Shared line loop: ids, clock offsets, and the no-silent-drops rule."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from ..schema import UNPARSED, Event

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def run(path: Path, source_type: str, prefix: str, parse_line: Callable[[str], dict],
        default_host: str, offsets: dict[str, int] | None) -> tuple[list[Event], dict]:
    """parse_line(text) returns {timestamp, host, action, user?, src_ip?, dst_ip?, extra?} or raises.

    offsets[host] = seconds the host clock is AHEAD of true time; corrected = raw - offset.
    Unparsed lines inherit the previous event's timestamps so they sort next to their neighbours.
    """
    offsets = offsets or {}
    lines = Path(path).read_bytes().decode("utf-8", errors="replace").split("\n")
    if lines and lines[-1] == "":
        lines.pop()  # the file's final newline is not a line
    events: list[Event] = []
    stats = {"lines": len(lines), "events": 0, "unparsed": 0, "blank": 0}
    for n, text in enumerate(lines, start=1):
        text = text.removesuffix("\r")
        if not text.strip():
            stats["blank"] += 1
            continue
        base = dict(event_id=f"{prefix}-L{n}", source_type=source_type, raw_file=Path(path).name,
                    raw_line=n, raw_text=text)
        try:
            f = parse_line(text)
            raw_ts, off = f["timestamp"], offsets.get(f["host"], 0)
            ev = Event(**base, timestamp=raw_ts - timedelta(seconds=off), raw_timestamp=raw_ts,
                       clock_corrected=bool(off), host=f["host"], user=f.get("user"),
                       src_ip=f.get("src_ip"), dst_ip=f.get("dst_ip"), action=f["action"],
                       extra=f.get("extra", {}))
        except Exception as e:  # a bad line must never stop the run
            prev = events[-1] if events else None
            ev = Event(**base, timestamp=prev.timestamp if prev else EPOCH,
                       raw_timestamp=prev.raw_timestamp if prev else EPOCH, clock_corrected=False,
                       host=default_host, user=None, src_ip=None, dst_ip=None, action=UNPARSED,
                       extra={"reason": f"{type(e).__name__}: {e}"[:200]})
            stats["unparsed"] += 1
        events.append(ev)
    stats["events"] = len(events)
    return events, stats
