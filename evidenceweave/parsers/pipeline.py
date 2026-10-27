"""parse_case: three raw logs -> one sorted event list."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ..schema import SOURCE_TYPES, Event
from . import auth_parser, nginx_parser, windows_parser

LOGS = {"auth": "linux_auth.log", "nginx": "nginx_access.log", "windows": "windows_events.jsonl"}


@dataclass
class Case:
    name: str
    events: list[Event]
    hosts: dict[str, dict]  # name -> {ip, os, ...}; empty when hosts.json is absent
    stats: dict[str, dict]  # source_type -> {lines, events, unparsed, blank}
    clock_offsets: dict[str, int] = field(default_factory=dict)


def load_hosts(case_dir: Path) -> dict[str, dict]:
    p = case_dir / "hosts.json"
    if not p.exists():
        return {}
    return {h["name"]: h for h in json.loads(p.read_text(encoding="utf-8"))["hosts"]}


def parse_case(case_dir, year: int | None = None, clock_offsets: dict[str, int] | None = None) -> Case:
    case_dir = Path(case_dir)
    offsets = dict(clock_offsets or {})
    hosts = load_hosts(case_dir)
    if year is None:
        manifest = case_dir / "manifest.json"
        if not manifest.exists():
            raise ValueError("syslog year unknown: no manifest.json, pass year")
        year = json.loads(manifest.read_text(encoding="utf-8"))["assumed_syslog_year"]
    web = next((n for n, h in hosts.items() if h.get("role") == "web"), "web01")

    paths = {s: case_dir / "logs" / f for s, f in LOGS.items()}
    runs = {"auth": lambda p: auth_parser.parse(p, year, offsets),
            "nginx": lambda p: nginx_parser.parse(p, offsets, web),
            "windows": lambda p: windows_parser.parse(p, offsets)}
    events: list[Event] = []
    stats: dict[str, dict] = {}
    for s in SOURCE_TYPES:
        if paths[s].exists():
            ev, stats[s] = runs[s](paths[s])
            events += ev
    order = {s: i for i, s in enumerate(SOURCE_TYPES)}
    events.sort(key=lambda e: (e.timestamp, order[e.source_type], e.raw_line))
    return Case(case_dir.name, events, hosts, stats, offsets)


def write_events(case: Case, path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for e in case.events:
            f.write(json.dumps(e.to_dict()) + "\n")
