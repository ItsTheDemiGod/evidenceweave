"""Normalized event schema (planned; fleshed out in Phase 2)."""
from dataclasses import dataclass


@dataclass
class Event:
    event_id: str
    timestamp: str  # UTC ISO-8601
    host: str
    user: str
    src_ip: str
    source_type: str
    action: str
    raw_file: str
    raw_line: int
    raw_text: str
