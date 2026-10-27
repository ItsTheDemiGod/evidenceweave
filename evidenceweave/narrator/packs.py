"""Evidence packs: exactly what the LLM may see (and cite) for one chain stage."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..schema import SOURCE_TYPES, Event, iso_z

MAX_RAW_CHARS = 300
_ORDER = {s: i for i, s in enumerate(SOURCE_TYPES)}


@dataclass
class Pack:
    stage: str
    status: str
    start_time: str
    end_time: str
    summaries: list  # deterministic finding summaries
    entities: dict
    counts: dict
    notes: list  # plain-text missing-evidence info
    evidence_lines: list  # "<ID> | <timestamp> | <raw text>"
    allowed_cite_ids: list  # exactly the IDs shown, chronological
    full_evidence_ids: list  # every evidence ID of the stage
    evidence_shown: int = 0
    evidence_total: int = 0
    omitted: int = 0
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def load_events(path) -> dict[str, Event]:
    with Path(path).open(encoding="utf-8") as f:
        return {e.event_id: e for e in (Event.from_dict(json.loads(line)) for line in f if line.strip())}


def spread(items: list, k: int) -> list:
    """Deterministic pick of k items: always the first and last, the rest evenly spaced."""
    n, k = len(items), max(k, 2)
    if n <= k:
        return list(items)
    return [items[round(i * (n - 1) / (k - 1))] for i in range(k)]


def event_line(e: Event, max_chars: int = MAX_RAW_CHARS) -> str:
    raw = e.raw_text if len(e.raw_text) <= max_chars else e.raw_text[:max_chars] + "..."
    return f"{e.event_id} | {iso_z(e.timestamp)} | {raw}"


def build_packs(chain: dict, findings: list[dict], events: dict[str, Event], max_evidence: int = 12,
                max_chars: int = MAX_RAW_CHARS) -> list[Pack]:
    by_id = {f["finding_id"]: f for f in findings}
    packs = []
    for st in chain["stages"]:
        members = [by_id[i] for i in st["finding_ids"]]
        evs = sorted((events[i] for i in st["evidence_event_ids"] if i in events),
                     key=lambda e: (e.timestamp, _ORDER[e.source_type], e.raw_line))
        shown = spread(evs, max_evidence)
        ents = {k: sorted({v for f in members for v in f["entities"][k]}) for k in ("ips", "users", "hosts", "urls")}
        counts = {k: v for f in members for k, v in f["details"].items() if isinstance(v, int) and not isinstance(v, bool)}
        notes = [f"NOT PROVABLE FROM THE LOGS: {u['summary']}" for u in chain["unprovable_items"]
                 if u["affects_stage"] == st["stage"]]
        if st["status"] == "partial" and not notes:
            notes.append("Some findings in this stage are only partially supported by the logs.")
        packs.append(Pack(
            stage=st["stage"], status=st["status"], start_time=st["start_time"], end_time=st["end_time"],
            summaries=[f["summary"] for f in members if f["status"] != "unprovable"], entities=ents, counts=counts,
            notes=notes, evidence_lines=[event_line(e, max_chars) for e in shown],
            allowed_cite_ids=[e.event_id for e in shown], full_evidence_ids=list(st["evidence_event_ids"]),
            evidence_shown=len(shown), evidence_total=len(evs), omitted=len(evs) - len(shown)))
    return packs
