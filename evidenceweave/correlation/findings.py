"""Finding: one rule's conclusion, with the events that prove it."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from ..schema import from_iso_z, iso_z

STAGES = ("brute_force", "initial_access", "privilege_escalation", "persistence", "lateral_movement",
          "web_recon", "missing_evidence")
STATUSES = ("confirmed", "attempts_only", "partial", "unprovable")


@dataclass
class Finding:
    finding_id: str  # F-<rule>-<n>, n in time order within the rule
    rule: str
    stage: str
    status: str
    start_time: datetime  # UTC, from the events' (possibly clock-corrected) timestamps
    end_time: datetime
    hosts: list
    entities: dict  # {ips, users, hosts, urls}: sorted lists
    evidence_event_ids: list  # sorted by (source, line)
    summary: str  # template-based, deterministic
    details: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.stage not in STAGES or self.status not in STATUSES:
            raise ValueError(f"bad stage/status: {self.stage}/{self.status}")

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["start_time"], d["end_time"] = iso_z(self.start_time), iso_z(self.end_time)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Finding:
        return cls(**{**d, "start_time": from_iso_z(d["start_time"]), "end_time": from_iso_z(d["end_time"])})
