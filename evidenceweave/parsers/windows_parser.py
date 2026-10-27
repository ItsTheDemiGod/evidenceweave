"""Windows Security events as JSON lines: {TimeCreated, EventID, Computer, Channel, EventData{}}."""
from __future__ import annotations

import json

from .. import schema as S
from ..schema import from_iso_z
from .common import run

# EventID -> (action, EventData field holding the user)
EVENTS = {4624: (S.WIN_LOGON_SUCCESS, "TargetUserName"), 4625: (S.WIN_LOGON_FAILED, "TargetUserName"),
          4672: (S.WIN_SPECIAL_PRIVILEGES, "SubjectUserName"), 4688: (S.WIN_PROCESS_CREATED, "SubjectUserName"),
          4698: (S.WIN_TASK_CREATED, "SubjectUserName"), 4720: (S.WIN_USER_CREATED, "TargetUserName")}


def parse(path, offsets: dict[str, int] | None = None):
    def parse_line(text: str) -> dict:
        obj = json.loads(text)
        if not isinstance(obj, dict):
            raise ValueError("JSON line is not an object")
        eid = int(obj["EventID"])
        if eid not in EVENTS:
            raise ValueError(f"unknown EventID {eid}")
        action, user_field = EVENTS[eid]
        data = obj.get("EventData") or {}
        ip = data.get("IpAddress")
        return {"timestamp": from_iso_z(obj["TimeCreated"]), "host": obj["Computer"], "action": action,
                "user": data.get(user_field), "src_ip": ip if ip not in (None, "", "-") else None,
                "extra": {"event_id": eid, **data}}

    return run(path, "windows", "WIN", parse_line, "unknown", offsets)
