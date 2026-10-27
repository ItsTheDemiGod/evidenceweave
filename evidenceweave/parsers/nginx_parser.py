"""nginx/Apache combined log format."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from ..schema import WEB_REQUEST
from .common import run

COMBINED = re.compile(r'^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+) ([^"]*)" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"$')


def parse(path, offsets: dict[str, int] | None = None, host: str = "web01"):
    def parse_line(text: str) -> dict:
        m = COMBINED.match(text)
        if not m:
            raise ValueError("not combined log format")
        ip, user, stamp, method, req_path, proto, status, size, ref, ua = m.groups()
        ts = datetime.strptime(stamp, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
        return {"timestamp": ts, "host": host, "action": WEB_REQUEST, "src_ip": ip,
                "user": None if user == "-" else user,
                "extra": {"method": method, "path": req_path, "protocol": proto, "status": int(status),
                          "bytes": 0 if size == "-" else int(size), "referrer": ref, "user_agent": ua}}

    return run(path, "nginx", "NGX", parse_line, host, offsets)
