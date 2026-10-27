"""Linux syslog auth.log (web01). No year in syslog: caller supplies it; time assumed UTC."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from .. import schema as S
from .common import run

LINE = re.compile(r"^(\w{3}) +(\d{1,2}) (\d\d:\d\d:\d\d) (\S+) ([\w.\-/]+)(?:\[(\d+)\])?: (.*)$")
FAILED = re.compile(r"Failed password for (invalid user )?(\S+) from (\S+) port (\d+)")
ACCEPTED = re.compile(r"Accepted (\S+) for (\S+) from (\S+) port (\d+)")
SESSION = re.compile(r"pam_unix\((\w+):session\): session (opened|closed) for user ([^\s(]+)(?:\(uid=(\d+)\))?"
                     r"(?: by (?:\(uid=\d+\)|([^\s(]+)\(uid=\d+\)))?")
SUDO = re.compile(r"(\S+) : (?:TTY=(\S+) ; )?(?:PWD=(\S+) ; )?(?:USER=(\S+) ; )?COMMAND=(.*)$")
USERADD = re.compile(r"new user: name=([^,\s]+), UID=(\d+)")
CRON_CMD = re.compile(r"\((\S+)\) CMD \((.*)\)$")


def _message(prog: str, msg: str) -> dict:
    if prog == "sshd":
        if m := FAILED.match(msg):
            inv, user, ip, port = m.groups()
            return dict(action=S.SSH_INVALID_USER if inv else S.SSH_LOGIN_FAILED, user=user, src_ip=ip,
                        extra={"port": int(port)})
        if m := ACCEPTED.match(msg):
            how, user, ip, port = m.groups()
            return dict(action=S.SSH_LOGIN_SUCCESS, user=user, src_ip=ip, extra={"method": how, "port": int(port)})
    if prog in ("sshd", "sudo", "CRON") and (m := SESSION.match(msg)):
        svc, state, user, uid, by = m.groups()
        extra = {"service": svc, **({"uid": int(uid)} if uid else {}), **({"by": by} if by else {})}
        if prog == "CRON":
            return dict(action=S.CRON_SESSION_OPENED if state == "opened" else S.CRON_SESSION_CLOSED,
                        user=user, extra=extra)
        return dict(action=S.SESSION_OPENED if state == "opened" else S.SESSION_CLOSED, user=user, extra=extra)
    if prog == "sudo" and (m := SUDO.match(msg)):
        user, tty, pwd, target, cmd = m.groups()
        return dict(action=S.SUDO_COMMAND, user=user,
                    extra={"command": cmd, "tty": tty, "pwd": pwd, "target_user": target})
    if prog == "useradd" and (m := USERADD.match(msg)):
        return dict(action=S.USER_CREATED, user=m[1], extra={"new_user": m[1], "uid": int(m[2])})
    if prog == "CRON" and (m := CRON_CMD.match(msg)):
        return dict(action=S.CRON_COMMAND, user=m[1], extra={"command": m[2]})
    raise ValueError("unrecognised auth message")


def parse(path, year: int, offsets: dict[str, int] | None = None):
    def parse_line(text: str) -> dict:
        m = LINE.match(text)
        if not m:
            raise ValueError("not a syslog line")
        mon, day, hms, host, prog, pid, msg = m.groups()
        ts = datetime.strptime(f"{year} {mon} {day} {hms}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
        f = _message(prog, msg)
        f["extra"] = {**f["extra"], "program": prog, **({"pid": int(pid)} if pid else {})}
        return {"timestamp": ts, "host": host, **f}

    return run(path, "auth", "AUTH", parse_line, "web01", offsets)
