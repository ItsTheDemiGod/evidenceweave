"""Normalized event schema and the fixed action taxonomy."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

SSH_LOGIN_FAILED = "ssh_login_failed"
SSH_INVALID_USER = "ssh_invalid_user"
SSH_LOGIN_SUCCESS = "ssh_login_success"
SESSION_OPENED = "session_opened"
SESSION_CLOSED = "session_closed"
SUDO_COMMAND = "sudo_command"
USER_CREATED = "user_created"
CRON_SESSION_OPENED = "cron_session_opened"
CRON_SESSION_CLOSED = "cron_session_closed"
CRON_COMMAND = "cron_command"
WEB_REQUEST = "web_request"
WIN_LOGON_SUCCESS = "win_logon_success"
WIN_LOGON_FAILED = "win_logon_failed"
WIN_SPECIAL_PRIVILEGES = "win_special_privileges"
WIN_PROCESS_CREATED = "win_process_created"
WIN_TASK_CREATED = "win_task_created"
WIN_USER_CREATED = "win_user_created"
UNPARSED = "unparsed"

ACTIONS = frozenset({
    SSH_LOGIN_FAILED, SSH_INVALID_USER, SSH_LOGIN_SUCCESS, SESSION_OPENED, SESSION_CLOSED, SUDO_COMMAND,
    USER_CREATED, CRON_SESSION_OPENED, CRON_SESSION_CLOSED, CRON_COMMAND, WEB_REQUEST, WIN_LOGON_SUCCESS,
    WIN_LOGON_FAILED, WIN_SPECIAL_PRIVILEGES, WIN_PROCESS_CREATED, WIN_TASK_CREATED, WIN_USER_CREATED,
    UNPARSED})
SOURCE_TYPES = ("auth", "nginx", "windows")  # also the tie-break order when timestamps are equal


def iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def from_iso_z(s: str) -> datetime:
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)  # no zone written => UTC


@dataclass
class Event:
    event_id: str  # AUTH-L<n> | NGX-L<n> | WIN-L<n>, n = 1-based line in raw_file
    timestamp: datetime  # UTC; equals raw_timestamp unless clock_corrected
    raw_timestamp: datetime  # UTC instant exactly as written in the log
    clock_corrected: bool
    host: str
    user: str | None
    src_ip: str | None
    dst_ip: str | None
    source_type: str
    action: str
    raw_file: str
    raw_line: int
    raw_text: str
    extra: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.action not in ACTIONS:
            raise ValueError(f"unknown action {self.action!r}")
        if self.source_type not in SOURCE_TYPES:
            raise ValueError(f"unknown source_type {self.source_type!r}")

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["timestamp"], d["raw_timestamp"] = iso_z(self.timestamp), iso_z(self.raw_timestamp)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Event:
        return cls(**{**d, "timestamp": from_iso_z(d["timestamp"]),
                      "raw_timestamp": from_iso_z(d["raw_timestamp"])})
