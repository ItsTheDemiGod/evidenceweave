"""Held-out corruption pool, frozen before the Phase 6b evaluation runs. Do not edit after the freeze commit."""
import hashlib
import json

HELDOUT_NO_ENTITY_CLAIMS = [
    "The attacker wiped the shell history afterwards.",
    "The attacker uploaded stolen credentials to a public paste site.",
    "The attacker installed a keylogger on the workstation.",
    "The attacker tampered with the backup schedule.",
    "The attacker stopped the logging service to avoid detection.",
    "The attacker encrypted the shared network drives.",
    "The attacker harvested saved browser cookies.",
    "The attacker dumped password hashes from the server.",
    "The attacker disabled multi-factor authentication for the accounts.",
    "The attacker connected onward to an internal database server.",
    "The attacker added a new key to the account's trusted keys.",
    "The attacker turned off the host's automatic updates.",
    "The attacker copied several gigabytes of payroll records offsite.",
    "The attacker covered their tracks by editing the system clock.",
]

HELDOUT_ENTITY_FABRICATIONS = [
    ", after which data was sent to 198.18.4.77",
    ", and a tool was fetched from http://files.badhost.example/tool.bin",
    ", and a file named C:\\Windows\\Temp\\svc_update.exe was dropped",
    ", then /opt/.hidden/loader.sh was executed",
    ", and the session continued on host db-prod07",
    ", under the account 'backupadmin'",
    ", and the account tmp_ops logged in",
    ", using the address 203.0.114.9",
    ", and a script update_check.ps1 was run",
    ", reaching the domain c2.exfil-net.example",
]

HELDOUT_ENTITY_KINDS = dict(zip(HELDOUT_ENTITY_FABRICATIONS, [
    "ip", "url", "windows_path", "posix_path", "hostname", "user_quoted", "user_account", "ip", "bare_file", "domain"]))


def pool_sha256(*lists) -> str:
    return hashlib.sha256(json.dumps(lists, sort_keys=True).encode("utf-8")).hexdigest()
