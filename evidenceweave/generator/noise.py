"""Benign background events plus the hard-mode decoy IP."""
from __future__ import annotations

import random
from datetime import datetime, timedelta

from .attack import ATTACKER, DAY
from .formats import Entry, auth, nginx, win

DECOY = "198.51.100.23"
END = DAY + timedelta(hours=8)
USERS = ["alice", "bob", "carol", "deploy"]
UIDS = {"alice": 1003, "bob": 1004, "carol": 1005, "deploy": 1001}
SUDO_CMDS = ["/usr/bin/apt update", "/usr/bin/systemctl restart nginx", "/usr/bin/journalctl -u sshd",
             "/usr/bin/tail -n 50 /var/log/syslog", "/usr/bin/apt upgrade -y", "/usr/bin/systemctl status nginx"]
WEB_PATHS = ["/", "/index.html", "/about", "/products", "/products/17", "/products/42", "/contact",
             "/static/css/main.css", "/static/js/app.js", "/images/logo.png", "/api/v1/items",
             "/favicon.ico", "/robots.txt", "/blog", "/blog/2026/10/release-notes", "/login", "/search?q=widgets"]
WEB_UA = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/118.0.0.0 Safari/537.36",
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 Safari/605.1.15",
          "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0",
          "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
          "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/118.0 Mobile Safari/537.36",
          "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
          "curl/8.1.2", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0"]
WIN_USERS = ["alice", "bob", "carol", "dave", "fin_admin"]
WIN_PROCS = [(r"C:\Windows\System32\notepad.exe", "notepad.exe"),
             (r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe"),
             (r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE", "EXCEL.EXE /dde"),
             (r"C:\Windows\System32\cmd.exe", "cmd.exe /c dir C:\\Finance"),
             (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
              "powershell.exe -File C:\\Scripts\\nightly_backup.ps1"),
             (r"C:\Windows\System32\svchost.exe", "svchost.exe -k netsvcs"),
             (r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", "OUTLOOK.EXE")]


def rand_ts(rng: random.Random, a: datetime = DAY, b: datetime = END) -> datetime:
    return a + timedelta(seconds=rng.uniform(0, (b - a).total_seconds()))


def internal_ip(rng: random.Random) -> str:
    return f"10.0.0.{rng.randint(10, 60)}"


def public_ip(rng: random.Random) -> str:
    while True:
        ip = f"{rng.choice([24, 66, 73, 81, 91, 104, 151, 185])}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
        if ip not in (ATTACKER, DECOY):
            return ip


def ssh_sessions(rng: random.Random, n: int, a: datetime = DAY, b: datetime = END) -> list[Entry]:
    out: list[Entry] = []
    for _ in range(n):
        u, ip, pid = rng.choice(USERS), internal_ip(rng), rng.randint(1000, 4999)
        t, port = rand_ts(rng, a, b), rng.randint(1024, 29999)
        if rng.random() < 0.15:  # harmless typo before success
            out.append(auth(t - timedelta(seconds=15), f"sshd[{pid}]",
                            f"Failed password for {u} from {ip} port {port - 1} ssh2"))
        how = rng.choice(["password", "publickey"])
        out.append(auth(t, f"sshd[{pid}]", f"Accepted {how} for {u} from {ip} port {port} ssh2"))
        out.append(auth(t, f"sshd[{pid}]",
                        f"pam_unix(sshd:session): session opened for user {u}(uid={UIDS[u]}) by (uid=0)"))
        out.append(auth(t + timedelta(seconds=rng.randint(300, 7200)), f"sshd[{pid}]",
                        f"pam_unix(sshd:session): session closed for user {u}"))
    return out


def sudo_usage(rng: random.Random, n: int, a: datetime = DAY, b: datetime = END) -> list[Entry]:
    out: list[Entry] = []
    for _ in range(n):
        u, t = rng.choice(["alice", "carol"]), rand_ts(rng, a, b)
        out.append(auth(t, "sudo", f"{u} : TTY=pts/1 ; PWD=/home/{u} ; USER=root ; COMMAND={rng.choice(SUDO_CMDS)}"))
        out.append(auth(t, "sudo", f"pam_unix(sudo:session): session opened for user root(uid=0) by {u}(uid={UIDS[u]})"))
        out.append(auth(t + timedelta(seconds=rng.randint(1, 30)), "sudo",
                        "pam_unix(sudo:session): session closed for user root"))
    return out


def cron_jobs(rng: random.Random, hard: bool) -> list[Entry]:
    jobs = [(60, "root", "cd / && run-parts --report /etc/cron.hourly"),
            (15, "root", "/usr/local/bin/healthcheck.sh")]
    if hard:
        jobs.append((5, "www-data", "/usr/bin/php /var/www/html/cron.php"))
    out: list[Entry] = []
    for every, user, cmd in jobs:
        t = DAY + timedelta(minutes=17 if every == 60 else 0)
        while t < END:
            p, uid = rng.randint(1000, 4999), 0 if user == "root" else 33
            out += [auth(t, f"CRON[{p}]", f"pam_unix(cron:session): session opened for user {user}(uid={uid}) by (uid=0)"),
                    auth(t, f"CRON[{p}]", f"({user}) CMD ({cmd})"),
                    auth(t, f"CRON[{p}]", f"pam_unix(cron:session): session closed for user {user}")]
            t += timedelta(minutes=every)
    return out


def web_traffic(rng: random.Random, n: int, a: datetime = DAY, b: datetime = END) -> list[Entry]:
    ips = [public_ip(rng) for _ in range(max(20, n // 8))]
    out: list[Entry] = []
    for _ in range(n):
        path = rng.choice(WEB_PATHS)
        r = rng.random()
        status = 200 if r < 0.82 else 304 if r < 0.9 else 301 if r < 0.94 else 404 if r < 0.98 else 500
        post = path == "/login" and rng.random() < 0.5
        out.append(nginx(rand_ts(rng, a, b), rng.choice(ips), "POST" if post else "GET", path, status,
                         rng.randint(180, 48000), rng.choice(["-", "https://www.example.com/", "https://www.google.com/"]),
                         rng.choice(WEB_UA)))
    return out


def windows_noise(rng: random.Random, skew: int, scale: int) -> list[Entry]:
    out: list[Entry] = []
    for _ in range(30 * scale):
        u, t = rng.choice(WIN_USERS), rand_ts(rng)
        lt = rng.choice(["2", "3", "10", "3"])
        out.append(win(t, skew, 4624, {"TargetUserName": u, "LogonType": lt,
                                       "IpAddress": "-" if lt == "2" else internal_ip(rng), "WorkstationName": "ws-fin01"}))
        if u == "fin_admin":
            out.append(win(t + timedelta(milliseconds=2), skew, 4672,
                           {"SubjectUserName": u, "PrivilegeList": "SeSecurityPrivilege SeBackupPrivilege"}))
    for _ in range(50 * scale):
        (exe, cmd), u = rng.choice(WIN_PROCS), rng.choice(WIN_USERS)
        out.append(win(rand_ts(rng), skew, 4688, {"SubjectUserName": u, "NewProcessName": exe, "CommandLine": cmd,
                                                  "ParentProcessName": r"C:\Windows\explorer.exe"}))
    for _ in range(4 * scale):  # real users mistyping passwords
        out.append(win(rand_ts(rng), skew, 4625, {"TargetUserName": rng.choice(WIN_USERS), "LogonType": "2",
                                                  "IpAddress": "-", "Status": "0xC000006A"}))
    return out


def decoy(rng: random.Random, skew: int) -> list[Entry]:
    """Scanner that fails and probes but never succeeds, plus benign admin events that look scary."""
    note = f"decoy IP {DECOY}: noisy but never succeeds and is not part of the attack"
    out: list[Entry] = []
    for base in (DAY + timedelta(hours=1, minutes=20), DAY + timedelta(hours=2, minutes=50)):
        for port in rng.sample(range(30000, 40000), 3):
            out.append(auth(base + timedelta(seconds=rng.uniform(0, 120)), f"sshd[{rng.randint(1000, 4999)}]",
                            f"Failed password for invalid user {rng.choice(['admin', 'pi', 'test'])} "
                            f"from {DECOY} port {port} ssh2", benign_note=note, marker=f"port {port} ssh2"))
    ts = DAY + timedelta(hours=1, minutes=40)
    for path in rng.sample(["/wp-login.php", "/xmlrpc.php", "/.env", "/phpmyadmin/", "/admin", "/config.php",
                            "/wp-admin/", "/backup.sql", "/.git/HEAD", "/server-status", "/login", "/test.php"], 12):
        ts += timedelta(seconds=rng.uniform(1, 20))
        out.append(nginx(ts, DECOY, "GET", path, 404, 162, "-", "Mozilla/5.0 zgrab/0.x", benign_note=note))
    t = DAY + timedelta(hours=3, minutes=5)
    out.append(win(t, skew, 4720, {"SubjectUserName": "fin_admin", "TargetUserName": "temp_intern"},
                   benign_note="helpdesk (fin_admin) legitimately created account temp_intern"))
    out.append(win(t + timedelta(minutes=2), skew, 4698,
                   {"SubjectUserName": "fin_admin", "TaskName": r"\GoogleUpdateTaskMachineCore",
                    "TaskContent": r"C:\Program Files\Google\Update\GoogleUpdate.exe /c"},
                   benign_note="legitimate vendor scheduled task creation"))
    return out
