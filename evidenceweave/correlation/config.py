"""Tunable thresholds and suspicious-command patterns for the correlation rules."""
import re
from dataclasses import dataclass, field, fields

_I = re.IGNORECASE
# Extend this list to teach the rules new bad commands. Each entry is a compiled regex searched in the command text.
DEFAULT_SUSPICIOUS_PATTERNS = [
    re.compile(r"\b(curl|wget)\b[^|;]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", _I),  # curl/wget piped to a shell
    re.compile(r"\b(curl|wget|fetch|iwr|invoke-webrequest|invoke-restmethod)\b.*\|\s*(sudo\s+)?(ba|z|da)?sh\b", _I),
    re.compile(r"base64\s+(-d|--decode)\b.*\|\s*(ba|z|da)?sh\b", _I),
    re.compile(r"chmod\s+\S*\+x\S*\s+(/tmp|/var/tmp|/dev/shm)/", _I),
    re.compile(r"\b(nc|ncat|netcat)\b.*\s-\w*e\b", _I),
    re.compile(r"bash\s+-i\b.*?/dev/tcp/", _I),
    re.compile(r"(?<!\w)-(enc|encodedcommand)\b", _I),  # PowerShell encoded command
    re.compile(r"FromBase64String", _I),
    re.compile(r"\b(iex|invoke-expression)\b", _I),
    re.compile(r"DownloadString", _I),
    re.compile(r"(?=.*(?<!\w)-nop\w*)(?=.*(?<!\w)-w(indowstyle)?\s+hidden)", _I),
]
DEFAULT_SENSITIVE_PATHS = ("/.env", "/.git", "/wp-admin", "/wp-login", "/phpmyadmin", "/admin", "/backup",
                           "/config", "/server-status", "/cgi-bin")


@dataclass
class CorrelationConfig:
    brute_force_min_failures: int = 8
    brute_force_window_seconds: int = 600
    access_after_failures_window_seconds: int = 1800
    web_recon_min_requests: int = 15
    web_recon_min_error_ratio: float = 0.6  # share of 403/404 responses
    web_recon_window_seconds: int = 900
    web_recon_min_sensitive_paths: int = 3  # distinct sensitive paths that count even below the thresholds
    cross_host_tolerance_seconds: int = 300  # B.start >= A.start - tolerance across hosts; we do NOT estimate skew
    lateral_window_seconds: int = 900
    sudo_after_access_window_seconds: int = 1800
    cron_session_match_seconds: int = 60
    web_recon_error_statuses: tuple = (403, 404)
    sensitive_path_fragments: tuple = DEFAULT_SENSITIVE_PATHS
    suspicious_patterns: list = field(default_factory=lambda: list(DEFAULT_SUSPICIOUS_PATTERNS))

    def to_dict(self) -> dict:
        d = {f.name: getattr(self, f.name) for f in fields(self)}
        d["suspicious_patterns"] = [p.pattern for p in self.suspicious_patterns]
        d["web_recon_error_statuses"] = list(self.web_recon_error_statuses)
        d["sensitive_path_fragments"] = list(self.sensitive_path_fragments)
        return d
