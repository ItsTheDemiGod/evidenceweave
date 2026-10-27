"""Rule 6: scanner-like web traffic from one IP (many errors, or several sensitive paths)."""
from __future__ import annotations

from collections import Counter, defaultdict

from ...schema import WEB_REQUEST
from .. import util as U

NAME = "web_recon"


def run(events, cfg, hosts, prior=()):
    by_ip = defaultdict(list)
    for e in sorted(U.usable(events), key=U.order_key):
        if e.action == WEB_REQUEST and e.src_ip:
            by_ip[e.src_ip].append(e)

    def sensitive(w):
        return sorted({p for x in w if (p := x.extra.get("path", "").split("?")[0].lower())
                       and any(frag in p for frag in cfg.sensitive_path_fragments)})

    def errors(w):
        return sum(1 for x in w if x.extra.get("status") in cfg.web_recon_error_statuses)

    def rate_hit(w):
        return len(w) >= cfg.web_recon_min_requests and errors(w) / len(w) >= cfg.web_recon_min_error_ratio

    def ok(w):
        return rate_hit(w) or len(sensitive(w)) >= cfg.web_recon_min_sensitive_paths

    out = []
    for ip, reqs in sorted(by_ip.items()):
        for i, j in U.burst_spans(reqs, cfg.web_recon_window_seconds, ok):
            burst = reqs[i:j + 1]
            sens, err = sensitive(burst), errors(burst)
            signals = [s for s, hit in (("request_rate_and_errors", rate_hit(burst)),
                                        ("sensitive_paths", len(sens) >= cfg.web_recon_min_sensitive_paths)) if hit]
            out.append(U.make(
                NAME, "web_recon", "attempts_only", burst,  # the chain builder upgrades attributed ones
                f"{len(burst)} web requests from {ip} in {U.secs(burst[0].timestamp, burst[-1].timestamp)}s, "
                f"{err} of them 403/404, touching {len(sens)} sensitive paths.",
                U.entities(ips=[ip], hosts=sorted({e.host for e in burst})),
                {"request_count": len(burst), "error_count": err, "error_ratio": round(err / len(burst), 3),
                 "sensitive_paths": sens, "signals": signals,
                 "status_counts": {str(k): v for k, v in sorted(Counter(x.extra.get("status") for x in burst).items())},
                 "thresholds": {"min_requests": cfg.web_recon_min_requests,
                                "min_error_ratio": cfg.web_recon_min_error_ratio,
                                "window_seconds": cfg.web_recon_window_seconds,
                                "min_sensitive_paths": cfg.web_recon_min_sensitive_paths}}))
    return U.number(NAME, out)
