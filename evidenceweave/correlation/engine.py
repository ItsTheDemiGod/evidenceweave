"""Run every rule, then the chain builder. Inputs: parsed events + hosts.json only."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from ..parsers.pipeline import Case, parse_case
from . import util as U
from .chain import build_chain
from .config import CorrelationConfig
from .rules import RULES


def correlate(case: Case, cfg: CorrelationConfig | None = None):
    cfg = cfg or CorrelationConfig()
    events = U.usable(case.events)
    findings = []
    for rule in RULES:
        findings += rule.run(events, cfg, case.hosts, tuple(findings))
    stats = {"events_read": len(case.events), "unparsed_skipped": len(case.events) - len(events),
             "findings_per_rule": {r.NAME: Counter(f.rule for f in findings)[r.NAME] for r in RULES}}
    chain, findings = build_chain(findings, case.hosts, cfg, case.name, case.clock_offsets, stats)
    return findings, chain


def correlate_case(case_dir, cfg=None, year=None, clock_offsets=None):
    case = parse_case(case_dir, year, clock_offsets)
    findings, chain = correlate(case, cfg)
    return case, findings, chain


def write_outputs(case_name: str, findings, chain, out_dir) -> Path:
    d = Path(out_dir) / case_name
    d.mkdir(parents=True, exist_ok=True)
    dump = lambda o: json.dumps(o, indent=2) + "\n"
    (d / "findings.json").write_text(
        dump({"case_name": case_name, "findings": [f.to_dict() for f in findings]}), encoding="utf-8", newline="\n")
    (d / "chain.json").write_text(dump(chain), encoding="utf-8", newline="\n")
    return d
