"""Phase 5b Part 0: write output/diagnosis_phase5b.md from the saved Phase 5 verification reports.

The verdict labels are hand-assigned (see VERDICTS); this script only assembles the facts around them.
Inputs are snapshots under output/diagnosis_inputs/ so later live runs cannot change the count.
"""
import json
from collections import Counter, defaultdict
from pathlib import Path

G, V, P = "GENUINE_NARRATOR_ERROR", "VERIFIER_TOO_STRICT", "PROMPT_DESIGN_PROBLEM"
CAP = "The prompt never states the 8-cite cap and shows 12 evidence lines, so citing everything shown is invited."
# (case, stage, sentence_index) -> {attempt or None: (verdict, justification)}; None = every attempt
VERDICTS = {
    ("case01", "brute_force", 0): (P, "The stage evidence holds only failure events, yet the prompt's summary mentions the later success; no allowed "
                                      "citation can show it. " + CAP),
    ("case01", "initial_access", 0): (G, "Copy error: the IP lost a dot (203.0113.45); the cited event shows 203.0.113.45."),
    ("case01", "initial_access", 1): (P, "The 36 failed attempts come from the linked brute-force finding, but the stage evidence is only the success "
                                         "event, so no allowed citation can show a failed login."),
    ("case01", "persistence", 0): (P, "'20 minutes after initial access' comes from the summary; the initial-access event is not in the stage "
                                      "evidence, so the cited account-creation line alone cannot show it."),
    ("case01", "persistence", "cap"): (P, "A two-claim sentence over 12 shown lines; " + CAP),
    ("case01", "persistence", "four"): (G, "States four executions but cites events showing fewer; the four CMD lines were available and within the cap."),
    ("case01", "lateral_movement", 0): (G, "Calls the plain 4624 logon 'privileged'; the separate special-privileges event was available but not cited."),
    ("case01", "web_recon", 0): (P, "One sentence summarising 26 requests over 12 shown lines. " + CAP),
    ("case01", "executive_summary", 0): (P, "Representative IDs are the first/last event of each stage: the brute-force ones are failures, so the "
                                            "'successful login' the summary text invites cannot be cited. 9 cites also exceeds the cap."),
    ("case02", "brute_force", 0): (P, CAP),
    ("case02", "brute_force", 1): (P, "'A successful login followed' - the success event is not in the brute-force stage evidence."),
    ("case02", "brute_force", 2): (P, "A counts sentence over 11 shown lines. " + CAP),
    ("case02", "initial_access", 1): (P, "Failed attempts come from the linked finding; the stage evidence is only the success event."),
    ("case02", "lateral_movement", 0): (G, "Claims a successful login but cites only a failed-logon (4625) event; the host web01 is not in the cited event."),
    ("case02", "lateral_movement", "time"): (P, "The pack shows contradictory times: events.jsonl carried clock-corrected timestamps while the stage range "
                                                "and raw_text carry the uncorrected ones (stale artifact from an earlier --clock-offset run)."),
    ("case02", "lateral_movement", "selfcontradict"): (V, "The sentence's time matches the cited raw_text; the judge's own reason is self-contradictory "
                                                          "('launched at 02:43:42.510Z ... not 02:43:42.510Z')."),
    ("case02", "lateral_movement", "powershell"): (V, "'a scheduled task was created to run a PowerShell script' IS shown by the task-created event "
                                                      "(its content runs powershell); the phrase table only accepts process/sudo/cron events for 'PowerShell'."),
    ("case02", "web_recon", 0): (P, "26-requests summary over 12 shown lines. " + CAP),
    ("case02", "web_recon", "intent"): (G, "'indicating an attempt to identify potential vulnerabilities' is speculation about intent that the lines do not show."),
    ("case02", "executive_summary", "success"): (P, "Representative IDs for the brute-force stage are failures only; the success cannot be cited."),
    ("case02", "executive_summary", "cron"): (P, "The persistence stage's first/last events are cron session lines, so the suspicious command is not citable."),
    ("case02", "executive_summary", "lateral"): (V, "The judge is given the stage summaries as ground truth (labelled lateral_movement, describing the network logon) "
                                                   "but insisted that 'moved laterally' is not in the log lines."),
    ("case02", "executive_summary", "overstate"): (G, "'26 requests to sensitive paths' overstates: the summary says 26 requests touching 10 sensitive paths."),
    ("case02", "executive_summary", "omission"): (V, "The number 26 is correct and grounded; the judge's complaint is that a detail (23 errors) was omitted, "
                                                    "which does not make the sentence unsupported."),
}


def pick(case, stage, idx, attempt, text, codes, judge_reason):
    k = (case, stage, idx)
    if k in VERDICTS:
        return VERDICTS[k]
    if case == "case01" and stage == "persistence":
        return VERDICTS[(case, stage, "four" if "JUDGE_PARTIAL" in codes else "cap")] if idx == 0 and attempt > 0 else VERDICTS[(case, stage, 0)]
    if case == "case02" and stage == "lateral_movement":
        if idx == 1:
            return VERDICTS[(case, stage, "selfcontradict" if attempt == 2 else "time")]
        return VERDICTS[(case, stage, "powershell")]
    if case == "case02" and stage == "web_recon" and idx == 1:
        return VERDICTS[(case, stage, "intent")]
    if case == "case02" and stage == "executive_summary":
        t = text.lower()
        if "successful login" in t:
            return VERDICTS[(case, stage, "success")]
        if "cron" in t:
            return VERDICTS[(case, stage, "cron")]
        if "laterally" in t:
            return VERDICTS[(case, stage, "lateral")]
        if "26 requests to sensitive" in t:
            return VERDICTS[(case, stage, "overstate")]
        return VERDICTS[(case, stage, "omission")]
    raise KeyError(k)


def main(base="output"):
    base = Path(base)
    inp = base / "diagnosis_inputs"
    entries, table = [], defaultdict(Counter)
    for case in ("case01", "case02"):
        rep = json.loads((inp / f"{case}_verification_report.json").read_text(encoding="utf-8"))
        ev = {}
        for line in (inp / f"{case}_events.jsonl").read_text(encoding="utf-8").splitlines():
            e = json.loads(line)
            ev[e["event_id"]] = e
        for v in rep["verdicts"]:
            if v["source"] != "llm" or v["accepted"]:
                continue
            fails = [(r["code"], r["detail"]) for lr in v["layer_results"].values() for r in lr["reasons"] if r["code"] != "NORMALIZED"]
            codes = [c for c, _ in fails]
            reason = (v["judge"] or {}).get("reason", "")
            verdict, why = pick(case, v["stage"], v["sentence_index"], v["attempt"], v["text_original"], codes, reason)
            acts = sorted({ev[c]["action"] for c in v["cites_final"] if c in ev})
            for c in codes:
                table[c][verdict] += 1
            entries.append((case, v, fails, acts, verdict, why, reason))
    out = ["# Phase 5b diagnosis of every failing sentence (Phase 5 reports, all attempts)", "",
           f"Source: saved `verification_report.json` of case01 and case02 from the second Phase 5 live run "
           f"(snapshots in `output/diagnosis_inputs/`). Failing LLM sentences: **{len(entries)}**.", "",
           "Labels: GENUINE_NARRATOR_ERROR = claims something the cited events do not show; VERIFIER_TOO_STRICT = the sentence is "
           "supported and the check is wrong/over-strict; PROMPT_DESIGN_PROBLEM = no allowed set of citations could support what the "
           "prompt invites the model to say. A sentence with several codes carries one verdict, counted under each of its codes.", ""]
    for n, (case, v, fails, acts, verdict, why, reason) in enumerate(entries, 1):
        out += [f"### {n}. {case} | {v['stage']} | attempt {v['attempt']} | sentence {v['sentence_index']}",
                f"- Sentence: {v['text_original']}",
                "- Failures: " + "; ".join(f"`{c}` {d}" for c, d in fails),
                f"- Judge reason: {reason}" if reason else "- Judge reason: (judge not reached)",
                f"- Cited event actions ({len(v['cites_final'])} cites): {', '.join(acts) or '(none)'}",
                f"- **Verdict: {verdict}** - {why}", ""]
    verdicts = [G, V, P]
    out += ["## Failure code x verdict (a sentence counts under each of its codes)", "",
            "| failure code | " + " | ".join(verdicts) + " | total |", "|---|" + "---|" * (len(verdicts) + 1)]
    for c in sorted(table):
        out.append(f"| {c} | " + " | ".join(str(table[c][x]) for x in verdicts) + f" | {sum(table[c].values())} |")
    per = Counter(e[4] for e in entries)
    out += ["", "Sentences per verdict: " + ", ".join(f"{x}={per[x]}" for x in verdicts), "",
            "## What the diagnosis says", "",
            "**Verifier checks to loosen (general reasons only):**",
            "- `SEMANTIC_MISMATCH` for the tool name 'PowerShell': a scheduled-task event (like cron or sudo) shows a command being run, "
            "so `win_task_created` is added to the supporting actions of the process/command phrase. Nothing else is loosened.",
            "- Not loosened: `TOO_MANY_CITES` (a deliberate cap; the cause is the prompt), the entity checks (no false positive remained after "
            "the Phase 5 user-name fix), the other semantic phrases (every remaining mismatch was a real claim/evidence gap).", "",
            "**Problems the fact-sheet design must remove (PROMPT_DESIGN_PROBLEM is the largest class):**",
            "- Stage evidence sets cannot contain facts the prompt asks about (a success in the brute-force stage, the failed attempts in the "
            "initial-access stage, the initial access in the persistence stage): facts must cite the LINKED finding's events and those IDs must "
            "join the stage's allowed list.",
            "- The cap of 8 cites is never stated and the pack shows 12 lines: facts carry 1-3 cites each and sentences copy them.",
            "- Executive-summary representative IDs (first/last event of a stage) are not the key action events: use each stage's first two facts "
            "with their own cites.",
            "- Stale artifact: events.jsonl and chain.json came from different clock-offset settings; the pipeline must regenerate "
            "unless the stored settings match (fixed in Phase 5b).",
            "- Judge: one self-contradictory reason and one 'omission is not support' complaint; the hardened judge derives the verdict in code "
            "from quoted claims instead of trusting its own verdict field.",
            "- Repair: the model repeated identical sentences in every round; repair needs temperature/seed variation and sentence-level feedback."]
    (base / "diagnosis_phase5b.md").write_text("\n".join(out) + "\n", encoding="utf-8", newline="\n")
    return len(entries), {c: dict(v) for c, v in table.items()}, dict(per)


if __name__ == "__main__":
    print(main())
