# EvidenceWeave demo kit

## Timed script (7 minutes)

| Time | Say | Do |
|---|---|---|
| 0:00-0:45 **Problem** | "An analyst has three log files from three systems and an hour. LLMs summarise well but invent details; an invented IP in an incident report is worse than no report." | Title slide. |
| 0:45-1:30 **One command** | "One command parses the logs, finds the attack with deterministic rules, lets a local LLM narrate only proven facts, verifies every sentence and writes one offline HTML file." | Run `scripts\demo.ps1` (or `python -m evidenceweave.cli analyze --case-dir data\cases\case02`). Show the five progress lines while it runs. |
| 1:30-2:30 **Report: top** | "The headline is computed from the chain, not written by the model: N of 6 stages established, one partially unprovable." | Report opens. Point at the banner, summary strip, then the timeline. Click a stage bar: the page scrolls to its card. |
| 2:30-4:00 **Report: a stage** | "Left: facts the rules established. Right: the narrative sentences that survived verification. Each carries a badge." | Open the `initial_access` card. Hover a badge (tooltip lists the checks). Click a cite chip: the drawer shows the raw log line, the context lines, corrected vs logged time. Press Esc. |
| 4:00-5:00 **Hallucination catch** | "Every rejected sentence is recorded. Here the narrator wrote something the logs do not say." | In a terminal: `python -c "import json;r=json.load(open('output/case02/verification_report.json'));print(r['summary']['failure_code_histogram']);print([(v['text_original'],[x['code'] for x in v['layer_results']['entities']['reasons']]) for v in r['verdicts'] if not v['accepted']][:3])"`. Read one rejected sentence and its code (e.g. `IP_NOT_GROUNDED`, `PATH_NOT_GROUNDED`). Say: "It never reached the report." |
| 5:00-6:00 **Could not prove** | "The log shows a cron job running as svc_backup but nothing creating that account. We say so instead of guessing." Also: the decoy IP with failed logins is in the attempts-only lane: "no successful access observed". | Scroll to "What could not be proven" and "Attempts only". Click its evidence chips. |
| 6:00-7:00 **Results** | "Measured against the synthetic answer key, ..." | Open the results slide (numbers: see *Results (filled in Phase 6b)* below). Close with limits: synthetic data, plain prose, imperfect local judge. |

## Backup plan

1. Pre-generated reports need no Ollama: open `docs/demo/sample_report_case02.html` (full LLM run) or
   `docs/demo/sample_report_case02_no_llm.html` (deterministic mode). Both contain synthetic data only and work offline.
2. If Ollama misbehaves live: `python -m evidenceweave.cli analyze --case-dir data\cases\case02 --no-llm` takes seconds and prints no model calls;
   say plainly that this is the deterministic report without the LLM and the judge (the report shows a banner saying so).
3. Record a screen capture of one full run beforehand (Win+G or OBS) and keep it next to the slides.

## Pre-demo checklist

- [ ] Ollama is running (`ollama serve`; `python scripts\check_ollama.py` answers for both models)
- [ ] Both models are present: `qwen2.5:7b-instruct`, `llama3.1:8b`
- [ ] venv active: `.\.venv\Scripts\Activate.ps1`, `python -m pytest -q` is green
- [ ] Laptop plugged in, sleep and screen lock off, notifications off
- [ ] Heavy apps closed (the 7B and 8B models need the RAM)
- [ ] Run the demo once beforehand so both models are loaded (first load is slow)
- [ ] `data\cases\case02` exists (the demo script generates it)
- [ ] Backup reports open in a second browser tab

## Likely questions

1. **Why not let the LLM do everything?** It would invent details, and a 7B model cannot hold thousands of log lines. Rules find the attack; the LLM only rewrites facts. A naive chunked baseline we ran covered fewer attacker entities and was far less supported.
2. **How do you know it is correct?** The chain is scored against a synthetic answer key (precision/recall per step); every narrative sentence is checked against the cited log lines. We have not checked it on real logs.
3. **Is the data real?** No. All logs are synthetic with a planted attack and known ground truth; the report footer says so.
4. **What does the judge add?** Deterministic checks catch wrong entities. The judge (a different model) catches claims that use correct entities but say something the cited lines do not show. It must quote the log line; the quote is matched exactly.
5. **What happens when the judge is wrong?** It is imperfect and not fully reproducible (agreement 0.8-0.96 between its two runs). We double-judge, require exact quotes, treat disagreement as rejection, and measure false rejections and misses with a corruption test. A sentence with no checkable entity can still slip through.
6. **Why 7B local models?** Free, private (logs never leave the machine), reproducible. The cost is plain prose, which is acceptable because facts come from rules.
7. **What is the clock-offset story?** Windows hosts can have a skewed clock. We never estimate skew automatically; you pass `--clock-offset HOST=SECONDS`. Cross-host links use a tolerance (default 300 s). The report shows the offsets applied.
8. **What would you do next?** Real-world logs, more sources, held-out corruption tests, a manual audit of the report text, and a stronger narrator.
9. **What if the LLM output is rejected?** The sentence is dropped or replaced by the deterministic fact; it is never shown unverified. The report counts accepted, dropped and fallback units.
10. **Can an attacker poison the report through log text?** Log lines are untrusted: the HTML never interprets them as markup (escaped JSON, textContent rendering, no links), and a test injects script strings to prove it.
11. **Why can the same run give slightly different results?** Local models are only partly deterministic even at temperature 0 and a fixed seed; the run metadata (model digests, Ollama version, options) is stored with every output.
12. **What does "unprovable" mean here?** The logs show an effect (a cron job as svc_backup) but not the cause (the account creation). Absence of evidence is not proof of absence, so the report says what is missing.

## Results (filled in Phase 6b)

_Placeholder: the multi-case evaluation, held-out corruption pool and manual audit are Phase 6b. No numbers are claimed here yet._
