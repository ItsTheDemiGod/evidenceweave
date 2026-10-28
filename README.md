# EvidenceWeave

EvidenceWeave is a log-correlation agent that runs entirely on your own machine (local Ollama, no paid APIs).

- It reads mixed logs (Linux `auth.log`, nginx access logs, Windows event logs as JSON) and normalizes them into one event schema.
- Deterministic correlation rules find the attack chain (brute force, access, privilege escalation, persistence, lateral movement, web recon).
- A local LLM only *narrates* facts that the rules already established; every sentence must cite event IDs.
- A verifier checks each sentence (citations, IPs, times, users, paths, commands, claim semantics, independent judge model) and drops what it cannot support.
- The result is one self-contained HTML report, evaluated against a synthetic answer key.

## Requirements

- Python 3.12 (a venv; the project was built with the standard Windows Python 3.12)
- [Ollama](https://ollama.com) running locally, with two models: `qwen2.5:7b-instruct` (narrator) and `llama3.1:8b` (judge)
- Python packages: `requests`, `jinja2`, `pytest` (see `requirements.txt`)
- Not needed for `--no-llm` mode: Ollama and the models

## Quickstart (Windows PowerShell)

```powershell
python -m venv .venv                                   # use the standard python.org Python 3.12
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
ollama pull qwen2.5:7b-instruct ; ollama pull llama3.1:8b
python -m evidenceweave.cli generate --case case02 --difficulty hard --seed 7
python -m evidenceweave.cli analyze --case-dir data\cases\case02       # full pipeline, opens output\case02\report.html
python -m evidenceweave.cli analyze --case-dir data\cases\case02 --no-llm   # no Ollama needed
```

Or run `scripts\demo.ps1` (generates the case if needed, falls back to `--no-llm` when Ollama is not answering).

## Pipeline

```
 generator            (synthetic logs + answer key, evaluation only)
    |
 parsers              auth.log / nginx / windows json  ->  normalized events (events.jsonl)
    |
 correlation rules    findings (F-<rule>-<n>)  ->  attack chain (chain.json), attempts-only actors, unprovable items
    |
 facts                deterministic atomic facts per stage, each with its cited event IDs
    |
 LLM narrator         rewrites the facts as 2-5 sentences per stage (qwen2.5:7b-instruct)   [skipped with --no-llm]
    |
 verifier             structure -> fact refs -> entity grounding -> claim semantics -> independent double judge (llama3.1:8b)
    |  repair loop    rejected sentences are rewritten up to 2 times; still failing => dropped / facts shown verbatim
    |
 report               one offline HTML file: timeline, stage cards, evidence drawer, what could not be proven
```

The rules decide what happened. The LLM never sees the answer key and cannot add facts.

## Command reference

| Command | What it does |
|---|---|
| `generate --case NAME --difficulty easy\|hard --seed N [--out data/cases]` | synthetic logs + `answer_key.json` + `hosts.json` + `manifest.json` |
| `parse --case-dir D [--clock-offset HOST=SECONDS] [--year Y] [--out output]` | normalized `events.jsonl` |
| `correlate --case-dir D [--tolerance-seconds N] [--brute-force-min-failures N ...]` | `findings.json`, `chain.json` |
| `narrate --case-dir D [--mode chain\|baseline\|both] [--model M] [--narration-mode facts\|raw]` | `narrative.json` (LLM) |
| `verify --case-dir D [--mode chain\|baseline\|corruption\|all] [--judge-model M] [--no-judge] [--repeat N]` | `narrative_verified.json`, `verification_report.json`, ... |
| `analyze --case-dir D [--no-llm] [--reuse] [--model M] [--judge-model M] [--max-retries 2] [--max-cites 8] [--single-judge] [--num-ctx 16384] [--no-open]` | parse, correlate, narrate, verify, report in one command |
| `report --case-dir D [--no-open]` | rebuild `report.html` from existing outputs (no pipeline, no LLM) |
| `python scripts/check_against_key.py --case-dir D` | measure the chain against the answer key (evaluation only) |
| `python scripts/check_ollama.py` | check Ollama and both models |

`analyze` flags worth knowing: `--no-llm` builds the report from deterministic facts only (banner shown in the report);
`--reuse` skips narrate + verify when their outputs are newer than `chain.json`; if Ollama is unreachable or a model is missing,
`analyze` prints the exact fix command and suggests `--no-llm`. `--clock-offset HOST=SECONDS` is the only way clock skew is corrected.

## Output files (`output/<case>/`)

| File | Content |
|---|---|
| `events.jsonl` | normalized events (UTC, raw timestamp kept) |
| `findings.json` | every rule finding with evidence IDs |
| `chain.json` | attack chain stages, attempts-only actors, unprovable items, thresholds, applied clock offsets |
| `narrative.json` | the narrator's raw output plus the facts it was given |
| `narrative_verified.json` | only sentences that passed verification (`source` llm / deterministic / template) |
| `verification_report.json` | every verdict of every attempt, repair log, judge statistics |
| `report.html` | the self-contained report |
| `narrator_raw/` | exact prompts and replies |

## Project layout

```
evidenceweave/
  generator/   synthetic cases + answer key          parsers/    log -> Event
  correlation/ rules, chain builder                  narrator/   facts, prompts, Ollama client
  verifier/    layers, judge, repair, corruption     report/     data builder, template, renderer
  analyze.py   analyze + report commands             cli.py  schema.py  config.py  runmeta.py
scripts/       check_ollama, check_against_key, demo.ps1     docs/  DEMO.md, demo/ (sample reports)
tests/         pytest suite (fakes only, no real Ollama)
```

## Limitations

- Validated on synthetic cases with planted attacks only; not tested on real-world logs.
- The narrator can only restate verified facts, so the prose is plain and somewhat repetitive.
- The local judge (llama3.1:8b) is imperfect and only partly reproducible; it is cross-checked by exact-quote matching,
  double judging and deterministic layers, but an entity-free sentence phrased unusually may still pass.
- Cross-host time correlation uses a tolerance; clock skew is never estimated or auto-corrected.
- Absence of evidence in the logs is not proof of absence.

## Tests

```powershell
.\.venv\Scripts\Activate.ps1
python -m pytest            # no test calls Ollama
```

## Evaluation

Measured results (all arms, held-out corruption test, manual audit): see [docs/RESULTS.md](docs/RESULTS.md).
