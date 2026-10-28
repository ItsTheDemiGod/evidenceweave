# Changes under evidenceweave/ after the evaluation started (freeze log)

## 1. Ollama request timeout 1800 s -> 600 s (infrastructure fix, 2026-10-28)
- Reason: the harness stalled for ~57 minutes in `baseline/eval_e2` (narrate step, after chunk_003, no log output, Ollama idle with the model loaded). A hung request must fail and be retried instead of stalling silently.
- File: `evidenceweave/narrator/llm.py` (`OllamaClient.__init__` default `timeout`: 1800 -> 600). The judge client already used 300 s and is unchanged.
- No rule, verifier check, prompt or threshold changed. A timed-out call already returns a failed `LLMResult`, and `call_json` retries once.
- Runs repeated: `baseline/eval_e2` and all later stages (corruption, raw, swap). Stages S1-S3 and `baseline/eval_e1` ran with the old default; the timeout never fired in them, so their behaviour is identical.
- Effect on provenance: the code SHA-256 at the end differs from the start by this one file (expected).
