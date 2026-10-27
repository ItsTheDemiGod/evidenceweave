"""Local Ollama client with a strict {"sentences": [{"text", "cites"}]} output contract."""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Protocol

import requests

from ..config import OLLAMA_MODEL, OLLAMA_URL

SENTENCES_SCHEMA = {
    "type": "object",
    "properties": {"sentences": {"type": "array", "items": {
        "type": "object",
        "properties": {"text": {"type": "string"}, "cites": {"type": "array", "items": {"type": "string"}}},
        "required": ["text", "cites"]}}},
    "required": ["sentences"]}
RETRY_REMINDER = "\n\nReminder: reply with ONLY valid JSON of the form {\"sentences\": [{\"text\": \"...\", \"cites\": [\"ID\"]}]}."


class LLMError(RuntimeError):
    """Ollama itself is unreachable or the model is missing (not a bad model reply)."""


@dataclass
class LLMResult:
    ok: bool  # reply parsed into the sentences structure
    raw: str
    parsed: dict | None
    seconds: float
    json_mode: str = "schema"  # schema | json
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    error: str | None = None


class LLMClient(Protocol):
    model: str
    options: dict
    json_mode: str

    def complete(self, system: str, user: str) -> LLMResult: ...


def parse_sentences(text: str) -> dict | None:
    """The reply as a dict, only if it has the exact sentences structure. Never raises."""
    try:
        obj = json.loads(text)
        sents = obj["sentences"]
        if not isinstance(sents, list) or not all(
                isinstance(s, dict) and isinstance(s.get("text"), str) and isinstance(s.get("cites"), list)
                and all(isinstance(c, str) for c in s["cites"]) for s in sents):
            return None
        return obj
    except (ValueError, KeyError, TypeError):
        return None


class OllamaClient:
    def __init__(self, model: str = OLLAMA_MODEL, url: str = OLLAMA_URL, num_ctx: int = 8192,
                 temperature: float = 0, seed: int = 42, keep_alive: str = "10m", timeout: int = 1800,
                 schema: dict | None = None, validator=None):
        self.model, self.url, self.keep_alive, self.timeout = model, url.rstrip("/"), keep_alive, timeout
        self.options = {"temperature": temperature, "seed": seed, "num_ctx": num_ctx}
        self.schema, self.validator = schema or SENTENCES_SCHEMA, validator or parse_sentences
        self.json_mode = "schema"  # drops to "json" (sticky) if the server rejects the schema

    def _post(self, system: str, user: str):
        body = {"model": self.model, "stream": False, "keep_alive": self.keep_alive, "options": self.options,
                "format": self.schema if self.json_mode == "schema" else "json",
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        try:
            return requests.post(f"{self.url}/api/chat", json=body, timeout=self.timeout)
        except requests.ConnectionError as e:
            raise LLMError(f"Ollama is not reachable at {self.url} ({e}). Start it with: ollama serve") from e

    def complete(self, system: str, user: str) -> LLMResult:
        t0 = time.time()
        try:
            r = self._post(system, user)
            if r.status_code == 404 and "not found" in r.text.lower():
                raise LLMError(f"Model '{self.model}' is not installed. Run: ollama pull {self.model}")
            if r.status_code != 200 and self.json_mode == "schema":
                self.json_mode = "json"  # server rejected the JSON-schema form: fall back to plain JSON mode
                r = self._post(system, user)
                if r.status_code == 404 and "not found" in r.text.lower():
                    raise LLMError(f"Model '{self.model}' is not installed. Run: ollama pull {self.model}")
            if r.status_code != 200:
                return LLMResult(False, r.text[:2000], None, time.time() - t0, self.json_mode,
                                 error=f"HTTP {r.status_code}")
            data = r.json()
            raw = data.get("message", {}).get("content", "")
            parsed = self.validator(raw)
            return LLMResult(parsed is not None, raw, parsed, time.time() - t0, self.json_mode,
                             data.get("prompt_eval_count"), data.get("eval_count"),
                             None if parsed is not None else "reply does not match the expected JSON structure")
        except (requests.Timeout, ValueError) as e:  # timeout / unreadable HTTP body: a failed call, not a crash
            return LLMResult(False, "", None, time.time() - t0, self.json_mode, error=f"{type(e).__name__}: {e}")


@dataclass
class CallRecord:
    parsed: dict | None
    attempts: int
    seconds: float
    tokens: int | None
    transcript: str  # exact prompts and replies, for narrator_raw/
    failed_parses: int = 0
    retries: int = 0
    json_mode: str = "schema"
    last: LLMResult | None = field(default=None, repr=False)


def call_json(client: LLMClient, system: str, user: str, retry: bool = True) -> CallRecord:
    """One logical call: retry ONCE (same prompt + reminder) only if the reply was not parseable JSON."""
    parts, seconds, tokens, failed, res = [], 0.0, None, 0, None
    for attempt in (1, 2):
        prompt = user if attempt == 1 else user + RETRY_REMINDER
        res = client.complete(system, prompt)
        seconds += res.seconds
        if res.prompt_tokens is not None or res.completion_tokens is not None:
            tokens = (tokens or 0) + (res.prompt_tokens or 0) + (res.completion_tokens or 0)
        parts.append(f"=== SYSTEM ===\n{system}\n=== USER (attempt {attempt}) ===\n{prompt}\n"
                     f"=== REPLY (attempt {attempt}, ok={res.ok}, {res.seconds:.1f}s, mode={res.json_mode}"
                     f"{', error=' + res.error if res.error else ''}) ===\n{res.raw}\n")
        if res.parsed is not None:
            break
        failed += 1
        if not retry:
            break
    return CallRecord(res.parsed, len(parts), seconds, tokens, "\n".join(parts), failed, len(parts) - 1,
                      res.json_mode, res)


def safe_name(model: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", model)
