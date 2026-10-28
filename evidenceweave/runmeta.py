"""run_metadata block written into every narrative / verification output: what produced these numbers."""
from __future__ import annotations

import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import requests

from .config import OLLAMA_URL

REPO = Path(__file__).resolve().parent.parent


def _get(url: str, path: str):
    try:
        r = requests.get(f"{url}{path}", timeout=5)
        r.raise_for_status()
        return r.json(), None
    except Exception as e:  # never fail a run because metadata is unavailable
        return None, f"{type(e).__name__}: {e}"


def _git() -> dict:
    try:
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True, timeout=10)
        dirty = subprocess.run(["git", "status", "--porcelain"], cwd=REPO, capture_output=True, text=True, timeout=10)
        if head.returncode != 0:
            return {"git_commit": None, "git_dirty": None, "git_note": head.stderr.strip()[:200] or "git rev-parse failed"}
        return {"git_commit": head.stdout.strip(), "git_dirty": bool(dirty.stdout.strip()), "git_note": None}
    except Exception as e:
        return {"git_commit": None, "git_dirty": None, "git_note": f"{type(e).__name__}: {e}"}


def collect(models: list[str], ollama_options: dict, prompt_versions: dict, narration_mode: str, max_cites: int,
            max_facts_per_stage: int | None, url: str = OLLAMA_URL) -> dict:
    """models: every model used; ollama_options: call type -> options (narrator attempt 0, repair, judge run 1, judge run 2)."""
    ver, ver_note = _get(url, "/api/version")
    tags, tag_note = _get(url, "/api/tags")
    digests = {m["name"]: m.get("digest") for m in (tags or {}).get("models", [])}
    return {
        "collected": True, "date": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "ollama_version": (ver or {}).get("version"), "ollama_version_note": ver_note,
        "model_digests": {m: digests.get(m) for m in models},
        "model_digests_note": tag_note or (None if all(m in digests for m in models) else "model not listed by /api/tags"),
        "ollama_options": ollama_options, "prompt_versions": prompt_versions, "narration_mode": narration_mode,
        "max_cites": max_cites, "max_facts_per_stage": max_facts_per_stage,
        "python_version": platform.python_version(), **_git()}
