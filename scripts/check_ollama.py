import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from evidenceweave.config import OLLAMA_MODEL, OLLAMA_URL, SECONDARY_MODEL  # noqa: E402


def main():
    try:
        tags = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5).json()
    except requests.RequestException as e:
        sys.exit(f"Ollama not reachable at {OLLAMA_URL} ({e}).\nRun: ollama serve")
    installed = [m["name"] for m in tags.get("models", [])]
    print("Installed models:", ", ".join(installed) or "(none)")

    ok = True
    for model in (OLLAMA_MODEL, SECONDARY_MODEL):
        if model not in installed:
            print(f"[MISSING] {model} -> run: ollama pull {model}")
            ok = False
            continue
        t = time.time()
        r = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": model, "prompt": "Reply with the single word: ready", "stream": False},
            timeout=300,
        )
        r.raise_for_status()
        print(f"[{model}] {r.json()['response'].strip()!r} ({time.time() - t:.1f}s)")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
