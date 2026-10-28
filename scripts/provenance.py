"""Write eval/provenance.json (section 'start' or 'end'). Usage: provenance.py start|end [--pool-commit HASH]"""
import argparse
import datetime
import hashlib
import json
import platform
import subprocess
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
MODELS = ["qwen2.5:7b-instruct", "llama3.1:8b"]


def code_hash():
    files = sorted(p for p in (ROOT / "evidenceweave").rglob("*") if p.is_file() and "__pycache__" not in p.parts)
    per = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    h = hashlib.sha256()
    for k in sorted(per):
        h.update(k.encode() + b"\0" + per[k].encode() + b"\0")
    return h.hexdigest(), per


def git(*a):
    return subprocess.run(["git", *a], cwd=ROOT, capture_output=True, text=True).stdout.strip()


def snapshot():
    try:
        ver = requests.get("http://localhost:11434/api/version", timeout=10).json().get("version")
        tags = {m["name"]: m["digest"] for m in requests.get("http://localhost:11434/api/tags", timeout=10).json()["models"]}
    except Exception as e:  # noqa: BLE001
        ver, tags = f"unavailable: {e}", {}
    h, per = code_hash()
    # clean = no tracked-file changes (untracked logs/outputs do not count)
    dirty = git("status", "--porcelain", "--untracked-files=no")
    return {"date": datetime.datetime.now().astimezone().isoformat(timespec="seconds"), "git_commit": git("rev-parse", "HEAD"),
            "working_tree_clean_tracked": not dirty, "dirty_files": dirty.splitlines(), "python": sys.version.split()[0],
            "platform": platform.platform(), "ollama_version": ver, "model_digests": {m: tags.get(m) for m in MODELS},
            "code_sha256": h, "code_file_hashes": per}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("section", choices=["start", "end"])
    ap.add_argument("--pool-commit")
    a = ap.parse_args()
    path = ROOT / "eval" / "provenance.json"
    doc = json.loads(path.read_text()) if path.exists() else {}
    doc[a.section] = snapshot()
    if a.pool_commit:
        doc["heldout_pool_commit"] = a.pool_commit
    if "start" in doc and "end" in doc:
        s, e = doc["start"]["code_file_hashes"], doc["end"]["code_file_hashes"]
        doc["code_changed"] = doc["start"]["code_sha256"] != doc["end"]["code_sha256"]
        doc["changed_files"] = sorted(k for k in set(s) | set(e) if s.get(k) != e.get(k))
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    print(a.section, doc[a.section]["code_sha256"], doc[a.section]["ollama_version"])
