import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
OUTPUT_DIR = ROOT / "output"

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("EVIDENCEWEAVE_MODEL", "qwen2.5:7b-instruct")
SECONDARY_MODEL = "llama3.1:8b"  # used later for the model comparison
