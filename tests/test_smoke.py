import subprocess
import sys


def test_imports():
    import evidenceweave.cli, evidenceweave.config, evidenceweave.schema  # noqa: F401
    for p in ("generator", "parsers", "correlation", "narrator", "verifier", "report"):
        __import__(f"evidenceweave.{p}")


def test_cli_help():
    r = subprocess.run([sys.executable, "-m", "evidenceweave.cli", "--help"], capture_output=True, text=True)
    assert r.returncode == 0
    assert "generate" in r.stdout and "analyze" in r.stdout and "evaluate" in r.stdout
