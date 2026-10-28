#!/bin/bash
# Phase 5b live suite. Resumable: every step writes a marker when it finishes, finished steps are skipped on restart.
cd /c/Users/demia/Desktop/evidenceweave
PY=.venv/Scripts/python.exe
mkdir -p live5b
run() {
  name=$1; shift
  if [ -f "live5b/$name.done" ]; then echo "skip $name (done)"; return; fi
  echo "################ $name: $*"; date
  $PY -u -m evidenceweave.cli verify "$@" --num-ctx 16384 > "live5b/$name.log" 2>&1
  code=$?
  echo "exit=$code"; date
  if [ $code -eq 0 ]; then touch "live5b/$name.done"; fi
}
run facts_case01 --case-dir data/cases/case01 --mode chain --narration-mode facts --repeat 3
run facts_case02 --case-dir data/cases/case02 --mode chain --narration-mode facts --repeat 3
run raw_case01 --case-dir data/cases/case01 --mode chain --narration-mode raw
run raw_case02 --case-dir data/cases/case02 --mode chain --narration-mode raw
run corr_case01 --case-dir data/cases/case01 --mode corruption --narration-mode facts --repeat 3
run corr_case02 --case-dir data/cases/case02 --mode corruption --narration-mode facts --repeat 3
echo ALL-DONE
