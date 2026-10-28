# EvidenceWeave demo: generate the case if missing, check Ollama, run analyze, open the report.
# Usage: .\scripts\demo.ps1 [-NoLlm] [-Case case02] [-Seed 7]
param(
    [switch]$NoLlm,
    [string]$Case = "case02",
    [int]$Seed = 7
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$activate = Join-Path $root ".venv\Scripts\Activate.ps1"
if (Test-Path $activate) { . $activate } else { Write-Host "venv not found at .venv - using python from PATH" }

$caseDir = Join-Path $root "data\cases\$Case"
if (-not (Test-Path $caseDir)) {
    Write-Host "Generating $Case (hard, seed $Seed)..."
    python -m evidenceweave.cli generate --case $Case --difficulty hard --seed $Seed
}

if (-not $NoLlm) {
    try {
        Invoke-RestMethod -Uri "http://localhost:11434/api/tags" -TimeoutSec 5 | Out-Null
    } catch {
        Write-Host "Ollama is not answering at http://localhost:11434 - falling back to --no-llm (deterministic report)."
        Write-Host "To use the LLM, start it with: ollama serve"
        $NoLlm = $true
    }
}

$extra = @()
if ($NoLlm) { $extra += "--no-llm" }
python -m evidenceweave.cli analyze --case-dir $caseDir @extra
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "Report: $(Join-Path $root "output\$Case\report.html")"
