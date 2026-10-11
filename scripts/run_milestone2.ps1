<#
.SYNOPSIS
  Milestone 2 run on Windows: scrape lists, fit on the training fold, build tier A features, leakage check.

.DESCRIPTION
  Run after `git pull` on main and after the milestone 1 build produced data\processed\pool.parquet:

      powershell -ExecutionPolicy Bypass -File scripts\run_milestone2.ps1

  Steps (stops at the first failing one and names it):
    1. python -m features lists   (scrape platforms, brands, keywords, shorteners; needs internet)
    2. python -m features fit     (bigram and TLD numbers from the training fold only)
    3. python -m features build   (data\processed\features_a.parquet)
    4. python -m features build --split time_slice / heldout_source  (features_a_<part>.parquet)
    5. python -m experiments.feature_source_check  (reports\tables\feature_source_check.csv)
#>

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
$env:PYTHONUTF8 = "1"

if (-not (Test-Path "data\processed\pool.parquet")) {
    Write-Host "data\processed\pool.parquet is missing: run the milestone 1 build first." -ForegroundColor Red
    exit 1
}
$py = if (Test-Path ".venv\Scripts\python.exe") { ".venv\Scripts\python.exe" } else { "python" }

function Invoke-Step {
    param([string]$Name, [scriptblock]$Command)
    Write-Host ""
    Write-Host "==> $Name" -ForegroundColor Cyan
    & $Command
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED at step: $Name (exit code $LASTEXITCODE)" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

Invoke-Step "scrape lists" { & $py -m features lists }
Invoke-Step "fit (training fold only)" { & $py -m features fit }
Invoke-Step "build tier A features" { & $py -m features build }
foreach ($part in @("time_slice", "heldout_source")) {
    if (Test-Path "data\processed\$part.parquet") {
        Invoke-Step "build tier A features: $part" { & $py -m features build --split $part }
    }
}
Invoke-Step "source-leakage check" { & $py -m experiments.feature_source_check }

Write-Host ""
Write-Host "Done. Send reports\tables\feature_source_check.csv (or the flagged rows)." -ForegroundColor Green
