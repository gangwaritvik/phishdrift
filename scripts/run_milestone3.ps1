<#
.SYNOPSIS
  Milestone 3 run on Windows: tier B (HTML) features for every processed part, then the tier B
  source-leakage check.

.DESCRIPTION
  Run after `git pull` on main, with data\processed\pool.parquet, time_slice.parquet and
  heldout_source.parquet in place (milestone 1 build, including the benign crawl):

      powershell -ExecutionPolicy Bypass -File scripts\run_milestone3.ps1

  Needs about 3 GB of free disk space. The HTML is read from the 10 GB pool a few hundred rows at a
  time, so memory stays small. Add -Workers N to change the number of worker processes
  (default: the number of CPUs minus 1, at most 4).

  Steps (stops at the first failing one and names it):
    1. python -m features build --tier B                          (pool)
    2. python -m features build --tier B --split time_slice
    3. python -m features build --tier B --split heldout_source   (skipped by the build if the part
                                                                   has no HTML at all)
    4. python -m experiments.feature_source_check --features-file features_b.parquet
       (reports\tables\feature_source_check_b.csv)

  Safe to stop with Ctrl+C at any time. To resume, run the same command again: finished shards
  (data\interim\features_b\<part>\shard_*.parquet) are kept and skipped. If the pool was rebuilt
  since the shards were written, the build says so; delete data\interim\features_b\<part> then.
#>

param([int]$Workers = 0)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
$env:PYTHONUTF8 = "1"

$NeedGB = 3
$Parts = @("pool", "time_slice", "heldout_source")

$missing = @($Parts | Where-Object { -not (Test-Path "data\processed\$_.parquet") })
if ($missing.Count -gt 0) {
    Write-Host "Missing input file(s) in data\processed: $($missing -join ', ')" -ForegroundColor Red
    Write-Host "Run the milestone 1 build first (scripts\run_milestone1.ps1)." -ForegroundColor Red
    exit 1
}

$drive = (Get-Location).Drive
if ($drive -and ($null -ne $drive.Free)) {
    $freeGB = [math]::Round($drive.Free / 1GB, 1)
    if ($freeGB -lt $NeedGB) {
        Write-Host "Only $freeGB GB free on drive $($drive.Name): (need about $NeedGB GB). Free some space first." -ForegroundColor Red
        exit 1
    }
    Write-Host "Disk space: $freeGB GB free (need about $NeedGB GB)."
}

$py = if (Test-Path ".venv\Scripts\python.exe") { ".venv\Scripts\python.exe" } else { "python" }
$workerArgs = if ($Workers -gt 0) { @("--workers", "$Workers") } else { @() }

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

Write-Host "Tier B build. Safe to stop with Ctrl+C; run the same command again to resume."
$finished = $false
try {
    foreach ($part in $Parts) {
        Invoke-Step "tier B features: $part" {
            & $py -m features build --tier B --split $part @workerArgs
        }
    }
    Invoke-Step "tier B source-leakage check" {
        & $py -m experiments.feature_source_check --features-file features_b.parquet --out reports\tables\feature_source_check_b.csv
    }
    $finished = $true
}
finally {
    if (-not $finished) {
        Write-Host ""
        Write-Host "Stopped before the end. Rerun the same command to resume; finished shards are kept." -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Output files:" -ForegroundColor Green
$outputs = @(Get-ChildItem "data\processed\features_b*.parquet" -ErrorAction SilentlyContinue) +
    @(Get-ChildItem "reports\tables\feature_source_check_b.csv" -ErrorAction SilentlyContinue)
foreach ($f in $outputs) {
    Write-Host ("  {0}  ({1:N1} MB)" -f $f.FullName, ($f.Length / 1MB))
}
Write-Host ""
Write-Host "Done. Send reports\tables\feature_source_check_b.csv (or the flagged rows) and the 'done:' line printed for each part." -ForegroundColor Green
