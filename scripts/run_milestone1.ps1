<#
.SYNOPSIS
  Milestone 1 data run on Windows, from a fresh clone: venv, tests, collector, pooled corpus build.

.DESCRIPTION
  Run from anywhere (the script moves to the repo root):

      powershell -ExecutionPolicy Bypass -File scripts\run_milestone1.ps1

  Steps (stops at the first failing one and names it):
    1. create .venv and install the package with dev + dataset extras
    2. pytest
    3. python -m collector run
    4. python -m data_pipeline inspect phreshphish
    5. python -m data_pipeline build
    6. python -m collector crawl --seeds phiusiil urlphish
    7. python -m data_pipeline build --reuse-interim --reload phiusiil urlphish live

  Exit code 2 from the collector or the build means "partial" (a feed or source was skipped,
  e.g. a manual download is missing); the run continues with a warning. Any other non-zero
  exit code stops the run. Exit code 3 from a build is the depth check: see reports\data_card.md.

  Optional keys are read from the environment (set them before running, never commit them):
    $env:URLHAUS_AUTH_KEY, $env:PHISHTANK_APP_KEY, $env:HF_TOKEN
#>

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
$env:PYTHONUTF8 = "1"   # Windows defaults to cp1252; reports and HTML are UTF-8

function Invoke-Step {
    param([string]$Name, [scriptblock]$Command, [switch]$AllowPartial)
    Write-Host ""
    Write-Host "==> $Name" -ForegroundColor Cyan
    & $Command
    $code = $LASTEXITCODE
    if ($code -eq 0) { return }
    if ($AllowPartial -and $code -eq 2) {
        Write-Host "    '$Name' finished with skipped parts (exit 2); see the log above." -ForegroundColor Yellow
        return
    }
    Write-Host ""
    Write-Host "FAILED at step: $Name (exit code $code)" -ForegroundColor Red
    if ($code -eq 3) {
        Write-Host "Depth check failed: see reports\data_card.md for the bucket." -ForegroundColor Red
    }
    exit $code
}

# --- Pre-flight: manual downloads (README "Get the sources") -------------------------------
Write-Host "==> Checking manual downloads in data\raw" -ForegroundColor Cyan
$manual = [ordered]@{
    "Phish360"       = { @(Get-ChildItem "data\raw\phish360\*.parquet" -ErrorAction SilentlyContinue).Count -gt 0 }
    "Phish-Blitz"    = { (Test-Path "data\raw\phishblitz\phishing_resources") -and (Test-Path "data\raw\phishblitz\legitimate_resources") }
    "Phishpedia 30k" = { @(Get-ChildItem "data\raw\phishpedia" -Directory -ErrorAction SilentlyContinue).Count -gt 0 }
    "URL-Phish"      = { @(Get-ChildItem "data\raw\urlphish\*.csv" -ErrorAction SilentlyContinue).Count -gt 0 }
    "PhishStorm"     = { Test-Path "data\raw\phishstorm\urlset.csv" }
}
$missing = @()
foreach ($name in $manual.Keys) {
    if (& $manual[$name]) { Write-Host "    found:   $name" }
    else { Write-Host "    MISSING: $name" -ForegroundColor Yellow; $missing += $name }
}
if ($missing.Count) {
    Write-Host "    Missing sources are skipped by the build (see the README table for where to put them)." -ForegroundColor Yellow
}

Write-Host "==> Checking optional API keys" -ForegroundColor Cyan
$keys = [ordered]@{
    "URLHAUS_AUTH_KEY"  = "URLhaus blocklist is skipped"
    "PHISHTANK_APP_KEY" = "PhishTank feed is skipped"
    "HF_TOKEN"          = "only needed if PhreshPhish is gated for you"
}
foreach ($k in $keys.Keys) {
    if ([string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($k))) {
        Write-Host "    unset: $k ($($keys[$k]))" -ForegroundColor Yellow
    } else {
        Write-Host "    set:   $k"
    }
}

# --- 1. Virtual environment ---------------------------------------------------------------
Invoke-Step "create venv" {
    if (Test-Path ".venv\Scripts\python.exe") { $global:LASTEXITCODE = 0; return }
    if (Get-Command py -ErrorAction SilentlyContinue) {
        py -3.11 -m venv .venv
        if ($LASTEXITCODE -ne 0) { py -3 -m venv .venv }
    }
    else { python -m venv .venv }
}
. .\.venv\Scripts\Activate.ps1
Invoke-Step "pip install" { python -m pip install -e ".[dev,datasets]" }

# --- 2-7. Tests, collector, corpus build --------------------------------------------------
Invoke-Step "pytest" { python -m pytest }
Invoke-Step "collector run" { python -m collector run } -AllowPartial
Invoke-Step "inspect phreshphish" { python -m data_pipeline inspect phreshphish }
Invoke-Step "build" { python -m data_pipeline build } -AllowPartial
Invoke-Step "crawl phiusiil + urlphish seeds" { python -m collector crawl --seeds phiusiil urlphish } -AllowPartial
Invoke-Step "rebuild with crawled pages" {
    python -m data_pipeline build --reuse-interim --reload phiusiil urlphish live
} -AllowPartial

Write-Host ""
Write-Host "Done. Data card: $(Join-Path (Get-Location) 'reports\data_card.md')" -ForegroundColor Green
Write-Host "Check the inspect output above against the phreshphish columns in configs\datasets.yaml."
