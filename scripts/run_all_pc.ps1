<#
.SYNOPSIS
  One command for the PC jobs of milestone 3: registers the 12-hourly collector task, starts the
  out-of-distribution legitimate-page crawl in its own window, and builds the tier B (HTML) features.

.DESCRIPTION
  From the repo folder (or double-click RUN_PC_JOBS.bat):

      powershell -ExecutionPolicy Bypass -File scripts\run_all_pc.ps1

  1. Free-disk check (stops below -MinFreeGB, default 6).
  2. scripts\schedule_collector.ps1 (registers PhishDriftCollector), then starts one run of it.
  3. scripts\run_ood_crawl.ps1 in a second window (network bound, saves every 25 sites).
  4. scripts\run_milestone3.ps1 in this window (CPU and disk bound, saves every shard).

  Everything is safe to stop with Ctrl+C and to rerun: finished shards and sites are kept.
  -Workers sets the tier B worker processes (default 2, so the laptop stays usable next to the crawl).
  -SkipOod / -SkipTierB / -SkipCollector run only part of it.
#>

[CmdletBinding()]
param(
    [int]$Workers = 2,
    [int]$MinFreeGB = 6,
    [switch]$SkipOod,
    [switch]$SkipTierB,
    [switch]$SkipCollector
)

$ErrorActionPreference = "Continue"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
$env:PYTHONUTF8 = "1"
. (Join-Path $PSScriptRoot "common.ps1")

$free = Get-FreeDiskGB -Path $repo
if ($null -ne $free) {
    Write-Host "Free disk space: $free GB (need about $MinFreeGB GB)"
    if ($free -lt $MinFreeGB) {
        Write-Host "Not enough free space. Free some space (the old data\raw downloads you no longer need) and run this again." -ForegroundColor Red
        exit 1
    }
}

if (-not $SkipCollector) {
    Write-Host ""
    Write-Host "==> 1/3 collector schedule" -ForegroundColor Cyan
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "schedule_collector.ps1")
    if ($LASTEXITCODE -eq 0) {
        try {
            Start-ScheduledTask -TaskName "PhishDriftCollector"
            Write-Host "Started one collector run in the background (log: data\logs\collector_*.log)."
        }
        catch { Write-Host "Could not start the task now: $($_.Exception.Message)" -ForegroundColor Yellow }
    }
    else { Write-Host "Collector schedule failed; the other jobs continue." -ForegroundColor Yellow }
}

if (-not $SkipOod) {
    Write-Host ""
    Write-Host "==> 2/3 natural-page crawl (opens a second window)" -ForegroundColor Cyan
    $oodArgs = '-NoProfile -ExecutionPolicy Bypass -NoExit -File "{0}"' -f (Join-Path $PSScriptRoot "run_ood_crawl.ps1")
    Start-Process -FilePath "powershell.exe" -ArgumentList $oodArgs -WorkingDirectory $repo
}

if (-not $SkipTierB) {
    Write-Host ""
    Write-Host "==> 3/3 tier B features" -ForegroundColor Cyan
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "run_milestone3.ps1") -Workers $Workers
    $code = $LASTEXITCODE
    if ($code -ne 0) { Write-Host "Tier B stopped (exit code $code). Run this again to resume." -ForegroundColor Yellow }
}

Write-Host ""
Write-Host "Main window finished. The crawl window may still be running; it can stay open." -ForegroundColor Green
