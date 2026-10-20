<#
.SYNOPSIS
  Render a sample of the natural legitimate pages with the installed Chrome or Edge (headless), then
  compare the page model's false alarms on raw HTML vs the rendered DOM.

.DESCRIPTION
  From the repo folder:

      powershell -ExecutionPolicy Bypass -File scripts\render_ood.ps1

  Needs data\raw\ood_html\pages\*.parquet from scripts\run_ood_crawl.ps1 -HtmlPass (pages with
  stored raw HTML). Draws 300 of them (fixed seed, at most 2 per site; configs\render.yaml) and loads
  each one afresh in the locally installed Chrome (or Edge) with
      --headless=new --dump-dom --virtual-time-budget=8000 --user-data-dir=<new empty temp folder>
  so your own browser profile, extensions and sign-ins are never used. Each page has a hard 45 s
  limit; after it the browser is killed. 4 pages render in parallel. Only legitimate pages are
  rendered (the OOD set has no phishing URL). No Playwright needed; nothing is installed.

  Output: data\raw\ood_render\ (sample.csv, raw\, rendered\, status\, render_index.csv). Then, if
  node is on PATH, runs  python -m experiments.render_gap  ->  reports\render_gap.md and
  reports\tables\render_gap.csv.

  Safe to stop with Ctrl+C and rerun: finished pages are skipped and running browsers are killed.
  Output is also appended to data\logs\render_ood_YYYY-MM-DD.log.

  Options: -Size N (first draw only), -Workers N, -Limit N (stop after N pages this run, e.g. 10 as
  a test), -RetryFailed (try timed-out / failed pages again), -Browser PATH (chrome.exe or
  msedge.exe if it is not found), -Resample (draw a new sample), -NoReport (render only),
  -MinFreeGB N (stop if the drive has less free space).
#>

[CmdletBinding()]
param(
    [int]$Size = 0,
    [int]$Workers = 0,
    [int]$Limit = 0,
    [switch]$RetryFailed,
    [string]$Browser = "",
    [switch]$Resample,
    [switch]$NoReport,
    [int]$MinFreeGB = 1
)

$ErrorActionPreference = "Continue"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
$env:PYTHONUTF8 = "1"
. (Join-Path $PSScriptRoot "common.ps1")

$free = Get-FreeDiskGB -Path $repo
if ($null -ne $free) {
    Write-Host "Free disk space: $free GB"
    if ($free -lt $MinFreeGB) {
        Write-Host "Less than $MinFreeGB GB free: not starting. Free some space or lower -MinFreeGB." -ForegroundColor Red
        exit 1
    }
}
else { Write-Host "Free disk space could not be read; continuing." -ForegroundColor Yellow }

$py = Find-PhishDriftPython -RepoRoot $repo
if (-not (Test-PhishDriftPython -Python $py -RepoRoot $repo)) {
    Write-Host "The collector does not import with $py. Install first: $py -m pip install -e .[dev]" -ForegroundColor Red
    exit 1
}
$outDir = (& $py -c "from phishdrift.config import load_config, resolve; print(resolve(load_config('render')['paths']['out_dir']))").Trim()

$logDir = Join-Path $repo "data\logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$log = Join-Path $logDir ("render_ood_{0}.log" -f (Get-Date -Format "yyyy-MM-dd"))

function Invoke-Logged {
    param([string[]]$ArgList)
    Write-Host "==> $py $($ArgList -join ' ')" -ForegroundColor Cyan
    & $py @ArgList 2>&1 | ForEach-Object {
        $line = "$_"
        Write-Host $line
        Add-Content -Path $log -Value $line -Encoding UTF8
    }
    return $LASTEXITCODE
}

$argList = @("-u", "-m", "collector", "render-ood")
if ($Size -gt 0) { $argList += @("--size", "$Size") }
if ($Workers -gt 0) { $argList += @("--workers", "$Workers") }
if ($Limit -gt 0) { $argList += @("--limit", "$Limit") }
if ($RetryFailed) { $argList += "--retry-failed" }
if ($Browser) { $argList += @("--browser", $Browser) }
if ($Resample) { $argList += "--resample" }
$code = Invoke-Logged -ArgList $argList

$index = Join-Path $outDir "render_index.csv"
Write-Host ""
if ($code -eq 130) { Write-Host "Interrupted: finished pages are saved. Run this script again to continue." -ForegroundColor Yellow }
elseif ($code -ne 0) { Write-Host "render-ood failed (exit code $code). See $log" -ForegroundColor Red }
if (Test-Path $index) {
    $rows = @(Import-Csv $index)
    $groups = $rows | Group-Object status | ForEach-Object { "{0} {1}" -f $_.Name, $_.Count }
    Write-Host ("Index: {0}  ({1} pages: {2})" -f $index, $rows.Count, ($groups -join ", ")) -ForegroundColor Green
}
else { Write-Host "No index yet: $index" -ForegroundColor Yellow }
if (Test-Path $outDir) {
    $bytes = (Get-ChildItem $outDir -Recurse -File | Measure-Object -Property Length -Sum).Sum
    Write-Host ("Folder {0}: {1:N1} MB in total" -f $outDir, ($bytes / 1MB))
}
if ($code -ne 0) { exit $code }

if ($NoReport) { exit 0 }
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host "node is not on PATH: install Node.js, then run" -ForegroundColor Yellow
    Write-Host "    $py -m experiments.render_gap --index `"$index`""
    exit 0
}
$code = Invoke-Logged -ArgList @("-u", "-m", "experiments.render_gap", "--index", $index)
if ($code -eq 0) {
    Write-Host "Report: reports\render_gap.md (copy it and reports\tables\render_gap*.csv to the cloud session)" -ForegroundColor Green
}
else { Write-Host "render_gap failed (exit code $code). See $log" -ForegroundColor Red }
exit $code
