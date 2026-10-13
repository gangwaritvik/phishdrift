<#
.SYNOPSIS
  Crawl legitimate inner pages for the out-of-distribution false-positive set (evaluation only).

.DESCRIPTION
  From the repo folder:

      powershell -ExecutionPolicy Bypass -File scripts\run_ood_crawl.ps1

  Needs data\processed\ from a corpus build (pool.parquet etc., or the meta_*.parquet copies): every
  domain in them is excluded from the sample. Picks 1500 Tranco domains (seeded, spread over rank
  bands, head skipped), fetches 3-5 inner pages each respecting robots.txt, and writes
  data\raw\ood\ood_urls.csv (url, domain, label, crawled_at, ok) - the small file to copy to the cloud.
  Nothing from data\raw\ood is ever read by the corpus build.

  Safe to stop with Ctrl+C and rerun: finished sites are kept and skipped next time. Output is also
  appended to data\logs\ood_crawl_YYYY-MM-DD.log.

  Options: -SampleSize N (first draw only), -Limit N (stop after N sites this run, e.g. 20 as a
  test), -Resample (draw a new sample), -MinFreeGB N (stop if the drive has less free space),
  -HtmlPass (second pass over the sites that worked, HTML stored, into data\raw\ood_html; needs the
  first pass output).
#>

[CmdletBinding()]
param(
    [int]$SampleSize = 0,
    [int]$Limit = 0,
    [switch]$Resample,
    [switch]$HtmlPass,
    [int]$MinFreeGB = 2
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
$oodDir = (& $py -c "from phishdrift.config import load_config, resolve; print(resolve(load_config('collector')['paths']['ood_dir']))").Trim()

$logDir = Join-Path $repo "data\logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$log = Join-Path $logDir ("ood_crawl_{0}.log" -f (Get-Date -Format "yyyy-MM-dd"))

$argList = @("-u", "-m", "collector", "crawl-ood")
if ($SampleSize -gt 0) { $argList += @("--sample-size", "$SampleSize") }
if ($Limit -gt 0) { $argList += @("--limit", "$Limit") }
if ($Resample) { $argList += "--resample" }
if ($HtmlPass) { $argList += "--html-pass"; $oodDir = Join-Path (Split-Path -Parent $oodDir) "ood_html" }

Write-Host "==> $py $($argList -join ' ')" -ForegroundColor Cyan
& $py @argList 2>&1 | ForEach-Object {
    $line = "$_"
    Write-Host $line
    Add-Content -Path $log -Value $line -Encoding UTF8
}
$code = $LASTEXITCODE

$csv = Join-Path $oodDir "ood_urls.csv"
Write-Host ""
if ($code -eq 130) { Write-Host "Interrupted: finished sites are saved. Run this script again to continue." -ForegroundColor Yellow }
elseif ($code -ne 0) { Write-Host "crawl-ood failed (exit code $code). See $log" -ForegroundColor Red }
if (Test-Path $csv) {
    $item = Get-Item $csv
    $rows = @(Import-Csv $csv)
    $okRows = @($rows | Where-Object { $_.ok -eq "True" })
    $sites = @($okRows | Select-Object -ExpandProperty domain -Unique)
    Write-Host ("Output: {0}  ({1:N1} KB, {2} rows, {3} usable pages (ok) from {4} sites)" -f $csv, ($item.Length / 1KB), $rows.Count, $okRows.Count, $sites.Count) -ForegroundColor Green
    Write-Host "Copy this file to the cloud session. Use only rows with ok == True."
}
else { Write-Host "No output file yet: $csv" -ForegroundColor Yellow }
if (Test-Path $oodDir) {
    $bytes = (Get-ChildItem $oodDir -Recurse -File | Measure-Object -Property Length -Sum).Sum
    Write-Host ("Folder {0}: {1:N1} MB in total" -f $oodDir, ($bytes / 1MB))
}
exit $code
