<#
.SYNOPSIS
  Collect deep legitimate URLs of popular sites for training: a crawl with HTML and a Common Crawl list.

.DESCRIPTION
  From the repo folder:

      powershell -ExecutionPolicy Bypass -File scripts\run_popular_crawl.ps1

  Two seed sets, both started from Chrome's most visited sites (CrUX list, downloaded and cached):
    popular      the crawler visits each site, reads robots.txt and its sitemap, keeps 3-5 inner pages
                 with their HTML (robots.txt and Crawl-delay obeyed)
    commoncrawl  asks the Common Crawl index for URLs it already holds for each site (one request a
                 second, no page is fetched, no HTML)
  Sites already in the corpus, in the out-of-distribution evaluation set, in the feed index or tried
  before are skipped (the evaluation pages must never become training data). Needs data\processed\
  from a corpus build for that exclusion list.

  Safe to stop with Ctrl+C and rerun: results are saved every 25 sites and finished sites are skipped
  next time. Every request has a time limit and a site that hangs is abandoned. It uses its own lock,
  so the scheduled collector keeps running. Output is also appended to data\logs\popular_crawl_*.log.

  Options: -DomainsPerRun N (sites per seed set this run; try 20 first as a test), -Seeds NAMES,
  -MinFreeGB N (stop if the drive has less free space).

  Afterwards rebuild the pool with the new source:
      python -m data_pipeline build --reuse-interim --reload popular
#>

[CmdletBinding()]
param(
    [int]$DomainsPerRun = 0,
    [string[]]$Seeds = @("popular", "commoncrawl"),
    [int]$MinFreeGB = 5
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
$logDir = Join-Path $repo "data\logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$log = Join-Path $logDir ("popular_crawl_{0}.log" -f (Get-Date -Format "yyyy-MM-dd"))

$argList = @("-u", "-m", "collector", "crawl", "--seeds") + $Seeds
if ($DomainsPerRun -gt 0) { $argList += @("--domains-per-run", "$DomainsPerRun") }

Write-Host "==> $py $($argList -join ' ')" -ForegroundColor Cyan
& $py @argList 2>&1 | ForEach-Object {
    $line = "$_"
    Write-Host $line
    Add-Content -Path $log -Value $line -Encoding UTF8
}
$code = $LASTEXITCODE

Write-Host ""
if ($code -eq 130) { Write-Host "Interrupted: finished sites are saved. Run this script again to continue." -ForegroundColor Yellow }
elseif ($code -ne 0) { Write-Host "crawl failed (exit code $code). See $log" -ForegroundColor Red }

& $py -m collector popular-summary
exit $code
