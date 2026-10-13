<#
.SYNOPSIS
  One collector run with its output appended to data\logs\collector_YYYY-MM-DD.log.

.DESCRIPTION
  This is what the scheduled task "PhishDriftCollector" runs (see schedule_collector.ps1). You can
  also run it by hand:

      powershell -ExecutionPolicy Bypass -File scripts\run_collector_once.ps1

  Runs `python -m collector run` (feeds, benign crawl, first-seen domain capture). The collector
  is safe to stop at any time and refuses to start while another run is active, so a manual run
  and the task never overlap. API keys are read from the environment, or from %USERPROFILE%\.phishdrift.env
  or <repo>\.env (KEY=VALUE lines, never committed): URLHAUS_AUTH_KEY, PHISHTANK_APP_KEY.

  Exit code: 0 ok, 2 partial (a feed or the capture failed; see the log), anything else = failure.
#>

$ErrorActionPreference = "Continue"   # native stderr lines must not stop the script (PowerShell 5.1)
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
$env:PYTHONUTF8 = "1"
. (Join-Path $PSScriptRoot "common.ps1")

$logDir = Join-Path $repo "data\logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$log = Join-Path $logDir ("collector_{0}.log" -f (Get-Date -Format "yyyy-MM-dd"))

function Write-Log([string]$Text) { Add-Content -Path $log -Value $Text -Encoding UTF8 }

try {
    Import-EnvFile (Join-Path $env:USERPROFILE ".phishdrift.env")
    Import-EnvFile (Join-Path $repo ".env")
    $py = Find-PhishDriftPython -RepoRoot $repo
}
catch {
    Write-Log ("{0} ERROR {1}" -f (Get-Date -Format s), $_.Exception.Message)
    exit 1
}

$started = Get-Date
Write-Log ("==== {0} START python={1}" -f (Get-Date -Format s), $py)
& $py -u -m collector run 2>&1 | ForEach-Object { Write-Log ("$_") }
$code = $LASTEXITCODE
Write-Log ("==== {0} END exit={1} seconds={2}" -f (Get-Date -Format s), $code, [int]((Get-Date) - $started).TotalSeconds)
exit $code
