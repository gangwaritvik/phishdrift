<#
.SYNOPSIS
  Registers (or updates) the Windows scheduled task "PhishDriftCollector": the live-feed collector
  every 12 hours.

.DESCRIPTION
  From the repo folder, in a normal (non-elevated) PowerShell:

      powershell -ExecutionPolicy Bypass -File scripts\schedule_collector.ps1            # register / update
      powershell -ExecutionPolicy Bypass -File scripts\schedule_collector.ps1 -RunNow    # start once, show the log
      powershell -ExecutionPolicy Bypass -File scripts\schedule_collector.ps1 -Remove    # delete the task

  What the task does: runs scripts\run_collector_once.ps1 (= `python -m collector run`, python/venv
  found as in the other scripts) at 06:15 and 18:15 (-FirstRun, -EveryHours), also 2 minutes after
  you log on, and as soon as possible after a missed start (laptop asleep or off). Output is appended
  to data\logs\collector_YYYY-MM-DD.log. Limits: 3 hours per run (-TimeLimitHours), never two runs at
  once (a second start is ignored), runs on battery, only with a network connection.

  Logon mode: the task is first registered with logon type S4U ("run whether the user is logged on
  or not", no password stored). If Windows refuses that, it falls back to "only while logged on" and
  says so. With S4U the task cannot use network shares or saved credentials; the internet works.
  Environment variables set with setx are not always visible to S4U tasks: put API keys in
  %USERPROFILE%\.phishdrift.env or <repo>\.env (KEY=VALUE lines) instead.

  Re-running this script updates the existing task (idempotent). -WakeToRun lets the task wake the
  laptop from sleep.
#>

[CmdletBinding()]
param(
    [switch]$Remove,
    [switch]$RunNow,
    [string]$FirstRun = "06:15",
    [int]$EveryHours = 12,
    [int]$TimeLimitHours = 3,
    [switch]$InteractiveOnly,
    [switch]$WakeToRun
)

$ErrorActionPreference = "Stop"
$TaskName = "PhishDriftCollector"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
. (Join-Path $PSScriptRoot "common.ps1")

function Show-TaskStatus {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) { Write-Host "Task $TaskName is not registered." -ForegroundColor Yellow; return }
    $info = Get-ScheduledTaskInfo -TaskName $TaskName
    $logon = [string]$task.Principal.LogonType
    Write-Host ""
    Write-Host "Task:            $TaskName"
    Write-Host "State:           $($task.State)"
    if ($logon -eq "S4U") {
        Write-Host "Runs:            whether or not you are logged on (S4U, no password stored)"
    }
    else {
        Write-Host "Runs:            only while you are logged on (logon type $logon)" -ForegroundColor Yellow
    }
    $next = $info.NextRunTime
    if ($next -and $next.Year -gt 2000) { Write-Host "Next run:        $next" }
    else {
        $slot = (Get-Date).Date + [TimeSpan]::Parse($FirstRun)
        while ($slot -lt (Get-Date)) { $slot = $slot.AddHours($EveryHours) }
        Write-Host "Next run:        $slot (computed from -FirstRun and -EveryHours; Windows has not filled it in yet)"
    }
    if ($info.LastRunTime -and $info.LastRunTime.Year -gt 2000) {
        Write-Host "Last run:        $($info.LastRunTime)  (result $($info.LastTaskResult); 0 = ok, 2 = partial)"
    }
    else { Write-Host "Last run:        never" }
    Write-Host ("Log files:       " + (Join-Path $repo "data\logs\collector_YYYY-MM-DD.log"))
}

if ($Remove) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Removed task $TaskName." -ForegroundColor Green
    }
    else { Write-Host "Task $TaskName is not registered; nothing to remove." }
    exit 0
}

# --- python check (fails early with a clear message, not at 06:15) -------------------------
$py = Find-PhishDriftPython -RepoRoot $repo
if (-not (Test-PhishDriftPython -Python $py -RepoRoot $repo)) {
    Write-Host "Python found at $py cannot import the collector and its packages." -ForegroundColor Red
    Write-Host "Install them first:  $py -m pip install -e `".[dev,datasets]`"" -ForegroundColor Red
    exit 1
}
Write-Host "Python: $py"

# --- task definition ----------------------------------------------------------------------
$existed = [bool](Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
$wrapper = Join-Path $repo "scripts\run_collector_once.ps1"
$psExe = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
$argLine = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}"' -f $wrapper
$action = New-ScheduledTaskAction -Execute $psExe -Argument $argLine -WorkingDirectory $repo

$start = (Get-Date).Date + [TimeSpan]::Parse($FirstRun)
$every = New-TimeSpan -Hours $EveryHours
$repeat = New-ScheduledTaskTrigger -Once -At $start -RepetitionInterval $every -RepetitionDuration (New-TimeSpan -Days 3650)
$user = "$env:USERDOMAIN\$env:USERNAME"
$logon = New-ScheduledTaskTrigger -AtLogOn -User $user
$logon.Delay = "PT2M"

$settingsArgs = @{
    StartWhenAvailable         = $true                                  # run as soon as possible after a missed start
    MultipleInstances          = "IgnoreNew"                            # never two runs at once
    ExecutionTimeLimit         = (New-TimeSpan -Hours $TimeLimitHours)
    AllowStartIfOnBatteries    = $true
    DontStopIfGoingOnBatteries = $true
    RunOnlyIfNetworkAvailable  = $true
}
if ($WakeToRun) { $settingsArgs["WakeToRun"] = $true }
$settings = New-ScheduledTaskSettingsSet @settingsArgs
$description = "PhishDrift live-feed collector: python -m collector run every $EveryHours hours (repo: $repo). Log: data\logs."

function Register-Collector([string]$LogonType) {
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType $LogonType -RunLevel Limited
    $task = New-ScheduledTask -Action $action -Trigger @($repeat, $logon) -Settings $settings -Principal $principal -Description $description
    Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null
}

$mode = "S4U"
if ($InteractiveOnly) { $mode = "Interactive"; Register-Collector "Interactive" }
else {
    try { Register-Collector "S4U" }
    catch {
        Write-Host "Could not register with 'run whether logged on or not' (S4U): $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "Registering for 'run only while logged on' instead." -ForegroundColor Yellow
        $mode = "Interactive"
        Register-Collector "Interactive"
    }
}
if ($existed) { Write-Host "Updated task $TaskName (logon type $mode)." -ForegroundColor Green }
else { Write-Host "Registered task $TaskName (logon type $mode)." -ForegroundColor Green }

# --- run once now and follow the log ---------------------------------------------------------
if ($RunNow) {
    $log = Join-Path $repo ("data\logs\collector_{0}.log" -f (Get-Date -Format "yyyy-MM-dd"))
    $seen = 0
    if (Test-Path $log) { $seen = @(Get-Content $log).Count }
    Start-ScheduledTask -TaskName $TaskName
    Write-Host "Started. Showing $log (Ctrl+C stops the display only; the task keeps running)." -ForegroundColor Cyan
    $began = Get-Date
    $sawRunning = $false
    while ($true) {
        Start-Sleep -Seconds 2
        if (Test-Path $log) {
            $lines = @(Get-Content $log)
            if ($lines.Count -gt $seen) {
                $lines[$seen..($lines.Count - 1)] | ForEach-Object { Write-Host $_ }
                $seen = $lines.Count
            }
        }
        $state = (Get-ScheduledTask -TaskName $TaskName).State
        if ($state -eq "Running") { $sawRunning = $true }
        elseif ($sawRunning -or ((Get-Date) - $began).TotalSeconds -gt 30) { break }
    }
    if (Test-Path $log) {
        $lines = @(Get-Content $log)
        if ($lines.Count -gt $seen) { $lines[$seen..($lines.Count - 1)] | ForEach-Object { Write-Host $_ } }
    }
    if (-not $sawRunning) { Write-Host "The task did not start within 30 seconds; check Task Scheduler." -ForegroundColor Yellow }
}

Show-TaskStatus
