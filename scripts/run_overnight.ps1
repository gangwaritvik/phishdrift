<#
.SYNOPSIS
  Long data run that survives a closed terminal and resumes after a crash.

.DESCRIPTION
  Start it detached (closing the window then does not stop it):

      Start-Process powershell -WindowStyle Hidden -ArgumentList '-ExecutionPolicy','Bypass','-File','scripts\run_overnight.ps1'

  Steps, each logged to its own file in the repo folder (build1.log, seeds.log, crawl.log, build2.log):
    1. python -m data_pipeline build          (PhreshPhish is loaded one shard per dataset file;
                                               running this script again resumes where it stopped)
    2. python -m data_pipeline seeds
    3. python -m collector crawl --seeds phiusiil
    4. python -m data_pipeline build --reuse-interim --reload phiusiil urlphish live

  Progress: Get-Content build1.log -Tail 5 -Wait     Finished: a line "ALL STEPS DONE" in run.log
  Optional: set $env:HF_TOKEN (free Hugging Face read token) before starting for faster downloads.
#>

$ErrorActionPreference = "Continue"
Set-Location (Split-Path -Parent $PSScriptRoot)
$env:PYTHONUTF8 = "1"
$py = ".\.venv\Scripts\python.exe"
powercfg /change standby-timeout-ac 0
powercfg /change hibernate-timeout-ac 0

function Step($name, $log, $argList) {
    "$(Get-Date -Format s) START $name" | Out-File run.log -Append -Encoding utf8
    & $py -u @argList 2>&1 | ForEach-Object { "$_" } | Out-File $log -Append -Encoding utf8
    "$(Get-Date -Format s) END   $name (exit $LASTEXITCODE)" | Out-File run.log -Append -Encoding utf8
}

Step "build" "build1.log" @("-m", "data_pipeline", "build")
Step "seeds" "seeds.log" @("-m", "data_pipeline", "seeds")
Step "crawl" "crawl.log" @("-m", "collector", "crawl", "--seeds", "phiusiil")
Step "build2" "build2.log" @("-m", "data_pipeline", "build", "--reuse-interim", "--reload", "phiusiil", "urlphish", "live")
"$(Get-Date -Format s) ALL STEPS DONE" | Out-File run.log -Append -Encoding utf8
