# Helpers shared by the Windows scripts. Dot-source it:  . "$PSScriptRoot\common.ps1"
# (ASCII only: Windows PowerShell 5.1 reads BOM-less files as ANSI.)

function Find-PhishDriftPython {
    # Same discovery as the other scripts: the repo's .venv first, then the py launcher
    # (3.11, then any 3), then python on PATH. Returns the full path of python.exe.
    param([Parameter(Mandatory = $true)][string]$RepoRoot)
    $venv = Join-Path $RepoRoot ".venv\Scripts\python.exe"
    if (Test-Path $venv) { return $venv }
    if (Get-Command py -ErrorAction SilentlyContinue) {
        foreach ($v in @("-3.11", "-3")) {
            $exe = & py $v -c "import sys; print(sys.executable)" 2>$null
            if ($LASTEXITCODE -eq 0 -and $exe) { return ("$exe").Trim() }
        }
    }
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    throw "No Python found. Create the venv first: scripts\run_milestone1.ps1 (or py -3.11 -m venv .venv)."
}

function Test-PhishDriftPython {
    # True when the collector and its dependencies import from the repo folder.
    param([Parameter(Mandatory = $true)][string]$Python, [Parameter(Mandatory = $true)][string]$RepoRoot)
    Push-Location $RepoRoot
    try {
        & $Python -c "import collector.__main__, pandas, requests, yaml, tranco" 2>$null
        return ($LASTEXITCODE -eq 0)
    }
    finally { Pop-Location }
}

function Import-EnvFile {
    # Reads KEY=VALUE lines (# comments allowed) into this process. Existing variables win.
    # Keeps API keys (URLHAUS_AUTH_KEY, PHISHTANK_APP_KEY) out of the task definition.
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path $Path)) { return }
    foreach ($line in Get-Content $Path) {
        $t = $line.Trim()
        if ($t -eq "" -or $t.StartsWith("#")) { continue }
        $i = $t.IndexOf("=")
        if ($i -lt 1) { continue }
        $k = $t.Substring(0, $i).Trim()
        $v = $t.Substring($i + 1).Trim().Trim('"').Trim("'")
        if (-not [Environment]::GetEnvironmentVariable($k)) {
            [Environment]::SetEnvironmentVariable($k, $v, "Process")
        }
    }
}

function Get-FreeDiskGB {
    # Free space in GB of the drive that holds $Path, or $null when it cannot be read (UNC path).
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        $drive = (Get-Item -LiteralPath $Path).PSDrive
        if ($null -ne $drive -and $null -ne $drive.Free) { return [math]::Round($drive.Free / 1GB, 1) }
    }
    catch { }
    return $null
}
