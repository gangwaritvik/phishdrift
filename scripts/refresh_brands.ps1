<#
.SYNOPSIS
  After a brand list change (configs/lists/brands.txt): rebuild the extension, and optionally the
  models that use brand names as features.

.DESCRIPTION
  Run from the repo folder after copying the update in:

      powershell -ExecutionPolicy Bypass -File scripts\refresh_brands.ps1            (extension only)
      powershell -ExecutionPolicy Bypass -File scripts\refresh_brands.ps1 -Model     (models too)

  Extension only (seconds): node extension\build.mjs (extension\dist; reload it in Chrome)

  -Model adds (long: the tier B step took about 3.5 hours last time; needs about 3 GB free disk):
    1. python -m features build [--split time_slice | heldout_source]   (tier A features)
    2. python -m features build --tier B [--split ...]   (tier B features; shards built with the
                                                           old lists are deleted first, once)
    3. python -m experiments.blend2 --splits 0 --save-models data\models
                                   --reports data\models\reports_split0
       (the shipped split's models; its tables go to data\models, not reports\)
    4. python -m models.export_page --models data\models --split 0
       (js\data\tier_a_hybrid.json, js\data\tier_b_page.json and their parity fixtures)
    5. node extension\build.mjs

  -Rescrape runs `python -m features lists brands` first. It fetches today's Wikidata, so the list
  can differ from the reviewed one in the repo; leave it off unless a new review is planned.

  Stopping: Ctrl+C is safe. Tier B keeps finished shards and resumes when the same command is run
  again; the other steps restart from the beginning. The 10-split numbers in reports\ were measured
  with the old list; the exported model is the only thing step 3-4 change.
#>

param([switch]$Model, [switch]$Rescrape, [int]$Workers = 0)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
$env:PYTHONUTF8 = "1"
. "$PSScriptRoot\common.ps1"

$py = Find-PhishDriftPython -RepoRoot (Get-Location).Path
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

if ($Model) {
    foreach ($part in @("pool", "time_slice", "heldout_source")) {
        if (-not (Test-Path "data\processed\$part.parquet")) {
            Write-Host "Missing data\processed\$part.parquet; -Model needs the built corpus." -ForegroundColor Red
            exit 1
        }
    }
    $free = Get-FreeDiskGB -Path (Get-Location).Path
    if ($null -ne $free -and $free -lt 3) {
        Write-Host "Only $free GB free (need about 3 GB for -Model). Free some space first." -ForegroundColor Red
        exit 1
    }
}

if ($Rescrape) {
    Invoke-Step "scrape brands (Wikidata + reviewed files)" { & $py -m features lists brands }
}

if ($Model) {
    Invoke-Step "tier A features: pool" { & $py -m features build }
    foreach ($part in @("time_slice", "heldout_source")) {
        Invoke-Step "tier A features: $part" { & $py -m features build --split $part }
    }
    foreach ($part in @("pool", "time_slice", "heldout_source")) {
        # Shards written with other word lists are stale; delete them once (a resumed run keeps them).
        $stale = & $py -c "import json,sys; from pathlib import Path; from features.lists import lists_digest, load_lists; p = Path('data/interim/features_b/$part/plan.json'); print('stale' if p.exists() and json.loads(p.read_text()).get('lists') != lists_digest(load_lists()) else 'ok')"
        if ("$stale".Trim() -eq "stale") {
            Write-Host "Deleting tier B shards built with the old lists: data\interim\features_b\$part"
            Remove-Item -Recurse -Force "data\interim\features_b\$part"
        }
        Invoke-Step "tier B features: $part" { & $py -m features build --tier B --split $part @workerArgs }
    }
    Invoke-Step "train the shipped split (0)" {
        & $py -m experiments.blend2 --splits 0 --save-models data\models --reports data\models\reports_split0
    }
    Invoke-Step "export the address and page models" { & $py -m models.export_page --models data\models --split 0 }
}

Invoke-Step "build the extension" { Push-Location extension; try { node build.mjs } finally { Pop-Location } }

Write-Host ""
Write-Host "Done. Reload the unpacked extension from extension\dist in chrome://extensions." -ForegroundColor Green
