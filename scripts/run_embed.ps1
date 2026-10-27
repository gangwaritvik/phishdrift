<#
.SYNOPSIS
  One-split test of pretrained text embeddings for the tier A hybrid (Windows). Adds new files only.

.DESCRIPTION
  From the repository folder (the one with data\processed and .venv):

      powershell -ExecutionPolicy Bypass -File scripts\run_embed.ps1

  Steps (stops at the first failing one and names it):
    1. download the new and changed files (models\embed_scorer.py, models\char_cnn.py,
       experiments\embed_a.py, experiments\char_cnn_a.py, configs\embed.yaml)
    2. check the data, the free disk and that the files this test builds on are present
    3. install PyTorch (CPU) and sentence-transformers into .venv if missing
    4. smoke test on 2,000 rows with the real model (reports\embed_smoke); this also downloads the model
    5. the real run on split 0 (reports\embed_split0); embeddings are cached on disk, 3 hour limit
    6. copy reports\embed_split0\SUMMARY.md to the clipboard: paste it back into the chat

  Safe to stop with Ctrl+C at any time; running the same command again continues from the cached
  embeddings and skips finished stages. Do not run it at the same time as another heavy job.
#>

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
$env:PYTHONUTF8 = "1"
$branch = "claude/project-thread-w7x133"
$raw = "https://raw.githubusercontent.com/gangwaritvik/phishdrift/$branch"
$py = if (Test-Path ".venv\Scripts\python.exe") { ".venv\Scripts\python.exe" } else { "python" }

function Step([string]$Name) { Write-Host ""; Write-Host "==> $Name" -ForegroundColor Cyan }
function Fail([string]$Msg) { Write-Host $Msg -ForegroundColor Red; exit 1 }

Step "1. download the new and changed files"
foreach ($f in @("models/embed_scorer.py", "models/char_cnn.py", "experiments/embed_a.py",
                 "experiments/char_cnn_a.py", "configs/embed.yaml")) {
    $dest = $f -replace "/", "\"
    Invoke-WebRequest "$raw/$f" -OutFile $dest -UseBasicParsing
    if ((Get-Item $dest).Length -lt 200) { Fail "download of $f looks empty" }
    Write-Host "  $f ok ($((Get-Item $dest).Length) bytes)"
}

Step "2. checks"
foreach ($f in @("splits.parquet", "meta_pool.parquet", "meta_time_slice.parquet", "meta_heldout_source.parquet",
                 "features_a.parquet", "features_a_time_slice.parquet", "features_a_heldout_source.parquet")) {
    if (-not (Test-Path "data\processed\$f")) { Fail "missing data\processed\$f" }
}
$needs = @(
    @("models\text_scorers.py", "def piece_texts"), @("models\hybrid.py", "class HybridA"),
    @("experiments\hybrid_a.py", "VARIANTS"), @("experiments\tier_a.py", "def normalised_features"),
    @("configs\models.yaml", "hybrid2:")
)
foreach ($n in $needs) {
    if (-not (Test-Path $n[0]) -or -not (Select-String -Path $n[0] -Pattern $n[1] -SimpleMatch -Quiet)) {
        Fail "$($n[0]) is missing or older than this test expects (needs '$($n[1])'). Tell Claude; nothing was changed."
    }
}
$free = [math]::Round((Get-PSDrive C).Free / 1GB, 1)
$ram = [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB, 1)
Write-Host "  free disk $free GB, free RAM $ram GB"
if ($free -lt 3) { Fail "less than 3 GB free disk: free some space first" }
if ($ram -lt 6) { Write-Host "  low free RAM: close other programs for a safer run" -ForegroundColor Yellow }

Step "3. PyTorch (CPU) and sentence-transformers"
& $py -c "import torch" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  PyTorch not installed: installing the CPU build (about 200 MB)"
    & $py -m pip install torch --index-url https://download.pytorch.org/whl/cpu
    if ($LASTEXITCODE -ne 0) { Fail "PyTorch install failed (see the lines above)" }
}
& $py -c "import sentence_transformers" 2>$null
if ($LASTEXITCODE -ne 0) {
    & $py -m pip install sentence-transformers
    if ($LASTEXITCODE -ne 0) { Fail "sentence-transformers install failed (see the lines above)" }
}
& $py -c "import torch; print('  torch', torch.__version__, 'threads', torch.get_num_threads())"

Step "4. smoke test on 2,000 rows with the real model (downloads about 90 MB)"
$t = Get-Date
& $py -m experiments.embed_a --smoke 2000 --reports reports\embed_smoke --cache-dir reports\embed_smoke\cache --max-hours 0.5
if ($LASTEXITCODE -ne 0) { Fail "smoke test failed (see the lines above); the real run was not started" }
Write-Host ("  smoke test took {0:N0} s" -f ((Get-Date) - $t).TotalSeconds)

Step "5. real run on split 0 (embeddings cached on disk, stops after 3 hours)"
& $py -m experiments.embed_a --max-hours 3
$code = $LASTEXITCODE
if ($code -eq 3) {
    Write-Host "Time limit reached. Run the same command again to continue." -ForegroundColor Yellow
} elseif ($code -ne 0) {
    Fail "the run failed (see the lines above); cached embeddings are kept, run it again after a fix"
}

Step "6. result"
$summary = "reports\embed_split0\SUMMARY.md"
if (Test-Path $summary) {
    Get-Content $summary -Raw | Set-Clipboard
    Write-Host "  $summary copied to the clipboard: paste it into the chat." -ForegroundColor Green
}
