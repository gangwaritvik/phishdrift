# Look-alike training examples (E2): how to run the full-pool test

Nothing here changes the shipped model, thresholds, extension or any dataset. The augmentation is off by
default; every output goes to new folders. Results of the cloud run: `reports/lookalike_e2/SUMMARY.md`,
`reports/lookalike_e2/cost.md`.

## What the code does

- `models/lookalike_aug.py` `with_lookalikes(train, k, ...)` adds to the TRAINING rows of split k only:
  look-alike domains of brands (label phishing, four styles: digit swap, deleted letter, inserted letter,
  brand + lure word) and the official domains of the same brands (label legitimate), 2% of the training
  rows of each. Brands are split into 5 folds by hash; split k holds out fold `k % 5`. Those brands, and
  every variant of them, never reach training (`LeakageError` otherwise). A brand's variants share one group
  for the out-of-fold text scores. Test look-alikes use the held-out brands in nine styles, five of which
  (transpose, leet, `rn`/`vv`, Unicode, other suffix) are never trained on.
- `experiments/hybrid_a.py --variant hybrid2_la`: the same hybrid2 model trained with those rows (the
  real training path; `hybrid2` is the unchanged baseline).
- `models/export_hybrid.py --lookalike`: exports the E2 bundle; it refuses to write the shipped files.
- `experiments/lookalike_a.py --models E0 E2`: trains E0 and E2 on identical splits, thresholds from the
  same natural calibration slice, scores every extra URL once (look-alikes, real feed URLs, legitimate
  near-neighbours), keeps per-split tables and merges them into `SUMMARY.md`. On the cloud sample it
  gives the same numbers as `hybrid_a` for E0 and E2 (checked on split 0: test recall at 1% 71.22 / 71.37,
  held-out 75.32 / 73.42 in both).

## Prerequisites (PC)

- The PC folder is not a git clone: download the changed files, as before. In PowerShell:

```powershell
cd C:\Users\test\Downloads\PBL\phishdrift
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
$env:PYTHONUTF8 = 1
.\.venv\Scripts\Activate.ps1
$b = "https://raw.githubusercontent.com/gangwaritvik/phishdrift/claude/project-thread-tmbpkv"
$files = "attacks/lookalike.py", "features/brand_mismatch.py", "models/lookalike_aug.py",
  "models/export_hybrid.py", "configs/lookalike_exp.yaml", "experiments/lookalike_a.py",
  "experiments/lookalike_cost.py", "experiments/hybrid_a.py", "experiments/latency.py",
  "js/bench/latency.mjs", "configs/eval/ood_urls.csv"
foreach ($f in $files) {
  New-Item -ItemType Directory -Force (Split-Path $f) | Out-Null
  Invoke-WebRequest "$b/$f" -OutFile $f
}
if (-not (Test-Path configs\lists\confusables.json)) {
  Invoke-WebRequest "$b/configs/lists/confusables.json" -OutFile configs\lists\confusables.json
}
Select-String -Path models\lookalike_aug.py -Pattern "def with_lookalikes"   # must print one line
```

- `data\processed` must hold the built pool (`meta_pool`, `features_a`, `splits`, and the time slice and
  held-out source parts), as for `refresh_brands.ps1 -Model`. `configs\lists\brand_domains.json` is the
  PC's Wikidata map; do not overwrite it. About 2 GB free disk and 5 GB free RAM per process (estimates).
- The real-feed comparison needs the Phishing.Database ACTIVE list (65 MB):

```powershell
curl.exe -L -o data\interim\active.txt https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt
python -m experiments.lookalike_a --make-feed-json data\interim\active.txt data\interim\feedsets.json
```

## Run

Step 1, smoke test (a few minutes; checks every code path on 3,000 rows, results are not meaningful):

```powershell
python -m experiments.lookalike_a --processed data\processed --reports data\reports_e2\smoke --split 0 --smoke 3000 --models E0 E2 --feed-json data\interim\feedsets.json --natural-csv configs\eval\ood_urls.csv
```

Step 2, split 0 on the full pool, with both models saved (to `data\models_e2`, not a shipped path):

```powershell
$env:PHISHDRIFT_THREADS = 1   # or leave unset to let LightGBM use all cores (then run one process at a time)
python -m experiments.lookalike_a --processed data\processed --reports data\reports_e2\lookalike --split 0 --models E0 E2 --feed-json data\interim\feedsets.json --natural-csv configs\eval\ood_urls.csv --save-models data\models_e2
```

Step 3, splits 1 to 9 (same command, one after another; two PowerShell windows can each take half if RAM
allows; do not run heavy jobs beside them):

```powershell
foreach ($k in 1..9) {
  python -m experiments.lookalike_a --processed data\processed --reports data\reports_e2\lookalike --split $k --models E0 E2 --feed-json data\interim\feedsets.json --natural-csv configs\eval\ood_urls.csv
}
```

Step 4, merge the report and measure size, latency and parity of both bundles (split 0):

```powershell
python -m experiments.lookalike_a --reports data\reports_e2\lookalike --render --data-note "the PC pool, 10 domain-grouped splits"
python -m models.export_hybrid --split 0 --out data\models_e2\e0_bundle.json --parity-out data\models_e2\e0_parity.json --reports data\reports_e2\export_e0
python -m models.export_hybrid --split 0 --lookalike --out data\models_e2\e2_bundle.json --parity-out data\models_e2\e2_parity.json --reports data\reports_e2\export_e2
python -m experiments.lookalike_cost --e0 data\models_e2\e0_bundle.json data\models_e2\e0_parity.json --e2 data\models_e2\e2_bundle.json data\models_e2\e2_parity.json --out data\reports_e2\lookalike
```

Optional cross-check of the real training path on split 0 (about as long as one split of Step 2 each;
skip it if time is short, the cloud run already showed identical numbers):

```powershell
python -m experiments.hybrid_a --processed data\processed --reports data\reports_e2\hybrid2 --splits 0 --variant hybrid2
python -m experiments.hybrid_a --processed data\processed --reports data\reports_e2\hybrid2_la --splits 0 --variant hybrid2_la
```

## Outputs

- `data\reports_e2\lookalike\SUMMARY.md`: all tables (main metrics incl. `time_slice` and `natural`,
  paired change against E0 per split, look-alikes of unseen brands and styles, `paypa1.com` cases,
  official-domain and near-neighbour false alarms, feed URLs, shuffled-label control, leakage tripwire),
  `near_flagged_by_E2_not_E0.csv`, `cost.md`.
- `data\reports_e2\lookalike\split_K\tables\`: one set of files per split (`main_E0.csv`, `main_E2.csv`,
  `thr_*.csv`, `scores_*.parquet`, `ev_meta.parquet`, `control.csv`, `sizes.csv`, `DONE`).
- `data\models_e2\split_0\E0.pkl`, `E2.pkl`, the two bundles. Nothing under `js\data`, `extension\` or
  `tests\fixtures` is written.

## Time and memory

Measured on the cloud sample (a fifth of the pool, 4 cores, one thread per process): one split takes
about 13 minutes (E0 about 7, E2 about 6), a process held about 0.8 GB at the points I looked. The PC
pool is about 5.6 times larger, so my guess is 1 to 1.5 hours per split with one thread and 3 to 5 GB of
memory; 10 splits one after another would take roughly 10 to 15 hours, about half that with two
processes. These PC figures are scaled guesses, not measurements. Run Step 2 first and read its log
(`E0 evaluated (...)`, `E2 evaluated (...)` lines) before starting the rest.

## Resume and recovery

- Rerun the same command. A split with a `DONE` file is skipped; a split without it resumes: a model whose
  `main_<model>.csv` exists is not retrained, an unfinished fit starts over (there is no checkpoint inside
  a fit).
- Ctrl+C or a crash is safe for the data (nothing outside the reports and models folders is written).
  If the run died while writing, delete that split's folder (`data\reports_e2\lookalike\split_K`) and
  rerun that split only; other splits are unaffected.
- A `LeakageError` means a generated name equals a real site in the split or a held-out brand reached
  training; stop and send me the message, do not work around it.

## How to read the result before deploying

Decide against the paired lines in `SUMMARY.md` (per split, so spread is visible), not one number:

1. Ordinary detection: recall at 1% and 0.1% FPR on `test`, `heldout_source` and `time_slice` against E0
   (the proposed bar is 2 points; a smaller change is inside the spread).
2. False alarms: `natural` pages at the cal-side thresholds; official domains; legitimate near-neighbours.
3. Look-alikes: `paypa1.com` (own suffix) per style, seen and unseen; unlisted names (no gain expected).
4. Cost: `cost.md` (size, latency, parity must stay exact).
