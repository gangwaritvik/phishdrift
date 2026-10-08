# PhishDrift

The best practical phishing detector we can build: maximum detection at low false-positive
rates, trained on many pooled datasets with our own feature extraction. See
[docs/PROJECT_SPEC.md](docs/PROJECT_SPEC.md).

## Setup

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,datasets]"
pytest && ruff check .
```

## Data (milestone 1)

On Windows, `powershell -ExecutionPolicy Bypass -File scripts\run_milestone1.ps1` runs every step below from a fresh clone.

### 1. Get the sources

PhreshPhish (Hugging Face) and PhiUSIIL (UCI) download automatically. Put the others here
(only the URL, label, date and HTML are ever read; every precomputed feature column is ignored):

| Source | Put it in | Where to get it |
| --- | --- | --- |
| Phish360 | `data/raw/phish360/*.parquet` | from the dataset's authors (no public download link) |
| Phish-Blitz | `data/raw/phishblitz/{phishing,legitimate}_resources/` | link in the `Duddu-Hriday/Phish-Blitz` GitHub README |
| Phishpedia 30k | `data/raw/phishpedia/<site>/{info.txt,html.txt}` | Google Drive link in the Phishpedia GitHub README |
| URL-Phish | `data/raw/urlphish/*.csv` | Mendeley Data |
| PhishStorm | `data/raw/phishstorm/urlset.csv` | Aalto University PhishStorm page |

Check that each source's column names match `configs/datasets.yaml`:

```bash
python -m data_pipeline inspect phish360
```

### 2. Collect live data (every 12 hours)

```bash
# Optional credentials (environment variables, never committed):
export URLHAUS_AUTH_KEY=...      # free abuse.ch key (URLhaus is a blocklist only, never training data)
export PHISHTANK_APP_KEY=...     # PhishTank is skipped without it
export HF_TOKEN=...              # if the PhreshPhish dataset is gated for you

python -m collector run          # schedule it: scripts/cron_example.txt
```

One run fetches OpenPhish, Phishing.Database and PhishTank into the first-seen index, stores
URLhaus separately as a blocklist, crawls 3-5 robots.txt-allowed inner pages from a sample of
benign seed domains (Tranco, PhiUSIIL legitimate, URL-Phish benign), and records RDAP, DNS and
TLS facts for each new live host at first-seen time (tier C).

### 3. Build the pooled corpus

```bash
python -m data_pipeline build                 # load all sources, dedup, holdouts, 10 splits, data card
python -m data_pipeline seeds                 # (also run by build) crawl seeds from PhiUSIIL / URL-Phish
python -m collector crawl --seeds phiusiil urlphish   # inner pages for those seeds
python -m data_pipeline build --reuse-interim --reload phiusiil urlphish live   # add crawled pages
```

The build stops (exit code 3) if any URL-depth bucket of the training pool is more than 90%
one class, after writing `reports/data_card.md` so you can see which bucket. The fix is more
benign inner pages (crawl), not relaxing the check.

Outputs in `data/processed/`:

- `pool.parquet` training pool (with per-source class weights); `splits.parquet` assigns it to
  train / cal / test for 10 domain-grouped splits
- `heldout_source.parquet` (Phish360), `time_slice.parquet` (PhreshPhish's later test split plus
  the newest live data), `eval_only.parquet` (natural legitimate pages): never trained on
- `manifest.json`; the data card in `reports/data_card.md` and tables in `reports/tables/`

Every split is by registrable domain (public suffix only): no domain is on two sides of any
split or holdout. `data/` is gitignored; datasets are never committed.
