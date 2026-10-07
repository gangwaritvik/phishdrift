# PhishDrift

Do phishing detectors that score ~99% on standard benchmarks survive time and attackers, and
which fixes actually restore performance? See [docs/PROJECT_SPEC.md](docs/PROJECT_SPEC.md).

## Setup

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,datasets]"
pytest && ruff check .
```

## Data (milestone 1)

```bash
# Optional credentials (environment variables, never committed):
export URLHAUS_AUTH_KEY=...      # free abuse.ch key
export PHISHTANK_APP_KEY=...     # PhishTank is skipped without it
export HF_TOKEN=...              # if the PhreshPhish dataset is gated for you

python -m collector run                  # one daily collection (schedule it: scripts/cron_example.txt)
python -m data_pipeline inspect phreshphish   # check column names match configs/datasets.yaml
python -m data_pipeline build            # load -> dedup -> random + time splits -> data card
```

Outputs:

- `data/raw/feeds/YYYY-MM-DD/` raw feed snapshots; `data/interim/feeds_first_seen.parquet` first-seen index
- `data/processed/<dataset>/{random,time}/{train,test}.parquet` plus `manifest.json`
- `reports/data_card.md` and `reports/tables/data_card.csv`

Every split is by registered domain (eTLD+1): no domain is in both train and test.
`data/` is gitignored; datasets are never committed.
