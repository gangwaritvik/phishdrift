# tier-c-data

Raw tier C captures written by `.github/workflows/tier-c-capture.yml` (orphan branch, never merged into `main`).

- `data/interim/domain_info/YYYY-MM-DD.jsonl`: first-seen RDAP / DNS / TLS facts, one record per registrable domain.
- `data/interim/feeds_first_seen.parquet`: first-seen index of the live phishing feeds.
- `data/raw/ood*/ood_sample.txt`: natural legitimate sites kept out of the benign capture.
