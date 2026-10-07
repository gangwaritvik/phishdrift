# Progress log

Append an entry at the end of every task. Newest at the bottom. Keep entries short.

## Status

- Current step: 1 of 10, schema + loaders + dedup + depth check (code done on PR #1; needs a real
  data run on Ritvik's machine)
- Deadline: assumed 2026-10-23 (about 3 weeks from 2026-10-02; confirm)

## Open decisions

- Exact deadline date
- Prior study artifacts (crawler benign pools, natural legitimate harvest, platform list): available?
  If not, `configs/platforms.yaml` is built from published lists and the OOD set is crawled fresh.
- Phish360 download access (held-out source; Phish-Blitz is the fallback)
- Brand list for squatting features (which Indian banks / payment apps)
- Whether to attempt Tier 4 (brand matching) or keep it as future work

## Log

### 2026-10-08 — Project set up
- Added CLAUDE.md, docs/PROJECT_SPEC.md, docs/FEATURES_AND_DATA.md, this file.
- Next: milestone 1 (collector, dataset loaders, dedup, domain + time splits, data card).

### 2026-10-07 — Milestone 1 code: collector, loaders, dedup, splits, data card
- Changed: Python project (`pyproject.toml`, ruff, pytest, CI in `.github/workflows/ci.yml`),
  `configs/{collector,datasets,splits}.yaml`, shared `phishdrift/` (schema, eTLD+1, cached HTTP client),
  `collector/` (OpenPhish, PhishTank, URLhaus, Tranco benign + inner pages, first-seen index),
  `data_pipeline/` (PhreshPhish, PhiUSIIL, live-feed loaders; exact + SimHash near-dup dedup;
  domain-disjoint random and time splits; data card), 67 tests in `tests/`.
- Decisions: eTLD+1 honours PSL private suffixes (each `*.github.io` site is its own domain).
  Near-dup HTML is removed within a label only, so phishing clones of real pages are kept.
  URLs labelled both phishing and benign are dropped. Time split drops test rows whose domain is in
  train. PhiUSIIL has no per-row dates, so it gets only the random split. URLhaus rows are tagged
  `threat=malware` and excluded from the `live` dataset unless `include_threats` adds them.
  Each dataset is split separately (no mixing sources, which would let a model learn the dataset).
- Results: none on real data yet. Code was built in a sandbox without access to the feeds, Hugging
  Face or UCI; tested with fixtures and a synthetic end-to-end run.
- Next: run `python -m data_pipeline inspect phreshphish` and fix `phreshphish.columns` in
  `configs/datasets.yaml` if names differ; run `python -m data_pipeline build`; schedule the
  collector daily; commit `reports/data_card.md`; then milestone 2 (URL features + E1).
- Open questions: PhishTank key availability; whether PhreshPhish's own date column is the
  collection date we want for the time split; confirm deadline date.

### 2026-10-07 — Design change: pooled best-practical detector (docs only)
- Changed: CLAUDE.md, docs/PROJECT_SPEC.md, docs/FEATURES_AND_DATA.md rewritten for the new goal
  (pooled sources, own feature engine, platform masking, depth rule for PhiUSIIL legit, tiers A/B/C with
  stacking, runtime layers incl. optional LLM, corrected feeds, 10-split evaluation with negative
  controls). Added "Lessons from prior work" to PROJECT_SPEC.md citing report sections.
  Moved the prior report to docs/prior_work/representation_sensitivity_report.pdf.
- Superseded: the old E1/E2/E3 experiment plan and milestone list. Milestone 1 code (PR #1) is kept
  as a base but has known conflicts with the new rules (listed in the plan).
- Next: revised plan for approval, then milestone 1 (schema + loaders + dedup + depth check).
- Open questions: meaning of "dedupe by registrable domain across all sources"; access to the prior
  study's crawler pools, natural legitimate harvest and platform list; exact deadline.

### 2026-10-07 — Step 1: pooled corpus (schema, loaders, dedup, depth check) + collector fixes
- Plan v3 approved (`/mnt/project-files/phishdrift/plan_v3_revised.md`). PR #1 reworked; the old
  per-dataset random/time splits are gone.
- Changed: `phishdrift/domains.py` (U1 public-suffix-only domain by default, U2 private-aware kept as
  `domain_u2`; `url_key` for cross-source dedup; `url_depth`), `phishdrift/schema.py` (adds `depth`,
  `origin`), `data_pipeline/sources.py` (loaders for every source; only URL/label/date/HTML read),
  `data_pipeline/corpus.py` (pooled build), `data_pipeline/split.py` (10 domain-grouped
  train/cal/test splits, hard leakage checks), `data_pipeline/datacard.py`, `collector/` (URLhaus
  blocklist-only, Phishing.Database added, 12 h polling, robots.txt rules and Crawl-delay obeyed,
  seeds from Tranco/PhiUSIIL/URL-Phish, first-seen RDAP/DNS/TLS capture in `domain_capture.py`).
- Decisions (plan v3 defaults): each registrable domain stays in one source (earliest date, then
  source priority) with at most 20 URLs per domain; domains in more than one phishing source are
  removed everywhere; held-out source = Phish360; time slice = PhreshPhish's official test split +
  newest 20% of live rows; natural legit pages are evaluation-only; crawled inner pages belong to the
  source that seeded them (PhiUSIIL-, URL-Phish- or Tranco/live-seeded); depth buckets 0/1/2/3/4+,
  majority class downsampled to 80% where needed, build stops if any bucket is >90% one class;
  per-source class weights with no source above 35% of the training weight.
- Results: none on real data yet (the sandbox can't reach the dataset hosts). 116 tests pass with
  fixtures and a synthetic end-to-end build, including the depth check stopping a homepage-only
  benign corpus.
- Next: on Ritvik's machine: download the manual sources, `python -m data_pipeline inspect <source>`
  to confirm column names, schedule `python -m collector run` every 12 h, run
  `python -m data_pipeline build`, commit `reports/data_card.md`. Then step 2 (URL features with
  platform masking, feature registry, `docs/FEATURE_DICTIONARY.md`).
- Open questions: Phish360 and Phish-Blitz download access; PhreshPhish column names and whether its
  date is the collection date; prior study artifacts; exact deadline.
