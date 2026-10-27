# Progress log

Append an entry at the end of every task. Newest at the bottom. Keep entries short.

## Status

- Done: milestones 1-5 (data, tier A and tier B features, training, stack, calibration), 8 (JS port +
  parity), the blend (tier B when a page has usable HTML, else tier A) and the false-alarm check on natural
  pages; milestone 9 skeleton (backend + extension), first real-site test on 2026-10-13; tier C capture and
  features (milestone 7) with a preliminary, granularity-limited experiment. Report draft written.
- Running on the PC: collector every 12 h (06:15 and 18:15 IST) capturing both classes for tier C.
- Next: tier C on the fresh captures, real-site extension check, robustness section, report.
- Deadline: Monday 2026-10-19 (Ritvik, 2026-10-12). Tier C is kept (cut the LLM layer first).

## Open decisions

- Phish360 has no public download, so the held-out source is PhishStorm (URL only); tier B has no held-out
  source.
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

### 2026-10-08 — Windows run script for milestone 1
- Changed: `scripts/run_milestone1.ps1` (venv + install, pytest, collector run, inspect phreshphish,
  build, crawl PhiUSIIL/URL-Phish seeds, rebuild; stops at the first failing step; reports missing
  manual downloads and unset optional keys first); one-line pointer in README.
- Next: Ritvik runs it on their PC and shares `reports/data_card.md` and the inspect output.

### 2026-10-11 — Real PhreshPhish run, manual downloads, Phish-Blitz loader
- Changed: PhreshPhish load is now resumable zstd shards (`data/interim/phreshphish.parquet/`) and uses
  hand-downloaded files from `data/raw/phreshphish/` when present (`local_dir`), so a stalled Hugging Face
  transfer can be replaced by `curl -C -`. `scripts/finish_download.ps1` moves/fetches the 33 missing files
  and starts the detached build. New `openphish_blitz` loader for the Phish-Blitz PhishingSamples release
  (URL list line `i` ↔ `fully_downloaded/<i>_<domain>/`; HTML only from fully downloaded pages; date from the
  list file name); test `test_openphish_blitz_loader`.
- Results: PhreshPhish 66 of 77 files loaded, 565,959 rows at last check (published size 372k; to explain in
  the data card). URL-Phish (116,600 rows, 16,600 phishing) and PhishStorm (96,005 rows) are in `data/raw/`
  with the columns the config expects. No data card yet; the run is still going.
- Next: wait for the overnight chain, read `reports/data_card.md`, flag anything >99%, then add Phish-Blitz
  (and Phishpedia/Phish360 when disk allows) with `build --reuse-interim --reload NAME`.
- Open questions: why PhreshPhish has more rows than published; Phish360 access; disk space for Phishpedia (18 GB).

### 2026-10-11 — Milestone 1 closed: real data run
- Changed: memory-safe copy of kept rows (per-file `iter_batches`, 500 rows), rows with a missing label
  dropped, UTF-8 seed files, Phish-Blitz and PhishStorm fixes.
- Results (`reports/data_card.md`): pool 465,975 URLs / 382,115 domains, 140,535 phishing (30.2%);
  time slice 80,637 URLs; 1,105 shared phishing domains removed; depth check passed (worst bucket 72.8%
  one class). Nothing above 99% was reported, but there is no held-out source yet.
- Open questions: Phish360 missing (no held-out source); Phish-Blitz only 248 URLs; PhiUSIIL dates are the
  load date (2026-10-11), so the time slice must not rely on them; PhreshPhish 666k rows vs 372k published
  (162k removed as near-duplicate HTML); Phishpedia (18 GB) when disk allows.

### 2026-10-11 — Step 2: tier A URL features (code)
- Changed: `features/` (registry with 99 features in 9 groups, platform masking, lists, fit, extract,
  scrape, dictionary, CLI), `configs/features.yaml`, `configs/platforms.yaml` (1,916 entries from the PSL
  private section), `configs/lists/*.txt` (offline seeds), `docs/FEATURE_DICTIONARY.md` (generated),
  `experiments/feature_source_check.py`, tests per group (full suite passes).
- Decisions: bigram likelihood and TLD risk are fitted on train folds only (`configs/lists/fitted.json`,
  NaN until fitted); brand matching uses edit distance <= 2 for brands of 4+ letters.
- Next on the PC: `python -m features lists` (scrape brands/keywords/shorteners), `python -m features fit`,
  `python -m features build`, then `python -m experiments.feature_source_check`; review flagged features.
  Then step 3 (HTML features) and the JS parity port.
- Open questions: review of the scraped brand list; which flagged features to drop.

### 2026-10-11 — Milestone 1+2 merged (PR #4); milestone 2 run script
- Changed: PR #4 merged into main (CI fix: `huggingface_hub` in dev extras). Added `scripts/run_milestone2.ps1`
  (lists, fit, build, source-leakage check in one command).
- Next: Ritvik runs it on the PC and shares `reports/tables/feature_source_check.csv`; then review flagged
  features, add Phishpedia and a held-out source, then milestone 3 (HTML features).

### 2026-10-11 — Wikidata fix, within-class source check, Phishpedia, accent fix
- Changed: Wikidata brand scrape now runs seven light per-type queries (PRs #6, #7; brands 67 -> 794).
  `experiments/feature_source_check.py` also reports source eta2 within each class (`eta2_source_within`).
  Phishpedia loader reads the dict-style `info.txt` (PR #8). `_clean_brand` strips accents (Hermès -> hermes).
- Results (`reports/data_card.md`): pool 474,987 URLs / 387,855 domains, 149,675 phishing (31.5%);
  Phishpedia adds 9,580 phishing URLs (2019-2020); depth check passed (worst bucket 72.8%); nothing >99%.
  Feature source check: 17 of 99 features flagged (path/length features separate sources more than classes).
- Next: benign inner-page crawl at scale (PhiUSIIL + URL-Phish seeds), rebuild with `--reload phiusiil urlphish live`,
  rebuild features and re-run the source check; milestone 3 plan.
- Open questions: Phish360 (held-out source); PhiUSIIL dates are the load date; drop vs keep the flagged features
  (decide at training with a with/without comparison); deadline date; lists still need Ritvik's one-time review.

### 2026-10-11 — Parallel benign crawl with checkpoints
- Changed: `collector/benign.py` crawls sites in parallel (`crawler.workers: 16`) and saves results every
  `crawler.checkpoint_every: 100` domains (a stopped run keeps finished domains; before, nothing was saved until a
  seed set finished). `HttpClient` per-host delay is thread-safe. Test for the parallel path.
- Next: Ritvik copies the update and reruns `python -m collector crawl --seeds phiusiil urlphish`, then rebuilds.

### 2026-10-11 — Crawl time limits
- Changed: the PhiUSIIL part of the crawl ran (760 sites, 2,150 pages, 425 sites with a full set); the URL-Phish part
  stalled on slow sites. Added `http.max_download_s: 30` (wall-clock cap per response) and
  `crawler.domain_deadline_s: 240` (no new requests to a site after that), with tests.
- Next: Ritvik copies the update and reruns the crawl (done domains are skipped), then rebuilds the pool.

### 2026-10-11 — Faster crawl on dead sites
- Changed: crawler-only HTTP settings (`crawler.http`: 1 retry, 8 s connect timeout) so a dead site costs about 15 s,
  not about 90 s; results are saved every 25 domains. After the first restart the crawl had done 1,060 PhiUSIIL sites
  (2,878 pages) but a batch of 100 took over 15 minutes.

### 2026-10-11 — Crawl no longer waits on a stuck site
- Changed: `collector/benign.py` runs sites on daemon threads (`run_parallel`) with a hard limit per site, so one
  stuck site is abandoned and recorded as `timed_out` instead of freezing a batch; the sliding window keeps all
  `workers` busy (before, a batch of 25 used only 25 of 48 workers); `select_inner_pages` stops after 5 pages and
  scans at most 2,000 sitemap URLs (huge sitemaps were scanned end to end); default workers 48.
- Cause of the second freeze: not confirmed (no traceback); the last save was at 19:18 UTC with 1,410 PhiUSIIL sites done.

### 2026-10-11 — Milestone 2 run on real data; held-out source set to PhishStorm
- Real run: pool rebuilt with the benign crawl (479,657 URLs / 387,856 domains, 149,675 phishing); tier A features built
  and checked (`reports/tables/feature_source_check.csv`): the same 17 of 99 features are flagged (source eta2 within
  class 0.05-0.39 against label eta2 under 0.09, e.g. `n_slash`, `path_depth`, `entropy_url`, `url_len`). Strongest label
  signals are unflagged: `tld_risk` 0.265, `suspicious_tld` 0.139. The path-word features are 57% NaN (no path).
- Decision (Ritvik, card): Phish360 has no public download, so `holdouts.heldout_source` is now `phishstorm` (both
  classes, 2014, URL only). Caveats: no HTML (tier A only), depth 0 is 97% phishing and depth 4+ 91% phishing inside it,
  so its score needs the depth-matched check. Training loses PhishStorm rows. Switch back when Phish360 files arrive.
- Changed: `configs/datasets.yaml`; `python -m features build --split NAME` writes `features_a_<NAME>.parquet` for any
  processed part; `scripts/run_milestone2.ps1` also builds the time slice and held-out features.
- Next: Ritvik reruns the pool build with the new held-out source, then `run_milestone2.ps1`; then milestone 3
  (HTML features) on his go.

### 2026-10-12 — Tier A training over 10 splits; JS port with parity test (cloud)
- Changed: `models/gbdt.py`, `models/char_ngram.py`, `experiments/metrics.py` (fixed-FPR operating points,
  granularity flag), `experiments/tier_a.py` (10 domain-grouped splits, LightGBM / XGBoost with and without
  the 17 source-flagged features, char n-gram TF-IDF + LR; `tld_risk` and bigram likelihood refitted on each
  split's train side; hard domain/URL overlap checks; representation check on `https://www.<domain>`;
  depth buckets; shuffled-label controls; resumable per split), `configs/models.yaml`. JS port in `js/`
  (all 99 tier A features, public-suffix trie, `npm test`), `features/js_export.py`,
  `tests/fixtures/url_parity.json` (272 URLs), Node step in CI.
- Results (`reports/tier_a.md`, median of 10 splits): test ROC-AUC 0.918 LightGBM / 0.936 char n-gram,
  recall 57.5% / 61.3% at FPR 1% and 39.6% / 40.7% at 0.1%. Held-out PhishStorm (59,485 URLs, 33,056
  domains): LightGBM 0.914, recall 58.6% at 1% and 40.0% at 0.1%, but the cal-side 1% threshold gives
  2.6% FPR there. Time slice: 0.950 / 0.960. Normalised URLs: 0.829 / 0.856 (the representation gap the
  prior report found, smaller here). Dropping the 17 flagged features lowers held-out AUC to 0.891, so
  all features stay. Controls 0.4933 / 0.4997, none flagged. Nothing above 99%.
- Decision: shuffled-label controls train without sample weights; with the heavy per-source weights
  they sat at 0.43-0.45 through a leaf-size artifact (unweighted 0.49-0.50 in a scratch check).
- Gap: no out-of-distribution FPR yet; there is no naturally browsed legitimate set (needs a crawl).
- Next: LOSO table and stacked + calibrated model (running), PR #15, then the tier A browser export.

### 2026-10-12 — Why tier A recall was low, and the hybrid model (cloud)
- Diagnosis (`reports/loso.md`, split 0 error analysis): 70% of missed phishing URLs are bare domains with
  no path, mostly PhiUSIIL (recall at FPR 1%: PhiUSIIL 47%, PhreshPhish 66%, URL-Phish 79%). A model with
  only the domain name to judge has a ceiling; the HTML tier is where this should improve.
  Leave-one-source-out shows thresholds do not transfer: holding out PhreshPhish the cal-side 1% threshold
  gives 20.6% FPR, and the trivial `tld_risk` baseline (43% recall at 1% FPR) beats both models there
  (30%, 8%), so the models also learn source style.
- Tried on split 0, chosen on its calibration slice only (recall at FPR 1% / 0.1%): LightGBM 58.2 / 40.0,
  bigger LightGBM 59.1 / 41.4, unweighted 59.0 / 41.6, char n-gram 60.4 / 37.8, host-only char n-gram
  47.5 / 31.7, log-odds average 65.4 / 45.1, **LightGBM with out-of-fold char n-gram scores (URL and
  host) as two extra features 68.4 / 50.1**.
- Changed: `models/hybrid.py`, `experiments/hybrid_a.py` (10 splits, one result file per split so
  processes run in parallel; `PHISHDRIFT_THREADS` limits threads per booster), `experiments/hybrid_checks.py`
  (normalised-URL check, shuffled-label control), `models/explain.py` and `js/src/explain.js` (TreeSHAP
  reasons), `models/export.py` and `js/src/model.js` (browser LightGBM with parity test).
- Results (`reports/hybrid_a.md`, median of 10 splits, recall at FPR 1% / 0.1%): test 69.0 / 50.3
  (LightGBM 57.5 / 39.6); held-out PhishStorm 69.0 / 48.8 (58.6 / 40.0); newest time slice 73.1 / 52.0
  (66.0 / 52.9). Cal-side thresholds give 3.6% FPR on PhishStorm and 1.6% on the time slice. PhiUSIIL
  stays weakest (55.5 / 38.4). Nothing above 99%.
- Rule added to CLAUDE.md: run independent work in parallel (Ritvik's request).
- Checks (`reports/hybrid_checks.md`, 10 splits): shuffled-label control mean ROC-AUC 0.4962, not flagged;
  test URLs normalised to `https://www.<domain>`: ROC-AUC 0.870, recall 44.3 / 29.8 (LightGBM alone 0.829).
- Stacked model (`reports/stack_a.md`, LightGBM + XGBoost + char n-gram, logistic-regression meta model,
  isotonic calibration; recall at FPR 1% / 0.1%): test 66.5 / 46.3, held-out PhishStorm 70.8 / 47.1,
  time slice 72.3 / 54.6; its cal-side thresholds give FPR 2.4% on PhishStorm (hybrid 3.6%), Brier
  0.068, ECE 0.004 on test. Mixed against the hybrid (test 69.0 / 50.3, PhishStorm 69.0 / 48.8, time
  slice 73.1 / 52.0): the hybrid is better on test, the stack on PhishStorm at 1% and the time slice at
  0.1%. Both are within a few points; the hybrid is a single model and is the one exported.
- Browser (`js/src/hybrid.js`, `models/export_hybrid.py`): the hybrid with 100,000-term char vocabularies
  (8 MB; split 0 test ROC-AUC 0.951 vs 0.952 with 500,000 terms; 272-URL parity with Python in `npm test`
  and pytest), about 2 ms per URL, SHAP reasons about 100 ms on request.
- Open: the thresholds do not hold across sources (leave-one-source-out shows the cal-side 1% threshold
  giving 20.6% FPR on a held-out PhreshPhish) so a conservative threshold or per-source calibration is
  needed; no naturally browsed legitimate set yet for the OOD FPR; HTML tier (tier B) needs the PC.
- Next: backend + extension skeleton (milestone 9) using `js/src/hybrid.js`; tier B when the PC is back.


### 2026-10-12 — Milestone 9 skeleton: FastAPI backend + Chrome extension (cloud)
- PR #15 merged first (tier A models, hybrid, JS port). Branch restarted from main.
- Changed: `backend/` (FastAPI: `/health`, `/score`, `/domain-info`, `/feedback`, `/lists/{manifest,blocklist,allowlist}`;
  per-domain TTL cache, rate limit, domain-only input, fail-soft lookups; hashed list builder
  `python -m backend build-lists`), `configs/backend.yaml`, `docs/BACKEND.md`, `tests/test_backend.py`,
  `tests/fixtures/list_key_parity.json` (95 cases, checked in Python and JavaScript). `extension/` (MV3: service
  worker, content script, banner, warning page with proceed/report, popup, daily list sync, `build.mjs` that
  packs `js/src` and the model bundle into `extension/dist`, unit tests, `e2e/smoke.mjs`). CI runs the extension tests.
- Decisions (mine, not validated): the backend is asked about a domain only when the on-device model already
  flagged the address (privacy and latency); domain and page evidence can raise suspicious to dangerous but never
  warn on a safe URL; backend domain rules are placeholders (young domain, no DNS/TLS, free cert), not a tier C model;
  allowlist is Tranco top 50,000 (`allowlist_top_n`), rank only cuts the list.
- Results: pytest 205 passed, ruff clean, `npm test` extension 16 and js 6 pass. Headless Chromium smoke test passes
  with a stub backend and with the real backend: safe page untouched, suspicious banner, cross-site password form
  escalates to warning, dangerous warning with reasons / report (domain only) / proceed anyway, blocklist hit on an address
  the model passes, backend-down fail-open. Pages were local, not real sites.
- Not done: real sites, Safe Browsing, LLM layer, screenshots, icons; no live RDAP/DNS/TLS call has succeeded
  (sandbox offline); the list builder has not run on real feeds or Tranco; a dangerous page can start loading
  before the warning replaces it (webNavigation cannot block).
- Next: run the collector and `build-lists` on the PC when Ritvik is back, try on real sites; tier B waits for the PC.

### 2026-10-12 — Tier C features and experiment (cloud, milestone 7 code)
- Changed: `features/domain_features.py` (`compute_c`, 29 features in groups registration / dns / tls),
  `REGISTRY_C` / `NAMES_C` / `GROUPS_C` in `features/registry.py`, tier C section in
  `docs/FEATURE_DICTIONARY.md`, `features/build_c.py` + `python -m features build --tier C [--info-dir] [--out]`,
  `experiments/tier_c.py` (eligibility filters, 10 domain-grouped splits, LightGBM / no-age / age baseline /
  shuffled control, optional `--with-a` bare-host hybrid2 score, time check, importance), `tier_c` block in
  `configs/models.yaml`, `tests/test_domain_features.py`, `tests/test_tier_c.py`.
- Decisions: latest host record per host and latest RDAP record with data per domain; a record answered by
  the collector PC's filtering resolver (sinkhole addresses) has NaN DNS/TLS values and is ineligible; a TLS
  `gaierror` gives NaN, not `tls_ok = 0`; certificate fields only for verified handshakes.
- Results: 2026-10-12 capture = 350 phishing hosts / 142 domains, no benign. Eligible: 50 phishing hosts
  (165 platform, 130 filtered by the PC's resolver, 5 not resolving removed), so the experiment wrote the
  counts-only report (no model).
- Next: benign captures (Tranco live crawl) on the PC, then `python -m features build --tier C` and
  `python -m experiments.tier_c`.

### 2026-10-13 — Tier B, blended detector, false-alarm check, collector fixes for tier C (cloud)
- Changed: `features/html_features.py` + `features/build_b.py` (84 page features), `models/text_scorers.py` and the
  `hybrid2` variant (URL, host, path and word scorers), `experiments/{tier_b,blend,ood_fpr,ood_fpr_b}.py`,
  `collector/{ood,lock}.py` and the Windows scripts, brand list trimmed by 14 generic words (tier A rebuilt),
  browser bundle re-exported (11.7 MB, hybrid2). Collector: legitimate-host capture for tier C, DNS over HTTPS
  (the PC's resolver answers 0.0.0.0 for known phishing hosts), per-host deadline, RDAP retries, Tranco cache race fix.
- Results (median of 10 splits, recall at FPR 1% / 0.1%; `reports/blend.md`, `reports/tier_b.md`, `reports/ood_fpr.md`,
  `reports/hybrid2.md`): blended detector (page model when the page has HTML, address model otherwise) test 73.7 / 58.6,
  held-out PhishStorm 71.5 / 53.2, newest time slice 84.2 / 62.2; address-only hybrid2 on the same sets 68.8 / 50.4,
  71.5 / 53.2, 73.2 / 48.0. On pages with HTML: 94.2 / 82.0 (address-only 78.3 / 60.8). Pages without HTML: 64.7 / 47.3.
  False alarms on 2,555 ordinary legitimate pages from 562 sites outside every set: 3.6% at the 1% threshold and
  0.7% at 0.1% (pages with HTML), 4.3-5.3% and 0.6-1.0% by address alone; no homepage-shortcut spike.
- Caveats: HTML coverage depends on the source (PhiUSIIL, URL-Phish and PhishStorm saved none), so the pooled number
  is a lower bound; usable HTML is more common on legitimate than phishing pages (PhreshPhish 91% vs 63%), so the
  page-model figures may be optimistic; the held-out source has no HTML, so the page-model gain is not measured there.
- Next: tier C needs benign captures from the PC (collector update delivered; first run 2026-10-13 06:15 IST), then
  `python -m features build --tier C` and `python -m experiments.tier_c`; stack/LOSO still on the old brand list.

### 2026-10-13 — False alarm on web.whatsapp.com: bundled allowlist
- Found by Ritvik's first real-site test: the extension called web.whatsapp.com dangerous. Reproduced with the
  exported model (score 0.991 against the 0.990 dangerous threshold; reasons all from the char/word text scores).
  The URL model alone flags 161 of the Tranco top 1,000 homepages (10 as dangerous): the most impersonated brands
  (facebook, instagram, whatsapp, netflix, microsoftonline) look like phishing to a URL model. Without a backend
  the extension had no allowlist at all, because lists only arrived by sync.
- Changed: the extension ships `extension/data/allowlist.json` (Tranco top 50,000 hashed, 49,648 domains after
  platform removal, built with `python -m backend build-lists --tranco-file`); `withBundledAllowlist` in
  `extension/src/lists.js` uses it until a synced allowlist exists and drops any synced-blocklist domain from it.
  Smoke test page-check URL changed from `/b` to `/login` (the re-exported hybrid2 model scores `/b` just under the
  suspicious threshold). `npm test` 17 pass, e2e smoke passes.
- Open: sites outside the top 50,000 still meet the model's measured false-alarm rate on natural pages
  (`reports/blend_ood.md`, about 4-5% at the 1% threshold), and brand sites outside the list (regional banks)
  are the riskiest. Reported OOD FPR stays measured with the allowlist disabled, as the spec requires.

### 2026-10-13 — Stack and LOSO refreshed on the reviewed brand list; summary tables; report draft
- Reran `experiments.stack_a` (10 splits) and `experiments.loso` (splits 0-2) on the rebuilt features with the
  reviewed brand list, 4 processes in parallel (`PHISHDRIFT_THREADS=1`, one reports dir each, then merged).
  Changes are small: stack test 66.5 / 46.3 (unchanged), held-out PhishStorm 71.2 / 47.9 (was 70.8 / 47.1),
  time slice 72.4 / 54.5 (`reports/stack_a.md`); leaving out PhreshPhish the cal-side 1% threshold now gives
  20.1% FPR (was 20.6%) and the `tld_risk` baseline still beats both models there (`reports/loso.md`).
- New `experiments/summary_tables.py` -> `reports/summary.md`: precision, F1, recall and FPR at the cal-side
  thresholds for every model and set, and the depth-matched tier A table, built from the per-split run tables
  only (no training). Test in `tests/test_summary_tables.py`.
- `reports/hybrid_checks.md` labelled the URL count as domains; it now gives both.
- Report draft (all sections, numbers copied from `reports/` with a source line each, TODO list and a list of
  inconsistencies between result files) in the project folder: `phishdrift/report/report_draft.md`.
- Running: address-only (normalised URL) check and shuffled-label control for hybrid2 (`--variant hybrid2`).
- Next: tier C rerun after the 18:15 IST collector run; fix the report draft's open inconsistencies.

### 2026-10-13 — Hybrid2 representation check and shuffled-label control
- `python -m experiments.hybrid_checks --variant hybrid2` over 10 splits (4 processes in parallel):
  test URLs normalised to `https://www.<registrable domain>` give ROC-AUC 0.8697 [0.8682, 0.8715], recall
  44.3 / 29.8 at FPR 1% / 0.1% (raw test 0.9536); shuffled-label control mean ROC-AUC 0.4940, not flagged
  (`reports/hybrid2_checks.md`, per-split files in `reports/tables/hybrid2_checks/`). Same picture as the first hybrid.
- Still missing for the evaluation list: checks for the tier B model and the blend, the adversarial section,
  blocklist coverage, latency, real-site check.

### 2026-10-13 — Robustness section: six URL evasion families (milestone 6 item)
- New `attacks/` (homoglyph/punycode, subdomain stuffing, brand injection, path/query padding and encoding,
  shortener wrapping, TLD swap + hyphenation; deterministic, tests in `tests/test_attacks.py`) and
  `experiments/robustness.py` (`robustness` block in `configs/models.yaml`). Per split: hybrid2 trained clean
  (`base`, the model in the extension) and hybrid2 trained with one variant of 12% of the train rows (both
  classes) for every family except the held-out one (split k holds out family k mod 6); variants keep their
  parent's domain and are in training only. Thresholds are the clean cal-side 1% / 0.1% FPR points.
  Evaluated on 4,000 test phishing and 6,000 test legitimate URLs per family. 6 splits (not 10: each split
  trains two models, about 1 hour); one run was killed by the container's memory limit and rerun.
- Results (`reports/robustness.md`, median over 6 splits): clean recall at FPR 1% / 0.1% is 69.6 / 52.1 for
  `base` and 68.6 / 50.2 for `adv`. The base model is hard to evade with these rewrites (subdomain stuffing
  2.4% evade, padding 1.3%, shortener 2.9% at the suspicious threshold, against 30.5% for unmodified phishing)
  because it flags the artefacts themselves: it also flags 63.5% (subdomain stuffing), 72.5% (padding) and
  97.2% (shortener) of legitimate URLs rewritten the same way. Adversarial training with both classes removes
  that (1.1-2.1% false alarms on seen families, shortener 0.0%) and brings evasion back to the clean rate
  (32-41%; shortener 100%, a short link carries nothing for a URL model). A held-out family gets neither
  benefit: false alarms and evasion stay at the base model's level (one split per family).
- Reading: the base model's apparent robustness is over-suspicion, not understanding; the extension needs the
  allowlist and shortener expansion / blocklist layers for real traffic. Rewrites are synthetic (random lure
  words, brands from our own list); real attacker URLs may differ.
- Not done: blocklist coverage, latency, real-site check, tier B robustness.

### 2026-10-13 — Tier C on the 12:45 UTC capture (first run with both classes and the capture-lag filter)
- Capture (`data/interim/domain_info/2026-10-12.jsonl`, `2026-10-13.jsonl`): 1,668 legitimate and 460 phishing
  hosts. Eligible after filters (platform 331 phishing, PC resolver 49, not resolving 269 benign / 18 phishing,
  captured more than 2 h after first seen 83 phishing, tier A pool overlap 29 / 21): 1,369 benign hosts
  (741 domains) and 119 phishing hosts (91 domains); median capture 0.2 h / 0.1 h after first seen.
- Results (`reports/tier_c.md`, median of 10 domain-grouped splits, test side 24 phishing / 275 benign hosts):
  tier C LightGBM ROC-AUC 0.778 [0.623, 0.905]; domain age alone 0.614; the tier A model on the bare host
  0.797; tier C plus that score 0.866 [0.658, 0.909]. Shuffled-label control 0.519, not flagged. Recall at FPR
  1% / 0.1% is 25.0 / 20.8 for tier C and 25.0 / 22.9 combined, but every fixed-FPR point is granularity-limited
  (2 false positives allowed at 1% on the cal side), so treat them as unmeasured. Top features:
  `days_since_rdap_change` 16.1%, `domain_age_days` 13.2%, `cert_age_days` 11.7%.
- Reading: tier C carries signal beyond domain age and adds to the address model, but with 119 phishing hosts
  the size of the gain is not established. Needs more captured days (the time check needs 3).
- Next: let the collector run for more days; rerun `python -m features build --tier C` and
  `python -m experiments.tier_c --with-a` on the staged files.

### 2026-10-13 — Latency of the in-browser model
- `python -m experiments.latency` (runs `js/bench/latency.mjs` in Node/V8 over the 272 parity URLs, 5 runs):
  scoring one URL takes a median 1.6 ms (95th percentile 2.3 ms); scoring and explaining it (TreeSHAP reasons)
  156.5 ms (196.1 ms); start-up per browser session parses the 11.7 MB bundle in 166 ms and builds the model in
  73 ms (`reports/latency.md`). Backend response times are not measured (network lookups, cached per domain).
- Blocklist coverage is not measurable on the corpus (the test URLs come from datasets collected in other
  periods than our live feeds); it can only be measured forward, as the share of newly listed feed URLs whose
  domain was already on an earlier list, once the collector has run for several days.

### 2026-10-13 — Shipped extension on natural legitimate pages (offline real-world check)
- `python -m experiments.shipped_verdicts` (runs `js/bench/verdicts.mjs`: bundled allowlist, then the tier A
  model at its suspicious and dangerous thresholds, in the order of `background.js`; blocklist, backend and
  page layers not applied; no page visited). On the 2,555 usable natural pages (562 sites): allowlist covers
  1,072 (42.0%); model alone flags 115 (4.5%); shipped 71 (2.8%: 64 suspicious, 7 dangerous, 38 domains);
  71 of the 1,483 pages on sites outside the top 50,000 (4.8%). On the Tranco top 1,000 homepages 941 are
  allowlisted; the other 59 are shared-hosting/CDN/shortener domains left out by design (`reports/shipped_verdicts.md`).
- This is a measurement on known-legitimate URLs, not a browsing test: the real-site check still needs
  Ritvik's own browsing (false-alarm screenshots) and the sandbox cannot open real sites.

### 2026-10-13 — Tier B leakage checks on the HTML rows
- `python -m experiments.tier_b_checks` (10 splits, one file per split in `reports/tables/tier_b_checks/`):
  `ab_lgbm` test ROC-AUC 0.9928; shuffled-label control mean 0.5071 (not flagged); the 84 HTML features alone
  0.9853 on test and 0.9573 on the time slice; 2.15% of test rows have an exact HTML-feature twin in train,
  and without them the ROC-AUC is 0.9921 (`reports/tier_b_checks.md`). No sign of leakage, but still a
  single-source result (PhreshPhish) with no held-out source that has HTML.

### 2026-10-13 — Allowlist: learned open-hosting zones (Ritvik: "fix allow list")
- Found with a 21-link sample test: a fresh OpenPhish URL on `*.swedencentral.cloudapp.azure.com` showed safe,
  because the allowlist trusted all of `azure.com`. Also found: the list builder blocked a whole allowlisted domain
  for one bad URL (URLhaus lists `github.com/<user>/.../a.exe`, so `github.com` would be blocked after a sync).
- Changed (`backend/lists.py`, `configs/backend.yaml` `lists.open_hosting`, `extension/src/lists.js`,
  `extension/src/combine.js`): every phishing host below an allowlisted domain marks the child zone that contains
  it (`cloudapp.azure.com`, `drive.google.com`); many one-URL children make the whole domain a zone (`weebly.com`).
  No addresses are written by hand: zones come from the feeds plus the corpus's phishing URLs
  (`--phishing-file`, never blocklisted). Inside a zone the allowlist does not apply and bad URLs are listed one by
  one; allowlisted domains are never blocked as a whole; an exact listed URL overrides the allowlist.
- Results: bundled allowlist rebuilt from Tranco top 50,000 + the PC's feeds and URLhaus + pool phishing: 49,564
  domains, 341 zones (42 whole domains); `www.google.com`, `web.whatsapp.com`, `portal.azure.com` stay allowlisted.
  The azure link is now suspicious (it was used to learn its zone, so this is not an independent test). Natural
  pages unchanged (71 of 2,555 flagged); Tranco top 1,000: 934 allowlisted, 58 flagged (`reports/shipped_verdicts.md`).
- Limit: a hosting zone nobody has abused in our data is still trusted until it appears in a feed.

### 2026-10-13 — Blend checks: normalised addresses and shuffled-label control
- `python -m experiments.blend_checks` (10 splits, one file per split in `reports/tables/blend_checks/`). Test
  ROC-AUC 0.9618 (HTML rows 0.9958, others 0.9335). With every address feature taken from
  `https://www.<domain>` (page features kept): 0.9132 overall, 0.9830 on HTML rows, 0.8687 on the rest; recall
  at 1% FPR 73.7% -> 53.8% (HTML rows 94.2% -> 84.0%). The page carries most of the signal where there is one.
- Shuffled-label control mean ROC-AUC 0.5358, not flagged; likely raised above 0.5 by the isotonic step, which is
  fitted with the true cal labels and can map source differences in a shuffled score onto source phishing rates
  (inferred). The earlier hybrid2 control without calibration was 0.4940.
- One split's normalised HTML recall at 0.1% FPR is 0 (`reports/blend_checks.md`); the median is 65.7%.
- Loop learning from user reports: Ritvik chose "report only"; the design is in the report's future work.

### 2026-10-13 — Depth-matched results for hybrid2; README
- `python -m experiments.hybrid_depth` (10 splits, `reports/hybrid2_depth.md`): ROC-AUC per depth bucket for the
  shipped model. Held-out PhishStorm: depth 1-3 give 0.954-0.960 against 0.9587 overall, so its result is not
  PhishStorm's depth imbalance; depth 0 (91 benign URLs) is 0.7985 and the cal 1% threshold flags 30.2% of those
  benign URLs. Depth 0 is the weakest bucket on test (0.9209) and the time slice (0.9270) too.
- README rewritten: results table (from `reports/`), architecture diagram (Mermaid), repository layout, how to load
  the extension.

### 2026-10-14 — Detector improvements: page model in extension, agree rule, IPW, domain rules
- Summary of five improvements from the "detector improvements" branch (PR #22):
  1. **Page model in the extension** (`js/src/html_features.js`, `js/src/htmlparser.js`, `js/src/pystr.js`,
     `js/src/page.js`, `models/page_model.py`, `models/export_page.py`, `extension/src/background.js`,
     `extension/src/combine.js`, `extension/src/content.js`, `extension/build.mjs`): the content script sends
     page HTML to the service worker; the service worker scores it with the tier B page model (LightGBM on
     tier A + tier B features, exported to `js/data/tier_b_page.json` 2.46 MB); reasons for the page model are
     from `models/explain.py`'s `REASONS_B` sentences with late-sort for generic amounts.
  2. **IPW fairness correction** (`experiments/blend2.py`): `propensity()` model (HistGradientBoosting) estimates
     P(usable HTML | URL features, source) per class; IPW-corrected recall on HTML pages is 1–2 pp lower than
     the unadjusted figure, confirming the numbers are defensible.
  3. **"Agree" verdict rule** (`experiments/blend2.py`, `js/src/page.js`, `models/export_page.py`): a suspicious
     banner on a page with usable HTML now requires both the page model and the address model to exceed their
     1% thresholds; reduces false alarms on natural legitimate pages with HTML from 4.7% → 2.4% while cutting
     recall on those pages by about 4.5 pp (93% → 88.5%).
  4. **Source-robust thresholds** (`experiments/blend2.py`, `reports/blend2_rules.md`): `_ws` variants use the
     highest per-source cal 1%/0.1% threshold (set by PhreshPhish for the address score; this is not shipped
     by default but is documented for future use if source generalisability is the priority).
  5. **Domain rules grounded in data** (`experiments/domain_rules.py`, `backend/checks.py`, `configs/backend.yaml`,
     `reports/domain_rules.md`): `domain_unregistered` fires on 22% of legit and phishing alike (demoted to
     `info`); `tls_unverified` fires on 5.1% legit vs 9.3% phishing (demoted to `info`); `domain_young` (age < 30
     d) fires on 28% phishing vs 1% legit; `no_mx_no_spf` 56% vs 9% — strongest signals stay at the original severity.
- JS parity tests: `tests/fixtures/html_parity.json` (382 synthetic pages), `tests/fixtures/page_parity.json`
  (Python's blended scores and verdicts for those pages from split 0's model); `npm test` 20 pass (16 original + 3
  combine tests + html_parity + page_parity).
- Results (median of 10 splits, `reports/blend2_rules.md`, shipped `agree` rule):

  | set | recall (warned) | false alarms | recall (dangerous) | false alarms (dangerous) |
  |---|---|---|---|---|
  | test | 73.5% | 0.9% | 60.0% | 0.1% |
  | test:html | 88.5% | 0.4% | 86.6% | 0.2% |
  | test:nohtml | 67.1% | 1.1% | 48.8% | 0.1% |
  | time slice | 80.7% | 0.8% | 66.7% | 0.2% |
  | time slice:html | 73.5% | 0.4% | 69.3% | 0.2% |
  | held-out PhishStorm (no HTML) | 84.0% | 4.8% | 65.0% | 0.3% |
  | OOD legit (no HTML, 2,555 pages) | n/a | 5.3% | n/a | 1.1% |
  | OOD legit with HTML (2,226 pages) | n/a | 2.4% | n/a | 1.3% |

  PhishStorm 4.8% false alarms: the cal threshold (trained on PhreshPhish-heavy data) does not transfer to this
  2014 URL-only source. `agree_ws` brings it to 3.9% at a cost of 1.4 pp recall on the test set.
  Dangerous rate on PhishStorm 0.3% — well-controlled.
- Open: whether to ship `agree` (current, 88.5% recall, 0.4% false alarms on HTML pages) or `agree_ws` (87.9%,
  0.3%) as the default; the `_ws` threshold is set by PhreshPhish's cal slice and may not generalise to other new
  sources better than the pooled threshold does.
- Next: update the report draft with these results; real-site check (Ritvik's browsing); tier C rerun.

### 2026-10-14 — URL-layer test on fresh feed URLs; open-hosting zones learned from phishing history
- Test (`js/bench/verdicts.mjs`, address layer + bundled allowlist, no page model): 200 active hosts from
  Phishing.Database and 104 regional brand / login URLs (Indian, EU and Asian banks, payment apps, big login pages).
  Before: 62.5% of phishing warned, 0 of 104 false alarms; 12 model-flagged phishing hosts shipped safe because
  their hosting domain (`000webhostapp.com`, `blogspot.be`, `tw1.ru`, `xsph.ru`, `ydns.eu`, ...) was allowlisted.
- Cause: the open-hosting learner had almost no evidence for these domains. The corpus drops domains shared by
  several phishing sources (the pool has 0 phishing URLs on `000webhostapp.com` or `weebly.com`), and the PC's
  feeds cover only a few days.
- Changed (Ritvik: no hand-written addresses): `backend/__main__.py` downloads `lists.open_hosting.evidence_urls`
  (Phishing.Database `phishing-links-ACTIVE.txt`, 789k URLs, cached 1 day) and passes it to the unchanged learner
  as zone evidence only (never blocklisted, never training data); `--no-evidence` skips it; `.txt` URL lists
  accepted by `--phishing-file`; tests for both. The learner then marks 174 allowlisted domains as whole open
  zones (all those above plus `mystrikingly.com`, `squarespace.com`, `tumblr.com`, regional blogspot, dynamic DNS,
  ...) and adds child zones (`sites.google.com`, `chat.whatsapp.com`); `google.com`, `microsoft.com`, `apple.com`,
  `paypal.com`, `github.com` stay allowlisted.
- Bundled `extension/data/allowlist.json` updated in the cloud by applying those zones to the existing list (no
  Tranco download here); the 200 test hosts were left out of the evidence so the re-test is independent. The
  next PC `build-lists` run produces the same from scratch.
- Results after: 68.5% of the 200 phishing hosts warned (73 dangerous, 64 suspicious), none silenced by the
  allowlist; 0 of 104 regional brand URLs flagged; natural legitimate pages 69 of 2,555 flagged (2.7%; was 71).
- Open: the 63 remaining misses are bare hosts the address model scores clean; the page layer is the next check.

### 2026-10-15 — Extension stress test and five fixes
- Stress test (report in the project folder: `phishdrift/report/stress_test_2026-10-15.md`): fresh feed phishing,
  hosting-platform phishing, six evasion families, hand-made long URLs, a robustness set and 138 legitimate login
  pages in headless Chromium. Five real gaps found and fixed:
  1. A very long URL threw in `wordStats` (`Math.min(...array)` overflow) and every check was skipped. Now a loop;
     URLs over 32,768 characters and scoring errors give a soft warning (`extension/src/address.js`).
  2. Allowlisted sites were never page-checked, and the zone learner missed path tenants (`telegra.ph/x`,
     `notion.so/x`) and busy subdomain tenants. Path segments on the bare domain now count as tenants, 20 distinct
     phishing subdomains open a whole domain (`min_children_whole`), and on allowlisted pages the page model can
     raise a banner (never more) when the page has a password field and scores at the dangerous threshold.
  3. Shorteners are never allowlisted (18 removed) and never judged by the address model; the target is scored.
  4. The redirect target is scored at `onCommitted`, before the page renders, not only from the content script.
  5. `history.replaceState` cannot lower a verdict (per-tab floor; the page message takes the worst of the reported,
     committed and floor verdicts); login forms added after load are re-checked (MutationObserver, at most 3 times).
- Results (address layer + bundled allowlist; before -> after): hosting-platform phishing warned 81.0% -> 85.9%;
  OpenPhish 92.3% -> 92.7%; Phishing.Database active 82.0% -> 82.2%; natural legitimate pages 2.7% unchanged;
  regional brand sites 0%; legitimate pages with HTML through the page path 1.17% -> 1.21% flagged; short links:
  legitimate links wrapped in a shortener 29.6% -> 0.0% flagged at the address, phishing wrapped 24.6% -> 0.0% at the
  address, which is now decided at the target (unwrapped phishing in that set: 86.6% warned; inferred from the code
  path, not measured in a browser). Robustness set: no errors, slowest URL 631 ms.
- The 10-split model numbers are unchanged: no model changed, and they are measured with the allowlist off.
- Tests: pytest, ruff, `npm test` in `js/` (11) and `extension/` (30), e2e smoke passes.
- Not done: back-to-safe navigation, full-hash blocklist matching, iframes/blob pages, list-sync sanity checks.

### 2026-10-15/19 — Page-check gaps from the red-team review and stress test (extension 0.1.1)
- Changed (`extension/src/{combine,background,content,address,pagefacts,warning}.js`, new `trust.js`,
  `domain.js`, `navigation.js`; `js/src/{page,html_features}.js`; `backend/app.py`; manifest):
  1. The page model can raise any verdict but lower one only on a page with no password, one-time-code, card or
     PIN field (in the page or a frame); the address model's dangerous verdict always stands.
  2. In-page route changes also ask the content script to send the page again (up to 5 rechecks).
  3. Content script in all frames (`all_frames`, `match_about_blank`, `match_origin_as_fallback`, file pages):
     a frame asking for credentials blocks lowering; a cross-site one is judged at its own address and HTML.
     blob: pages stand for the site that built them, about:blank/srcdoc for the inherited origin; pages with no
     address (data:, sandboxed frames, malformed) are not scored and warn only if they ask for credentials
     (a blob: address used to score 0.99, a malformed one 0.98).
  4. "Take me back to safety" goes to the tab's last safe page on another site, else a new tab (no history.back()).
  5. Banner in a closed shadow root in the top layer (popover) with important inline styles; a page that keeps
     removing or hiding it gets the full warning page ("tried to hide PhishDrift's warning").
  6. A blocklist hit beats "trust this site"; trust entries expire after 30 days.
  7. The backend is never waited for: the verdict shows at once and a late "high" answer raises it. A failed
     lookup is `risk: "unknown"` with `error` (also on `/score`), never "low"; the extension remembers failures 30 s.
     Verdict cache cleared after a list sync.
  8. A bare login form (under 200 visible characters) is read by the page model, which can only raise there;
     the password-form rule still applies to such pages.
- Results (`python -m experiments.page_fixes_fpr`, `reports/page_fixes_fpr.md`; 2,373 natural legitimate pages
  with HTML, 2,226 readable by the page model; no backend, no blocklist; facts from stored HTML): warned with the
  bundled allowlist 1.21% -> 1.30% (27 -> 29 pages), dangerous 0.49% unchanged; without the allowlist 2.47% ->
  2.61%, dangerous 1.17% unchanged. Recall effect on phishing pages not measured (no phishing HTML in the cloud).
- Tests: `npm test` extension 41 and js 11, backend pytest 44, e2e smoke 15 steps in headless Chromium (new: frame
  login, banner hiding, SPA route, blob page, back to safety, trust vs blocklist, slow backend with late answer).
- Not done: rendered-DOM vs raw-HTML difference (train/serve), full-hash blocklist matching (lists thread).

### 2026-10-19 — Tester round 2 on PR #24: frames, shadow roots, stale banner
- Test thread (real Chromium, `/mnt/project-files/phishdrift/e2e_attack/harness.mjs`): 31 of 35 attack cases passed;
  four failed. Fixed three, the fourth is a harness artefact:
  1. A credential frame (cross-site, srcdoc or about:blank) on a page whose address looks safe is judged on its page
     score alone (`framePageVerdict` in `extension/src/combine.js`; the agree rule needs the address model too, and a
     frame's address says little). Frames on allowlisted, trusted or shortener addresses are skipped.
  2. Login forms inside open and closed shadow roots are counted (`chrome.dom.openOrClosedShadowRoot`) and their HTML
     is added inside `<body>` for the page model.
  3. A banner from an earlier verdict is removed when the page check comes back safe, unless a warning (from a frame)
     arrived meanwhile; the page handler re-reads the document's floor after applying its result (race with frames).
  4. 40,000-character address: the verdict is stored (suspicious, "extremely long"); the harness's Node server answers
     431, Chrome shows its own error page (`chrome-error://chromewebdata/`), so the harness cannot find the tab by URL
     and no content script runs there.
- Results: harness on the new build, all frame / srcdoc / shadow / back-to-safety cases pass; the three trust cases
  fail only because the harness's stub serves lists without the sha256 manifest the signed list sync now requires.
  False alarms (`reports/page_fixes_fpr.md`) unchanged at 1.30% (allowlist on) / 2.61% (off) on 2,226 readable
  pages. Credential-frame rule on the 164 non-allowlisted legitimate pages that ask for credentials, standing in
  for legitimate login frames (the set has no frames): 7 flagged as a frame (4.3%) against 8 as a page (4.9%).
- Tests: `npm test` extension 54, js 11, pytest, ruff, e2e smoke 16 steps (new: srcdoc login frame, closed-shadow lure).

### 2026-10-19 — Tester round 3: stale banner and "back to safety" timing
- Test thread rerun on e68eac6: 34 of 35 attack cases (PR #23: 21 of 35). Left: the address banner from commit
  time still showed after the page check said safe (G1 control; aoscforums.com and mehrhost.com natural pages),
  and "Take me back to safety" sometimes bounced back to the warning page.
- Cause and fix (`extension/src/background.js`, `content.js`, `warning.js`):
  1. The commit-time address verdict reached the page after the page check had started and was counted as a later
     warning, so the safe answer did not remove the banner. Verdict messages now carry `kind` ("commit" or
     "raise"); a commit-time one is ignored once the page check has answered and never blocks the safe answer.
  2. Verdicts still being worked out for a page the tab had left (the page check, slow scoring, a late backend
     answer) re-opened the warning page after "Take me back to safety". The worker now keeps each tab's current
     navigation; a verdict for an older one is dropped, and the warning page opens only if the tab has not moved
     on since the verdict was reached. A page judged safe after the tab left is still kept as a place to go back to.
  3. The warning page attaches its button handlers before it asks for the verdict, so an early click is not lost.
- Results: the tester's harness (`/mnt/project-files/phishdrift/e2e_attack/harness.mjs`) gives 35 of 35 in 4 full
  runs in a row (before the last fix: 1 or 2 of 4 runs clean). `npm test` extension 54, e2e smoke 16 steps.
  False-alarm numbers unchanged (the combiner did not change).
- Accepted cost of the page-model rule from 2026-10-15: on the tester's 400 natural pages, 3 more suspicious
  verdicts (fdownload.app/hi, dropmefiles.com/d1m2f, telegram.cn/buy/11): the address model flags them and the
  page model may no longer clear a page with login fields (5 -> 8 warned).

### 2026-10-19 — Lists, blocklist and sync hardening (fix thread, paired with a hands-on test thread)
- Changed: `backend/lists.py` (path-tenant learning with generic first segments, tenant-host keys only where the
  data shows one tenant per subdomain, Safe-Browsing-style URL expressions, 8-byte blocklist / 16-byte allowlist
  hashes, `top` sentinels, file sha256 in the manifest, ECDSA-signed manifest and `/config`, build history and
  `/lists/delta`), `backend/app.py` (`/register` + token-checked `/feedback` with per-install cap and dedupe,
  `/config`, `/lists/delta`, separate list rate bucket; never-warn refuses platforms, shorteners and learned
  zones), `backend/remote_config.py`, `configs/remote_config.yaml`, `extension/src/listsync.js` (signature,
  hashes, sanity limits, deltas, config checks), `keys.js`/`lists.js` (expression lookup), `background.js`/
  `config.js` (60-minute sync, cache clear after sync, settings validation, remote thresholds and never-warn),
  `extension/data/allowlist.json` rebuilt with 16-byte hashes. Tests: pytest 486+, extension 41, e2e smoke.
- Results (measured): blocklist token variants on shared hosts matched 0/300 -> 298/300 (query added),
  0/30 -> 24/25 (value changed), 0/189 -> 158/184 (last token), 0/300 -> 297/300 (token appended)
  (test thread, `/mnt/project-files/phishdrift/list_tests/REPORT.md`); feedback without token 200 -> 401.
  Bundled allowlist: 6 -> 16-byte hashes, 812 KB -> 1.63 MB, 49,335 -> 43,595 domains (rebuilt in the cloud from
  the old list's domains recovered via Umbrella/CrUX; Tranco is blocked here); natural legitimate pages flagged
  69 -> 72 of 2,555 (2.70% -> 2.82%); 3,300 fresh phishing URLs warned 2,844 both before and after.
- Not done: zone-aware address scoring inside open zones (sites.google.com); signatures are off until a key is
  made on the backend machine; the PC rebuild with Tranco (`python -m backend build-lists --tranco-file ...`)
  restores the 5,740 domains the cloud rebuild could not recover.

### 2026-10-19 — Brand and look-alike rules; threshold-transfer and render-gap tools (cloud)
- Changed: `features/brand_rules.py` + `js/src/brand_rules.js` (escalate-only rules: Unicode skeleton from the
  confusables table with punycode decoding, "1" read as l or i; embedded real domain; one letter away from a brand;
  brand + lure word; brand-page rule = brand in title / og:site_name / copyright + password, OTP, card or PIN field +
  domain not the brand's; phishing_catcher-style host score as a baseline), `features/brand_domains.py`
  (`python -m features brand-domains [--wikidata] [--misp] --confusables FILE`: brand -> official domains from
  Wikidata P856 and MISP vendor lists, platforms excluded), `configs/brand_rules.yaml`, page facts collected in the
  same parse as tier B (`features/html_features.py`, `js/src/html_features.js`; model features unchanged),
  `extension/src/combine.js` `brandEscalate` (one step per address hit and one for a brand page; never lowers,
  never touches trusted or blocklisted addresses; on allowlisted pages and short links only the page rule, up to
  suspicious), `experiments/brand_rules_eval.py`, parity fixture `tests/fixtures/brand_rules_parity.json`
  (175 URLs, 18 pages), `tests/test_brand_rules.py`. `configs/lists/brands.txt` replaced by the reviewed 772-brand list.
- Results (`reports/brand_rules.md`, allowlist off): address rules fire on 0 of 2,373 natural legitimate URLs
  (572 domains) and 0 of 114 regional brand sites; the brand-page rule on 1 of 2,373 natural pages
  (`cashinexch.com/redirect/facebook`). Caveat: the rules were tuned after seeing the natural set (vivacom.bg,
  pcloud, deutsche-bank, generic brand words), so these are not independent numbers. On the test thread's
  generated look-alikes (shipped address path + bundled allowlist, measured in Node): ASCII homoglyphs warned
  5 -> 42 of 45, edit distance 1 21 -> 53 of 92, punycode 84 -> 89 of 91, brand + word 36 -> 40 of 46; 0 of 120
  genuine brand hosts flagged before and after.
- Not fixed: TLD swaps (`icicibank.net`, `sbi.app`): a brand's name on another suffix is treated as its own site,
  because brands own many suffixes (`paypal.de`, `google.in`) and the map is too thin to tell. The URL model's false
  alarms on `paypal-community.com`, `coinbase.cloud`, `amazonaws.com` remain (the rules do not cause or fix them).
- Found: the shipped hybrid bundle carries the 67-word seed brand list, while training used the reviewed list
  (`models/export_hybrid.py` used `load_lists()` without the PC's lists). Re-export on the PC fixes it.
- Added but not run (needs the PC's data / the open web): `experiments/threshold_transfer.py` (five threshold
  rules incl. source-balanced and domain-bootstrap upper bounds, main and leave-one-source-out settings) and
  `collector/render.py` + `experiments/render_gap.py` + `scripts/render_ood.ps1` (render natural legitimate pages
  headless and compare page-model false alarms on raw vs rendered HTML). Tests pass with fixtures.
- Not done: Wikidata brand map (sandbox cannot reach Wikidata; MISP only, 17 brands), favicon hash.

### 2026-10-20 — Brand list additions, proposed for review (cloud)
- Changed: `configs/lists/brand_additions.txt` (127 brands: payments, crypto, marketplaces, social, gaming,
  work accounts, banks in the US, Canada, Europe, Asia-Pacific, Latin America and Africa, post and parcels,
  telecoms), merged into `configs/lists/brands.txt` (772 -> 899) in the cloud (Wikidata unreachable here).
  `features/scrape.py` now merges `brand_files` and drops `brand_exclude` (the 2026-10-12 generic words,
  which a rescrape would otherwise bring back). `experiments/brand_evidence.py` (phishing-feed counts per
  name, with the longer words that contain it). Tier B shard plans carry a word-list hash, so shards built
  with other lists are no longer reused silently (`features/build_b.py`, `lists_digest`).
  `scripts/refresh_brands.ps1` (brand-domain map, rules, extension; `-Model` rebuilds features and re-exports).
  `js/data/brand_rules.json` and `js/data/lists.json` regenerated.
- Selection (no popularity): at least 10 phishing registrable domains in 789,354 feed URLs
  (Phishing.Database ACTIVE + OpenPhish, 2026-10-20), not an everyday word or part of one, name = label of the
  brand's own site; Slack, Revolut, Swiggy and Monzo kept as asked despite almost no feed evidence. The
  left-out candidates and reasons are in `reports/brand_additions_review.md` (`reports/tables/brand_evidence.csv`).
- Results (`reports/brand_rules.md`): address rules 0 of 2,373 natural legitimate URLs and 0 of 114 regional
  brand sites (unchanged); brand-page rule 1 of 2,373 natural pages (same page); phishing `openphish_gh.txt`
  10 -> 13 of 300 (not independent of the selection). `commbank` was dropped after it flagged `combank.lk`.
- Not done: the models still use the old list (shipped address bundle: the 67-name seed list) until
  `scripts\refresh_brands.ps1 -Model` runs on the PC; brand-to-domain map needs Wikidata (PC).
- Open: Ritvik's review of the list (left-out candidates: halifax and huntington recommended).

### 2026-10-19 — Known gaps: local addresses, zone-aware scoring (measured, not shipped)
- Found while checking red-team gap 13 (IP hosts): public IP hosts are already warned (dangerous) by the address
  model, but so are local ones. `http://192.168.0.1/` (a router), `http://127.0.0.1:8000/login` and
  `http://localhost:3000/` got the warning page or a banner. Changed: `isLocalAddress` in
  `extension/src/address.js` (localhost and `*.localhost`, `.local`, `.lan`, `.internal`, `.home.arpa`,
  `.localdomain`, `.intranet`, private / loopback / link-local IPv4 and IPv6, single-label intranet names); such
  addresses are not scored and `combine` returns safe with a note (a blocklist hit still warns). None of the 3,250
  list-test URLs or the 300 OpenPhish URLs is local, so no measured number changes. Tests in
  `extension/test/{address,combine}.test.js`; `npm test` extension 56 pass, e2e smoke 16 steps pass.
- Lists gap 8 (pages inside learned open-hosting zones are read by the model as the big site's own address):
  `python -m experiments.zone_masking --cases <list test cases>` (`reports/zone_masking.md`) scores every case URL
  inside a zone as shipped and with the zone masked like a platform-list domain. Masking warns on 203 of 256
  phishing tenant URLs against 160 (sites.google.com 16 -> 59 of 100), but on 71 of 134 legitimate ones against 13:
  every generated Google Drive file link (20 of 20, all dangerous) and every Docs document link, and platform pages
  such as `notion.so/help` and `sites.google.com/new`. A capped variant (banner only at the dangerous threshold)
  gives 173 and 36. Not shipped: the model's prior for hosting platforms is too high for big-site zones, so tenant
  pages there stay with the page model. Also measured: as shipped, 10 of 20 generated Drive file links already get
  a suspicious banner from the address model (the page model may clear them; not measured in a browser).
- Red-team gap 5 (train/serve HTML): `python -m experiments.render_gap_offline` (`reports/render_gap_offline.md`) renders the
  2,373 natural legitimate pages' stored HTML in headless Chromium (offline: inline scripts run, external scripts,
  styles and frames do not), serialises the DOM as `content.js` does and scores raw and rendered through
  `js/bench/page_verdicts.mjs`. 2,334 rendered (39 failed). False alarms with the allowlist: 36 -> 36 warned
  (1.54%), dangerous 11 -> 10; without it 69 -> 67 warned, 30 -> 28 dangerous. No page went from safe to warned;
  median page-score change 0.000 (95th percentile 0.018). A lower bound: median rendered/raw length is 1.00 because
  external scripts did not run. The live-rendering number needs the PC: `scripts/render_ood.ps1` with `experiments/render_gap.py` (brand thread) does that.
- Still open (need Ritvik's PC): `python -m backend make-signing-key` + rebuild, and the Tranco `build-lists`
  run; live rendering for gap 5. Brand list additions (Slack, Revolut, Swiggy) are with the brand thread.
### 2026-10-20 — URL check page without the extension (cloud)
- Changed: `demo/` (`index.html`, `app.js`, `check.js`, `__main__.py`): `python -m demo` serves the repository on
  127.0.0.1 and opens a page where a pasted address gets the extension's verdict, score (against the suspicious and
  dangerous thresholds), reasons and the deciding layer. `check.js` loads the extension's own modules
  (`extension/src` with `js/src` as `lib/` through an import map; `extension/dist` in Node) and follows
  `layersFor()` / `evaluate()`: lists (`data/lists/` when built, else the bundled allowlist), tier A model,
  look-alike rules, combiner. The model's own score is also shown for allowlisted addresses. Model files are read
  from `js/data` at run time. Not applied: page model, password-form rule, backend, user trust, shortener expansion.
  Tests: `extension/test/demo.test.js` (5), `tests/test_demo.py`; checked in headless Chromium (desktop and phone width).

### 2026-10-20 — URL check page: animated layer-by-layer view (cloud)
- Ritvik found the first page vague and choppy. Redesigned `demo/index.html` and `demo/app.js`: the address is shown
  entering a vertical pipeline; a marker moves from layer to layer (allowlist, blocklist, address model, look-alike
  rules, combiner, and a greyed "page and domain checks" step that only the extension runs), each lighting up with what it
  found; the verdict panel then draws a shield (check, warning or cross) with the reasons and the model score on a
  meter against both thresholds. Row heights are fixed before the run so nothing jumps; only transform and opacity
  transitions; `prefers-reduced-motion` turns animation off; light and dark themes. `demo/check.js` now returns a
  per-layer `trace` (same decisions as before; no scoring change). Test added in `extension/test/demo.test.js`.
- The requested "UI UX Pro Max" skill is not available in this environment; the design follows general UI guidance.

### 2026-10-20 — URL check page: one screen per layer, new palette (cloud)
- Ritvik: the layer view was fixed cards with generic paragraphs. Reworked `demo/` so each layer is its own screen,
  played one after another, showing what it checked for the typed address: allowlist (domain, SHA-256 fingerprint,
  found or not), blocklist (the URL keys that were hashed and looked up), address model (score built from the real
  clues, in log-odds, on a gauge with both thresholds), look-alike rules (letters compared with the closest brand,
  after mapping look-alike characters), combiner (steps on a safe / suspicious / dangerous ladder), then the verdict.
  Step bar at the top; click a finished step to replay it; "Skip to verdict". New violet palette, light and dark.
- Changed: `demo/evidence.js` (new, reads the extension's own objects, changes no verdict), `demo/check.js`,
  `demo/index.html`, `demo/app.js`, test in `extension/test/demo.test.js`. No backend or list code touched.
- Checked in headless Chromium (desktop, 390 px dark) on the look-alike, normal, punycode and phishing examples;
  not on Ritvik's PC.

### 2026-10-20 — Stitch false alarm: popular tenant sites on platforms (cloud)
- Found by Ritvik's URL check page: `stitch.withgoogle.com` was suspicious. Cause: `withgoogle.com` is on the
  hosting-platform list (public suffix list), so the allowlist was skipped; the address model scored 0.902.
- Changed: `backend/lists.py` `tenant_sites` + `popular_origins` (CrUX top origins, `lists.tenant_sites` in
  `configs/backend.yaml`, `--origins-file`, `--no-tenant-sites`): a popular tenant that is its own site is allowlisted
  by exact host unless phishing was seen on it, it is a zone or a shortener. `extension/src/lists.js` looks the host up
  on shared addresses; demo wording. Bundled `extension/data/allowlist.json` gained 137 tenant hosts.
- Results (`reports/tenant_sites.md`): popular tenant homepages flagged 60 of 137 -> 0; phishing on platform hosts
  unchanged (2,740 of 3,000); natural legitimate pages unchanged (72 of 2,555); held-out phishing (OpenPhish 1,800,
  half of ACTIVE 394,527) on kept tenants 0. Tests: pytest, `npm test` extension 66.
- Next on the PC: `python -m backend build-lists --tranco-file ...` downloads the CrUX list itself.

### 2026-10-20 — Deep legitimate URLs of popular sites: crawl + Common Crawl seed sets (cloud, code only)
- Why: the address model's false alarms (2.8% of natural legitimate pages; `stitch.withgoogle.com`) come from benign
  training URLs that are mostly bare homepages. Ritvik chose "we crawl" and "use both" (crawler and Common Crawl index).
- Changed: `collector/popular.py` (CrUX host list, host selection, Common Crawl CDX reader), seed sets `popular`
  (crawler, HTML kept) and `commoncrawl` (index URLs, no HTML) in `configs/collector.yaml` (`scheduled: false`, run by
  name; own lock so the 12 h collector is never blocked; heartbeat at every checkpoint), new benign-only source
  `popular` in `configs/datasets.yaml` (`kind: crawl_only`, after `phiusiil` in the source priority; not in the time
  slice), `data_pipeline/sources.py` (`crawl_seed_names`, `commoncrawl` origin), `scripts/run_popular_crawl.ps1`,
  `python -m collector crawl --seeds ... --domains-per-run N`. Tests: `tests/test_collector_popular.py` (fixtures only).
- Rules kept: popularity picks hosts and is never stored or a feature; hosts in the corpus, the OOD evaluation set,
  the feed index, earlier crawls or with feed phishing are skipped (natural pages stay evaluation-only); robots.txt and
  Crawl-delay obeyed; the corpus still caps a registrable domain at 20 URLs, so a hosting platform's tenants share 20.
- Not measured: nothing was fetched (the sandbox cannot reach Common Crawl, CrUX hosts or the open web), so the real
  yield, the Common Crawl request shapes against the live API, and the effect on false alarms are unknown. Next: run
  `scripts\run_popular_crawl.ps1 -DomainsPerRun 20` on the PC as a test, then the full run, rebuild the pool
  (`python -m data_pipeline build --reuse-interim --reload popular`), retrain, and re-measure false alarms on the
  natural pages (`experiments.shipped_verdicts`, `reports/blend2_rules.md`).

### 2026-10-20 — Address model alone no longer blocks a page that asks for nothing (cloud)
- Found by Ritvik: the warning page blocked `https://www.mujtoppers.in/api/turnstile/verify` on a college
  study site. The address model scores it 0.989 against the 0.986 dangerous cutoff (the word "verify" on an
  unlisted `.in` domain; `/branch/second/subjects/CSE` on the same site scores 0.598). Probably a form post to
  a Cloudflare Turnstile verify endpoint that redirects back (inferred; the sandbox cannot reach the site):
  the old worker opened the warning page at `onBeforeNavigate`, before the server's redirect.
- Changed (`extension/src/background.js`, `combine.js`, `js/src/page.js`): before commit only a blocklist hit
  opens the warning page; a dangerous verdict from the address model alone (`addressOnly`) is shown as the
  banner at commit and becomes the warning page only if the page asks for a password, one-time code, card or
  PIN field, the page model's own score is over its dangerous cutoff (`pageDangerous`; the page verdict echoes
  the address), a second layer raises it (domain checks, look-alike rules), or no page check starts within
  5 s. Never lowered below suspicious. Extension 0.1.2.
- Results (`python -m experiments.address_only_blocks`, `reports/address_only_blocks.md`; warned shares
  unchanged by construction): natural legitimate pages blocked 11 -> 6 of 2,373 with the allowlist (30 -> 23
  without); time slice legitimate 85 -> 40 of 51,342, phishing 64.3% -> 62.5% blocked (72.3% warned either way);
  split 0 test legitimate 21 -> 15 of 19,109, phishing 84.4% -> 83.6%. Page facts come from stored features,
  not a live DOM; the PC's processed files were staged for this.
- Tests: `npm test` extension 65, js 15; e2e smoke 18 steps (new: address-only page gets the banner; a slow
  verify-and-redirect hop is not blocked; both fail on the old build); the tester's attack harness gives the
  same per-case results as before (33 of 35; the 2 trust cases fail on its stub lists, as on main).
- Cost: a phishing page whose address alone is dangerous now renders with the banner until the page check
  (document_idle, at most 5 s) before the warning page replaces it.

### 2026-10-20 — Ponytail plugin enabled for the project (cloud)
- Changed: `.claude/settings.json` adds the `DietrichGebert/ponytail` marketplace (MIT, v5.3.2) and enables
  `ponytail@ponytail`, so Claude Code sessions in this repo offer it after the user trusts the folder.
  Default level is `full`. Its two Node.js hooks need `node` on PATH. Not tested in a live Claude Code session.
- Next: open the repo in Claude Code on the PC, accept the plugin prompt, run `/ponytail-help`.

### 2026-10-20 — Popular-sites test crawl on the PC: Common Crawl index failed for every site (cloud)
- Ritvik's 20-site test (`run_popular_crawl.ps1 -DomainsPerRun 20`): Common Crawl seed set 20 of 20 sites `error`, 0 pages
  (log: connect timeout after 8 s, connection reset by the server, "connection pool is full"); the summary step then
  crashed because PowerShell 5.1 strips the double quotes of an inline `python -c` script.
- Cause (from the log, not reproduced here: the sandbox cannot reach the index): the index client inherited the
  crawler's fail-fast settings (8 s connect timeout, 1 retry) and the 48 crawler workers all used one connection
  pool, so requests to `index.commoncrawl.org` timed out or were reset and none was retried.
- Changed: `collector/popular.py` `commoncrawl_client` (own client: 30 s connect timeout, 4 retries with backoff 3,
  one request a second), 3 workers for the index (`popular.commoncrawl.workers`), `retry_errors` on both seed sets
  (sites that failed or timed out are tried again; the 20 failed sites are not marked done), `python -m collector
  popular-summary` replaces the inline script in `scripts/run_popular_crawl.ps1`. Tests added.
- Not measured: whether the index now answers (needs the PC). The crawler (`popular`) results of the same test run
  were not seen by me.

### 2026-10-20 — Popular-sites crawl, second PC test: crawler works, Common Crawl index still unreachable (cloud)
- Read Ritvik's log (`data/logs/popular_crawl_2026-10-20.log`, staged from the PC). The new code was running (retries
  with a 30 s connect timeout). Crawler seed set `popular`, 20 sites per test: 34 to 58 pages from 7 to 12 sites with
  pages (about 2 pages per site; 4 runs at 22:45, 23:08, 23:25, 23:28). Common Crawl seed set: 20 of 20 `error` in
  every run; the last run took 17 minutes and the log has 73 connect timeouts (30 s) and 3 connection resets from
  `index.commoncrawl.org`, so the PC's connection to the index server mostly never opens (the collection list loads,
  the index queries do not). Cause on the server or the network side; not fixed by retries.
- Changed: the summary command crashed (`args.verbose` missing on its parser: my bug in PR #34); the index seed set now
  stops after `max_consecutive_errors` (6) sites in a row fail and leaves the rest untried; `run_popular_crawl.ps1`
  runs the crawler only by default (`-Seeds popular,commoncrawl` adds the index). Tests added.
- Next: Ritvik runs the crawler at full size (about 2 pages per site, so 1,500 sites is roughly 3,000 pages;
  estimate); the index can be tried again later.

### 2026-10-20 — PhishGuard verification study run (research study, separate from the PhishDrift detector)
- New `phishguard/` package, `configs/phishguard.yaml` (plan and replication rule frozen at commit 082b058 before
  the run), `tests/test_phishguard.py`. One command: `python -m phishguard all` (resumable, one result file per job).
  Proposal: Claude Doc "PhishGuard: Study Report and Verification Proposal".
- Run: 291 jobs (25 URL cells x 10 splits, 4 page cells x 10 splits, 1 fingerprint check), 4 processes, no failures.
  Output `reports/phishguard/verification.md` and `reports/phishguard/tables/`.
- Part A verdicts (URLs): F1 replicated (100/100); H6 replicated (392/392); F3 partly (76%, 53% after depth
  reweighting); OOD partly (76%); F2 not replicated (0/100; R2-to-R4 share median 0.21 vs 0.87 in the first study);
  F4 not replicated (45%); H5 not replicated (26%, expected inconclusive); HP not testable (no platform domains
  left after the 5-per-domain cap). E0: PhiUSIIL cell raw AUC 0.864 vs 0.999 published, R4 0.791 vs 0.730.
  Shuffled-label controls 0.448-0.525, 1 of 100 flagged (urlphish__phiusiil, R1, LightGBM, 0.448; to investigate).
- Not done: investigation of the flagged control and of the E0 gap; PhishTank cells (not in the pool).

### 2026-10-20 — PhishGuard follow-up checks: PhiUSIIL gap and the flagged control
- Changed: `phishguard/checks.py` (`python -m phishguard.checks reproduce|control`); outputs
  `reports/phishguard/tables/reproduce.csv` (5 splits, XGBoost and char n-gram) and
  `reports/phishguard/tables/control_urlphish__phiusiil.csv` (10 splits x 5 shuffle seeds).
- Gap to the published PhiUSIIL numbers (median raw ROC-AUC, XGBoost / char n-gram): raw PhiUSIIL through our loader
  0.941 / 0.940 (published 0.999); sampled to 10,000 per class 0.934 / 0.923; shared domains removed 0.878 / 0.883;
  pool URL rules 0.873 / 0.882; study cell 0.867 / 0.853. Cleaning explains about 0.07; about 0.06 is already gone
  at the raw stage, most likely because our loader canonicalises the URL strings (inferred, not tested; the original
  CSV strings are not kept). R4 stays 0.79-0.85 at every stage (published 0.730). Benign depth 0 is 100% at every stage.
- Control: LightGBM on shuffled labels mean ROC-AUC 0.449 (SD 0.031, 50 runs), also 0.441 when the fitted features
  use shuffled labels; char n-gram 0.506. Below 0.5 for every seed, so a LightGBM artefact of this cell, not chance and
  not a leak (a leak pushes above 0.5); the same model at R4 and in the other 24 cells was not flagged.
- Next: write both into the study report as limitations; optionally rerun the control unweighted / larger leaves.

### 2026-10-20 — Google Stitch skills enabled for the project (cloud)
- Changed: `.claude/settings.json` declares an inline marketplace `stitch-skills` with the three plugins of
  `google-labs-code/stitch-skills` (Apache-2.0; `stitch-design`, `stitch-build`, `stitch-utilities`, 16 skills),
  pinned to commit 0337446, and enables them. Skills only: no hooks, no MCP server config, no install scripts.
  Several skills call the Stitch MCP server and some pass a Stitch API key to scripts; the key stays on the PC.
- Checked in a scratch folder with Claude Code 2.1.304: after the folder is trusted, `claude plugin install
  <name>@stitch-skills --scope project` installs all three and the 16 skills load.
- Next: on the PC, run the three install commands once from the repo folder and add the Stitch MCP server locally.
### 2026-10-20 — Addresses-only seed set `popular_urls` for lakhs of legitimate inner pages (cloud, code only)
- Ritvik asked for lakhs of legitimate inner pages. The sandbox cannot reach Common Crawl, Hugging Face, Tranco or Kaggle
  (proxy 403), so everything runs on the PC. Chosen (decision card): addresses first, HTML at scale second.
- Changed: `collector/benign.py` seed sets can override crawler settings with `crawl:`; new seed set `popular_urls` in
  `configs/collector.yaml` (CrUX hosts, `store_html: false`, `inner_pages_max: 20`, pages belong to source `popular`),
  included in `popular-summary`; test in `tests/test_collector_popular.py`.
- Not measured: yield per site, time, effect on false alarms. Estimate only: 8-10 addresses per site, about 1 hour per lakh.
- Known limit before a big HTML crawl: `store.write_crawl` rewrites the whole day file at each checkpoint and `load_crawl`
  loads all HTML at once; the HTML round needs part files and a streaming load.
- Next: Ritvik's 10k-page rebuild finishes first; then a 500-site test of `popular_urls`.

### 2026-10-21 — Popular-sites crawler, 5,000-site pass (cloud)
- Ritvik's PC run (log excerpt, not the file): 5,000 sites, 10,818 deep pages; status ok 2,133, no_pages 1,295,
  robots_disallow_all 891, few_pages 364, robots_unreadable 303, crawl_delay_too_long 14. The end-of-run summary crashed
  with the old `args.verbose` error, so the PC still lacks PR #37.
- Next: update the PC from PR #37, rebuild the pool with `--reload popular`, retrain, re-measure false alarms.

### 2026-10-21 — Retrain stopped: meta_pool.parquet missing after the pool rebuild (cloud)
- Ritvik's `refresh_brands.ps1 -Model` failed at "train the shipped split (0)": `data\processed\meta_pool.parquet` not found.
  Cause (code): `write_parts` deletes every `*.parquet` in `data\processed` before writing, and nothing in the repo
  wrote the `meta_<part>.parquet` files that `experiments/tier_a.load_part` reads (they were made by hand earlier).
- Changed: `data_pipeline.pipeline.write_meta` (called at the end of every build) and `python -m data_pipeline meta`
  (writes the three meta files from the part files without reading html). Test added.
- Next: Ritvik runs `python -m data_pipeline meta`, then the training step again.

### 2026-10-21 — shipped_verdicts crashed on Windows (cloud)
- `python -m experiments.shipped_verdicts` failed on the PC with `UnicodeEncodeError` (cp1252) writing the URL list: a
  natural page address contains a non-ASCII letter. Changed: the temp file and the node subprocess output are read and
  written as UTF-8 (`experiments/shipped_verdicts.py`). Checked with two addresses incl. non-ASCII; not run on the PC.

### 2026-10-21 — Retrain on the pool with the popular-sites crawl: false alarms on natural pages (PC run, read in the cloud)
- Pool rebuilt with `--reload popular` (14,026 crawled inner pages from the 5,000-site pass plus earlier tests; the lakh
  address-only pass was run before the rebuild), then `refresh_brands.ps1 -Model` (tier A and B features, split 0 trained,
  models exported, extension built) on the PC. Both changes (new benign data, 899-brand list) went in together.
- Results (`reports/shipped_verdicts.md`, `data/models/reports_split0/blend2.md` from the PC; the natural pages were excluded from
  the crawl): shipped extension flags 8 of 2,555 natural legitimate pages (0.3%, none dangerous; was 72, 2.82%); address model
  alone 19 (0.7%; was 115, 4.5%); sites outside the top 50,000: 8 of 1,579 (0.5%; was 71 of 1,483, 4.8%). Split 0 blend recall at
  FPR 1%: test 74.2, held-out PhishStorm 71.0, time slice 81.7 (earlier 10-split medians 73.7, 71.5, 84.2). PhishStorm cal 1% FPR 3.2%.
- Caveats: one split against earlier 10-split medians; crawl hosts and natural pages both come from popular-site lists;
  brand-list change not separated. The 10-split tables in `reports/` are not refreshed.
- Next: rerun the 10-split blend (`experiments.blend2`) on the new pool for the report numbers; `shipped_verdicts` encoding fix is PR #41.

### 2026-10-21 — 10-split blend2 rerun on the pool with the popular-sites crawl (cloud)
- `python -m experiments.blend2` over 10 domain-grouped splits on the rebuilt pool and 899-brand list, 4 processes in
  parallel (`PHISHDRIFT_THREADS=1`, one reports dir each, then merged). Files: `reports/blend2.md`, `reports/blend2_rules.md`,
  `reports/blend2_fair.md`, `reports/tables/blend2_*.csv`. Allowlist and blocklist off; median [min, max].
- Results (shipped `agree` rule, warned recall / false alarms): test 71.6 / 0.9; test with HTML 87.7 / 0.4; time slice
  77.5 / 0.8 (blend 81.3 / 1.1); held-out PhishStorm 79.0 / 3.0 (a_only 77.9 / 2.7; `_ws` rules 76.9 / 2.3); natural
  legitimate pages (2,555, no HTML) 1.0 false alarms, dangerous 0.2 (before the crawl: 5.3 / 1.1). Pooled 1% address
  threshold 0.7042 vs source-robust 0.8101 (set by phreshphish in all 10 splits).
- Reading: the false-alarm gain on natural pages holds over 10 splits; recall is about flat (blend test 73.3 vs 73.7
  before, time slice 81.3 vs 84.2). Brand-list change not separated from the crawl.
- Next: `experiments.threshold_transfer` (PhishStorm false alarms), then brand candidates from feed evidence.

### 2026-10-21 — Threshold transfer, main setting (10 splits, cloud)
- `python -m experiments.threshold_transfer --setting main` (4 processes, scores cached; `reports/threshold_transfer.md`,
  `reports/tables/threshold_transfer_*.csv`). Address model hybrid2, rules fitted on cal side, allowlist off, median of 10.
- Target 1%: held-out PhishStorm false alarms / test recall: pooled (current) 2.7 / 68.6; worst_source 1.6 / 64.2;
  ucb_boot 1.2 / 61.9; ucb_binom 1.2 / 61.8; balanced = pooled. Natural pages 0.9 -> 0.7 / 0.6 / 0.5. At 0.1% only
  ucb_binom changes anything (recall 51 -> 36), so the dangerous threshold stays. Not run: loso setting.
- Open: which rule the extension ships for "suspicious" (decision with Ritvik).

### 2026-10-21 — URL check page: calmer theme; repo model files brought up to the retrained export (cloud)
- Changed: `demo/index.html` and `demo/app.js` restyle only (neutral greys with one steel-blue accent, light and dark;
  no glow rings, pill shapes, shake or scanning sweep; smaller radii and plainer intro text). Layout, layers and
  verdict logic unchanged.
- Model check (measured by SHA-256 of files staged from the PC): on the PC, `js/data` (what `python -m demo` loads) and
  `extension/dist/data` (the loaded extension) hold the same `tier_a_hybrid.json`, `tier_b_page.json` and
  `brand_rules.json`, exported 2026-10-21T12:47Z with the 899-brand list. So the page on the PC already used the
  latest model. The repository still had the 2026-10-13 address bundle (67-brand seed list, thresholds 0.850 / 0.986).
- Copied the PC's export into the repo: `js/data/{tier_a_hybrid,tier_b_page,brand_rules}.json`,
  `tests/fixtures/{hybrid_parity,page_parity}.json`, `configs/lists/brand_domains.json` (Wikidata map). New thresholds
  0.834 / 0.980. One demo test asserted the old model's score for `paypa1.com/signin` (now 0.69, suspicious via the
  look-alike rule rather than the model); it now uses `paypa1.com/signin/verify-account`.
- Tests: `npm test` js 15 and extension 70 pass; page checked in headless Chromium (desktop light, 390 px dark).

### 2026-10-22 — Per-source "suspicious" level exported and measured (PC run, read in the cloud)
- The first export on the PC ran on old code (PC files dated 10-20 lacked PR #43), so nothing changed (suspicious 0.834,
  8 of 2,555 natural pages flagged). Delivered the three files, reran `models.export_page --split 0` (about 15 minutes),
  `node extension\build.mjs`, `experiments.shipped_verdicts`.
- Results (split 0, `reports/shipped_verdicts.md` from the PC): address "suspicious" 0.834 -> 0.904 (dangerous 0.980 unchanged);
  natural legitimate pages flagged 8 -> 5 of 2,555 (0.3% -> 0.2%, none dangerous); cal-side 1% FPR on held-out PhishStorm
  3.2% -> 1.28%; recall at the shipped suspicious threshold: test 63.3, held-out 72.6 (cal-side numbers in the bundle).
- Copied the PC's bundles and parity fixtures into the repo (`js/data/tier_{a_hybrid,b_page}.json`, `tests/fixtures/{hybrid,page}_parity.json`).
### 2026-10-22 — Extension "suspicious" level set per source (code; export runs on the PC)
- Ritvik chose "worst source" on the card (`reports/threshold_transfer.md`: held-out PhishStorm false alarms 2.7 -> 1.6,
  natural pages 0.9 -> 0.7, address-only test recall 68.6 -> 64.2, median of 10 splits). `configs/models.yaml`
  `eval.suspicious_rule: worst_source`; `models/export_hybrid.py` and `models/export_page.py` then export the highest
  per-source cal 1% point as "suspicious" (address and blend); "dangerous" stays pooled (no rule helped there).
- Not run: the export needs the split-0 pickle on the PC (`python -m models.export_page --split 0`, then
  `node extension\build.mjs`). Tests pass (export/hybrid/page tests); the shipped numbers will be those of split 0.
- Next: Ritvik runs the export; then recheck natural pages with `experiments.shipped_verdicts`.


### 2026-10-22 — Blocklist rebuilt after every collector run (cloud, script only)
- Why: Ritvik asked whether feeds are collected regularly. The collector task runs every 12 h, but `python -m backend
  build-lists` was a separate manual command, so the blocklist the extension syncs was only as new as the last manual build.
- Changed: `scripts/run_collector_once.ps1` runs `python -m backend build-lists` after the collector (same log; exit 2
  if the build fails). The scheduled task runs this file, so copying it to the PC is enough; no new task.
- Not checked: whether `build-lists` finishes inside the task's 3 h limit, or whether the PC has the backend (uvicorn)
  running; Tranco and CrUX downloads in the scheduled run (a failed Tranco download writes an empty allowlist; the
  extension rejects an allowlist that shrank, see `extension/src/listsync.js`).


### 2026-10-22 — LLM brand check (Gemini) replaces the brand and look-alike rules (cloud)
- Ritvik: drop the old rules completely (no fallback, no shadow), use Google. Plan: `/mnt/project-files/phishdrift/plans/llm_layer_plan.md`.
- Changed: `backend/llm.py` + `POST /llm-check` (Gemini REST adapter, strict four-field JSON parser, `judge`: raise only for a
  confident brand claim on a site that is not the brand's own; provider failure or bad output = no opinion, not cached; daily
  call cap; `llm` block in `configs/backend.yaml`; key only from `GEMINI_API_KEY`); extension (`background.js` `llmWanted` /
  `llmLookup`, `combine.js` `llmEscalate`: one step up, dangerous only if the page asks for credentials, never on blocklisted,
  trusted, allowlisted or short-link addresses; setting `llmCheck`, default off). Sent: host name only (no path words, no URL).
- Removed: `features/{brand_rules,brand_parity,brand_domains}.py`, `js/src/brand_rules.js`, `js/data/brand_rules.json`,
  `configs/brand_rules.yaml`, brand-domain and confusables maps, parity fixture, their tests and `experiments/brand_rules_eval.py`;
  the demo's look-alike screen is now a note that the LLM step needs the backend. The brand list stays as a model feature list.
- Left in place (dead but harmless, parity-tested): `page_facts` collection in `features/html_features.py` / `js/src/html_features.js`.
- Tests: stub provider only, no network. Not measured: everything about quality. `min_confidence` 0.7, `llmGrayLow` 0.5 and the
  Gemini model name are untuned/unverified defaults; no model call has ever been made.
- Known loss: look-alikes the address model scores below the gray zone (the old rules caught `paypa1.com` style hosts) are now
  missed unless the LLM is asked; measure in `experiments/llm_eval.py` (not written yet).
- Next: Ritvik creates a Gemini key and sets `GEMINI_API_KEY` on the backend machine; then `experiments/llm_eval.py` on the PC.

### 2026-10-22 — Popup switch for the LLM brand check (cloud)
- Changed: `extension/src/popup.{html,js}` checkbox writes `settings.llmCheck` (default off; read by `getSettings` on every check).
  Found while delivering PR #47 to the PC: only `extension/src/address.js` there was older than main (missing `isLocalAddress`),
  fixed by copying; other extension, js/src and backend files matched by size.
- Not tested in a browser (no popup test harness); `npm test` extension passes.

### 2026-10-22 — URL check page shows the AI brand check (cloud)
- Ritvik: show the AI step on the URL check page. `python -m demo [--backend URL]` now serves `POST /api/llm-check`, which forwards the
  host name only (validated, nothing else) to the local backend's `/llm-check` (a page cannot call it directly: CORS); fails soft (502).
  `demo/check.js` asks for every address the allowlist, blocklist and short-link rules did not decide (the extension asks only borderline
  ones, so the page asks more often) and passes the answer to the combiner; `demo/app.js` layer 4 shows what was sent, the model's
  answer and whether our code raised the verdict; states: no backend, unreachable, no key (`disabled`), no opinion.
- Checked with a stub backend in headless Chromium (layer 4 scene text read back); tests: pytest demo 2, `npm test` extension 69. Not run
  against the real Gemini.

### 2026-10-22 — Blocklist grows with the Phishing.Database ACTIVE feed (cloud)
- Ritvik: the blocklist was only 9,302 domains / 35,107 URLs (our collector's own URLs). Chose "add it" on the card.
- Changed: `lists.blocklist_feeds` in `configs/backend.yaml` (ACTIVE, cached 1 day); `build-lists` blocklists those URLs by URL key
  only (`exact_block_urls` in `backend/lists.py`), never by registrable domain; `--no-feeds` skips them; extension manifest gets
  `unlimitedStorage` (storage.local default quota is 10 MB). Tests: stubbed feed, no network.
- Measured (cloud, ACTIVE of 2026-10-22, 789k lines, no Tranco so no allowlist candidates): 862k URL hashes, 17.2 MB blocklist JSON;
  Node parse 127 ms + Set build 446 ms, about 90 MB heap. Domain-level listing of the same feed would have blocked 51 of 3,493 natural
  pages (inmotionhosting.com, getresponse.com, google.com.bh ...); URL-level blocks 1 (`https://google.by/`, the feed lists that address).
- Not measured: extension start-up and memory in a real browser with this list, sync time on a slow link, effect on phishing recall.
- Next: Ritvik runs `python -m backend build-lists --tranco-file ...` on the PC and checks the extension loads; decide if the 17 MB is acceptable.

### 2026-10-22 — URL check page: light theme, explanations removed (cloud)
- Ritvik: light theme, attractive, no explanatory paragraphs. `demo/index.html` is light only (indigo accent, white rounded
  cards with soft shadows, logo header); removed the intro line, the "What this page covers" block, the list/model info line
  (an error still shows if the model fails to load), each layer's lead sentence, the registrable-domain caption and the
  build-lists hint. Detection logic and numbers unchanged. `npm test` extension 69 pass; checked in headless Chromium
  (1280 px and 390 px).

### 2026-10-22 — First real Gemini calls: model name, quota and timeout (cloud, from Ritvik's backend log)
- With the logging from PR #51 the failures were readable: `gemini-3.8-flash` answered HTTP 429 "exceeded your current quota" (key and
  model name accepted, no quota for that model on a free key); `gemini-3.5-flash-lite` answered, but the 4 s read timeout expired.
- Changed: model `gemini-3.5-flash-lite` (PR #52); backend `llm.timeout_s` 4 -> 15, extension `llmTimeoutMs` 4000 -> 20000 (limit 30000),
  URL check page proxy 8 -> 25 s. The extension never waits for the answer (late answers raise the verdict), so the longer limit costs no page load time.
- Not measured: Gemini latency per call (only known to exceed 4 s once), answer quality, the free-tier quota of the new model.

### 2026-10-22 — Gemini model chosen by timing on Ritvik's key (cloud, from his PowerShell test)
- Same trivial request on his free key: `gemini-3.8-flash` HTTP 429 (0.4 s), `gemini-3.5-flash-lite` 22.3 s (the 15 s limit expired),
  `gemini-3.5-flash` answered "OK" in 2.1 s. Config model set to `gemini-3.5-flash`. One call each, so latency and quota are not characterised.

### 2026-10-26 — Shortener list scraped from public lists (cloud)
- Ritvik: "scrape famous url shortener from internet" and no hand-written lists. `lists.shortener_urls` in `configs/features.yaml`
  now points at two public lists (PeterDaveHello/url-shorteners, boutetnico/url-shorteners); `python -m features lists shorteners`
  merges them with the old 25-name seed. `configs/lists/shorteners.txt` 25 -> 1,793 entries (90 are subdomains, which never match
  a registrable domain); `js/data/lists.json` and `js/src/pydata.js` regenerated.
- Measured: of 300 OpenPhish URLs 2 are on the list (same 2 as before); regional brand sites 0 of 116; of 3,493 natural legitimate
  URLs 12 (aka.ms, blip.tv, eepurl.com, sched.co). pytest, `npm test` js 11 and extension 69 pass. Browser harness (local pages)
  short-link and redirect cases 13 of 13 on the rebuilt extension, plus one host only on the new list.
- Not done: the shipped model was trained with the 25-name list, so its "is a shortener" feature differs for the new names until
  the PC retrains; a list learned from feed data (hosts that only redirect) is not built.

### 2026-10-26 — Learned shorteners: `python -m collector learn-shorteners` (cloud, code only)
- Ritvik: "go" on learning the shortener list from feed data. `collector/shorteners.py`: candidates = registrable domains with at
  least `min_short_urls` (20) one-segment, token-length <= 12 feed URLs (feed index plus optional `extra_url_files`); each gets
  `probe_urls` (5) HEAD probes (`HttpClient.head`, redirects not followed, no body); a domain is a shortener when >= 3 probes
  answered and >= 80% redirect to another registrable domain. Writes `data/interim/learned_shorteners.txt` and the evidence table
  `reports/tables/learned_shorteners.csv`; `python -m features lists shorteners` merges the file (`shorteners_files`). All limits in
  `configs/collector.yaml` `shorteners:`. Tests: `tests/test_collector_shorteners.py` (stubbed HEAD, no network).
- Not run on real data (the cloud cannot reach the feeds or probe hosts); thresholds are untuned defaults; yield unknown.
- Probes send one HEAD per short URL from the PC's address to hosts that appear in phishing feeds; no page is fetched or followed.
- Next on the PC: run it after a collector run, read the CSV, then rescrape the list, `export-js`, rebuild the extension.

### 2026-10-26 — Gemini brand check: evaluation script, not yet run (cloud)
- Ritvik asked about the Gemini fix; the 10-22 entry says no quality number exists. The cloud has no Gemini key (the key lives on
  the backend machine), so nothing was asked of the model. The Google API itself is reachable from the cloud (403 without a key).
- Changed: `experiments/llm_eval.py` (legitimate hosts = the natural pages `configs/eval/ood_urls.csv`, 2,555 ok rows; phishing = a
  seeded sample of a feed file; look-alikes = `attacks` homoglyph and TLD swap applied to the legitimate URLs, 150 each; the
  address layer via `js/bench/verdicts.mjs` splits every set by "address model passes / flags"; raise rate at confidence cutoffs
  0.5-0.9 from cached answers; resumable, stops on HTTP 429), `.github/workflows/llm-eval.yml` (manual run, key from the
  repository secret `GEMINI_API_KEY`), `tests/test_llm_eval.py` (stub provider).
- Checked with a stub provider end to end (sets built, address layer run, report written); no real model answer exists.
- Next: someone adds the secret `GEMINI_API_KEY` in the repository settings and starts the workflow (about 1,200 calls in all; the
  free-key daily quota is not known, so the run resumes over days).

### 2026-10-26 — AI brand check hosted on Netlify (cloud, code only)
- Ritvik has no PC access, so the Gemini check moves off the PC. Netlify Drop cannot run functions, so the
  demo site is now built from the repository (`netlify.toml`, `deploy/netlify_build.sh`, `docs/HOSTING.md`).
- Changed: `netlify/functions/llm-check.mjs` (POST `/api/llm-check` and `/llm-check`; key from the site's
  `GEMINI_API_KEY`; Netlify per-IP rate limit 20 a minute; per-instance day cache and daily cap
  `llm.hosted` in `configs/backend.yaml`), `js/src/llm_check.js` (JavaScript copy of `backend/llm.py`),
  `python -m backend export-llm-js` -> `js/data/llm_check.json` + `tests/fixtures/llm_parity.json`
  (16 cases, checked by pytest and `npm test`); extension setting `llmUrl` with a popup field (empty = backend).
- Tested here: parity, function with a fake Gemini (key only in a header, cache, errors, bad input, daily
  cap), esbuild bundle of the function, the build script (30 MB site, blocklist 872,658 URL hashes), and the
  built site in headless Chromium with the function behind it: a fake "PayPal" answer shows "Imitation".
- Not tested: a real Netlify deploy (build image, `rateLimit` behaviour), a real Gemini call (no key here).
- Next: Ritvik connects the repo on Netlify and adds the key (docs/HOSTING.md, about 5 minutes).

### 2026-10-26 — Hosted demo "Could not load the model: Load failed" on a phone (cloud)
- Ritvik's screenshot of the Netlify site on an iPhone (Safari). "Load failed" is Safari's wording for a network-level fetch
  error, not an HTTP status, so a model or list download was cut off (cause not confirmed: the cloud cannot reach netlify.app).
- Changed: `demo/app.js` `read` retries once and names the file in the error; `demo/check.js` treats a failed 17 MB blocklist
  download as "no list" instead of stopping the page. The model file (11.7 MB) is still required.
- Not tested on a phone or on Netlify.
- 2026-10-26 later: the hosted page loaded on the phone; its AI step answered `provider_failed` (the function had a key, so it
  is not "disabled"; the Gemini call itself failed: quota, model name or a timeout, not yet known). Changed: the function now returns
  `detail` (Google's error text, never the key) and the page shows it, so the next screenshot names the cause.

### 2026-10-26 — Hosted AI check: bad_answer; output limit raised (cloud)
- Ritvik's next screenshot of the hosted page: the AI step now answers `bad_answer` (the call reached Gemini; the text did not parse
  as the four-field JSON). Likely cause (inferred, not seen): `max_output_tokens: 200` cut the JSON off, since a thinking model spends
  part of the limit on thinking. Changed: `llm.max_output_tokens` 200 -> 1024 (backend and hosted function share it), the function
  returns the first 160 characters of an unparseable answer as `detail`, and the site's cache header is `max-age=0, must-revalidate`
  (the screenshot still showed the old page text because of `max-age=3600`).
- Not tested against real Gemini.

### 2026-10-26 — Hosted AI check: real cause was Gemini quota (HTTP 429); model fallback (cloud)
- Probed the live function from a GitHub runner (the cloud sandbox cannot reach netlify.app; `.github/workflows/hosted-check.yml`,
  runs on push and by hand): both test hosts answered `provider_failed`, detail "HTTP 429: You exceeded your current quota" after 0.4-0.6 s.
  So the key and the site work; the main model has no free quota on this key right now (the earlier `bad_answer` call did get through once).
- Changed: `llm.hosted.fallback_models` (`gemini-3.5-flash-lite`, `gemini-3.1-flash-lite`; names unverified); the function tries them in order on
  429/404/503 within one timeout; the error text names the model. Test added. Not measured: which model has quota on his key.

### 2026-10-26 — AI check prompt made general, with a phishing judgment (cloud)
- Ritvik: not only brand impersonation and not only banks. `backend/llm.py` `SYSTEM` now asks for a phishing judgment of any kind of site;
  the answer has a fifth field `phishing` (0 to 1) next to `brand`, `brand_domain`, `confidence` (brand claim) and `reason`. `judge`
  raises with kind "brand" (as before) or kind "phishing" when `phishing >= llm.phishing_min` (0.85, untuned; `phishing_min` is optional in
  `judge` so the PR #55 evaluation script keeps working, with the phishing rule off). One step up only, never lowers (extension unchanged
  apart from the reason text). Same change in `js/src/llm_check.js`, the Netlify function, the extension reason, the demo page; parity
  cases (+4) regenerated. Input is still the host name only: path words are not sent (a path adds little for this judgment and costs privacy).
- Tested: parity, backend, extension and demo tests with fake answers. Not measured: how good Gemini's phishing probability is; 0.85 is a
  guess. PR #55's cached answers lack the new field and are rejected by `parse`, so rerun its evaluation after both merge.

### 2026-10-26 — URL check page: loading screen (cloud)
- Ritvik: the hosted page takes a while to load the model. `demo/index.html` + `demo/app.js`: a loading card over the
  page lists each file being fetched with MB received ("x of y MB" when the server sends an uncompressed size), a bar
  (by bytes when all sizes are known, else by files finished), "retrying" on the second attempt and "failed"; hidden
  once loading ends, and the old error text still shows on failure. `demo/check.js` now fetches the lists alongside
  the model instead of after it. Checked in headless Chromium at 2 MB/s (390 px) and with the model download blocked;
  not checked on Netlify (compressed responses: MB only, bar by files) or on a phone.

### 2026-10-26 — Hosted AI check timing out: each model gets its own share of the time (cloud)
- Ritvik's page showed `provider_failed: TimeoutError` (9 s limit). Probed the live function from a GitHub runner with six fresh
  hosts: all six answered `TimeoutError` after 9.15-9.27 s (earlier the same site answered in 1.0-1.6 s). So the main model
  (`gemini-3.5-flash`) did not answer within 9 s on those calls; the fallback chain was never reached because a timeout is not an
  HTTP error and the whole 9 s was one shared deadline. Why Gemini was slow is not known (overload, thinking time or a cold start;
  not measured, the cloud has no key).
- Changed: `askGemini` gives each model an equal share of the remaining time (3 s each for three models, whole milliseconds:
  `AbortSignal.timeout` throws RangeError on fractions, which my first version hit), moves on after a timeout or HTTP 429/404/500/503,
  and the error text lists every attempt with its time. Tests: slow first model replaced by the second; cap test unchanged.
- Not measured: which model answers in time right now; a 3 s share may be short for a slow day.

### 2026-10-26 — Short links followed to their destination (cloud)
- Ritvik: short links were skipped, not opened. Checked what happened: the URL check page never followed a short link
  (it showed "short link" and stopped). The extension does see the destination (the browser follows the redirect and
  `onCommitted` scores the landing address before the page renders), but its shortener layer used the model bundle's
  25 names, not the 1,793 of `js/data/lists.json` (PR #54), so e.g. `aka.ms` was scored or allowlisted as a site of its own.
- Changed: `js/src/short_links.js` (follow hops while the address is on a shortener; HEAD, then GET with a 32 KB read for
  `<meta refresh>`; the first address off a shortener is returned without being requested) and
  `netlify/functions/expand.mjs` (`POST /api/expand`; only shortener addresses accepted; ports 80/443; connections to
  private, loopback, link-local and reserved addresses refused at connect time; 5 hops, 8 s; 20 a minute per IP;
  `short_links` in `configs/backend.yaml`, exported to `js/data/short_links.json`). `demo/check.js` checks the destination
  instead of stopping ("Short link X leads to Y"); `withShorteners` in `extension/src/lists.js` gives the extension and the
  page the full list (the model keeps the list it was trained with). `js/bench/expand_probe.mjs` +
  `.github/workflows/short-link-probe.yml` follow real short links from a GitHub runner.
- Tests: `npm test` js 25, extension 73, pytest pass, ruff clean. The e2e smoke test fails at its first step in this
  container on main as well (Chromium shows `chrome-error://`), so it was not run. Not tested: a real Netlify deploy.

### 2026-10-26 — Claim check of the coverage checklist, quick wins and recent reports (cloud)
- Ritvik: short links were reported as handled while the URL check page did not follow them. Re-checked every "covered / passed /
  handled" claim against main 22582a1; table with labels (verified / reported only / wrong) in `audit/coverage_checklist.md`.
- Verified: extension short-link and redirect cases 13 of 13 (headless Chromium, local pages); natural-page false alarms 5 of 2,555
  with the shipped model (the committed `reports/shipped_verdicts.md` still showed 71, regenerated); tests js 25, extension 74,
  pytest 560, ruff clean; hosted helper follows bit.ly, aka.ms, t.co, is.gd from a GitHub runner and the live page judges the destination.
- Wrong or stale: the demo page called 192.168.0.1 dangerous (fixed: `demo/check.js` uses `isLocalAddress`, test added) and said "the
  allowlist keeps it safe" for an unfollowed short link (fixed: `demo/app.js`); tinyurl.com and cutt.ly are not followed (preview page,
  403), so the page still cannot judge those; the attack harness gives 23 of 35 on today's build (its "suspicious address" now scores
  0.75 under the 0.904 cut-off) and 32 of 35 after swapping that one address; PR #55 (AI check evaluation) is still open.
- Measured now: look-alike coverage with the AI check off: homoglyph 2%, one letter off 1%, brand + word 78%, TLD swap 54%,
  punycode 87% warned. Live AI check: 4 of 6 then 2 of 2 hosts answered, 4-9 s per call.
- Added `.github/workflows/audit-probe.yml` (live-site probe: files, `/api/expand`, `/api/llm-check`, short links in a browser).
- Not done: tinyurl/cutt.ly following, recalibrating the harness in the repo, the AI-check accuracy set (PR #55), anything needing the PC.

### 2026-10-26 — tinyurl.com followed; cutt.ly and other shortener warning pages reported plainly (cloud)
- Why: the claim check (PR #64) found the URL check page could not follow tinyurl.com (preview page) or cutt.ly (403).
  Looked at the real answers from a GitHub runner (run 40404563171, request = our own User-Agent, no evasion):
  tinyurl.com answers a link it has flagged with a redirect to its own `/app/nospam/...` page, but the same answer carries the
  real long address in the response header `x-lighttpd-longurl`; `preview.tinyurl.com` is behind a Cloudflare challenge (403,
  left alone). cutt.ly answers the one OpenPhish link we have with a redirect to `/guard/<code>`, whose page (HTTP 403) is titled
  "Cuttly Safe Redirecting system blocked that redirect": the service itself blocked the link; no destination is given.
- Changed: `js/src/short_links.js` reads a destination from a response header named `x-...longurl` (`headerDestination`;
  the address is only checked, never requested, and must be a web address) and reports a shortener's own non-redirecting page as
  `service_page` (was `no_redirect`); `netlify/functions/expand.mjs` returns response headers to `expand`; `demo/check.js`
  words `service_page` as "the link's own service sent it to one of its pages (...): usually a warning, preview or removed-link
  page". No verdict is raised from a service page: the destination is unknown. New `js/bench/shortener_survey.mjs` and
  `.github/workflows/short-link-survey.yml` follow up to 3 real links for each of the 30 shortener domains most seen in the
  Phishing.Database ACTIVE feed (789,054 lines on 2026-10-26) with the hosted function's own code.
- Results (GitHub runner, 2026-10-26, run 40405109457): `https://tinyurl.com/2wjsu676` (before: stopped at the no-spam page)
  now FOLLOWED to its destination in one HEAD request. `http://www.cutt.ly/ZyWDEv25/` stops with `service_page` (cutt.ly guard,
  403): not followable by design of the service; I did not try to get around it. aka.ms (2 of 2) and short.gy (1 of 3) followed.
  Survey of 12 shortener domains from the feed, 32 links: 5 followed in all (incl. the extra links), the rest 403/523 from the
  service (short.gy, v.ht, 8u.cz, cutt.us: bot blocks), dead (bit.do timeouts, tiny.cc refused, rdcu.be no DNS), removed
  (gg.gg back to its home page) or not shorteners at all.
- Found: `js/data/lists.json` shorteners contains free-hosting and non-shortener names that do appear in feeds (x10.mx, 8u.cz,
  kr3w.de, t.me, rdcu.be); the scraped list (PR #54) needs a quality pass. Not done here.
- Not measured: a benign tinyurl or cutt.ly link (cannot create one without an account); whether tinyurl sends the header
  for unflagged links (then the ordinary Location redirect applies and was already followed). Tests: `npm test` js 27,
  extension 74, ruff clean.

### 2026-10-26 — Attack harness in the repo, recalibrated at run time (cloud)
- Ritvik: fix the gaps found by the claim check (PR #64); this one is "the harness reports 23 of 35". The harness was in the
  project folder, with `evil-blocked.com` hard-coded as the "suspicious" address; after the retrain it scores 0.75, under the
  0.904 cut-off, so the page-based cases lost their trigger. The extension had not broken.
- Changed: `extension/e2e/attack/` (`harness.mjs`, `calibrate.mjs`, `pages/`, `run.sh`, `offline.sh`, `lo_up.py`,
  `results.md`), `.github/workflows/attack-harness.yml` (manual). `calibrate.mjs` scores candidate hosts with the shipped
  model and picks suspicious, dangerous, safe and "dangerous by address only" test hosts; it stops with an error if a band is
  empty. Fake blocklist no longer contains `example.com` (the extension refuses a list with a top site, so the trust cases
  never saw a blocklisted domain). "Back to safety" cases use a dangerous page that asks for a password; new case
  `D-address-only-dangerous-is-banner` pins the 2026-10-20 behaviour. Each change is explained in `results.md`.
- Results (measured, headless Chromium, local pages): 36 of 36 pass in 3 runs (one with the network cut off), 2 info lines.
  Same harness with only the address swapped: 34 of 35. Old harness: 23 of 35.
- Not done: the 2026-10-26 quick-win cases (short links, redirects, PDF) stay in the project folder; the workflow has not run on a GitHub runner yet.


### 2026-10-26 — Offline look-alike check (works with the AI check off) (cloud)
- Why: the claim check (PR #64) measured that with the AI check off only 2% of `micr0soft.com`-style and 1% of `paypl.com`-style
  look-alikes were warned. Ritvik asked for an offline check learned from data, no hand-typed lists.
- Changed: `js/src/lookalike.js` (two escalate-only rules: `homograph` = the name equals a brand's name after look-alike characters are
  folded, punycode decoded; `edit1` = one edit or neighbouring swap from a brand name of 6+ letters), `features/lookalike.py` +
  `python -m features lookalike` -> `js/data/lookalike.json` from `configs/lists/brands.txt` (899 brands), the brand-to-own-domains map
  (`configs/lists/brand_domains.json`, Wikidata + MISP) and the Unicode confusables table (`configs/lists/confusables.json`), both
  restored from before the 10-22 removal; `configs/lookalike.yaml`; `extension/src/combine.js` `lookalikeEscalate` (one step up: safe to
  suspicious, to dangerous only if the page asks for credentials; never lowers; never on trusted, blocklisted, allowlisted, short-link
  or local addresses; shares `stepUp` with the AI check), `background.js` (computed per address, cached with the layers),
  `demo/check.js` + `demo/evidence.js` (combiner step and model trace line; no new screen), `extension/build.mjs`, `deploy/netlify_build.sh`.
  `js/bench/lookalike.mjs` + `experiments/lookalike_eval.py` -> `reports/lookalike.md`, `reports/tables/lookalike.csv`.
- Not brought back: the old `embedded`, `combo` and brand-page rules, and the Python mirror of the browser rule (no parity fixture; the
  JS rule is the only implementation and is tested in `extension/test/lookalike.test.js`).
- Results (`reports/lookalike.md`, shipped address path with the bundled allowlist, no page/backend/blocklist; generated look-alikes of
  894 brands on the list, warned before -> after): ASCII look-alike letters 0.2% -> 99.8%, punycode 68.3% -> 100%, one letter off
  0.5% -> 79.0%, brand + word 77.0% (unchanged), TLD swap 23.4% (unchanged, not handled). The same families made from 241-455 site
  names that are NOT on the brand list: unchanged (0% ASCII, 0% one letter), because the rule can only protect brands on the list.
- False alarms (rule hits): natural legitimate pages 0 of 2,555; regional brand sites 0 of 114; `brand.com` of 894 brands 0. On two
  public domain lists used only as test data (OpenDNS top 10k and random 10k, 15,948 not on the allowlist) the rule fired on 20
  addresses, 14 of them not allowlisted; most are real typosquats (facobook.com, hpotmail.com, compcast.net); the clear legitimate ones
  are blogher.org/.com, xiami.com, fenjer.org, mahindras.org, telegraf.biz (6 of 15,948, 0.04%), each a suspicious banner.
  Real OpenPhish hosts (300): 199 -> 200 warned (4 rule hits).
- Tuned on: `min_edit_len` 6 was chosen on these same legitimate sets (natural pages, regional sites, OpenDNS lists): 5 added false
  alarms on bader.at (bayer) and vivacom.bg (viacom), 4 also on ocbc.com; 7 lost one-letter coverage (68%). So the false-alarm numbers
  above are not an independent test of that choice.
- Limits: the generated look-alikes are made from the same brand list the rule uses, so their catch rates are an upper bound for brands
  on the list and say nothing about brands outside it. Brands with no entry in the brand-to-domains map (about 170 of 899) are
  protected only by the "same name on another suffix is the brand's own" rule. A brand's name on another suffix (`paypal.xyz`) is not
  caught. Not run in a real browser (the e2e smoke test cannot start Chromium in this container); `npm test` extension 82, js 25, pytest, ruff pass.

### 2026-10-26 — Retrain with the 1,793-name shortener list (PC run by Ritvik, read in the cloud)
- Ritvik ran the learner (feed index alone: 0 candidates; with the Phishing.Database ACTIVE file: 61 probed, 3 kept: `fy9.in`, `th.link`,
  `urlth.me`), merged the list (1,796 entries) and ran `refresh_brands.ps1 -Model`. Exported model dated 2026-10-26 21:24 IST.
- Results (split 0, pasted by Ritvik, not re-run here): natural legitimate pages flagged 5 of 2,555 (0.2%, none dangerous), model alone
  12 / 3, 5 of 1,579 outside the top 50,000: identical to 2026-10-22. Blend recall at FPR 1% test 74.2, held-out PhishStorm 71.0, time
  slice 81.7: identical to 2026-10-21. Ritvik's answer to "is blend2.md dated today?" was "no change"; read as "no change in the
  results" (the file's date was not confirmed), so either the shortener feature moved nothing or the report was not rewritten.
- Not measured: whether the 10-split medians change; the learner finds few shorteners (most probed hosts gave no answer or no redirect).

### 2026-10-27 — PDFs, downloads and other file types (cloud)
- Ritvik: "what about PDF websites or other file types". Checked the code and ran real Chromium (attack harness, local pages, offline,
  new `F-` cases in `extension/e2e/attack/harness.mjs`; PDF viewer included).
- Verified before the change: a PDF is a normal committed page (content script runs in the viewer's page): banner on a suspicious or
  dangerous address, warning page on a blocklisted one; a link clicked inside a PDF is checked like any navigation (warning page).
  A download does not commit: the extension showed nothing (toolbar badge only) and overwrote the open page's stored verdict and
  badge with the file address's verdict (a safe page turned to "suspicious" in the popup, its later rechecks were dropped as "left").
- Changed (`extension/src/background.js`, `combine.js` `downloadWarning`, `content.js` banner `headline`): a navigation Chrome reports
  as `net::ERR_ABORTED` (a download) restores the page's own tab state and badge, keeps it as the tab's current navigation, and a
  suspicious file address shows a banner on that page ("a file was just downloaded from <domain>, and that address looks suspicious").
  A blocklisted file address still opens the warning page. Never lowers a verdict; no file-type or extension list.
- Results (real Chromium, `F-` cases): 9 pass, 0 fail, 4 info; full harness 45 pass, 0 fail, 6 info; `npm test` extension 84 pass.
- Not fixed: the file is not stopped (it has already started when the warning shows; MV3 cannot block per URL against the list);
  a new tab sent straight to a file has no page for a banner (badge only); PDF/file contents are not read; a download from an
  allowlisted address is trusted; the URL check page scores the address only (it cannot see a content type) and says "Not a web
  address" for data:, javascript: and mailto:.

### 2026-10-27 — Picture-only login page rule (cloud)
- Gap (claim check, PR #64): a page whose sign-in box is one image or canvas (no password field, almost no text) on a safe-looking
  address got no warning. Changed: `extension/src/content.js` `visualFacts` (readable text, input fields, share of the window the
  largest img / canvas / svg / CSS background picture covers), `extension/src/pagefacts.js` `isPictureOnly` (under 100 characters of text,
  no fields, picture at least 10% of the window, no credential fields), `extension/src/combine.js` (safe is raised to suspicious when
  `pictureOnly` and the address model's score is at least `PICTURE_MIN_PROB` = 0.5; never lowers; not on trusted, allowlisted,
  blocklisted, short-link or local addresses). New: `js/bench/picture_facts.mjs`, `js/bench/address_probs.mjs`,
  `experiments/picture_only.py` -> `reports/picture_only.md`.
- Measured (`reports/picture_only.md`; 2,373 natural legitimate pages with stored HTML, 2,335 rendered offline in headless Chromium,
  images and styles never load): no text and no fields 84 pages (52 with the allowlist), plus a picture element 23 (16), plus a picture
  over 10% of the window as far as the offline render can measure 4 (2). Raised by the rule at gate 0.5: 0 of 2,335 under every
  definition and with or without the allowlist (0.4: 1 page, which has no picture, so the rule would not apply; 0.3: 4, same). Rule of three:
  the true rate on such pages is under about 0.13%. Phishing side, address only (5,000 random URLs of Phishing.Database ACTIVE, 2026-10-26;
  no phishing HTML exists here): the address model warns 3,887; 885 are warned by neither the address model nor the page path for a page the
  page model cannot read; of those 531 (60%) score 0.5 or more and would be raised if their page were picture-only (0.6: 418, 0.8: 132).
- Why 0.5: the lowest gate where even the loosest legitimate definition (no text, no fields, picture not required) gives 0 alarms. The legitimate
  counts are tiny (a few pages), so the gate is not tuned finely; the phishing and legitimate sets were both used to pick it, so these are
  not independent numbers. The area share 10% is a guess for a login-box-sized picture (the offline render cannot measure real image sizes).
- Browser test (`extension/e2e/smoke.mjs` step 4d, headless Chromium, network cut, local canvas page with a generic "Sign in" box and no brand):
  address scoring 0.60 gets the banner and a stored verdict of suspicious (layer page); the same page at 0.45 and an ordinary text page at 0.77
  get nothing. `npm test` extension 89 pass. The rest of that smoke file still fails here (its first steps use `wikipedia.org`, which Chromium
  upgrades to https, and `evil-blocked.com/a`, which no longer scores suspicious after the retrain), so step 4d was run in a trimmed copy.
- Stale banner (suspicious address, picture page, stored verdict safe): not reproduced. 4 runs on `evil-blocked.info` and 2 on `.com` of the
  round-2 picture case gave banner and stored verdict in agreement every time (the new rule keeps them in agreement on pages it covers).
- Not done / limits: a picture-only page on an address scoring under 0.5 is still not warned (about 40% of the feed phishing that nothing else
  warns, address side); no real picture-only phishing page was available; a picture drawn after load is not rechecked (only new input fields
  trigger a recheck); the rule needs layout (it runs in the content script, so it cannot be measured on stored HTML except as the upper and
  lower bounds above).

### 2026-10-27 — One-split CharCNN test for the tier A hybrid: no gain on a sample of the pool (cloud)
- Why: the conference-paper plan (`/mnt/project-files/phishdrift/paper/conference_plan.md`) lists a deep member for the tier A
  hybrid as an add-on experiment behind a stop rule. The PC was not reachable (Remote Control refused), so it ran in the cloud.
- Changed (new files only; nothing shipped or configured for the shipped model is touched): `models/char_cnn.py` (multi-scale
  character CNN, same fit/score interface as the other text scorers, checkpoint after every epoch, deadline), `configs/char_cnn.yaml`,
  `experiments/char_cnn_a.py` (split 0: CNN against the char n-gram LR next to it, shuffled-label control, hybrid2 with and without
  the CNN as a fifth out-of-fold scorer; test, per source, held-out source, natural pages, normalised URLs),
  `experiments/char_cnn_stage.py` (builds the processed folder from a URL sample), `scripts/run_char_cnn.ps1` (the same run for the
  PC, not used), `tests/test_char_cnn.py`, optional dependency `deep`.
- Data (differs from the PC's pool; stated in the report): the 116k-URL sample staged for the prior-study run, deduplicated by uid:
  84,938 pool URLs (PhreshPhish, PhiUSIIL, URL-Phish, Phishpedia, a few live), held-out PhishStorm 20,000, 2,555 natural pages;
  per-source weights, one domain-grouped split (seed 0). No time slice (no dates), no HTML. About a fifth of the PC pool, so the
  absolute numbers are not comparable with the 10-split tables.
- Results (`reports/char_cnn_sample_split0/SUMMARY.md`, one split, 6 epochs, about 28 s per epoch on 4 cores): CNN alone against
  the n-gram LR: test recall at FPR 1% 59.5 vs 61.4, held-out 53.3 vs 53.8, normalised URLs 36.4 vs 35.3; shuffled-label control
  0.5000. Hybrid2 with the CNN scorer against hybrid2: test 71.3 vs 71.2, held-out 74.4 vs 75.3, normalised 42.2 vs 42.1. All changes
  are within the 2-point bar (a proposal, not an approved rule): no gain from the deep member on this sample. Natural-page false
  alarms at the cal 1% point 3.1% (hybrid2) and 3.2% (with CNN), higher than the PC's pool (the sample has few crawled deep benign pages).
- Not done: the hybrid's own shuffled-label control, other splits, the full pool (PC data), a larger or different deep model.
- Next: decision with Ritvik and the mentor on whether to keep the deep member in the paper as a "no gain at this size" row.

### 2026-10-27 — Own demo site called dangerous: shared-host cap (cloud)
- Ritvik pasted the Netlify demo's address into the URL check page and it said phishing. Reproduced locally with the
  page's own checker (`demo/check.js` on the built extension): `https://loquacious-starship-3425f0.netlify.app/` scores
  0.983, above the 0.980 dangerous cutoff, decided by the address model alone (not the blocklist, look-alike rules,
  short-link rule; the AI check can only raise). Cause: the model has learned that a host on a free-hosting platform with
  a tenant-chosen name (Netlify's default `adjective-noun-hex` names are common among phished sites) looks like phishing.
- Changed: `extension/src/combine.js` caps the address model's verdict at suspicious on shared hosting (platforms and
  open-hosting zones) unless the page asks for credentials; the page model, a list or domain evidence can still reach
  dangerous. Tests in `extension/test/combine.test.js`. `js/bench/shared_hosts.mjs`, `experiments/shared_host_cap.py` ->
  `reports/shared_host_cap.md`; `.github/workflows/shared-host-probe.yml` asks the live page.
- Measured (Umbrella top 1M tenant hosts as a rough legitimate stand-in, 2,337 hosts; ACTIVE feed sample, 7,787 URLs; address
  layers only): dangerous 21.7% -> 0 on Umbrella tenants, 55.6% -> 0 on feed phishing; warned (suspicious or worse) unchanged
  at 49.0% and 83.1%. The site itself: dangerous -> suspicious. Not solved: half of ordinary tenant hosts still get the
  suspicious banner; that needs the model calibrated on benign tenant hosts (retrain, needs the PC's pool).

### 2026-10-27 — Tier C without the PC: capture on GitHub Actions, domain rows, hosted check (cloud)
- Ritvik: "start working on tier c and finish what is left", then "get a good number of figures" and "10k is low". Plan:
  `plans/tier_c_plan.md` (project folder). PR #72.
- Changed: capture moved to GitHub Actions (`.github/workflows/tier-c-capture.yml` hourly, `tier-c-legit.yml` daily in 8 shards,
  `tier-c-train.yml` weekly report), data on the orphan branch `tier-c-data` (`scripts/ci_data_branch.sh`; datasets never on main).
  `collector/domain_capture.py` captures one record per registrable domain (apex, `www.` fallback, platforms and IPs skipped, direct
  registry RDAP from the IANA bootstrap), `collector/capture_feeds.py` polls fresh phishing (OpenPhish, PhishTank, PhishStats with
  timestamps; bulk lists only count domains added after the first poll), `python -m collector capture-phishing | capture-legit`.
  Serving: `js/src/tier_c.js` (29 features, parity with Python on 240 cases), `js/src/domain_check.js`,
  `netlify/functions/domain-check.mjs`, `models/tier_c.py` (train, bundle `js/data/tier_c.json`, reasons), extension `tierCUrl`
  setting and combiner rule (raises suspicious to dangerous, never lowers, never warns on a safe address, off by default).
  `experiments/tier_c.py`: 14 h lag limit with a 2 h sensitivity run, `--a-scores` comparison with the shipped address model.
- Measured (runner probe): OpenPhish, registry RDAP, DoH, TLS handshakes and Tranco are reachable from GitHub runners; about a quarter of
  Tranco domains sit on TLDs with no RDAP server. 4,000 legitimate domains take 15-35 min per runner; 8 runners gave 32,025 domains in
  35 min (76% got an RDAP answer, 92% resolve). Phishing: 217 domains after the first hour (OpenPhish was mostly on platforms or already
  captured); realistic yield is a few hundred a day (guess from the feed rates seen, not a forecast).
- First look (10 domain-grouped splits, 44 phishing / 6,395 legitimate per test side; not final, one capture day): tier C ROC-AUC 0.829
  [0.757, 0.896], without age 0.817, age alone 0.679, with the shipped address model's score 0.853 (that model alone 0.836); recall at
  1% FPR 54.5% (tier C), 0.1% points granularity-limited; shuffled-label control 0.46, not flagged; nothing above 99%. Time check
  needs 3 capture days.
- Caveats: legitimate domains are Tranco-listed, so young legitimate sites are missing and the false-alarm rate on them is unmeasured;
  the address model's training pool is unknown here, which favours it; the Netlify function is tested with a fake network only.
- Next: merge PR #72 (starts the schedules), let 3 capture days pass, run `tier-c-train`, apply the gates, then ship `js/data/tier_c.json`.
