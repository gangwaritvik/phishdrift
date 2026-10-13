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
