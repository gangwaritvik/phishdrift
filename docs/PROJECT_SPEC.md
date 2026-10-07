# PhishDrift — project specification

## Context

- Solo student project, 6th semester, 3 credits, project-based learning.
- Must be novel versus earlier semesters (which built standard URL classifiers with 2–4 ML algorithms
  on static datasets).
- Builds on the prior study `docs/prior_work/representation_sensitivity_report.pdf` (v1.1.1,
  2026-09-10), cited below as "the report".
- Deadline: about 3 weeks from 2026-10-02 (confirm the exact date and update it here).
- The student is comfortable with Python, ML, web and extension development.

## Goal

Build the best practical phishing detector: maximum detection at low false-positive rates (recall at
FPR 1% and 0.1%), by pooling many public datasets and live feeds into one corpus and computing every
feature with our own extraction engine. Deliver it as a Chrome extension (MV3) + FastAPI backend.

The report showed that a benchmark score depends heavily on URL representation, source composition and
the particular split (§14, F1–F4). This project therefore treats the evaluation protocol as part of the
product: a detector only counts as good if it holds up on sources, time periods and legitimate pages it
never trained on.

Headline result to aim for (fill with real numbers from `reports/`):
"Pooled tiered detector reaches X% recall at 0.1% FPR on a held-out source and Y% on the newest time
slice (median of 10 domain-grouped splits), with Z% FPR on naturally browsed legitimate inner pages,
shipped as an explainable Chrome extension."

## Lessons from prior work

Each lesson cites the section of the report it comes from and the rule it produces here.

| # | Finding (report §) | Rule in this project |
|---|---|---|
| L1 | Raw-URL ROC-AUC on PhiUSIIL was 0.9988 and fell to 0.7297 when URLs were normalised to `https://www.<registrable domain>`; the pattern replicated across XGBoost, logistic regression and char n-grams (§13.1, §13.2, §13.4). | Never report only raw-representation results; run a representation check on tier A. |
| L2 | PhiUSIIL legitimate URLs are 100% bare `https://www.<domain>` homepages, and its precomputed `URLSimilarityIndex == 100` almost perfectly identifies the legitimate class (§7). | Never use precomputed feature columns. PhiUSIIL legit is never the only benign source. |
| L3 | A benchmark-trained raw model flagged all 11,895 naturally collected legitimate URLs from 362 sites (FPR 1.0) against a held-out benchmark FPR of 0.00026; a surface-normalised model flagged 9.0% (§13.11). | Report out-of-distribution FPR on naturally browsed legitimate inner pages for every model. |
| L4 | 100% of PhiUSIIL legit URLs are depth 0, against 72.8% of PhiUSIIL phishing, 38.8% of PhishTank and 0% of the crawler benign pools (§13.7). | Report per-class depth distributions; fail the build if any depth bucket is >90% one class; depth-matched evaluation. |
| L5 | Masking specific hosting-platform identity increased held-out normalised AUC in 60 of 60 seed-cell comparisons (§13.9). | Platform-identity masking via `configs/platforms.yaml`; only `is_hosting_platform` is exposed. |
| L6 | 593 domains appeared in both phishing corpora, mostly hosting platforms and shorteners, carrying 34.28% of PhiUSIIL phishing rows and 59.51% of PhishTank rows (§8). | Remove domains that appear in more than one phishing source from all sources. |
| L7 | Symmetric registrable-domain dedup collapsed the benign class until low-FPR operating points became undefined (§8). | Domain dedup must keep enough benign rows to measure 0.1% FPR; check negative counts. |
| L8 | Normalised AUC varied across 10 splits with SD up to 0.1164, against at most 0.0026 for raw (§12.2, §13.6). | Report the median and spread over 10 domain-grouped splits, never one split. |
| L9 | Swapping the phishing corpus while holding benign fixed moved normalised AUC by 0.13–0.16 (§13.5). Transfer to an independent benign population stayed above chance (0.69–0.71) but rested on 119 domains (§13.8). | Leave-one-source-out table and a held-out source; report domain counts next to every result. |
| L10 | Char n-gram TF-IDF + logistic regression held up best under full normalisation (R4 0.8343 vs 0.7212 XGBoost, 0.6905 LR on engineered features) (§13.4). | Char n-gram TF-IDF + LR is a base learner; its vocabulary is fitted on training folds only. |
| L11 | Shuffled-label controls gave AUC ≈ 0.50 with no condition flagged under \|mean − 0.5\| > 0.05 (§13.12). | Keep shuffled-label negative controls with the same flag rule. |
| L12 | Fixed-FPR points use the largest attainable point at or below the target, and are reported with achieved FPR, threshold, negative count and 1/n_neg; points on <10 negatives are granularity-limited (§12.3). | Same operating-point procedure in `experiments/`. |
| L13 | Metrics are URL-weighted while URLs per domain ranged from 1.02 (PhiUSIIL legit) to ~23 (crawler pools) (§12.1, §16.1). | Report URL counts and domain counts separately; cap URLs per domain. |
| L14 | PhishTank's online-valid feed is biased toward long-lived phishing (median submission 2026-01) (§13.13, §16.2). | PhishTank is a secondary source only. |
| L15 | Grouping must use a case-normalised registrable-domain key; zero domain and URL overlap and TF-IDF vocabulary isolation were enforced as hard run-time failures (§9, §26). | Same hard failures in the split and model code. |
| L16 | Crawler reachability differed (946/1,200 vs 605/1,200 domains) and correlated with popularity (§8, §16.1). | Log crawl success per domain; report crawlability with the benign pool. |

## Data design

### Unified raw schema

`url, domain, label, date, source, html, depth` — see CLAUDE.md for definitions. Extra columns may be
kept for bookkeeping (e.g. the sub-feed a live URL came from) but are never model features.

### Sources

PhreshPhish (main; URL + HTML + dates), PhiUSIIL (URL column only), Phish360, Phish-Blitz,
Phishpedia 30k (phishing only), URL-Phish, PhishStorm, and our live feeds (OpenPhish,
Phishing.Database, PhishTank as secondary). Details and caveats: FEATURES_AND_DATA.md.

### Corpus build (before any split)

1. Load each source into the schema without any precomputed feature columns.
2. Canonicalise URLs identically for every source; dedupe by canonical URL across all sources (conflicting
   labels → dropped).
3. Remove every registrable domain that appears in more than one phishing source, from all sources.
4. Enforce registrable-domain disjointness across sources and cap URLs per domain (see open question in
   PROGRESS.md).
5. Near-duplicate HTML removal within each label.
6. Benign mix: PhiUSIIL legit homepages + PhreshPhish benign + inner pages crawled from PhiUSIIL-legit and
   Tranco seeds (3–5 inner pages per domain, robots.txt and rate limits respected).
7. Per-source class balance (both classes where possible) and depth balance; per-class depth report; the
   build fails if any depth bucket is >90% one class.
8. Carve out the held-out source and the newest time slice before any fitting.
9. Data card in `reports/`: per source URL and domain counts, dates, class balance, depth distribution,
   dedup and removal counts, crawl success.

## Models

- Feature engine and tiers: see CLAUDE.md and FEATURES_AND_DATA.md.
- Base learners per tier: LightGBM, XGBoost, char n-gram TF-IDF + logistic regression.
- Stacking: out-of-fold predictions (domain-grouped folds) feed a meta model per availability pattern
  (A, A+B, A+B+C), so missingness is never a feature.
- Adversarial URL variants from `attacks/` added to training folds only; each variant stays in its
  parent's domain group.
- Isotonic calibration on a domain-disjoint calibration slice. "Suspicious" = threshold at FPR 1%,
  "dangerous" = threshold at FPR 0.1%.
- Tier A exported for the browser (ONNX or tree-to-JS) with a Python–JS parity test.
- SHAP values mapped to plain-English reason strings.

## Product architecture

Runtime layers, cheapest first (details in CLAUDE.md): allowlist → blocklists → tier A URL model in
the browser → backend domain checks (tier C, unknown domains only) → page checks (content script,
tier B) → calibrated combiner → safe / suspicious / dangerous with reasons → optional LLM second
opinion (gray zone only, opt-in, can never override a blocklist hit or "dangerous").

Chrome extension (MV3): service worker (navigation checks, per-domain verdict cache), content script
(page checks, link hover checks), interstitial for "dangerous", banner for "suspicious", popup with
reasons, "report false positive" button.

FastAPI backend: `/score`, `/domain-info` (cached RDAP/DNS/TLS), `/feedback`, and a builder for compact
hashed blocklists the extension syncs daily. Per-domain cache, timeouts, rate limits.

## Evaluation

Main evaluation (all from `experiments/`, written to `reports/`):
1. 10 domain-grouped splits of the training pool: median and spread of recall at FPR 1% and 0.1%,
   precision, F1, ROC-AUC, PR-AUC, per tier and per base learner vs stack.
2. Held-out source and newest time slice: the same metrics, plus the FPR the calibrated thresholds
   actually produce there.
3. Leave-one-source-out table.
4. Depth-matched evaluation; representation check (tier A on `https://www.<registrable domain>`).
5. Out-of-distribution FPR on naturally browsed legitimate inner pages, for every model.
6. Shuffled-label negative controls (flag |mean AUC − 0.5| > 0.05).
7. Models measured with layers 1–2 disabled; blocklist coverage reported separately.
8. Leakage tripwire: any held-out-source result >99% is investigated before reporting.

Small robustness section:
- Drift: the newest-time-slice result compared with the 10-split median.
- Adversarial: evasion rate per attack family (homoglyph/punycode, subdomain stuffing, brand
  injection, path/query padding and encoding, shortener wrapping, TLD swap/hyphenation) before and
  after adversarial training, with one family held out; clean recall and FPR re-checked; benign
  stress test with long legitimate URLs and real shorteners.

## Milestones and acceptance criteria

1. **Data:** schema + all source loaders + corpus build (dedup, phishing-source domain removal,
   disjointness, depth balance and check) + holdouts + data card; collector running every 12 h with
   first-seen domain capture. Tests for schema, eTLD+1, dedup, depth check and split disjointness.
2. **URL features:** tier A features with platform masking, registered in the registry, a test per
   group; FEATURE_DICTIONARY.md generated.
3. **HTML features:** tier B features with tests.
4. **Tier A/B training:** LightGBM, XGBoost and char n-gram TF-IDF + LR per tier.
5. **Stacking + calibration:** meta models per availability pattern; isotonic calibration; FPR
   thresholds.
6. **Evaluation suite:** every item in "Evaluation" generated by script.
7. **Domain features + tier C** from first-seen captures.
8. **JS port + parity test:** `tests/fixtures/url_parity.json` (≥200 URLs) passing in Python and JS.
9. **Backend + extension** working end to end on real sites, reasons displayed.
10. **Optional LLM layer.**
11. **Report**, README with screenshots and architecture diagram, demo video.

## Cut list (cut from the top when behind)

1. Optional LLM layer
2. Logo/screenshot brand matching
3. Tier C model (keep the first-seen capture; report as future work)
4. Extension page checks beyond password/form-action checks
5. Leave-one-source-out for tier B (keep tier A)
Never cut: domain-grouped splits, 10-split reporting, held-out source and time slice, recall at fixed
FPR, OOD legitimate FPR, negative controls, popularity ban, platform masking, depth check.

## Report outline

1. Problem: why single-benchmark scores mislead (summary of the prior report)
2. Data: sources, corpus build, dedup and leakage controls, depth and source balance
3. Feature engine and models (tiers, stacking, calibration)
4. Evaluation: 10-split results, held-out source and time slice, LOSO, OOD FPR, controls, robustness
5. System: extension + backend, runtime layers, latency, privacy
6. Real-world check
7. Limitations (phishing on trusted hosts, compromised sites, cloaking) and future work
