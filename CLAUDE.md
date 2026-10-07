# PhishDrift — project instructions for Claude

Solo 6th-semester college project (3 credits, project-based learning). It must be novel: a plain
"ML classifier on a static phishing dataset" was done before and does not count.

Read these before starting any task:
- @docs/PROJECT_SPEC.md — goal, data design, models, runtime layers, evaluation, milestones, cut list,
  and "Lessons from prior work"
- @docs/FEATURES_AND_DATA.md — sources, feeds, feature tiers, data rules
- docs/FEATURE_DICTIONARY.md — every feature (generated from `features/registry.py`; never edit by hand)
- @docs/PROGRESS.md — what is done, what is next, open decisions (update it after every step)
- docs/prior_work/representation_sensitivity_report.pdf — the prior study these rules come from

## Goal

Build the best practical phishing detector: maximum detection at low false positives (recall at
FPR 1% and 0.1%), by pooling many datasets and live feeds and computing every feature with our own
extraction engine. Ship it as a Chrome extension (Manifest V3) + FastAPI backend, with a report and a
clean public GitHub repo. Drift and adversarial robustness are a small evaluation section.

What makes it novel (keep this true): the detector is built and evaluated under the protocol the prior
report argues for — multi-source pooling with domain-level leakage controls, platform-identity masking,
URL-depth balancing, tiered models without missingness leakage, leave-one-source-out and
out-of-distribution false-positive reporting, repeated domain-grouped splits and negative controls —
and then deployed as a layered, explainable extension.

## Data rules (non-negotiable)

- Unified raw schema: `url, domain, label, date, source, html, depth`.
  `domain` = registrable domain under the public-suffix-only definition (ICANN suffixes, lowercased).
  `label` 1 = phishing, 0 = benign. `date` UTC, nullable. `html` nullable.
  `depth` = number of non-empty `/`-separated path segments (query and fragment excluded).
- Never use any dataset's precomputed feature columns. Load URL, label, date and HTML only.
  (PhiUSIIL's `URLSimilarityIndex == 100` alone identifies its legitimate class.)
- Dedupe by canonical URL across ALL sources before any split. A URL with conflicting labels is dropped.
- Registrable-domain disjointness across sources, and remove every domain that appears in more than one
  phishing source from all sources (mostly hosting platforms and shorteners).
- PhiUSIIL legitimate URLs are valid benign data but are 100% bare `https://www.<domain>` homepages:
  never the only benign source; always mixed with deep benign URLs (PhreshPhish benign, crawler inner
  pages, Tranco-seeded inner pages). Their domains seed the inner-page crawler, the allowlist and the
  brand list.
- Report per-class depth distributions before training. The build fails if any depth bucket is
  more than 90% one class.
- Balance per source so every source contributes both classes where possible.
- Domain/DNS/WHOIS/TLS data only for live-feed URLs, captured at first-seen time. Never compute it today
  for old dataset URLs.
- Popularity signals (Tranco rank, search indexing, traffic, PageRank) are banned from models. They may
  be used only in the allowlist.
- Never visit phishing pages from a personal browser profile. Fetch live HTML only with a sandboxed
  headless browser, or use dataset-provided HTML. Crawlers respect robots.txt and rate limits.
- Never commit datasets (`data/` is gitignored).

## Feature engine

- One engine in `features/`: `extract(url, html, domain_info) -> dict[str, float]`. Missing values are
  explicit NaN, never silently 0.
- Every feature is registered once in `features/registry.py` (name, group, tier, definition, papers,
  availability, runtime cost, in-browser feasible). `docs/FEATURE_DICTIONARY.md` is generated from it,
  and a test fails if the doc is stale.
- Platform-identity masking: registrable domains listed in `configs/platforms.yaml` (web.app, github.io,
  pages.dev, firebaseapp.com, blogspot.com, ...) are replaced by a neutral token before URL features are
  computed. Only `is_hosting_platform` is exposed.
- Tier A URL features must give identical values in Python and JavaScript:
  `tests/fixtures/url_parity.json` (at least 200 varied URLs) is checked by both test suites.
- A unit test per feature group.

## Models

- Three tiers, never one model with missing values (missingness would reveal the source):
  A = URL features, all samples (runs in the browser). B = URL + HTML, samples with HTML.
  C = URL + HTML + domain/DNS/TLS, live-feed samples only.
- Base learners: LightGBM, XGBoost, and char n-gram TF-IDF + logistic regression. Stacked; the meta
  layer combines whichever tiers are available at inference.
- Adversarial URL variants from `attacks/` go into training folds only.
- Isotonic calibration. "Suspicious" and "dangerous" thresholds come from target FPRs (1% and 0.1%),
  never 0.5.

## Evaluation rules (non-negotiable)

- Group every split by registrable domain (public-suffix-only). Private-suffix-aware grouping is an
  option for sensitivity checks, never the default. Zero domain and zero canonical-URL overlap between
  train and test is a hard runtime failure.
- Report median and spread over 10 domain-grouped splits. Never a single split.
- Primary metric: recall at FPR 1% and 0.1%. Use the largest attainable point with achieved FPR at or
  below the target. Report achieved FPR, threshold and negative count with it, and mark points resting
  on fewer than 10 negatives as granularity-limited. Also report precision, F1, ROC-AUC and PR-AUC.
  Accuracy is never the headline.
- Leave-one-source-out table. Hold out one entire source and the newest time slice; never train or
  calibrate on them.
- Depth-matched evaluation, and a representation check: also evaluate tier A on URLs normalised to
  `https://www.<registrable domain>`.
- Out-of-distribution FPR on naturally browsed legitimate inner pages, reported separately for every
  model. A spike means the homepage shortcut has returned.
- Shuffled-label negative controls. Flag any condition with |mean AUC − 0.5| > 0.05.
- Measure models with the allowlist and blocklist layers disabled (the feeds supply our test URLs).
  Report blocklist coverage separately.
- Report URL counts and domain counts separately.
- Any result above 99% on a held-out source: assume leakage and investigate before reporting.
- Every number in the report comes from a script in `experiments/` that writes to `reports/`.
  No hand-typed results. Fixed seeds.

## Runtime layers (cheapest first; keep this order)

1. Allowlist: Tranco top N + curated brand domains + user-trusted. Exact registrable-domain match.
   Shared-hosting domains are excluded.
2. Blocklists: Google Safe Browsing (Update API, local hash prefixes) and cached feeds. On shared hosts
   match the full URL, not the domain.
3. URL model (tier A) in the browser.
4. Domain checks (backend, tier C) for unknown domains only.
5. Page checks (content script, tier B).
Then a calibrated combiner gives safe / suspicious / dangerous with plain-English reasons.
6. Optional LLM second opinion, built last: gray zone only, backend, opt-in, strict JSON output, page
   text treated as untrusted data, brand-vs-domain match checked in code. It can never override a
   blocklist hit or a "dangerous" verdict.

## Feeds and terms

- OpenPhish community feed (`openphish.com/feed.txt`): every 12 h, non-commercial only. Main live source.
- Phishing.Database (MIT): secondary live source.
- PhishTank: secondary only (registration closed since 2020; online-valid feed has survivorship bias).
- URLhaus (free abuse.ch Auth-Key): blocklist only. Mostly malware, not phishing training data.
- Google Safe Browsing: Update API only, non-commercial, key stays on the backend.
- Tranco via the `tranco` Python package: allowlist and benign crawl seeds.
- The backend builds compact hashed lists; the extension syncs them daily.

## Extension rules

- Three verdicts: safe / suspicious (banner) / dangerous (interstitial with "proceed anyway").
- Plain-English reasons (from SHAP / rule hits) for every warning.
- Privacy: score locally where possible; send only the domain (not the full URL or page content) to the
  backend; minimal permissions; no browsing history stored.
- Fail open with a soft warning if the backend times out; never freeze page loads.

## Repository layout (create as needed)

```
phishdrift/     shared: config, schema, domains (eTLD+1), canonical URLs, cached HTTP client
collector/      live feeds, benign inner-page crawler, first-seen domain capture, sandboxed HTML fetch
data_pipeline/  source loaders, corpus build (dedup, disjointness, depth check), splits, data card
features/       registry.py, url_features.py, html_features.py, domain_features.py, extract.py
attacks/        URL evasion transforms (homoglyph, subdomain stuffing, padding, shortener, TLD swap)
models/         gbdt.py, char_ngram.py, stack.py, calibrate.py, export.py
experiments/    every reported number: evaluation suite, LOSO, controls, robustness section
backend/        FastAPI: /score, /domain-info, /feedback, hashed list builder
extension/      Manifest V3: service worker, content script, warning page, popup
js/             tier A feature port + parity test runner
configs/        *.yaml (platforms.yaml, collector.yaml, datasets.yaml, splits.yaml, ...)
data/           raw/, interim/, processed/ (gitignored)
reports/        figures/, tables/ (generated)
tests/          pytest (+ fixtures/url_parity.json)
docs/           spec, features, feature dictionary, progress, prior_work/
```

## Conventions

- Python 3.11, type hints, `ruff` for lint/format, `pytest` for tests.
- Configs in `configs/*.yaml`; no magic numbers in scripts.
- Network calls (RDAP, DNS, TLS, feeds, crawling) have timeouts, retries and an on-disk cache.

## Working style

- Before writing code for a milestone, restate its acceptance criteria from PROJECT_SPEC.md.
- Design changes: show a plan and wait for approval. If anything conflicts with these docs, ask instead
  of guessing.
- Small, testable steps. Run tests before declaring a task done.
- After every step, append to docs/PROGRESS.md: what changed, results (with file paths), next step,
  open questions.
- When behind, follow the cut list in PROJECT_SPEC.md rather than adding features.
