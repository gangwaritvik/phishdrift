# PhishDrift — project instructions for Claude

Solo 6th-semester college project (3 credits, project-based learning). It must be novel: a plain
"ML classifier on a static phishing dataset" was already done in earlier semesters and does not count.

Read these before starting any task:
- @docs/PROJECT_SPEC.md — goals, experiments, architecture, milestones, cut list
- @docs/FEATURES_AND_DATA.md — features to implement, datasets, feeds
- @docs/PROGRESS.md — what is done, what is next, open decisions (update it at the end of every task)

## The research question

> Do phishing detectors that score ~99% on standard benchmarks survive (1) time and (2) attackers,
> and which fixes actually restore performance?

Deliverables: a report with honest numbers, a Chrome extension (Manifest V3) + FastAPI backend that
uses the hardened model, and a clean public GitHub repo.

## Non-negotiable evaluation rules

- Never report a random-split score alone. Always report random split AND time split side by side;
  the gap between them is the headline finding.
- Split by registered domain (eTLD+1), never by URL, so near-duplicates can't leak across train/test.
- Deduplicate URLs and near-identical HTML before splitting.
- Primary metric: recall (detection rate) at a fixed false-positive rate (report at FPR = 1% and 0.1%).
  Also report precision, F1, ROC-AUC, PR-AUC. Accuracy alone is never the headline.
- Do not use popularity shortcuts (Tranco rank, search-index presence) as model features; they make the
  model learn "famous vs obscure". They may be used only in the extension's allowlist layer.
- Benign data must include inner pages and free-hosted sites, not only homepages.
- Every number in the report must come from a script in `experiments/` that writes to `reports/`.
  No hand-typed results. Fix random seeds.
- If a result looks too good (>99% on a time split), assume leakage and investigate before reporting.

## Repository layout (create as needed)

```
collector/      daily feed collector (OpenPhish, PhishTank, URLhaus, Tranco benign)
data/           raw/, interim/, processed/  (gitignored; never commit datasets)
features/       url_features.py, html_features.py, domain_features.py (RDAP/DNS/TLS)
models/         train.py, stack.py, calibrate.py, export_onnx.py
attacks/        URL evasion transformations (homoglyph, subdomain stuffing, padding, shortener, TLD swap)
experiments/    e1_drift.py, e2_adversarial.py, e3_retrain.py, ablation.py
backend/        FastAPI service: /score, /domain-info; caches per domain
extension/      Manifest V3: service worker, content script, warning page, popup
reports/        figures/, tables/ (generated)
tests/          pytest
docs/           spec, features, progress
```

## Conventions

- Python 3.11, type hints, `ruff` for lint/format, `pytest` for tests.
- Feature extractors are pure functions: `extract(url: str, html: str | None) -> dict[str, float]`,
  with a unit test per feature group. Missing values are explicit (NaN), never silently 0.
- The same URL feature code must produce identical values in Python (training) and JavaScript
  (extension). Keep a parity test with a shared fixture file of URLs and expected values.
- Configs in `configs/*.yaml`; no magic numbers in scripts.
- Network calls (RDAP, DNS, TLS, feeds) have timeouts, retries and an on-disk cache.
- Respect each feed's terms and rate limits. Never visit phishing pages from a personal browser
  profile; fetch HTML only via a sandboxed headless browser or use dataset-provided HTML.

## Extension rules

- Layered verdict, cheapest first: allowlist → blocklist (Safe Browsing, cached feeds) →
  in-browser URL model → backend domain checks → page checks (content script).
- Three verdicts: safe / suspicious (banner) / dangerous (interstitial with "proceed anyway").
- Show plain-English reasons (from SHAP / rule hits) for every warning.
- Privacy: score locally where possible; send only the domain (not full URL or page content) to the
  backend; minimal permissions; no browsing history stored.
- Fail open with a soft warning if the backend times out; never freeze page loads.

## Working style

- Before writing code for a milestone, restate the acceptance criteria from PROJECT_SPEC.md.
- Small, testable steps. Run tests before declaring a task done.
- At the end of each task, append to docs/PROGRESS.md: what changed, results (with file paths),
  next step, open questions. This is how context carries across sessions and model switches.
- When unsure about scope, prefer the cut list in PROJECT_SPEC.md over adding features.
