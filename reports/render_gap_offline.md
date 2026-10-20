# Raw HTML against the rendered DOM: the page path's verdicts (red-team gap 5)

**Offline approximation, a lower bound.** The stored raw HTML of each page was rendered
in headless Chromium with every network request other than the page itself aborted:
inline scripts ran; external scripts, styles, frames and XHR did not. Real pages that
build their content with external scripts (most single-page apps) change much more when
rendered live, so the real gap is likely larger than this. The real measurement needs
live rendering on Ritvik's PC (sandboxed browser).

Pages: 2,373 naturally browsed legitimate pages with stored HTML (`ood_pages.parquet`).
Rendered OK: 2,334; failed: 39 (page.goto: 32, timeout: 7). Median render time 1.6 s; settle 1500 ms after load, hard limit 15 s per page. Median rendered/raw HTML length 1.00 (more than 10% longer: 10, more than 10% shorter: 65).

Verdicts from `js/bench/page_verdicts.mjs` (allowlist, URL model, page model, combiner as
in the service worker; no backend, no blocklist). Raw side: stored HTML, page facts from
the bench's tag scan. Rendered side: DOM serialised as `content.js` `pageHtml` does
(shadow roots appended; closed roots captured by wrapping `attachShadow`), page facts
read from the DOM as `collectPageFacts` does. Only pages that rendered are compared.

## False alarms

| allowlist | subset | side | pages | warned | % | dangerous | % |
|---|---|---|---|---|---|---|---|
| on | all rendered pages | raw HTML | 2,334 | 36 | 1.54% | 11 | 0.47% |
| on | all rendered pages | rendered DOM | 2,334 | 36 | 1.54% | 10 | 0.43% |
| on | page model reads both | raw HTML | 2,194 | 29 | 1.32% | 11 | 0.50% |
| on | page model reads both | rendered DOM | 2,194 | 29 | 1.32% | 10 | 0.46% |
| off | all rendered pages | raw HTML | 2,334 | 69 | 2.96% | 30 | 1.29% |
| off | all rendered pages | rendered DOM | 2,334 | 67 | 2.87% | 28 | 1.20% |
| off | page model reads both | raw HTML | 2,196 | 59 | 2.69% | 28 | 1.28% |
| off | page model reads both | rendered DOM | 2,196 | 57 | 2.60% | 26 | 1.18% |

## Verdict changes (raw -> rendered)

| allowlist | raised | lowered | transitions |
|---|---|---|---|
| on | 0 | 1 | dangerous->suspicious 1 |
| off | 0 | 3 | dangerous->safe 1, dangerous->suspicious 1, suspicious->safe 1 |

## Page model input (allowlist off, every page scored)

- Page model reads the page: raw 2,197, rendered 2,201; readable only raw 1, only rendered 5.
- Asks for credentials (password, one-time-code, card or PIN field): raw 222, rendered 213; changed on 9 pages.
- Blended page score, median absolute change: 0.0000 over all 2,334 pages (95th percentile 0.0180, max 0.3370); 0.0000 over the 2,196 pages the page model reads on both sides. Changed by more than 0.05 on 71 pages.

## Largest changes in the blended page score (allowlist off)

| domain | raw score | rendered score | change | verdict raw -> rendered | page model reads raw / rendered |
|---|---|---|---|---|---|
| linkmake.in | 0.612 | 0.275 | -0.337 | safe -> safe | yes / yes |
| ibroxnews.com | 0.550 | 0.275 | -0.275 | safe -> safe | yes / yes |
| s10.wiki | 0.600 | 0.348 | -0.252 | safe -> safe | yes / yes |
| igrupos.com | 0.600 | 0.348 | -0.252 | safe -> safe | yes / yes |
| afrihost.co.za | 0.550 | 0.348 | -0.202 | safe -> safe | yes / yes |
| kugou.com | 0.348 | 0.550 | +0.202 | safe -> safe | yes / yes |
| ihc.ru | 0.550 | 0.348 | -0.202 | safe -> safe | yes / yes |
| fdownload.app | 0.550 | 0.348 | -0.202 | safe -> safe | yes / yes |
| sharevision.app | 0.348 | 0.550 | +0.202 | safe -> safe | yes / yes |
| igrupos.com | 0.750 | 0.550 | -0.200 | safe -> safe | yes / yes |

Not measured here: live rendering with external scripts, other extensions' injected
nodes (password managers, ad blockers), and the recall effect on phishing pages (no
phishing HTML in this set).
