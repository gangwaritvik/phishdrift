# Page-check fixes: false alarms on natural legitimate pages

2,373 naturally browsed legitimate pages with stored HTML (2,226 the page model can read under the training rule).
Verdicts from `js/bench/page_verdicts.mjs`: allowlist, URL model, page model and combiner
as in the service worker; no backend, no blocklist; page facts read from the stored HTML
(not a live DOM). Before = the pipeline before 2026-10-15 (the page model may lower any
suspicious address); after = the page model may lower a verdict only on pages with no
password, one-time-code, card or PIN field, and bare login forms are read by the page
model.

| allowlist | subset | side | pages | warned | % | dangerous | % |
|---|---|---|---|---|---|---|---|
| on | all pages | before | 2,373 | 35 | 1.47% | 11 | 0.46% |
| on | all pages | after | 2,373 | 37 | 1.56% | 11 | 0.46% |
| on | pages the page model reads | before | 2,226 | 27 | 1.21% | 11 | 0.49% |
| on | pages the page model reads | after | 2,226 | 29 | 1.30% | 11 | 0.49% |
| off | all pages | before | 2,373 | 68 | 2.87% | 29 | 1.22% |
| off | all pages | after | 2,373 | 71 | 2.99% | 30 | 1.26% |
| off | pages the page model reads | before | 2,226 | 55 | 2.47% | 26 | 1.17% |
| off | pages the page model reads | after | 2,226 | 58 | 2.61% | 26 | 1.17% |

Pages whose verdict changed (0 safe, 1 suspicious, 2 dangerous):

| allowlist | url | verdict | layer after | asks credentials | short page |
|---|---|---|---|---|---|
| on | `https://indo126-x.com/daftar` | 0 -> 1 | url-model | True | False |
| on | `https://kuple.kr/best` | 0 -> 1 | url-model | True | False |
| off | `https://indo126-x.com/daftar` | 0 -> 1 | url-model | True | False |
| off | `https://linkmake.in/login.html` | 1 -> 2 | page-model | True | True |
| off | `https://kuple.kr/best` | 0 -> 1 | url-model | True | False |
| off | `https://othoba.com/${r}` | 0 -> 1 | url-model | True | False |

Credential frames (judged on the page score alone, without the address model's
agreement). This set has no frames; legitimate pages that ask for credentials, not
allowlisted, stand in for legitimate login frames:

| allowlist | credential pages | warned as a page | warned as a frame | dangerous as a frame |
|---|---|---|---|---|
| on | 164 | 8 (4.9%) | 7 (4.3%) | 1 |
| off | 223 | 20 (9.0%) | 20 (9.0%) | 4 |

Not measured here: the recall effect on phishing pages (no phishing HTML in this set).
