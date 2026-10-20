# Full blocks from the address model alone

Rule (2026-10-20): a dangerous verdict resting on the address model alone opens the warning page only if the page asks for a password, one-time code, card, CVV or UPI PIN, or the page model on its own also says dangerous; otherwise the page gets the banner. Pages are never lowered below suspicious, so the warned share cannot change. Before = the build given as `--old-dist`.

Natural legitimate pages: 2,373 pages with stored HTML (`js/bench/page_verdicts.mjs`). Time slice and split 0 test: rows with page features (`js/bench/block_rows.mjs`; credential fields read from the stored page features; no allowlist, blocklist, backend or brand rules).

| set | class | side | rows | warned | % | blocked | % |
|---|---|---|---|---|---|---|---|
| natural, allowlist off | legitimate | before | 2,373 | 71 | 2.99% | 30 | 1.26% |
| natural, allowlist off | legitimate | after | 2,373 | 71 | 2.99% | 23 | 0.97% |
| natural, allowlist on | legitimate | before | 2,373 | 37 | 1.56% | 11 | 0.46% |
| natural, allowlist on | legitimate | after | 2,373 | 37 | 1.56% | 6 | 0.25% |
| split_0 test | legitimate | before | 19,109 | 135 | 0.71% | 21 | 0.11% |
| split_0 test | legitimate | after | 19,109 | 135 | 0.71% | 15 | 0.08% |
| split_0 test | phishing | before | 7,066 | 6,266 | 88.68% | 5,964 | 84.40% |
| split_0 test | phishing | after | 7,066 | 6,266 | 88.68% | 5,909 | 83.63% |
| time slice | legitimate | before | 51,342 | 351 | 0.68% | 85 | 0.17% |
| time slice | legitimate | after | 51,342 | 351 | 0.68% | 40 | 0.08% |
| time slice | phishing | before | 11,050 | 7,986 | 72.27% | 7,108 | 64.33% |
| time slice | phishing | after | 11,050 | 7,986 | 72.27% | 6,902 | 62.46% |

Not measured here: the redirect-hop part of the change (no warning page before commit), covered by the browser smoke test (`extension/e2e/smoke.mjs`, step 4c); phishing pages that add their credential form after load are rechecked by the content script and are not modelled.
