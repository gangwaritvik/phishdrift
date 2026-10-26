# Attack harness results

`bash e2e/attack/run.sh [OUT] [filter]` (after `node build.mjs`); `offline.sh` runs it in a network namespace with only
the loopback interface. Headless Chromium, stub backend on :8000, local pages on :8123, every host name resolves to
127.0.0.1. Pages are local; no real site is contacted.

## What changed from the harness in the project folder (e2e_attack/harness.mjs)

The old harness reported 35 of 35 on 2026-10-19, then 23 of 35 on the retrained model (claim check, PR #64). Nothing in the
extension had broken; the harness's expectations had gone stale. Changes, all stated here:

1. **Test addresses are chosen at run time from the shipped model** (`calibrate.mjs`). A host is "suspicious" when the
   address model's score for every path the cases use lies between its suspicious and dangerous cut-offs, "dangerous"
   when all are at or above the dangerous cut-off, "safe" when all are below the suspicious cut-off. The run stops with
   an error if no candidate fits a band. Before, `evil-blocked.com` was hard-coded and fell to 0.75, under the 0.904
   cut-off, so every page-based case lost its trigger. (This is the 23 to 32 step.)
2. **The fake blocklist no longer lists `example.com`.** The extension refuses a blocklist that contains a top site
   (sanity check in `listsync.js`), so the sync was rejected and the two "trust" cases could never see a blocklisted
   domain. It now lists a host the model calls safe (so only the blocklist can warn on it) and the trusted test host.
   Behaviour unchanged; the test setup was wrong. (32 to 34.)
3. **"Take me back to safety" cases open a dangerous address with a page that asks for a password.** Since 2026-10-20 a
   dangerous verdict from the address model alone, on a page that asks for nothing, is a banner; the warning page needs a
   second reason (a password field, the page model's own dangerous score, or no page check within 5 s). The old case
   expected the warning page on a plain page. That is by design, not a regression. (34 to 35.)
4. **New case `D-address-only-dangerous-is-banner`** pins the by-design behaviour of point 3: an address the model calls
   dangerous, on an ordinary content page the page model does not call dangerous, gets the banner and not the warning page.
   Its host is also found by `calibrate.mjs` (a dangerous address whose content page the page model passes), because a
   benign page on a very high-scoring address is still called dangerous by the page model.

Nothing else was relaxed: no case was removed, no pass condition loosened.

## Runs on the current build (model cut-offs 0.9042 / 0.9795)

| run | result |
|---|---|
| old harness, unchanged (parent's claim check) | 23 of 35 |
| old harness, only the suspicious address swapped (claim check) | 32 of 35 |
| this harness, changes 1 and 2 only | 34 of 35 (new-tab case failed: change 3) |
| this harness, 1st full run | 36 of 36, 2 info |
| this harness, offline (`offline.sh`) | 36 of 36, 2 info |
| this harness, 3rd full run | 36 of 36, 2 info |

The two INFO lines record behaviour without a pass condition (`G1-control-no-cred`, `G-tiny-login-unknown`).

## Last run

```
PASS  G1-cred-page-clears-suspicious  ui=banner verdict=1 layer=url-model
INFO  G1-control-no-cred  ui=none verdict=0 layer=page-model
PASS  G3-delayed-form  ui=warning verdict=2
PASS  G3-click-revealed-form  ui=warning verdict=2
PASS  G3-over-recheck-cap  ui=banner verdict=1 layer=url-model
PASS  G3-closed-shadow-form  ui=banner verdict=1 layer=url-model
PASS  G4-cross-site-iframe-login  ui=warning verdict=2
PASS  G4-srcdoc-iframe-login  ui=warning verdict=2
PASS  G4-spa-pushstate  ui=warning verdict=2 url=chrome-extension://eklfbcccbmnbakalegcdfbddjaafihmk/warning.html?tab=1822478800
PASS  G4-spa-hash  ui=warning verdict=2
PASS  X-blob-page  ui=warning verdict=2 url=chrome-extension://eklfbcccbmnbakalegcdfbddjaafihmk/warning.
PASS  X-about-blank-page  ui=warning verdict=2 url=chrome-extension://eklfbcccbmnbakalegcdfbddjaafihmk/warning.
PASS  X-data-url  Chrome refused the navigation (still at http://evil-blocked.info:8123/)
PASS  X-address-rewrite  ui=warning verdict=2 url=chrome-extension://eklfbcccbmnbakalegcdfbddjaafihmk/warning.html?tab=1822478819
PASS  X-address-rewrite-lure  ui=warning verdict=2
PASS  X-banner-same-id  ui=warning verdict=2
PASS  X-banner-css-hidden  ui=warning verdict=2
PASS  X-banner-css-hidden-tag  ui=warning verdict=2
PASS  X-banner-removed  ui=warning verdict=2
PASS  X-back-to-safety-history  ended at http://localnews-daily.com:8123/articles/today
PASS  X-back-to-safety-new-tab  ended at chrome://new-tab-page/
PASS  D-address-only-dangerous-is-banner  ui=banner verdict=1 layer=page-model
PASS  G2-trust-then-blocklisted  trust={"ok":true,"key":"secure-blocked.net"} sync={"updated":true,"version":"stub2","at":1793050790558,"lists":"updat
PASS  G2-trust-on-blocklisted-page  trust={"ok":true,"key":"localnews-daily.org"} then ui=warning verdict=2
PASS  G2-trust-expiry  stored=[{"at":1793050789763,"key":"secure-blocked.net"},{"at":1793050791740,"key":"localnews-daily.org"}] after ageing 400 days
PASS  G-tiny-login-suspicious  ui=warning verdict=2
INFO  G-tiny-login-unknown  ui=warning verdict=2
PASS  X-odd-address-0  loaded=true stored=yes ui=none verdict=0 layer=local reasons=[]
PASS  X-odd-address-1  loaded=true stored=yes ui=none verdict=0 layer=local reasons=[]
PASS  X-odd-address-2  loaded=true stored=yes ui=none verdict=0 layer=local reasons=[]
PASS  X-odd-address-3  loaded=true stored=yes ui=none verdict=0 layer=url-model reasons=[]
PASS  X-odd-address-4  loaded=true stored=yes ui=none verdict=0 layer=url-model reasons=[]
PASS  X-odd-address-5  loaded=true stored=yes ui=none verdict=0 layer=url-model reasons=[]
PASS  X-odd-address-6  loaded=true stored=yes ui=banner verdict=1 layer=url-model reasons=["This address is extremely long, a trick used to hide where
PASS  X-odd-address-7  loaded=true stored=yes ui=none verdict=0 layer=url-model reasons=[]
PASS  X-odd-address-8  loaded=true stored=yes ui=none verdict=0 layer=url-model reasons=[]
PASS  X-backend-slow  loaded in 288 ms, ui=banner verdict=1 layer=page-model first warned at 655 ms, notes=[]
PASS  X-backend-down  ui=banner verdict=1 layer=page-model notes=[]
```

## Notes and limits

- Odd addresses (`X-odd-address-*`) only require that the page loads and a verdict is stored, as before. Most of them end
  with verdict "safe" on this build: their paths (`/a/blog`, `%zz%`) score lower than the calibrated paths, and the page
  model can clear a page that asks for nothing. Not a regression, but the case does not test warning strength.
- The quick-win cases of 2026-10-26 (short links, redirect chains, PDF, `file://`; 13 of 13) are still in the project
  folder (`e2e_attack/quickwins_2026-10-26/`) and were not folded in: they duplicate the harness set-up and use
  list-based host names, not model scores.
- Run after every retrain: `node build.mjs && bash e2e/attack/run.sh`. A calibration error means the candidate host names in
  `calibrate.mjs` need extending. A failing case is a real result.
