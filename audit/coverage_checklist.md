# What PhishDrift has and has not been tested against

Written 2026-10-26 from the repo (main at 3325c91) and the test write-ups in this folder (re-checked the same day, see "Claim check" below):
`audit/red_team_findings.md`, `report/stress_test_2026-10-15.md`, `e2e_attack/results.md`,
`list_tests/REPORT.md` and `docs/PROGRESS.md`. No code was changed and nothing new was run.

**How sure each line is:** "Tested" means a file in this folder or `reports/` has a number for it.
"Code only" means the code handles it but no test result exists. "Not found" means I found no code and no
test for it. That is a search of the files, not proof that the case fails.

Effort is a rough guess: S = under a day, M = 1 to 3 days, L = a week or more.


## Claim check, 2026-10-26 (re-checked against code on main 22582a1, plus a live-site probe)

Ritvik found that short links were reported as handled while the URL check page did not follow them. This
section re-checks the "covered / passed / handled" claims. Three different things are called "PhishDrift" and
they do not behave the same, so each row says which one it is about:

- **Extension**: the Chrome extension (the browser itself follows links, so it sees where a short link lands).
- **Demo page**: the URL check page (a web page, so it cannot open other sites; it uses a hosted helper).
- **Python**: the backend and the model-building code.

Labels: **verified** (I ran it today, how is said), **reported only** (a write-up says so; I could not rerun it
here), **wrong** (the claim did not hold; what is true is said, and whether I fixed it).

| Claim | Where | Label | What I did / found |
|---|---|---|---|
| Short links (bit.ly, tinyurl, t.co, is.gd, an unlisted host) end in a verdict on the page they lead to; 13 of 13 cases | Extension | **verified** | Reran `quickwins.mjs` in headless Chromium on today's build, network cut off, local test pages: all 13 short-link and redirect cases pass again (plus a 14th case for a newly listed shortener). Only local pages, not real shorteners. |
| Same claim, as if it covered every place | Demo page | **wrong until 22582a1** | The page stopped at "short link" and never followed it. PR #63 added a hosted helper that follows the link. Live check from a GitHub runner today: bit.ly, aka.ms, t.co and is.gd are followed and the destination is checked. **tinyurl.com and cutt.ly are not followed**: tinyurl answers with a "no spam" preview page, cutt.ly answers 403 to a data-centre address. Those are exactly the services seen in phishing feeds, so for them the page still says "could not be followed". |
| Same, but also the page's own text for an unfollowed short link | Demo page | **wrong, fixed here** | It said "No layer raised a concern" and "The allowlist is what keeps it safe" for a link it had not followed. Now it says the link was not followed. |
| Extension uses the full 1,793-name shortener list | Extension | **verified** | `extension/dist/data/lists.json` is loaded next to the model's own 25 names; aka.ms and bit.do are now treated as short links. 92 of the 1,793 entries are sub-names (e.g. `a.189.cn`) that can never match a site name; the log said 90. |
| The four short-link hosts used in the browser test "are already on the extension's list" | Extension | **verified** | All four were among the model's own 25 names, so the test did not depend on the new list. |
| Python side of the shortener list (the model's "is a short link" feature) | Python | **reported only** | The shipped model was trained with the 25-name list. The 1,793 names only matter after a retrain, which needs the data on the PC. The "learned from feeds" code (`collector/shorteners.py`) has never been run on real data. |
| Home-network addresses like 192.168.0.1 are not warned | Extension | **verified in unit tests only** | Not tested in a browser. |
| Same | Demo page | **wrong, fixed here** | The page called 192.168.0.1 "Dangerous" (live site today too). It now treats local addresses like the extension does; test added. |
| Public IP addresses are warned | Extension and demo page | **verified** | 8.8.8.8/login and two other IP hosts score dangerous on the demo path (same code as the extension). |
| 35 of 35 attack cases pass (late forms, frames, banner hiding, back to safety, trust, slow backend) | Extension | **wrong as stated** | Rerun today on today's build: **23 of 35**. Cause: the harness's "suspicious address" (`evil-blocked.com`) now scores 0.75, under the new "suspicious" cut-off (0.904) after the 10-21/22 retrain, so the page-based cases lost their trigger. With only that address swapped for one that still scores suspicious (`evil-blocked.info`): **32 of 35**. The 3 left: two "trust" cases fail because the harness's fake blocklist contains example.com, which the extension rightly refuses (a top-site sentinel), and one "tab opened straight to a dangerous page" expects a warning page but since 10-20 an address-only verdict gets a banner (by design). So the extension's behaviour holds; the harness needs recalibrating after each retrain. |
| 5 of 2,555 natural legitimate pages flagged after the retrain | Extension (address layer) | **verified** | Reran `experiments.shipped_verdicts` on the shipped model and bundled allowlist: 5 flagged (0.2%), none dangerous, address model alone 12 + 3. The committed `reports/shipped_verdicts.md` still showed the old 71 (2.8%); regenerated here. The Tranco-top-1,000 row is gone because there is no Tranco file in the cloud. |
| Look-alike coverage "unknown" since the rules were removed | Extension (address layer) | **now measured** | On the 10-19 generated sets (AI check off, bundled allowlist): ASCII homoglyphs (`micr0soft.com`) 2.2% warned (fresh brands 0%); one letter off (`paypl.com`) 1.1% (fresh 0%); brand + word 78% (fresh 69%); TLD swap 54% (fresh 47%); punycode 87%; hyphenated and embedded 88-98%. Before the rules were removed: homoglyph 93%. 4 of 40 coincidental brand-like genuine names are flagged. So the look-alike cases depend entirely on the AI check, which is off by default. |
| AI check (Gemini) "not measured" | Demo page and hosted helper | **partly measured** | Live from a GitHub runner: earlier today 4 of 6 hosts answered and 2 failed (HTTP 429 quota, timeout), each call 6-9 s; later 2 of 2 answered in 4 s, and `secure-paypa1-login.top` was raised as PayPal with confidence 1. So it works and is slow; accuracy on a real set is still not measured. |
| AI check script and manual workflow exist | Python | **wrong** | They are in PR #55, which is still open; `experiments/llm_eval.py` is not on main. |
| AI check is off by default in the extension | Extension | **verified** | `llmCheck: false` in `extension/src/config.js`; popup switch exists. Never run in a real browser by me. |
| infura-ipfs.io had 476 phishing URLs on the allowlist; not re-checked | Extension | **now re-checked** | The sample address is no longer allowlisted and scores dangerous (one URL only). |
| Last-token-changed blocklist match 160 of 193 | Python / extension | **verified against REPORT.md** | `list_tests/REPORT.md` says 160 of 193. `docs/PROGRESS.md` says 158/184, so the log disagrees with the report; I did not rerun the list tests. |
| Signing key not made, so list sync is not tamper-proof | Extension | **verified** | `LIST_PUBKEY = null` in `extension/src/lists_pubkey.js`. |
| Test counts in PROGRESS (js 25, extension 73) | All | **verified** | `npm test`: js 25 pass, extension 73 pass (74 with the test added here), pytest 560 pass (2 deselected, one needs the optional Hugging Face package), ruff clean. |
| Hosted page loads the model; loading screen with retry | Demo page | **partly verified** | Live page in headless Chromium: model and lists ready in 2-3 s, five short-link runs worked. The progress bar and the retry on a failed download were not inspected; a phone was not tried. |
| Real Netlify deploy, rate limits (20 a minute) | Demo page | **reported only** | The site is up; the rate limit was not tested. |
| Captcha cover then form, and a wallet recovery-phrase page, are warned; a picture-only login is not | Extension | **verified** | Reran `round2.mjs` on today's build (address swapped as above): captcha cover then form warned on both a suspicious and a safe-looking address; wallet phrase page banner on both; picture-only login on a safe-looking address: no warning (real gap). On the suspicious address the picture-only page ended with a banner still showing while the tab's stored verdict was safe (the harness flags it as a stale banner): a small inconsistency to look at. Local test pages only. **2026-10-27 follow-up:** the stale banner did not reproduce (4 runs on `evil-blocked.info`: banner and stored verdict both suspicious, because a page the page model cannot read is judged by the calibrated address score, and `/pic` scores 0.89 there; 2 runs on the original `.com` address: no banner and verdict safe, because `/pic` scores 0.45). The gap itself is closed only for addresses scoring 0.5 or more (see the "Pages that are only a picture" row). |

### Bigger gaps for Ritvik (not fixed here)

1. **Short links to tinyurl.com and cutt.ly cannot be followed by the demo page.** Both block or detour automated requests from a server. The extension is not affected (the browser follows the link itself). Options: show "could not be followed" plainly (done), or accept this limit and say so in the report.
2. **Look-alike names slip through when the AI check is off** (about 2% of one-letter and homoglyph look-alikes warned). Turning the AI check on by default costs a call to Google per borderline address and sends the host name.
3. **The attack harness must be recalibrated after every retrain**; as shipped it reports 23 of 35.
4. **The page-level checks on a followed short link do not exist on the demo page**: it judges the destination's address only (it cannot open the page).
5. Anything that needs the PC or the training data (retrain with the full shortener list, learned shorteners, signing key) stays blocked.

## Not covered at all

| Case | Why it matters | Effort |
|---|---|---|
| Hacked real websites (phishing page put on an old, honest site) | The site's address and age look clean, so only the page check can catch it. Common in real attacks. Not found as a test set. | M (collect a test set from feeds where the domain is old) |
| Fake login popups drawn inside the page ("browser in the browser") | The fake window shows a real-looking address bar that is just a picture. Not tested. | S (one test page in the attack harness) |
| Live copy of the real site through a middle-man server (Evilginx-style) | The page is the real login page, so only the address can give it away. Not tested separately. | M |
| "Approve this app" or device-code tricks on real Microsoft or Google pages | The page is genuine; the harm is the permission the user grants. The extension cannot see it. | L (likely future work only) |
| Pages that hide from scanners (captcha or "checking your browser" first) | **Browser test 2026-10-26: a form shown 6 s after a captcha-style cover is warned (2 of 2 runs).** The training-data effect is still unmeasured. Original note: | Our crawlers and datasets may have saved the harmless cover page, not the phishing page. The effect on training was never measured. | M |
| Pages that are only a picture, or draw the form on a canvas | The page model reads text and form fields, so a picture of a login box gives it almost nothing. **2026-10-27: partly closed.** A page with under 100 characters of text, no input fields and a picture covering at least 10% of the window is raised to suspicious when the address model scores the address 0.5 or more (`extension/src/pagefacts.js`, `combine.js`; browser test in `extension/e2e/smoke.mjs` step 4d). Still open: a picture-only page on an address scoring under 0.5 gets no warning (see `reports/picture_only.md`), and a picture drawn after load is not rechecked. | S to test, M to fix |
| Crypto wallet drainers ("connect your wallet") | **Browser test 2026-10-26: a recovery-phrase page got a banner on both addresses (2 of 2 runs); one generic page only.** Original note: | No password or card box, so the rule "never clear a page that asks for credentials" does not apply. The page model knows wallet words, but no test set exists. | M |
| Fake virus alerts, tech-support scams, "paste this into Run" pages | Not credential phishing, but users meet them often. No data, no rule. | M (out of scope is a fair answer) |
| Phishing PDFs opened in Chrome | **Partly tested 2026-10-26:** a PDF on a dangerous address gets a banner. Clicking a link inside a PDF was not tested (the headless viewer could not be clicked). | S |
| Phishing from search ads or poisoned search results | The real problem is a redirect chain through ad networks. Not tested. | M |
| QR-code phishing | The victim scans with a phone; the extension is desktop Chrome only. | Out of scope (say so in the report) |
| Other browsers and phones | Only Chrome desktop was built and tested. | Out of scope |

## Partly covered

| Case | What exists | What is missing | Effort |
|---|---|---|---|
| Phishing on hosting platforms (github.io, pages.dev, vercel, Firebase, Weebly, Wix) | Tested: 85.9% of 838 platform phishing URLs warned. Platform names are hidden from the model. Learned "open hosting zones" switch off the allowlist there. | Domain age and certificate checks are skipped on platforms by design, so only the address and page models judge them. | Done enough; report the limit |
| Phishing on big trusted sites (Google Sites, Docs, Forms, Drive, Notion, Telegraph, SharePoint) | Tested: notion.so 11 of 12, taplink 98 of 98, cloudapp.azure.com 32 of 37 warned. | sites.google.com only 16 of 100, telegra.ph 3 of 9. A fix was measured but not shipped (it also flagged every Drive file link). A new platform nobody has abused yet stays trusted. Google Forms, Microsoft Forms, OneDrive, Dropbox, Canva, Jotform were named as trusted and not tested. | M |
| IPFS gateway pages | Some gateways are on the platform list. | infura-ipfs.io had 476 phishing URLs on the allowlist on 10-15; not re-checked since. | S |
| Look-alike names (paypa1, punycode, one letter off) | Tested earlier with the look-alike rules (ASCII look-alikes 42 of 45 warned). | Those rules were removed on 10-22 and replaced by the Gemini check, which is off by default and never measured. Measured 10-26: homoglyph and one-letter look-alikes are now warned about 1-2% of the time with the AI check off (see "Claim check"). Brand name on another ending (`icicibank.net`) was never handled. | M (`experiments/llm_eval.py` is planned, not written) |
| **Gemini check, 2026-10-26** | **Not measured: the cloud has no Gemini key.** The evaluation script and a manual GitHub workflow are in PR #55 (still open, not on main) and tested with a stub only. It needs the repository secret `GEMINI_API_KEY`. | | | |
| Brand-new domains | Tier C (domain age, DNS, certificate): capture on GitHub Actions, domain-level training, JavaScript port and a hosted check function exist (2026-10-27). Shipping waits for the gates in `reports/tier_c.md`. | Result rests on 119 phishing hosts and every low-false-alarm number is too small to trust. The backend uses simple rules, not the tier C model. | M (needs more collector days) |
| Shifted blocklisted URLs (per-victim tokens) | Tested: 297 to 300 of 300 still match after the fix. | One case still weak: last path token changed, 160 of 193. Signing key not yet made, so list sync is not tamper-proof. | S |
| Attacks the model was not trained on | Six rewrite families tested; adversarial training helps on the five it saw. | A family it never saw got no benefit; the shipped model is the one without adversarial training. | Report it |
| Non-English phishing | Regional bank sites: 0 of 114 false alarms. | Keyword and brand lists are mostly English; no non-English phishing test set. | M |

## Covered and tested

All of these have a result in the files above.

- Login form added late, after a click, or after a timer (attack harness: 35 of 35 on 10-19; **32 of 35 on 10-26** after a recalibration, see "Claim check")
- Login form inside a frame, a cross-site frame, a srcdoc frame, or a hidden (shadow) part of the page
- Single-page app route changes, hash changes, and a page rewriting its own address
- `blob:` and `about:blank` pages; `data:` links (Chrome blocks them)
- Pages trying to hide or remove the warning banner
- "Trust this site" can no longer beat the blocklist, and trust expires after 30 days
- Very long addresses (used to switch off every check), odd addresses (hex or decimal IP, user:pass@, trailing dot, capitals)
- Raw IP addresses (warned) and home-network addresses like 192.168.0.1 (not warned; extension only, unit tests; the demo page was wrong until this change)
- Slow or dead backend (page still loads, warning still shows)
- Tampered or shrunken list updates (rejected; full protection needs the signing key)
- False alarms on ordinary legitimate pages (5 of 2,555 flagged after the retrain), regional banks, login pages
- Held-out data source and newest time slice (10 domain-grouped splits)
- **Ticked 2026-10-26:** short links (bit.ly, tinyurl, t.co, is.gd and a redirect host not on any list; server, script, meta-refresh, delayed and click-through redirects), redirect chains of up to 4 hops (email click link, short link, google.com open redirect), legitimate pages behind short links and click links (no false alarm), local HTML files. 13 of 13 cases passed in 3 runs. Local test pages only, not real shorteners. Details: `e2e_attack/quickwins_2026-10-26/results.md`.

## Suggested order if there is time

1. Done 2026-10-26: short links, redirect chains, `file://`, PDF on a bad address. Not done: clicking a link inside a PDF, the fake popup and picture-only login pages (not built, because a realistic one copies a real brand's sign-in screen).
2. Measure today's look-alike coverage with the Gemini check on and off (`experiments/llm_eval.py`).
3. Everything else goes in the report's Limitations section.
