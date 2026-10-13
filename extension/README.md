# PhishDrift Chrome extension (Manifest V3)

Skeleton of milestone 9. It works end to end against a local backend; it is not a polished
product yet (no icons, no options page, no store listing).

## Build and load

```
cd extension
node build.mjs        # writes extension/dist (gitignored): own files + js/src as lib/ + the model bundle
```

Chrome: `chrome://extensions` > Developer mode > Load unpacked > pick `extension/dist`.
Backend (optional, for domain checks, feedback and list sync): see `docs/BACKEND.md`; the default
address is `http://127.0.0.1:8000` (`src/config.js`, overridable in `chrome.storage.local.settings`).

## How a page is checked (cheapest first)

1. User trust ("Trust this site" in the popup) and the allowlist: safe, nothing else runs.
   Shared hosting platforms and learned open-hosting zones (`cloudapp.azure.com`,
   `drive.google.com`, `weebly.com`, ...; see docs/BACKEND.md) are never allowlisted, and an exact
   blocklisted URL overrides the allowlist. The extension ships with an allowlist
   (`extension/data/allowlist.json`, Tranco top 50,000, hashed) so it works before the first sync
   and without a backend; a synced allowlist replaces it, and a synced blocklist entry always
   removes a domain from it. Rebuild it with
   `python -m backend build-lists --tranco-file FILE --phishing-file data/processed/meta_pool.parquet --out DIR`
   and copy `DIR/allowlist.json`.
   The URL model alone flags 161 of the Tranco top 1,000 homepages (facebook.com, instagram.com,
   whatsapp.com, netflix.com, ...: the most impersonated brands look like phishing to it), so this
   layer is load-bearing, not optional.
2. Synced hashed blocklist (6-byte sha256 prefixes of the registrable domain; on shared hosts of the
   full URL): dangerous.
3. URL model on the device (`lib/hybrid.js`, the hybrid tier A model, about 2 ms per URL): safe,
   suspicious (threshold at FPR 1%) or dangerous (FPR 0.1%).
4. Only for addresses the model flagged: the backend gets the domain name (never the URL or page)
   for heuristic domain checks. If it does not answer within 2.5 s the page is checked with the
   model alone and the popup says so (fail open).
5. Content script: reports whether a password form exists and where it posts. A password form that
   posts to a different registrable domain, or over plain http, raises a flagged page to dangerous.

`src/combine.js` merges these into a verdict with plain-English reasons (TreeSHAP reasons from the
model, list and domain and page messages). Later layers can raise a verdict the model already
flagged but never create one from a safe URL, so the model's false-alarm budget stays the one
measured in `reports/`. The combiner is a transparent rule set, not yet validated on data.

- suspicious: banner at the top of the page (dismissable).
- dangerous: the tab is sent to `warning.html` with the reasons, "Take me back to safety",
  "This is a mistake" (reports the domain) and a small "Proceed anyway" link.

## Privacy

- The URL model, lists and page checks run on the device. Browsing history is not stored: the
  verdict for a tab is kept in `chrome.storage.session` (gone when the browser closes) and the
  caches are in memory. Only user-trusted site names and the synced lists are persistent.
- Sent to the backend: a domain name, only when the model flagged the address, and a domain plus
  a verdict number when the user presses a report button.
- Permissions: `storage`, `alarms` (daily list sync), `webNavigation` (see top-level navigations);
  host access only to the backend address. The content script runs on http and https pages to read
  form targets; it never sends page content anywhere.

## Known limits

- `webNavigation` cannot hold a request back, so a dangerous page may start loading for a moment
  before the warning replaces it. Blocking listed sites before the request (declarativeNetRequest)
  is a later step.
- Google Safe Browsing and the optional LLM second opinion are not wired in.
- The tier C domain model is not trained (cut list); backend domain checks are placeholder rules.

## Tests

- `npm test` (here): builds `dist`, then unit tests for the combiner, list matching, key/hash
  parity with Python (`tests/fixtures/list_key_parity.json`), page-form checks and the content
  script. CI runs it.
- `e2e/smoke.mjs`: loads the unpacked extension in Chromium with a stub backend and local pages
  (safe, banner, page-check escalation, warning page with proceed/report, blocklist hit, backend
  down). Needs Playwright; run by hand, not in CI.
