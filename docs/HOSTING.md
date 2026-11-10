# Hosting the URL check page and the AI brand check on Netlify

The online URL check page (`demo/`) and the Gemini brand check run on one free Netlify site built
from this repository. No computer of yours has to stay on.

- `netlify.toml` builds the site with `deploy/netlify_build.sh`: it copies the page, the extension
  code and the address model, and builds the blocklist from the public Phishing.Database feed
  (`lists.blocklist_feeds`). Every merge to `main` redeploys it.
- `netlify/functions/llm-check.mjs` answers `POST /api/llm-check` (and `/llm-check`) exactly like
  the backend's `/llm-check`: it sends only the host name to Gemini and decides in code
  (`js/src/llm_check.js`, a copy of `backend/llm.py`, checked against Python by
  `tests/fixtures/llm_parity.json`). Its settings come from `js/data/llm_check.json`; after a change
  to the `llm` block of `configs/backend.yaml` or to `backend/llm.py`, run
  `python -m backend export-llm-js`.
- `netlify/functions/expand.mjs` answers `POST /api/expand` `{url}`: for an address on a link
  shortener (`js/data/lists.json`) it follows the redirects (`js/src/short_links.js`) and returns
  the destination, which the page then checks like a typed address. It requests only shortener
  addresses (never the destination), runs nothing, uses ports 80/443 only and refuses hosts that
  resolve to private or local addresses. Limits: `short_links` in `configs/backend.yaml`
  (5 hops, 8 s), exported with the same `python -m backend export-llm-js`.

## Setup (once, in a browser)

1. Open <https://app.netlify.com>, sign in with GitHub, and choose **Add new project > Import an
   existing project > GitHub > gangwaritvik/phishdrift**. Leave every build setting as Netlify
   fills it in from `netlify.toml` and click **Deploy**.
2. In the new site: **Project configuration > Environment variables > Add a variable**. Key
   `GEMINI_API_KEY`, value: your Gemini key from <https://aistudio.google.com/apikey>, scope
   **Functions**. Mark it as secret if Netlify offers it. Then **Deploys > Trigger deploy >
   Deploy project** so the function picks the key up.
3. Optional: **Project configuration > Change project name** to get a nicer address.
4. Open the site and check an address that is not on the allowlist: the "LLM check" step should
   say "Nothing found" or "Imitation". "No opinion (disabled)" means the key is missing.

The same key can also be the `GEMINI_API_KEY` repository secret used by the Gemini evaluation
workflow; it is the same name in both places.

## The extension

In the extension popup, put `https://<your-site>.netlify.app/llm-check` in **AI check address** and
tick the AI check box. Only the website name is sent. Empty means the backend at `backendUrl`.

## Protecting the key

- The key is only in Netlify's environment variables. It is never in the repository, the page or the
  extension, and the function sends it to Google in a request header.
- Netlify blocks more than 20 checks a minute from one IP address before the function runs
  (`config.rateLimit`). Each function instance also caches answers for a day and stops after
  `llm.hosted.max_calls_per_day` Gemini calls a day (instances do not share this count).
- Make the key in a Google project without billing (the AI Studio default). Then the worst a stranger
  can do is use up the free daily quota; it can never cost money. The check then answers
  "no opinion" until the quota resets.

## The domain check (tier C)

`netlify/functions/domain-check.mjs` answers `POST /api/domain-check {"domain": "example.com"}` with a
verdict from the domain's age (registry RDAP), DNS and TLS certificate. It needs no key. It reads the model
`js/data/tier_c.json` at run time (`netlify.toml` ships it with the function); without that file it answers
`{"checked": false, "reason": "no_model"}` and nothing is guessed. The file exists only after
`python -m models.tier_c train` has run on captured data and the gates in `reports/tier_c.md` passed.

- It refuses IP addresses, local names, hosting platforms and link shorteners, and the TLS handshake goes only
  to a public address it looked up itself (the same guard as `expand.mjs`). No page is fetched.
- Netlify blocks more than 20 checks a minute from one IP address; each instance keeps an answer for an hour
  (`tier_c.serving` in `configs/models.yaml`) and gives up after `total_timeout_ms`.
- The extension asks it by default (`tierC: true`, `tierCUrl` in `extension/src/config.js`; a different site's address
  can go in the popup under **Domain check address**, and the box "Check the age and certificate of suspicious sites"
  switches it off). Only the registrable domain is sent, and only for addresses the address model already finds
  suspicious and the allowlist does not cover. The answer can raise suspicious to dangerous and add reasons; it never
  lowers a verdict or warns on an address that looked safe. A slow, failed or refused answer is no evidence: the
  verdict already shown stays, and the page is never held up.
- Not tested on a real Netlify deploy (build image, function time limit, `rateLimit`); the logic is tested with a
  fake network in `js/test/domain_check.test.js`.

## The page fetch (tier B on the URL check page)

A web page cannot read another site's HTML (CORS), so the model that reads a page (tier B) cannot run in the
browser against a typed address by itself. `netlify/functions/fetch-page.mjs` answers `POST /api/fetch-page
{"url": "https://..."}` with one plain GET of that address: `{ok, status, final, redirects, bytes, truncated, html,
error}`. The page then scores the HTML with the same code and model file as the extension (`js/src/page.js`,
`js/data/tier_b_page.json`) and shows the three tiers side by side under the verdict. Settings: `page_fetch` in
`configs/backend.yaml` (exported by `python -m backend export-llm-js` to `js/data/page_fetch.json`).

- Safe by construction: only http and https on ports 80 and 443; the first address and every redirect must be a
  public address, checked when the connection is made (a DNS answer cannot change in between) and for addresses
  written as IPs; 5 redirects, 9 seconds and 1.5 MB (after decompression) at most; no cookies are sent or kept; only
  an HTML answer is returned; nothing on the page is run and no other file of it is fetched. Netlify blocks more than
  10 fetches a minute from one IP address. It is one fetch of the address the visitor typed, not a crawl, so it does
  not read robots.txt.
- Privacy: unlike the extension (which sends only the domain), the full address reaches this function. Nothing is stored.
- Limits that remain: a server can show this function a different page than a visitor (it sends an honest user agent
  and does not hide); a page built by scripts arrives nearly empty and the page then says tier B could not read it and
  only tier A counts; training used stored HTML, so a live fetch is not the same input. The page does not run the
  extension's login-form rules (they need the live page) and does not fetch allowlisted, blocklisted or short-link
  addresses (a short link is followed to its destination first, as before).
- Tier C on the same page: `POST /api/domain-check` with the registrable domain, for every address the lists did not
  decide (the extension asks only suspicious ones, so the page shows the score more often).
- Not tested on a real Netlify deploy; the logic is tested with fakes and a local server in `js/test/fetch_page.test.js`
  and `extension/test/demo.test.js`.
