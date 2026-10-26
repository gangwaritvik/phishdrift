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
