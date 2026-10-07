# Features and data

Full research catalog with sources lives in the Claude Doc "Phishing Detection Feature Catalog".
This file is the implementation subset. Every implemented feature is listed in
`docs/FEATURE_DICTIONARY.md`, generated from `features/registry.py`.

## Sources (training and evaluation corpus)

Only URL, label, date and HTML are loaded from any source. Precomputed feature columns are never used.

| Source | Size (published) | HTML | Dates | Notes and caveats |
| --- | --- | --- | --- | --- |
| PhreshPhish (`phreshphish/phreshphish`, Hugging Face) | ~119k phishing / ~253k benign | yes | yes (Jul 2024 – Mar 2025; v1.0.1 later) | Main source. Benign from real browsing telemetry. Has an official later-in-time test split. CC BY 4.0, anti-phishing research only. |
| PhiUSIIL (UCI id 967, `ucimlrepo`) | 100,945 phishing / 134,850 legit | not used | no | URL column only. Label 1 = legitimate in the original (recode). Legit = 100% bare homepages (see rules below). Never use `URLSimilarityIndex`, `TLDLegitimateProb`, `URLCharProb` or any other column. CC BY 4.0. |
| Phish360 | 10,748 total | yes + screenshots | 2020–23 (per-row dates to check) | Legit includes login pages (hard negatives). Parquet. Download link and license to confirm. |
| Phish-Blitz | 5,000 phishing / 8,809 legit | yes (full page resources) | to check | Dataset and tool on GitHub. |
| Phishpedia 30k | 30k phishing | yes + screenshots | partly | Phishing only (contributes one class). |
| URL-Phish (Mendeley) | 16,600 phishing / 100,000 benign | no | phishing Nov 2024 – Sep 2025 | Benign from the Research Organization Registry (.edu/.gov, likely homepage-heavy): same handling as PhiUSIIL legit. |
| PhishStorm (Aalto) | 48,009 / 48,009 | no | no (2014) | Old; URLs often stored without a scheme. |
| Live feeds (our collector) | grows daily | via sandbox | first-seen | Only source for tier C. |
| Benign inner-page crawl | grows | optional | crawl date | 3–5 inner pages per seed domain from PhiUSIIL-legit and Tranco seeds. |
| Naturally browsed legitimate pages | — | — | — | Evaluation only: out-of-distribution FPR. |

Data card per source: URL and domain counts, dates, class balance, depth distribution, dedup and removal
counts, crawl success, license.

### PhiUSIIL legitimate URLs (rule)

They are valid benign data, but 100% are bare `https://www.<domain>` homepages. Used alone they create a
"has a path = phishing" shortcut: the prior report's raw model flagged 100% of naturally collected
legitimate URLs (report §13.11).
1. Never the only benign source; always mixed with deep benign URLs (PhreshPhish benign, crawler inner
   pages, Tranco-seeded inner pages).
2. Balance URL path depth across classes. Report per-class depth distributions before training and fail
   the build if any depth bucket is >90% one class.
3. Use PhiUSIIL legit domains as crawl seeds: sample domains and fetch 3–5 inner pages each (robots.txt
   and rate limits respected).
4. Use all PhiUSIIL legit domains for registrable-domain-level features and to seed the allowlist and
   brand list.

## Live feeds and lists

| Feed | Role | Terms / notes |
| --- | --- | --- |
| OpenPhish community (`openphish.com/feed.txt`) | Main live phishing source | Poll every 12 h; non-commercial only |
| Phishing.Database (Phishing-Database org on GitHub) | Secondary live phishing source | MIT license; use the "NEW today" lists for first-seen |
| PhishTank | Secondary only | Registration closed since 2020; online-valid feed has survivorship bias |
| URLhaus | Blocklist only | Free abuse.ch Auth-Key; mostly malware, not phishing training data |
| Google Safe Browsing | Blocklist (backend) | Update API with local hash prefixes, not Lookup; non-commercial; key stays on the backend |
| Tranco (`tranco` Python package) | Allowlist + benign crawl seeds | Rank never used as a model feature |

## Feature tiers

Feature definitions are reimplemented from Hannousse–Yahiouche (87 features; their published scripts
are the reference), PhiUSIIL (paper definitions; derived similarity scores skipped), the UCI 30-feature
set, and the lists below.

### Tier A — URL (all samples; runs in the browser; must match Python exactly)

Computed after platform-identity masking (`configs/platforms.yaml` → neutral token +
`is_hosting_platform`).
- Lengths: URL, host, domain, subdomain, path, query, TLD; shortest/longest/average word in URL, host, path
- Counts: `. - _ / @ ? & = % ~ + * : , ; $ |` and spaces, digits, letters, subdomain levels, path depth,
  query params, `www` and `com` tokens
- Ratios: digits/letters/special chars in URL and host
- Host form: IP as host (incl. hex/decimal), non-standard port, punycode `xn--`, `http`/`https`/`www`
  tokens inside host or path, double slash in path, TLD in path or subdomain, abnormal subdomain,
  prefix-suffix hyphen, path extension
- Obfuscation: %-encoding count and ratio, char continuation rate, longest repeated-char run
- Randomness: Shannon entropy of domain and URL, char-bigram likelihood (fitted on training benign
  only), random-domain score
- Words: suspicious keywords (login, verify, secure, update, account, kyc, wallet, bank, signin, otp,
  upi, ...), brand names in subdomain/path, domain-in-brand
- Squatting: min edit distance to a brand list (incl. Indian banks/payment apps), homoglyph
  normalisation then compare, combosquatting (`brand-` / `-brand`)
- Other: shortener domain, redirect params, embedded URL or email, suspicious TLD list, TLD risk score
  (learned from training folds only)
- Char n-gram TF-IDF of the masked URL (input to the TF-IDF + LR base learner, not a dictionary feature)

### Tier B — HTML (samples with HTML; content script and training)

- Forms: password field, credential-form count, action empty/blank/mailto/other-domain, hidden fields,
  submit button, OTP/card/CVV/UPI-PIN fields
- Links: hyperlink count, % internal/external/null (`#`, `javascript:`), safe anchors, links in
  meta/script/link tags, anchor-text vs href mismatch
- Resources: % external scripts/CSS/images/media, favicon present / from another domain
- Text: title present/empty, domain in title, domain- and URL-title match scores, description,
  copyright (and domain in copyright), bank/pay/crypto words, urgency words, brand in title/text not
  matching the domain, social links
- Structure: lines of code, longest line, page size, text-to-code ratio, iframes (hidden), meta refresh,
  right-click disabled, onmouseover tricks, popups, JS redirects, responsive viewport, robots meta
- Scripts: `eval`/`atob`/`unescape`/`document.write`, obfuscation entropy, exfil endpoints (Telegram
  bot API, webhooks, form relays)

### Tier C — domain / DNS / WHOIS / TLS (live-feed URLs only, captured at first-seen)

- Domain: age (RDAP), days to expiry, registration length, registered or not, privacy-redacted
  WHOIS, registrar category
- DNS: record exists, A/AAAA count, MX/SPF/DMARC present, NS count, min TTL, CNAME chain length
- TLS: HTTPS, valid cert, issuer type (free vs paid), validity period, cert age, SAN count, brand
  keyword in SANs
- Hosting: ASN class, free-hosting/platform flag (treated specially; must not stand in for phishing)
- Redirects: hop count, cross-domain hops, shortener in chain

### Excluded from all models

- Popularity: Tranco rank, web traffic, PageRank, Google index, links pointing to page (allowlist only)
- Blocklist membership (`statistical_report` in Hannousse–Yahiouche and UCI): blocklist layer only
- PhiUSIIL derived scores: `URLSimilarityIndex`, `TLDLegitimateProb`, `URLCharProb`
- Features that need every link on a page fetched live (Hannousse–Yahiouche `ratio_intErrors`,
  `ratio_extErrors`, internal/external redirection ratios): old pages can't be recomputed

### Stretch (tier 4)

- Brand-vs-domain check from logo (Phishpedia-style) or LLM brand inference
- Credential-page classifier on screenshot
- CT-log and passive-DNS features

## Known pitfalls

- Popularity features leak class labels; keep them out of the model.
- Hosting-platform identity (web.app, github.io, ...) does not transfer to unseen domains; mask it
  (prior report §13.9).
- URL depth differs systematically between sources and classes (report §13.7); balance and check it.
- Old datasets' HTML may be parked or takedown pages; prefer datasets that saved HTML at collection
  time, and treat junk HTML as missing.
- Sources record URLs differently (scheme present or missing, `www.`, trailing slash); canonicalise
  before computing features so formatting cannot reveal the source.
- URL-only adversarial training helps little in the literature; robustness comes mainly from features
  attackers can't cheaply change (domain age, cert, page intent) and multimodal fusion.
