# Features and data

Full research catalog with sources lives in the Claude Doc "Phishing Detection Feature Catalog".
This file is the implementation subset.

## Datasets

| Dataset | Use | Notes |
| --- | --- | --- |
| PhreshPhish (`phreshphish/phreshphish` on Hugging Face) | Main training set; dates enable E1/E3 | URL + HTML + date + target brand; CC BY 4.0, anti-phishing research only; v1.0.1 adds samples to Dec 2025 |
| PhiUSIIL (UCI id 967, `ucimlrepo`) | Second training/comparison set | 134,850 legit / 100,945 phishing, 54 features, CC BY 4.0 |
| Hannousse–Yahiouche (Mendeley, 87 features) | Comparison with prior papers only | 2020, balanced, inflated scores |
| Phishpedia 30k | Stretch: brand/visual work | URL, HTML, screenshot, brand |
| Live feeds: OpenPhish, PhishTank, URLhaus | Fresh phishing for time-split test, E3, real-world check | Timestamp first-seen; check each feed's terms |
| Tranco top list | Benign seeds + allowlist | Crawl inner pages too, not only homepages |

Data card per dataset: source, collection dates, counts, class balance, dedup stats, license.

## Features — Tier 1 (in-browser URL model, must match Python exactly)

- Lengths: URL, host, domain, subdomain, path, query, TLD; longest token
- Counts: `. - _ / @ ? & = % ~ +`, digits, letters, subdomain levels, path depth, query params
- Ratios: digits/letters/special chars in URL and host
- Host form: IP as host (incl. hex/decimal), non-standard port, punycode `xn--`, `https`/`www` tokens
  inside host or path, double slash in path
- Randomness: Shannon entropy of domain and URL, longest repeated-char run, char-bigram likelihood
- Words: suspicious keywords (login, verify, secure, update, account, kyc, wallet, bank, signin,
  otp, upi), brand names in subdomain/path, dictionary-word ratio
- Squatting: min edit distance to a brand list (include Indian banks/payment apps), confusable/homoglyph
  normalization then compare, combosquatting (`brand-` / `-brand`)
- TLD risk score (learned from training data only), shortener domain, redirect params, embedded email

## Features — Tier 2 (backend)

- Domain: age (RDAP), days to expiry, registrar, privacy-redacted WHOIS
- DNS: A/AAAA count, MX/SPF/DMARC present, NS count, min TTL, CNAME chain length
- TLS: HTTPS, issuer type (free vs paid), validity period, cert age, SAN count, brand keyword in SANs
- Hosting: ASN, country, free-hosting/platform flag (treat specially; don't let it stand in for phishing)
- Redirects: hop count, cross-domain hops, shortener in chain

## Features — Tier 3 (HTML/DOM, content script and training)

- Forms: password field, credential-form count, action empty/blank/mailto/other-domain, hidden fields,
  OTP/card/CVV/UPI PIN fields
- Links: % external, % null/self (`#`, `javascript:`), anchor-text vs href mismatch
- Resources: % external scripts/CSS/images, favicon from another domain
- Text: title–URL match score, brand in title/text not matching domain, urgency words
- Structure: iframes (hidden), meta refresh, right-click disabled, low text-to-code ratio, page size
- Scripts: `eval`/`atob`/`unescape`/`document.write`, obfuscation entropy, exfil endpoints
  (Telegram bot, webhooks)

## Features — Tier 4 (stretch)

- Brand-vs-domain check from logo (Phishpedia-style) or LLM brand inference
- Credential-page classifier on screenshot
- CT-log and passive-DNS features

## Known pitfalls

- Popularity features (rank, indexing) leak class labels; keep them out of the model.
- Free-hosting traits (deep subdomains) can track hosting platform more than phishing.
- Old datasets' HTML may be parked/takedown pages; prefer datasets that saved HTML at collection.
- URL-only adversarial training helps little in the literature; robustness comes mainly from
  features attackers can't cheaply change (domain age, cert, page intent) and multimodal fusion.
