# Brand list additions: review note (2026-10-20)

Proposed: 127 brands in `configs/lists/brand_additions.txt`, merged into `configs/lists/brands.txt`
(772 -> 899). Delete a line in `brand_additions.txt` to drop a brand; merging the PR freezes the list.

## How they were chosen

No popularity rank was used. A name is proposed when phishers use it now:

- It appears in at least 10 distinct registrable domains among 789,354 phishing URLs
  (Phishing.Database `phishing-links-ACTIVE.txt` plus the OpenPhish public feed, both fetched
  2026-10-20). Counts per name: `reports/tables/brand_evidence.csv`, from
  `python -m experiments.brand_evidence` (command at the end).
- Hits inside a longer unrelated word do not count. "revolut" had 244 raw hits, all inside
  "revolution"; the CSV's `top_words` column shows these words for every name.
- It is not an everyday word or part of one, because the URL features match brand names as
  substrings ("wise" is in "otherwise").
- The name is the label of the brand's own website (`cibc.com`, `revolut.com`), as with the Wikidata
  entries, so the brand-page rule recognises the real site.
- Exception: Slack, Revolut, Swiggy and Monzo were asked for by name and are kept, though the feeds
  have almost no phishing under those names. TikTok, Capital One and Roblox passed the test anyway.

The candidates were drawn from two places. The first was the most frequent words in phishing
hostnames that are not on the list yet. The second was a sweep of the gaps named in the request:
fintech, food delivery, social, gaming and regional banks. The candidates were picked by hand, and
the counts decided which of them stayed.

## What changed in the brand rules (measured)

`python -m experiments.brand_rules_eval` on the same sets as the 2026-10-13 run (`reports/brand_rules.md`):

| set | before | after |
|---|---|---|
| natural legitimate URLs (2,373), address rules | 0 | 0 |
| regional brand sites (114), address rules | 0 | 0 |
| natural legitimate pages, brand-page rule | 1 | 1 (same page) |
| phishing `openphish_gh.txt` (300), address rules | 10 | 13 |

The phishing row is not an independent test, because some of those URLs may also be in the feeds
used to choose the names. An earlier draft also included `commbank`. With it, the look-alike rule
warned on `combank.lk` (Commercial Bank of Ceylon) because the two names are one letter apart. It
is now in the "your call" list below.

## Left out: your call

Ranked by phishing domains. **Default: all left out.** Two are worth adding in my view (marked).

**Everyday words, or part of one** (the brand features would also fire on ordinary addresses):
dana 798 (in "ciudadana"), interac 461 (in "interactive"), absa 415, halifax 411 **(add: place
name, rarely in addresses)**, huntington 282 **(add: same)**, tangerine 266, booking 241,
millennium 216, intesa 216 (Italian word; `intesasanpaolo` is added), exodus 171, ledger 155,
saison 140, wise 139 (`transferwise` is added), ameli 125, orico 104 (in "historico"), intuit 79
(in "intuitive"), phantom 70, fidelity 65, epos (in "deposit"), and the rest in the CSV
(stripe, kraken, allegro, etsy, canva, asana, rapido, nationwide, interbank, yamato, postoffice,
okta, xero, mobilepay, etrade, evri, webex, mexc, ifood, ikea, rappi, cimb, minecraft, bybit).

**Clashes with another real site**: commbank 305 (one letter from `combank.lk`; add both commbank
and combank, or neither), unionbank 78 (inside `unionbankofindia`, already a brand, so its real
site would look like it contains a brand), anpost 68 (inside `japanpost`).

**The brand logs in on a site with another name** (the brand-page rule would warn on the real login
page): mygov 512 (`my.gov.au`), sparkasse 393 (each savings bank has its own domain), royalbank 268
(`rbc.com`), swisspost 117 (`post.ch`), fifththird (`53.com`), dbsbank and paylah (`dbs.com`),
myjcb (`jcb.co.jp`), quickbooks (`intuit.com`), hmrc and govuk (`gov.uk`), cashapp (`cash.app`),
zelle (inside bank sites), tmobile (`t-mobile.com`), ezpass, citrix (self-hosted logins),
societegenerale (`sg.fr` login), metrobank, ziraat, bendigo, bradesco, posteitaliane (`poste.it`),
canadapost. These can be added once the brand-to-domain map (step 1 below, Wikidata) lists their
own domains.

**Little or no phishing in the feeds** (fine to add, no evidence either way): klarna 5, gcash 5,
venmo 2, alipay 2, and 0 for zomato, doordash, deliveroo, instacart, blinkit, zepto, myntra,
meesho, nykaa, razorpay, bharatpe, delhivery, bluedart, hotstar. The feeds cover Indian brands
poorly, so a zero there says little.

**Already on the list but generic** (optional, for `brand_exclude`): about, time, smart.

## Where the list is used, and what needs your PC

1. **Brand and look-alike rules** (escalate-only, in the extension): `js/data/brand_rules.json` is
   regenerated in this PR, so the next extension build uses the new names with no PC work.
2. **Model features** (tier A and B count brand names in the address and page): the shipped models
   keep the list they were trained with until they are retrained. The shipped address bundle still
   carries the 67-name seed list (known since 2026-10-19), so retraining fixes that too.

On the PC, after copying the merged main in:

```
powershell -ExecutionPolicy Bypass -File scripts\refresh_brands.ps1          # map + rules + extension (minutes)
powershell -ExecutionPolicy Bypass -File scripts\refresh_brands.ps1 -Model   # also rebuild features and retrain split 0
```

`-Model` rebuilds tier A and B features (tier B took about 3.5 hours last time and resumes after
Ctrl+C), retrains split 0 with `experiments.blend2`, and re-exports both browser bundles. Tier B
shards built with the old lists are now detected by a word-list hash and rebuilt. Before this
change they would have been reused silently. The 10-split numbers in `reports/` were measured with
the old list. Only a full `experiments.blend2` rerun would update them.

`python -m features lists` (scraping Wikidata again) is optional (`-Rescrape`). It merges
`brand_additions.txt` and drops the reviewed generic words (`brand_exclude` in
`configs/features.yaml`), so those words cannot come back from Wikidata. Today's Wikidata can still
add or drop other names.

## Rebuilding the evidence table

```
python -m experiments.brand_evidence --phishing phishing-links-ACTIVE.txt openphish_feed.txt \
    --extra <names to check> --benign-csv data/raw/ood/ood_urls.csv data/raw/ood_html/ood_urls.csv
```

The table in this PR was built from the feeds as fetched on 2026-10-20, with all the names above
passed as `--extra`. The feeds change daily, so a later run gives different counts.
