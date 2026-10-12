# Tier A features in JavaScript

`src/features.js` is a line-by-line port of `features/url_features.py` (and `src/urlparts.js`,
`src/psl.js` of `features/urlparts.py` and the public-suffix split), so the browser extension
computes exactly the numbers the tier A model was trained on.

- `data/psl_icann.json`: ICANN public-suffix rules (with punycode aliases), and
  `data/lists.json`: word lists, platform list and fitted numbers. Both are written by
  `python -m features export-js`; never edit them by hand.
- Parity: `tests/fixtures/url_parity.json` (written by `python -m features parity`) holds 272
  URLs with the values Python computes. `npm test` checks JavaScript gives the same values;
  `pytest` checks the file still matches Python. CI runs both.

```js
import { buildLists, extract } from "./src/features.js";
const lists = buildLists(listsJson, pslRules);
const features = extract("https://paypa1.com/verify", lists, names);
```

## Tier A model

`src/model.js` scores a URL with the exported tier A model (`data/tier_a_model.json`, written by
`python -m models.export`): the LightGBM trees, the lists and fitted numbers it was trained
with, the "suspicious" (FPR 1%) and "dangerous" (FPR 0.1%) thresholds and the isotonic map, all
from one domain-grouped split. `tests/fixtures/model_parity.json` holds LightGBM's own
probability and reasons for each parity URL; `npm test` checks JavaScript reproduces them.

Reasons: `src/explain.js` computes TreeSHAP contributions on the trees (a port of
`models/explain.py`, equal to LightGBM's `pred_contrib`) and turns the features that push
hardest toward phishing into sentences from the bundle's `reasons` rules.

```js
import { loadModel, scoreUrl } from "./src/model.js";
const model = loadModel(bundleJson, pslRules);
const { prob, calibrated, verdict, reasons } = scoreUrl(model, "https://paypa1.com/verify");
// verdict: 0 safe, 1 suspicious, 2 dangerous; reasons: [{ feature, contribution, text }]
```

## Hybrid tier A model (the one to ship)

`src/hybrid.js` + `src/chargram.js` score a URL with the hybrid model (`data/tier_a_hybrid.json`,
8 MB, written by `python -m models.export_hybrid`): LightGBM on the 99 URL features plus the
scores of two char n-gram TF-IDF + logistic-regression models (masked URL, host). The char models
here have a 100,000-term vocabulary; the evaluated experiment (`reports/hybrid_a.md`) uses 500,000
terms, and the shipped size has its own metrics in `reports/tables/hybrid_export.csv`.
`tests/fixtures/hybrid_parity.json` holds Python's probability and reasons for every parity URL;
`npm test` checks JavaScript reproduces them.

Cost on a loaded 4-core machine: about 1 ms for features, 0.1 ms per char model and trees,
so about 2 ms per URL, plus about 100 ms for the SHAP reasons, which `scoreUrl(model, url,
{ withReasons: true })` computes only when a warning is shown.

```js
import { loadHybrid, scoreUrl } from "./src/hybrid.js";
const model = loadHybrid(bundleJson, pslRules);
const { prob, calibrated, verdict, reasons } = scoreUrl(model, url, { withReasons: true });
```
