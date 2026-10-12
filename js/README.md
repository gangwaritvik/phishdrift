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
