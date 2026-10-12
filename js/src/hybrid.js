// Hybrid tier A model in the browser: the 99 URL features plus two char n-gram scores (masked URL,
// host) feed the LightGBM trees, as models/hybrid.py. Bundle: js/data/tier_a_hybrid.json, written
// by `python -m models.export_hybrid`.

import { charProb, loadChar, logit } from "./chargram.js";
import { contributions, reasons } from "./explain.js";
import { buildLists, extract } from "./features.js";
import { DANGEROUS, SAFE, SUSPICIOUS, interp, rawScore } from "./model.js";
import { parse } from "./urlparts.js";

export function loadHybrid(bundle, pslRules) {
  return {
    names: bundle.names,
    lists: buildLists(bundle.lists, pslRules),
    trees: bundle.trees,
    thresholds: bundle.thresholds,
    isotonic: bundle.isotonic,
    reasonRules: bundle.reasons,
    explainOptions: bundle.explain,
    char: Object.fromEntries(Object.entries(bundle.char).map(([k, v]) => [k, loadChar(v)])),
  };
}

// Feature values in model.names order: URL features, then char_url and char_host.
export function featureValues(model, url) {
  const features = extract(url, model.lists, model.names);
  const parts = typeof url === "string" ? parse(url, model.lists.platforms, model.lists.psl) : null;
  const texts = { char_url: parts ? parts.canon : "", char_host: parts ? parts.host : "" };
  for (const [name, c] of Object.entries(model.char)) {
    features[name] = logit(charProb(c, texts[name]), c.eps);
  }
  return model.names.map((n) => features[n]);
}

export function scoreUrl(model, url, { withReasons = false } = {}) {
  const values = featureValues(model, url);
  const prob = 1 / (1 + Math.exp(-rawScore(model, values)));
  let verdict = SAFE;
  if (prob >= model.thresholds.dangerous) verdict = DANGEROUS;
  else if (prob >= model.thresholds.suspicious) verdict = SUSPICIOUS;
  const calibrated = interp(prob, model.isotonic.x, model.isotonic.y);
  // SHAP costs about 100 ms (scoring a URL costs about 2 ms), so reasons are asked for only
  // when a warning is shown.
  const why = withReasons
    ? reasons(contributions(model.trees, values), values, model.names, model.reasonRules, model.explainOptions)
    : [];
  return { prob, calibrated, verdict, reasons: why };
}
