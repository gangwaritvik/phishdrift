// Hybrid tier A model in the browser: the 99 URL features plus the text-scorer scores (char n-gram
// models of the masked URL, host and path; a word model of the URL) feed the LightGBM trees, as
// models/hybrid.py. Bundle: js/data/tier_a_hybrid.json, written by `python -m models.export_hybrid`.

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
    scorers: Object.fromEntries(Object.entries(bundle.scorers).map(([k, v]) => [k, loadChar(v)])),
  };
}

// The part of the masked URL a scorer reads (models/text_scorers.py PIECES).
function pieceText(parts, piece) {
  if (!parts) return "";
  if (piece === "url") return parts.canon;
  if (piece === "host") return parts.host;
  if (piece === "domain") return parts.domain;
  if (piece === "path") return parts.path + (parts.query ? `?${parts.query}` : "");
  throw new Error(`unknown scorer piece ${piece}`);
}

// Feature values in model.names order: URL features, then one score per text scorer.
export function featureValues(model, url) {
  const features = extract(url, model.lists, model.names);
  const parts = typeof url === "string" ? parse(url, model.lists.platforms, model.lists.psl) : null;
  for (const [name, c] of Object.entries(model.scorers)) {
    features[name] = logit(charProb(c, pieceText(parts, c.piece)), c.eps);
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
