// Tier A URL model in the browser: features (features.js) + the LightGBM trees, thresholds and
// isotonic map of js/data/tier_a_model.json (written by `python -m models.export`). The tree walk
// follows LightGBM's numerical decision exactly, on float32 feature values as in training.

import { contributions, reasons } from "./explain.js";
import { buildLists, extract } from "./features.js";

const ZERO_THRESHOLD = 1e-35; // LightGBM's kZeroThreshold
export const SAFE = 0;
export const SUSPICIOUS = 1;
export const DANGEROUS = 2;

export function loadModel(bundle, pslRules) {
  return {
    names: bundle.names,
    lists: buildLists(bundle.lists, pslRules),
    trees: bundle.trees,
    thresholds: bundle.thresholds,
    isotonic: bundle.isotonic,
    expectedValue: bundle.expected_value,
    reasonRules: bundle.reasons,
    explainOptions: bundle.explain,
  };
}

function leafValue(tree, x) {
  if (tree.f.length === 0) return tree.v[0];
  let node = 0;
  while (node >= 0) {
    let v = x[tree.f[node]];
    const missingType = tree.m[node];
    const nan = Number.isNaN(v);
    if (nan && missingType !== 2) v = 0;
    const missing = (missingType === 1 && Math.abs(v) <= ZERO_THRESHOLD) || (missingType === 2 && nan);
    const left = missing ? tree.d[node] === 1 : v <= tree.t[node];
    node = left ? tree.l[node] : tree.r[node];
  }
  return tree.v[~node];
}

// Sum of leaf values; `values` in the order of model.names.
export function rawScore(model, values) {
  const x = values.map((v) => Math.fround(v));
  let total = 0;
  for (const tree of model.trees) total += leafValue(tree, x);
  return total;
}

// np.interp with the ends clipped, as IsotonicRegression(out_of_bounds="clip").predict.
export function interp(v, xs, ys) {
  if (v <= xs[0]) return ys[0];
  const last = xs.length - 1;
  if (v >= xs[last]) return ys[last];
  let lo = 0;
  let hi = last;
  while (hi - lo > 1) {
    const mid = (lo + hi) >> 1;
    if (xs[mid] <= v) lo = mid;
    else hi = mid;
  }
  if (v === xs[lo]) return ys[lo];
  return ys[lo] + ((v - xs[lo]) * (ys[hi] - ys[lo])) / (xs[hi] - xs[lo]);
}

export function scoreFeatures(model, features) {
  const values = model.names.map((n) => features[n]);
  const prob = 1 / (1 + Math.exp(-rawScore(model, values)));
  let verdict = SAFE;
  if (prob >= model.thresholds.dangerous) verdict = DANGEROUS;
  else if (prob >= model.thresholds.suspicious) verdict = SUSPICIOUS;
  const calibrated = interp(prob, model.isotonic.x, model.isotonic.y);
  return { prob, calibrated, verdict };
}

// Plain-English reasons (with their log-odds contributions) for one feature dict.
export function explain(model, features) {
  const values = model.names.map((n) => features[n]);
  const phi = contributions(model.trees, values);
  return reasons(phi, values, model.names, model.reasonRules, model.explainOptions);
}

// Score one URL: `prob` is the model output the thresholds apply to, `calibrated` the isotonic
// probability for display and the runtime combiner, `verdict` 0 safe / 1 suspicious / 2 dangerous,
// `reasons` the plain-English reasons (only computed when `withReasons`; about 100 ms).
export function scoreUrl(model, url, { withReasons = false } = {}) {
  const features = extract(url, model.lists, model.names);
  const scored = scoreFeatures(model, features);
  const why = withReasons ? explain(model, features) : [];
  return { ...scored, reasons: why, features };
}
