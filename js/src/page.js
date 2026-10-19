// Page model in the browser: once the content script has the page's HTML, the tier B page features
// (html_features.js), the tier A features and the address model's text scores feed the page
// model's LightGBM trees, as models/page_model.py. Bundle: js/data/tier_b_page.json, written by
// `python -m models.export_page` together with the address model it shares its text scorers with.
//
// Verdict (the "agree" rule of experiments/blend2.py, bundle.rule): dangerous if the address model
// alone is over its dangerous threshold or the blended score is over the blend's dangerous
// threshold; suspicious if the blended score is over the blend's suspicious threshold and, on a
// page with usable HTML, the address model is also over its own suspicious threshold. The blended
// score is the calibrated page-model score when the page has usable HTML, else the calibrated
// address score.

import { contributions, reasons } from "./explain.js";
import { featureValues } from "./hybrid.js";
import { extractHtml } from "./html_features.js";
import { DANGEROUS, SAFE, SUSPICIOUS, interp, rawScore } from "./model.js";

export function loadPage(bundle) {
  return {
    names: bundle.names,
    trees: bundle.trees,
    reasonRules: bundle.reasons,
    explainOptions: bundle.explain,
    isoPage: bundle.isotonic_page,
    isoAddress: bundle.isotonic_address,
    tie: bundle.tie,
    thresholds: bundle.thresholds,
    rule: bundle.rule ?? "shipped",
  };
}

const calibrated = (prob, iso, tie) => interp(prob, iso.x, iso.y) + tie * prob;

// address: loadHybrid(...) model; page: loadPage(...) model.
// `allowShort`: also read a page with less visible text than training pages had (a bare login form
// clone); the result is marked `short`. The extension asks for it only on pages with a password
// field, and the combiner never lets the page model lower a verdict there, so on such a page the
// model can only add a warning.
export function scorePage(address, page, url, html, { withReasons = false, allowShort = false } = {}) {
  const aValues = featureValues(address, url);
  const probAddress = 1 / (1 + Math.exp(-rawScore(address, aValues)));
  const byName = Object.fromEntries(address.names.map((n, i) => [n, aValues[i]]));
  let pageFeatures = extractHtml(url, html, address.lists);
  let hasHtml = Object.values(pageFeatures).some((v) => !Number.isNaN(v));
  let short = false;
  if (!hasHtml && allowShort) {
    pageFeatures = extractHtml(url, html, address.lists, null, { minVisibleChars: 1 });
    hasHtml = short = Object.values(pageFeatures).some((v) => !Number.isNaN(v));
  }
  let probPage = null;
  let values = null;
  let blended;
  if (hasHtml) {
    values = page.names.map((n) => (n in pageFeatures ? pageFeatures[n] : byName[n]));
    probPage = 1 / (1 + Math.exp(-rawScore(page, values)));
    blended = calibrated(probPage, page.isoPage, page.tie);
  } else {
    blended = calibrated(probAddress, page.isoAddress, page.tie);
  }
  let verdict = SAFE;
  if (probAddress >= address.thresholds.dangerous || blended >= page.thresholds.dangerous) {
    verdict = DANGEROUS;
  } else if (
    blended >= page.thresholds.suspicious &&
    (page.rule !== "agree" || !hasHtml || probAddress >= address.thresholds.suspicious)
  ) {
    verdict = SUSPICIOUS;
  }
  const why =
    withReasons && hasHtml
      ? reasons(contributions(page.trees, values), values, page.names, page.reasonRules, page.explainOptions)
      : [];
  return { hasHtml, short, probAddress, probPage, blended, verdict, reasons: why };
}
