// Tier A model parity: for every URL in tests/fixtures/model_parity.json (LightGBM's own
// probabilities, written by `python -m models.export`), JavaScript features + tree walk must give
// the same probability.

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";

import { DANGEROUS, SAFE, loadModel, scoreUrl } from "../src/model.js";

const root = new URL("../../", import.meta.url);
const bundleUrl = new URL("js/data/tier_a_model.json", root);
const read = (path) => JSON.parse(readFileSync(new URL(path, root), "utf8"));

test("tier A model matches LightGBM on the parity URLs", { skip: !existsSync(bundleUrl) }, () => {
  const bundle = read("js/data/tier_a_model.json");
  const parity = read("tests/fixtures/model_parity.json");
  assert.equal(parity.bundle_created, bundle.created, "rerun python -m models.export");
  const model = loadModel(bundle, read("js/data/psl_icann.json"));
  assert.ok(parity.cases.length >= 200);
  const failures = [];
  for (const { url, prob, reasons } of parity.cases) {
    const got = scoreUrl(model, url, { withReasons: true });
    const where = JSON.stringify(url);
    if (!(Math.abs(got.prob - prob) <= 1e-12)) failures.push(`${where}: ${got.prob} vs ${prob}`);
    if (!(got.calibrated >= 0 && got.calibrated <= 1)) failures.push(`${where}: calibrated ${got.calibrated}`);
    const texts = got.reasons.map((r) => r.text);
    if (JSON.stringify(texts) !== JSON.stringify(reasons.map((r) => r.text))) {
      failures.push(`${where}: reasons ${JSON.stringify(texts)} vs ${JSON.stringify(reasons.map((r) => r.text))}`);
    }
    got.reasons.forEach((r, i) => {
      const want = reasons[i]?.contribution;
      if (!(Math.abs(r.contribution - want) <= 1e-9)) failures.push(`${where}: ${r.feature} ${r.contribution} vs ${want}`);
    });
  }
  assert.equal(failures.length, 0, failures.slice(0, 20).join("\n"));
});

test("verdicts follow the thresholds", () => {
  const tree = { f: [0], t: [0.5], m: [2], d: [1], l: [-1], r: [-2], v: [-4, 4] };
  const lists = { platforms: [], brands: [], keywords: [], shorteners: [], suspicious_tlds: [],
    redirect_params: [], fitted: { bigram_logprob: {}, bigram_floor: -20, tld_risk: {}, tld_default: 0.5 } };
  const bundle = { names: ["url_len"], lists, trees: [{ ...tree, c: [10], n: [5, 5] }],
    thresholds: { suspicious: 0.5, dangerous: 0.9 }, isotonic: { x: [0, 1], y: [0, 1] },
    expected_value: 0, reasons: { url_len: { text: "Long ({v}).", lo: null, hi: null } },
    explain: { top: 3, min_logodds: 0.1 } };
  const model = loadModel(bundle, ["com"]);
  // url_len > 0.5 goes right (+4, dangerous); NaN (unparsable) goes left by default (-4, safe).
  const hit = scoreUrl(model, "https://example.com/");
  assert.equal(hit.verdict, DANGEROUS);
  // One split on url_len: its contribution is the leaf value minus the cover-weighted mean (4 - 0).
  assert.deepEqual(hit.reasons, [{ feature: "url_len", contribution: 4, text: "Long (11)." }]);
  assert.equal(scoreUrl(model, null).verdict, SAFE);
});
