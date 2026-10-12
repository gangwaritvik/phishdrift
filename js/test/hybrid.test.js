// Hybrid tier A parity: for every URL in tests/fixtures/hybrid_parity.json (Python's fitted
// hybrid model, written by `python -m models.export_hybrid`), JavaScript features, char n-gram
// scores and trees must give the same probability and the same reasons.

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";

import { charProb, loadChar, logit } from "../src/chargram.js";
import { loadHybrid, scoreUrl } from "../src/hybrid.js";

const root = new URL("../../", import.meta.url);
const bundleUrl = new URL("js/data/tier_a_hybrid.json", root);
const read = (path) => JSON.parse(readFileSync(new URL(path, root), "utf8"));

test("hybrid model matches Python on the parity URLs", { skip: !existsSync(bundleUrl) }, () => {
  const bundle = read("js/data/tier_a_hybrid.json");
  const parity = read("tests/fixtures/hybrid_parity.json");
  assert.equal(parity.bundle_created, bundle.created, "rerun python -m models.export_hybrid");
  const model = loadHybrid(bundle, read("js/data/psl_icann.json"));
  assert.ok(parity.cases.length >= 200);
  const failures = [];
  for (const { url, prob, reasons } of parity.cases) {
    const got = scoreUrl(model, url, { withReasons: true });
    const where = JSON.stringify(url);
    if (!(Math.abs(got.prob - prob) <= 1e-6)) failures.push(`${where}: ${got.prob} vs ${prob}`);
    const texts = got.reasons.map((r) => r.text);
    const want = reasons.map((r) => r.text);
    if (JSON.stringify(texts) !== JSON.stringify(want)) {
      failures.push(`${where}: reasons ${JSON.stringify(texts)} vs ${JSON.stringify(want)}`);
    }
  }
  assert.equal(failures.length, 0, failures.slice(0, 20).join("\n"));
});

test("char n-gram scoring on a tiny model", () => {
  // Vocabulary: "ab", "bc" (n-grams of size 2 only). Text "abc": tf 1 each, idf 2 and 1.
  const model = loadChar({
    ngram_range: [2, 2], sublinear_tf: true, terms: ["ab", "bc"], idf: [2, 1], coef: [1, -1],
    intercept: 0.5, eps: 1e-6,
  });
  const norm = Math.sqrt(4 + 1);
  const z = 0.5 + (2 / norm) * 1 + (1 / norm) * -1;
  assert.ok(Math.abs(charProb(model, "abc") - 1 / (1 + Math.exp(-z))) < 1e-6);
  assert.equal(charProb(model, ""), 1 / (1 + Math.exp(-0.5))); // no terms: intercept only
  assert.ok(Math.abs(logit(0, 1e-6) + Math.log(999999)) < 1e-9);
});

test("word scoring: lowercase alphanumeric tokens and token pairs", () => {
  // Terms "pay", "login", "pay login" (pair, joined by one space); "Pay-Login" -> pay, login.
  const model = loadChar({
    kind: "word", piece: "url", ngram_range: [1, 2], sublinear_tf: true,
    terms: ["pay", "login", "pay login"], idf: [1, 2, 3], coef: [1, -1, 0.5], intercept: 0,
    eps: 1e-6,
  });
  const norm = Math.sqrt(1 + 4 + 9);
  const z = (1 * 1 + 2 * -1 + 3 * 0.5) / norm;
  assert.ok(Math.abs(charProb(model, "Pay-Login!!") - 1 / (1 + Math.exp(-z))) < 1e-6);
  assert.equal(charProb(model, "zzz"), 0.5); // no known terms: intercept only
});
