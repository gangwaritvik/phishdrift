// Python-JS parity for the brand and look-alike rules: tests/fixtures/brand_rules_parity.json
// (written by `python -m features parity`, features/brand_parity.py).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { addressSignals, catcherScore, loadBrandRules, pageSignal, punycodeDecode, withinOne } from "../src/brand_rules.js";
import { buildLists } from "../src/features.js";
import { analyzeHtml } from "../src/html_features.js";

const root = new URL("../../", import.meta.url);
const fixture = JSON.parse(readFileSync(new URL("tests/fixtures/brand_rules_parity.json", root), "utf8"));
const psl = JSON.parse(readFileSync(new URL("js/data/psl_icann.json", root), "utf8"));
const lists = buildLists(fixture.lists, psl);
const rules = loadBrandRules(fixture.rules, lists.psl, lists.platforms);
// JSON with sorted keys, so key order does not matter
const canon = (v) => JSON.stringify(v, (k, x) => (x && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.entries(x).sort()) : x));

test("address rules match Python", () => {
  const failures = [];
  for (const { url, signals } of fixture.cases) {
    const got = addressSignals(rules, url);
    if (canon(got) !== canon(signals)) {
      failures.push(`${JSON.stringify(url)}: js ${JSON.stringify(got)} python ${JSON.stringify(signals)}`);
    }
  }
  assert.equal(failures.length, 0, failures.slice(0, 20).join("\n"));
});

test("host score matches Python", () => {
  const failures = [];
  for (const { url, catcher } of fixture.cases) {
    const got = catcherScore(rules, url, lists.suspiciousTlds);
    const ok = catcher === null ? Number.isNaN(got) : Math.abs(got - catcher) <= 1e-9 * Math.max(1, Math.abs(catcher));
    if (!ok) failures.push(`${JSON.stringify(url)}: js ${got} python ${catcher}`);
  }
  assert.equal(failures.length, 0, failures.slice(0, 20).join("\n"));
});

test("page facts and the brand-page rule match Python", () => {
  const failures = [];
  for (const page of fixture.pages) {
    const facts = {};
    const { status } = analyzeHtml(page.url, page.html, lists, null, { facts, factBrands: rules.brandSet });
    if (status !== page.status) failures.push(`${page.url}: status ${status} vs ${page.status}`);
    if (canon(facts) !== canon(page.facts)) {
      failures.push(`${page.url}: facts ${JSON.stringify(facts)} vs ${JSON.stringify(page.facts)}`);
    }
    const sig = pageSignal(rules, page.url, facts);
    if (canon(sig) !== canon(page.signal)) {
      failures.push(`${page.url}: signal ${JSON.stringify(sig)} vs ${JSON.stringify(page.signal)}`);
    }
  }
  assert.equal(failures.length, 0, failures.join("\n"));
});

test("punycode and edit distance helpers", () => {
  assert.equal(punycodeDecode("pple-43d"), "аpple");
  assert.equal(punycodeDecode("bcher-kva"), "bücher");
  assert.equal(punycodeDecode("!!"), null);
  assert.ok(withinOne("paypal", "paypai"));
  assert.ok(withinOne("paypal", "pyapal"));
  assert.ok(!withinOne("paypal", "paypal"));
  assert.ok(!withinOne("adobe", "abode"));
});
