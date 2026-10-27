// Tier C parity: raw captured facts -> the 29 features of features/domain_features.py, and the
// RDAP / DNS / certificate parsers of collector/domain_capture.py, from
// tests/fixtures/tier_c_parity.json (written by `python -m models.tier_c parity`). The model
// scoring parity (tests/fixtures/tier_c_model_parity.json) runs when js/data/tier_c.json exists.

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";

import { buildTrie } from "../src/psl.js";
import { NAMES_C, computeC, dnsFacts, loadTierC, parseCert, parseRdap, scoreFeatures } from "../src/tier_c.js";

const root = new URL("../../", import.meta.url);
const read = (path) => JSON.parse(readFileSync(new URL(path, root), "utf8"));
const parity = read("tests/fixtures/tier_c_parity.json");
const psl = buildTrie(read("js/data/psl_icann.json"));

const same = (got, want) => (want === null ? Number.isNaN(got) : Math.abs(got - want) <= 1e-9 * Math.max(1, Math.abs(want)));

test("feature names and order match Python", () => {
  assert.deepEqual(NAMES_C, parity.names);
});

test("computeC matches Python on every parity case", () => {
  const lists = { brands: parity.brands, freeIssuers: parity.free_issuers, psl };
  const failures = [];
  for (const [i, c] of parity.cases.entries()) {
    const got = computeC(c.host_rec, c.domain_rec, lists);
    for (const n of parity.names) {
      if (!same(got[n], c.expected[n])) failures.push(`case ${i} ${n}: ${got[n]} vs ${c.expected[n]}`);
    }
  }
  assert.ok(parity.cases.length >= 200);
  assert.deepEqual(failures.slice(0, 10), []);
});

test("parseRdap matches Python", () => {
  for (const { input, expected } of parity.parsers.rdap) assert.deepEqual(parseRdap(input), expected);
});

test("parseCert reads Node's certificate object like Python reads ssl's", () => {
  assert.deepEqual(parseCert(parity.parsers.cert.node_input), parity.parsers.cert.python);
});

test("dnsFacts matches Python", async () => {
  const { host, domain, answers, expected } = parity.parsers.dns;
  const table = new Map(answers.map(([n, t, v]) => [`${n}|${t}`, v]));
  const query = async (name, rdtype) => {
    const v = table.get(`${name}|${rdtype}`) ?? [];
    if (v === "fail") throw Object.assign(new Error("slow"), { name: "TimeoutError" });
    return v;
  };
  assert.deepEqual(await dnsFacts(host, domain, query), expected);
});

const bundleUrl = new URL("js/data/tier_c.json", root);
test("tier C model matches Python on the parity rows", { skip: !existsSync(bundleUrl) }, () => {
  const bundle = read("js/data/tier_c.json");
  const par = read("tests/fixtures/tier_c_model_parity.json");
  assert.equal(par.bundle_created, bundle.created, "rerun python -m models.tier_c train");
  const model = loadTierC(bundle, read("js/data/psl_icann.json"));
  for (const { features, prob } of par.cases) {
    const values = Object.fromEntries(Object.entries(features).map(([k, v]) => [k, v === null ? Number.NaN : v]));
    assert.ok(Math.abs(scoreFeatures(model, values).prob - prob) <= 1e-6);
  }
});
