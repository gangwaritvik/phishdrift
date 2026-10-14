// Python-JS parity for the tier B page features: every page in tests/fixtures/html_parity.json
// (written by `python -m features parity`) must give the same status and values in JavaScript.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { buildLists } from "../src/features.js";
import { NAMES_B, analyzeHtml, extractHtml } from "../src/html_features.js";

const root = new URL("../../", import.meta.url);
const fixture = JSON.parse(readFileSync(new URL("tests/fixtures/html_parity.json", root), "utf8"));
const psl = JSON.parse(readFileSync(new URL("js/data/psl_icann.json", root), "utf8"));
const lists = buildLists(fixture.lists, psl);
const page = (spec) => (typeof spec === "string" ? spec : spec.map(([p, n]) => p.repeat(n)).join(""));

function same(a, b) {
  if (b === null) return Number.isNaN(a);
  if (Number.isNaN(a)) return false;
  if (Number.isInteger(b)) return a === b;
  return Math.abs(a - b) <= 1e-9 * Math.max(1, Math.abs(b));
}

test("fixture has at least 250 pages and the registry's names", () => {
  assert.ok(fixture.cases.length >= 250, `${fixture.cases.length} cases`);
  assert.deepEqual(NAMES_B, fixture.names);
});

test("every page gives Python's status and values", () => {
  const failures = [];
  fixture.cases.forEach(({ url, html, status, values }, k) => {
    const got = analyzeHtml(url, page(html), lists);
    const tag = `#${k} ${JSON.stringify(url)}`;
    if (got.status !== status) failures.push(`${tag} status: js ${got.status} python ${status}`);
    const row = got.values ?? extractHtml(url, "", lists);
    fixture.names.forEach((name, i) => {
      if (!(name in row)) failures.push(`${tag} ${name}: missing`);
      else if (!same(row[name], values[i])) failures.push(`${tag} ${name}: js ${row[name]} python ${values[i]}`);
    });
  });
  assert.equal(failures.length, 0, failures.slice(0, 40).join("\n"));
});
