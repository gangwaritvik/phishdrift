// Python-JS parity: every case in tests/fixtures/url_parity.json (written by
// `python -m features parity`) must give the same feature values in JavaScript.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { buildLists, extract } from "../src/features.js";

const root = new URL("../../", import.meta.url);
const fixture = JSON.parse(readFileSync(new URL("tests/fixtures/url_parity.json", root), "utf8"));
const psl = JSON.parse(readFileSync(new URL("js/data/psl_icann.json", root), "utf8"));
const lists = buildLists(fixture.lists, psl);

function same(a, b) {
  if (b === null) return Number.isNaN(a);
  if (Number.isNaN(a)) return false;
  return Math.abs(a - b) <= 1e-9 * Math.max(1, Math.abs(b));
}

test("fixture has at least 200 URLs", () => {
  assert.ok(fixture.cases.length >= 200, `${fixture.cases.length} cases`);
});

test("every feature matches Python", () => {
  const failures = [];
  for (const { url, values } of fixture.cases) {
    const got = extract(url, lists, fixture.names);
    fixture.names.forEach((name, i) => {
      if (!(name in got)) failures.push(`${JSON.stringify(url)} ${name}: missing`);
      else if (!same(got[name], values[i])) {
        failures.push(`${JSON.stringify(url)} ${name}: js ${got[name]} python ${values[i]}`);
      }
    });
    const extra = Object.keys(got).filter((k) => !fixture.names.includes(k));
    if (extra.length) failures.push(`${JSON.stringify(url)} extra: ${extra}`);
  }
  assert.equal(failures.length, 0, failures.slice(0, 40).join("\n"));
});

test("an address with ~200k path words does not overflow the call stack", () => {
  const url = `https://example.org/${Array.from({ length: 200_000 }, () => "ab").join("/")}`;
  const f = extract(url, lists);
  assert.equal(f.shortest_word_path, 2);
  assert.equal(f.longest_word_path, 2);
});
