// Page model parity: for every page of tests/fixtures/html_parity.json, Python's address and page
// probabilities, blended score, verdict and reasons (tests/fixtures/page_parity.json, written by
// `python -m models.export_page`) must come out the same in JavaScript.

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";

import { loadHybrid } from "../src/hybrid.js";
import { loadPage, scorePage } from "../src/page.js";

const root = new URL("../../", import.meta.url);
const read = (path) => JSON.parse(readFileSync(new URL(path, root), "utf8"));
const html = (spec) => (typeof spec === "string" ? spec : spec.map(([p, n]) => p.repeat(n)).join(""));
const close = (a, b, tol = 1e-6) => (b === null ? a === null : Math.abs(a - b) <= tol);

test("page model matches Python on the HTML parity pages", { skip: !existsSync(new URL("js/data/tier_b_page.json", root)) }, () => {
  const bundle = read("js/data/tier_b_page.json");
  const parity = read("tests/fixtures/page_parity.json");
  assert.equal(parity.bundle_created, bundle.created, "rerun python -m models.export_page");
  const pages = read("tests/fixtures/html_parity.json").cases;
  const address = loadHybrid(read("js/data/tier_a_hybrid.json"), read("js/data/psl_icann.json"));
  const page = loadPage(bundle);
  assert.ok(parity.cases.length >= 250);
  const failures = [];
  let withHtml = 0;
  for (const c of parity.cases) {
    const got = scorePage(address, page, c.url, html(pages[c.index].html), { withReasons: true });
    const tag = `#${c.index} ${JSON.stringify(c.url)}`;
    withHtml += c.has_html;
    if (got.hasHtml !== c.has_html) failures.push(`${tag} hasHtml ${got.hasHtml}`);
    if (!close(got.probAddress, c.prob_address)) failures.push(`${tag} address ${got.probAddress} vs ${c.prob_address}`);
    if (!close(got.probPage, c.prob_page)) failures.push(`${tag} page ${got.probPage} vs ${c.prob_page}`);
    if (!close(got.blended, c.blended)) failures.push(`${tag} blended ${got.blended} vs ${c.blended}`);
    if (got.verdict !== c.verdict) failures.push(`${tag} verdict ${got.verdict} vs ${c.verdict}`);
    const texts = JSON.stringify(got.reasons.map((r) => r.text));
    if (texts !== JSON.stringify(c.reasons.map((r) => r.text))) failures.push(`${tag} reasons ${texts}`);
  }
  assert.ok(withHtml >= 200, `${withHtml} pages with usable HTML`);
  assert.equal(failures.length, 0, failures.slice(0, 20).join("\n"));
});
