// The offline look-alike check (js/src/lookalike.js) on the shipped payload (js/data/lookalike.json).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { loadLookalike, lookalikeSignal, punycodeDecode, withinOne } from "../dist/lib/lookalike.js";
import { buildTrie } from "../dist/lib/psl.js";
import { psl as pslData, readDist } from "./helpers.js";

const rules = loadLookalike(readDist("data/lookalike.json"), buildTrie(pslData()));
const hit = (url) => lookalikeSignal(rules, url);

test("look-alike characters spelling a brand are caught, ASCII and punycode", () => {
  assert.equal(hit("https://paypa1.com/signin").rule, "homograph");
  assert.equal(hit("https://micr0soft.com/").brand, "microsoft");
  assert.equal(hit("http://rnicrosoft.com/").brand, "microsoft");
  assert.equal(hit("https://xn--pple-43d.com/").brand, "apple"); // Cyrillic a + pple
  assert.equal(hit("https://secure.g00gle.net/login").brand, "google");
});

test("one letter off a longer brand name is caught", () => {
  assert.deepEqual([hit("https://paypai.com/")?.rule, hit("https://paypai.com/")?.brand], ["edit1", "paypal"]);
  assert.equal(hit("https://facebok.com/")?.brand, "facebook");
  assert.equal(hit("https://microsfot.com/")?.brand, "microsoft");
});

test("a brand's own name on any suffix, and unrelated names, are left alone", () => {
  for (const url of ["https://paypal.com/", "https://www.paypal.de/x", "https://login.microsoft.com/", "https://example.com/", "https://wikipedia.org/wiki/Phishing"]) {
    assert.equal(hit(url), null, url);
  }
});

test("short brand names are not matched one letter off, IP hosts and hosting platforms are skipped", () => {
  assert.equal(hit("https://visaa.com/"), null);
  assert.equal(hit("http://192.168.1.1/paypa1"), null);
  assert.equal(hit("https://paypa1.github.io/"), null);
  assert.equal(hit("not a url"), null);
});

test("helpers: punycode decoding and distance one", () => {
  assert.equal(punycodeDecode("pple-43d"), "аpple");
  assert.equal(punycodeDecode("!"), null);
  assert.ok(withinOne("paypal", "paypai") && withinOne("paypal", "paypl") && withinOne("paypal", "paypall") && withinOne("paypal", "pyapal"));
  assert.ok(!withinOne("paypal", "paypal") && !withinOne("paypal", "payyyl"));
});

test("the payload is built from the brand list (no brand shorter than 4 letters)", () => {
  const payload = JSON.parse(readFileSync(new URL("../../js/data/lookalike.json", import.meta.url), "utf8"));
  assert.ok(payload.brands.length > 800 && payload.brands.every((b) => [...b].length >= 4));
  assert.ok(payload.brands.includes("paypal") && payload.domains.includes("paypal.com"));
});
