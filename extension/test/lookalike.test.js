import assert from "node:assert/strict";
import test from "node:test";

import { loadHybrid } from "../dist/lib/hybrid.js";
import { lookalikeHit } from "../dist/lib/lookalike.js";
import { readDist, psl } from "./helpers.js";

const model = loadHybrid(readDist("data/tier_a_hybrid.json"), psl());
const hit = (u) => lookalikeHit(model, u)?.kind ?? null;

test("look-alike spellings of brands are caught", () => {
  for (const u of ["https://paypa1.com/signin", "http://rnicrosoft.com", "https://g00gle.net/login", "https://аpple.com/id"]) {
    assert.equal(hit(u), "homoglyph", u);
  }
  assert.equal(hit("https://paypa1.com.evil.xyz/"), "subdomain");
  assert.equal(hit("https://paypal-secure-login.com/"), "hyphen");
  assert.equal(hit("https://slack-edge.com/"), null);
  assert.equal(hit("https://paypal.com.account-verify.xyz/"), "subdomain");
  assert.equal(hit("https://login.paypal.evil.net/"), "subdomain");
});

test("real brand names, other suffixes and ordinary sites are not hits", () => {
  for (const u of ["https://www.paypal.com/signin", "https://paypal.de", "https://www.google.co.in/", "https://web.whatsapp.com", "https://myshop-handmade-pottery.com", "https://1password.com", "http://192.168.0.1/", "https://somebody.github.io/paypal"]) {
    assert.equal(hit(u), null, u);
  }
});
