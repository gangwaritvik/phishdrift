import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { pageFlags } from "../dist/pagefacts.js";
import { buildTrie } from "../dist/lib/psl.js";
import { psl as loadPsl } from "./helpers.js";

const psl = buildTrie(loadPsl());

test("pageFlags: cross-domain and insecure password forms", () => {
  const f = (action, url = "https://shop.example.com/login") =>
    pageFlags({ passwordFields: 1, forms: [{ hasPassword: true, action }] }, url, psl);
  assert.deepEqual(f("https://shop.example.com/session"), {
    hasPassword: true,
    credFormCrossDomain: false,
    credFormInsecure: false,
    asksCredentials: true,
  });
  assert.equal(f("https://evil.test/collect").credFormCrossDomain, true);
  assert.equal(f("https://auth.example.com/x").credFormCrossDomain, false); // same registrable domain
  assert.equal(f("http://shop.example.com/x").credFormInsecure, true);
  const none = pageFlags({ passwordFields: 0, forms: [{ hasPassword: false, action: "https://evil.test/" }] }, "https://a.com/", psl);
  assert.deepEqual(none, { hasPassword: false, credFormCrossDomain: false, credFormInsecure: false, asksCredentials: false });
});

test("pageFlags: OTP / card fields and frames asking for credentials count as credentials", () => {
  const url = "https://a.com/";
  assert.equal(pageFlags({ passwordFields: 0, credentialFields: 1, forms: [] }, url, psl).asksCredentials, true);
  assert.equal(pageFlags({ passwordFields: 0, frameCredentials: true, forms: [] }, url, psl).asksCredentials, true);
  // frames and address-less pages have no page URL: flags still work
  assert.equal(pageFlags({ passwordFields: 1, forms: [{ hasPassword: true, action: "https://x.test/" }] }, null, psl).asksCredentials, true);
});

// content.js is a classic script; evaluate its function without a browser.
test("content script collects password forms and resolves their actions", () => {
  const src = readFileSync(new URL("../dist/content.js", import.meta.url), "utf8");
  const collect = new Function(`${src}; return collectPageFacts;`)();
  const form = (action, password) => ({
    getAttribute: () => action,
    querySelector: () => (password ? {} : null),
  });
  const doc = {
    forms: [form("/login", true), form("https://evil.test/p", true), form(null, false)],
    querySelectorAll: () => [{}, {}],
  };
  const facts = collect(doc, "https://a.com/start");
  assert.equal(facts.passwordFields, 2);
  assert.deepEqual(facts.forms, [
    { hasPassword: true, action: "https://a.com/login" },
    { hasPassword: true, action: "https://evil.test/p" },
    { hasPassword: false, action: "https://a.com/start" },
  ]);
});
