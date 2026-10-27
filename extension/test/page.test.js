import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { PICTURE_MAX_TEXT, PICTURE_MIN_AREA, pageFlags } from "../dist/pagefacts.js";
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
    pictureOnly: false,
  });
  assert.equal(f("https://evil.test/collect").credFormCrossDomain, true);
  assert.equal(f("https://auth.example.com/x").credFormCrossDomain, false); // same registrable domain
  assert.equal(f("http://shop.example.com/x").credFormInsecure, true);
  const none = pageFlags({ passwordFields: 0, forms: [{ hasPassword: false, action: "https://evil.test/" }] }, "https://a.com/", psl);
  assert.deepEqual(none, { hasPassword: false, credFormCrossDomain: false, credFormInsecure: false, asksCredentials: false, pictureOnly: false });
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

test("pageFlags: pictureOnly needs little text, no fields, a big picture and no credential fields", () => {
  const visual = { textChars: 20, fields: 0, pictures: 1, largest: 0.3 };
  const flags = (facts) => pageFlags({ passwordFields: 0, forms: [], ...facts }, "https://a.com/", psl).pictureOnly;
  assert.equal(flags({ visual }), true);
  assert.equal(flags({ visual: { ...visual, textChars: PICTURE_MAX_TEXT } }), false);
  assert.equal(flags({ visual: { ...visual, fields: 1 } }), false);
  assert.equal(flags({ visual: { ...visual, largest: PICTURE_MIN_AREA - 0.01 } }), false);
  assert.equal(flags({ visual: { ...visual, largest: PICTURE_MIN_AREA } }), true);
  assert.equal(flags({}), false);
  assert.equal(flags({ visual: null }), false);
  assert.equal(flags({ visual, passwordFields: 1 }), false); // asks for credentials: the other rules apply
});

test("content script measures text, fields and the largest picture (visualFacts)", () => {
  const src = readFileSync(new URL("../dist/content.js", import.meta.url), "utf8");
  const visualFacts = new Function(`${src}; return visualFacts;`)();
  const rect = (width, height) => ({ getBoundingClientRect: () => ({ width, height }) });
  const win = { innerWidth: 1000, innerHeight: 500, getComputedStyle: () => ({ backgroundImage: "none" }) };
  const doc = (text, fields, pictures) => ({
    body: {
      innerText: text,
      querySelectorAll: (sel) => (sel.startsWith("input") ? new Array(fields).fill({}) : sel === "img, canvas, svg" ? pictures : []),
      getBoundingClientRect: () => ({ width: 0, height: 0 }),
    },
  });
  // a 400x250 image on a 1000x500 window is 20% of it; whitespace in the text is collapsed
  assert.deepEqual(visualFacts(doc("  Click \n to  continue ", 0, [rect(400, 250)]), win), { textChars: 17, fields: 0, pictures: 1, largest: 0.2 });
  // a picture larger than the window counts as the whole window
  assert.equal(visualFacts(doc("", 2, [rect(5000, 4000)]), win).largest, 1);
  assert.equal(visualFacts({ body: null }, win), null);
});
