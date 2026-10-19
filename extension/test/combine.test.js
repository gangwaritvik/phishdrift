import assert from "node:assert/strict";
import { test } from "node:test";

import { BLOCKLIST_REASON, DANGEROUS, SAFE, SUSPICIOUS, combine } from "../dist/combine.js";

const model = (verdict, texts = ["why"]) => ({ verdict, prob: 0.5, reasons: texts.map((text) => ({ text })) });
const base = { trusted: false, allow: false, blocked: null, model: model(SAFE, []), domain: null, backendFailed: false };

test("user trust and allowlist win over everything, including a blocklist hit", () => {
  assert.equal(combine({ ...base, trusted: true, blocked: "domain", model: model(DANGEROUS) }).layer, "user-trusted");
  const allowed = combine({ ...base, allow: true, blocked: "domain", model: model(DANGEROUS) });
  assert.deepEqual([allowed.verdict, allowed.layer], [SAFE, "allowlist"]);
});

test("an exact listed URL overrides the allowlist (one bad file on a big site)", () => {
  const r = combine({ ...base, allow: true, blocked: "url", model: model(SAFE) });
  assert.deepEqual([r.verdict, r.layer], [DANGEROUS, "blocklist"]);
  assert.equal(combine({ ...base, trusted: true, allow: true, blocked: "url" }).layer, "user-trusted");
});

test("a blocklist hit is dangerous with its own reason and skips the model", () => {
  const r = combine({ ...base, blocked: "url", model: null });
  assert.deepEqual([r.verdict, r.layer, r.reasons], [DANGEROUS, "blocklist", [BLOCKLIST_REASON]]);
});

test("the URL model verdict and reasons pass through", () => {
  const r = combine({ ...base, model: model(SUSPICIOUS, ["a", "b"]) });
  assert.deepEqual([r.verdict, r.reasons, r.layer], [SUSPICIOUS, ["a", "b"], "url-model"]);
});

test("domain and page evidence never turn a safe URL into a warning", () => {
  const domain = { risk: "high", signals: [{ severity: "high", text: "Brand new domain." }] };
  const page = { hasPassword: true, credFormCrossDomain: true, credFormInsecure: false };
  assert.equal(combine({ ...base, domain }, page).verdict, SAFE);
});

test("high domain risk raises suspicious to dangerous; elevated only adds reasons", () => {
  const high = { risk: "high", signals: [{ severity: "high", text: "Registered 2 days ago." }, { severity: "info", text: "x" }] };
  const r = combine({ ...base, model: model(SUSPICIOUS), domain: high });
  assert.deepEqual([r.verdict, r.layer, r.reasons], [DANGEROUS, "domain", ["why", "Registered 2 days ago."]]);
  const elevated = { risk: "elevated", signals: [{ severity: "warn", text: "No mail records." }] };
  const e = combine({ ...base, model: model(SUSPICIOUS), domain: elevated });
  assert.deepEqual([e.verdict, e.reasons], [SUSPICIOUS, ["why", "No mail records."]]);
});

test("a password form posting to another site raises suspicious to dangerous", () => {
  const page = { hasPassword: true, credFormCrossDomain: true, credFormInsecure: false };
  const r = combine({ ...base, model: model(SUSPICIOUS) }, page);
  assert.equal(r.verdict, DANGEROUS);
  assert.match(r.reasons.at(-1), /different website/);
  const noPassword = { hasPassword: false, credFormCrossDomain: true, credFormInsecure: false };
  assert.equal(combine({ ...base, model: model(SUSPICIOUS) }, noPassword).verdict, SUSPICIOUS);
});

test("a backend failure adds a soft note and keeps the URL verdict", () => {
  const r = combine({ ...base, model: model(SUSPICIOUS), backendFailed: true });
  assert.equal(r.verdict, SUSPICIOUS);
  assert.match(r.notes[0], /unavailable/);
});

test("no model result means safe with a note", () => {
  const r = combine({ ...base, model: null });
  assert.equal(r.verdict, SAFE);
  assert.equal(r.notes.length, 1);
});

const pageModel = (verdict, hasHtml = true, texts = ["page why"]) => ({
  verdict,
  hasHtml,
  blended: 0.4,
  reasons: texts.map((text) => ({ text })),
});

test("the page model's verdict replaces the address verdict once the page is read", () => {
  const lowered = combine({ ...base, model: model(SUSPICIOUS) }, null, pageModel(SAFE));
  assert.deepEqual([lowered.verdict, lowered.reasons], [SAFE, []]);
  const raised = combine({ ...base, model: model(SAFE, []) }, null, pageModel(SUSPICIOUS));
  assert.deepEqual([raised.verdict, raised.layer, raised.reasons], [SUSPICIOUS, "page-model", ["page why"]]);
  const both = combine({ ...base, model: model(SUSPICIOUS, ["addr"]) }, null, pageModel(DANGEROUS));
  assert.deepEqual([both.verdict, both.reasons], [DANGEROUS, ["page why", "addr"]]);
});

test("the password-form rule applies only when the page model could not read the page", () => {
  const flags = { hasPassword: true, credFormCrossDomain: true, credFormInsecure: false };
  const read = combine({ ...base, model: model(SUSPICIOUS) }, flags, pageModel(SUSPICIOUS));
  assert.equal(read.verdict, SUSPICIOUS);
  const unread = combine({ ...base, model: model(SUSPICIOUS) }, flags, pageModel(SUSPICIOUS, false, []));
  assert.equal(unread.verdict, DANGEROUS);
});

test("high domain risk still raises a page-model suspicious verdict to dangerous", () => {
  const high = { risk: "high", signals: [{ severity: "high", text: "Registered 2 days ago." }] };
  const r = combine({ ...base, model: model(SAFE, []), domain: high }, null, pageModel(SUSPICIOUS));
  assert.deepEqual([r.verdict, r.layer], [DANGEROUS, "domain"]);
});

test("an allowlisted page warns only on the page model's strong evidence, and only as suspicious", () => {
  const pageModel = (strong) => ({ hasHtml: true, blended: 0.97, verdict: DANGEROUS, reasons: [{ text: "page" }], allowedPageWarning: strong });
  const quiet = combine({ ...base, allow: true, model: null }, null, pageModel(false));
  assert.deepEqual([quiet.verdict, quiet.layer], [SAFE, "allowlist"]);
  const loud = combine({ ...base, allow: true, model: null }, null, pageModel(true));
  assert.deepEqual([loud.verdict, loud.layer, loud.reasons], [SUSPICIOUS, "page-model", ["page"]]);
});

test("a short link is judged by its page, never by its own address; a listed one is dangerous", () => {
  const r = combine({ ...base, shortener: true, model: null });
  assert.deepEqual([r.verdict, r.layer], [SAFE, "shortener"]);
  const listed = combine({ ...base, shortener: true, blocked: "url", model: null });
  assert.deepEqual([listed.verdict, listed.layer], [DANGEROUS, "blocklist"]);
});

// --- brand and look-alike rules (escalate only) ---------------------------------------------
const look = (rule) => ({ rule, brand: "paypal", text: `look-alike ${rule}` });
const brandPage = { rule: "brand_page", brand: "paypal", text: "brand page" };

test("a look-alike address raises safe to suspicious and suspicious to dangerous", () => {
  const r = combine(base, null, null, { address: [look("homograph")], page: null });
  assert.deepEqual([r.verdict, r.layer, r.reasons], [SUSPICIOUS, "lookalike", ["look-alike homograph"]]);
  const d = combine({ ...base, model: model(SUSPICIOUS, ["m"]) }, null, null, { address: [look("embedded")], page: null });
  assert.deepEqual([d.verdict, d.reasons], [DANGEROUS, ["look-alike embedded", "m"]]);
});

test("one letter away raises one step", () => {
  assert.equal(combine(base, null, null, { address: [look("edit1")], page: null }).verdict, SUSPICIOUS);
  const r = combine({ ...base, model: model(SUSPICIOUS) }, null, null, { address: [look("edit1")], page: null });
  assert.equal(r.verdict, DANGEROUS);
});

test("brand page plus look-alike address go two steps; nothing ever lowers a verdict", () => {
  const r = combine(base, null, null, { address: [look("combo")], page: brandPage });
  assert.deepEqual([r.verdict, r.layer], [DANGEROUS, "brand-page"]);
  const d = combine({ ...base, model: model(DANGEROUS, ["m"]) }, null, null, { address: [], page: brandPage });
  assert.deepEqual([d.verdict, d.reasons], [DANGEROUS, ["brand page", "m"]]);
  assert.equal(combine({ ...base, model: model(DANGEROUS) }, null, null, { address: [], page: null }).verdict, DANGEROUS);
});

test("brand rules never act on trusted or blocklisted addresses; allowlisted pages get at most a banner", () => {
  const brand = { address: [look("homograph")], page: brandPage };
  assert.equal(combine({ ...base, trusted: true }, null, null, brand).verdict, SAFE);
  assert.equal(combine({ ...base, blocked: "url", model: null }, null, null, brand).layer, "blocklist");
  const allowed = combine({ ...base, allow: true }, null, null, brand);
  assert.deepEqual([allowed.verdict, allowed.layer, allowed.reasons], [SUSPICIOUS, "brand-page", ["brand page"]]);
  const addressOnly = combine({ ...base, allow: true }, null, null, { address: [look("homograph")], page: null });
  assert.equal(addressOnly.verdict, SAFE);
});
