import assert from "node:assert/strict";
import { test } from "node:test";

import { BLOCKLIST_REASON, DANGEROUS, NO_ADDRESS_REASON, SAFE, SUSPICIOUS, combine } from "../dist/combine.js";

const model = (verdict, texts = ["why"]) => ({ verdict, prob: 0.5, reasons: texts.map((text) => ({ text })) });
const base = { trusted: false, allow: false, blocked: null, model: model(SAFE, []), domain: null, backendFailed: false };

test("user trust silences the models but never a blocklist hit", () => {
  assert.equal(combine({ ...base, trusted: true, model: model(DANGEROUS) }).layer, "user-trusted");
  for (const blocked of ["domain", "url"]) {
    const r = combine({ ...base, trusted: true, blocked, model: null });
    assert.deepEqual([r.verdict, r.layer], [DANGEROUS, "blocklist"]);
  }
  const allowed = combine({ ...base, allow: true, blocked: "domain", model: model(DANGEROUS) });
  assert.deepEqual([allowed.verdict, allowed.layer], [SAFE, "allowlist"]);
});

test("an exact listed URL overrides the allowlist and trust (one bad file on a big site)", () => {
  const r = combine({ ...base, allow: true, blocked: "url", model: model(SAFE) });
  assert.deepEqual([r.verdict, r.layer], [DANGEROUS, "blocklist"]);
  assert.equal(combine({ ...base, trusted: true, allow: true, blocked: "url" }).layer, "blocklist");
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

const noCreds = { hasPassword: false, credFormCrossDomain: false, credFormInsecure: false, asksCredentials: false };
const login = { hasPassword: true, credFormCrossDomain: false, credFormInsecure: false, asksCredentials: true };

test("the page model lowers an address warning only on a page that asks for no credentials", () => {
  const lowered = combine({ ...base, model: model(SUSPICIOUS) }, noCreds, pageModel(SAFE));
  assert.deepEqual([lowered.verdict, lowered.reasons], [SAFE, []]);
  // a login page (the attacker's own HTML) cannot clear the address warning
  const kept = combine({ ...base, model: model(SUSPICIOUS, ["addr"]) }, login, pageModel(SAFE));
  assert.deepEqual([kept.verdict, kept.layer, kept.reasons], [SUSPICIOUS, "url-model", ["addr"]]);
  // an OTP / card field, or a frame asking for credentials, counts the same
  const otp = { ...noCreds, asksCredentials: true };
  assert.equal(combine({ ...base, model: model(SUSPICIOUS) }, otp, pageModel(SAFE)).verdict, SUSPICIOUS);
  // without page facts nothing is lowered
  assert.equal(combine({ ...base, model: model(SUSPICIOUS) }, null, pageModel(SAFE)).verdict, SUSPICIOUS);
  // dangerous by the address is never lowered
  assert.equal(combine({ ...base, model: model(DANGEROUS) }, noCreds, pageModel(SUSPICIOUS)).verdict, DANGEROUS);
});

test("the page model can always raise the address verdict", () => {
  const raised = combine({ ...base, model: model(SAFE, []) }, login, pageModel(SUSPICIOUS));
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

test("a page with no web address of its own is suspicious only when it asks for credentials", () => {
  const unscored = { ...base, model: null, unscored: true };
  const quiet = combine(unscored, noCreds);
  assert.deepEqual([quiet.verdict, quiet.layer], [SAFE, "none"]);
  const r = combine(unscored, login);
  assert.deepEqual([r.verdict, r.reasons], [SUSPICIOUS, [NO_ADDRESS_REASON]]);
  assert.equal(combine({ ...unscored, blocked: "url" }, login).verdict, DANGEROUS);
});
