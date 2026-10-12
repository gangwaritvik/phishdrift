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
