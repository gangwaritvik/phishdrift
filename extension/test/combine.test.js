import assert from "node:assert/strict";
import { test } from "node:test";

import {
  ADDRESS_ONLY_NOTE,
  BLOCKLIST_REASON,
  DANGEROUS,
  NO_ADDRESS_REASON,
  PICTURE_MIN_PROB,
  PICTURE_REASON,
  SAFE,
  SUSPICIOUS,
  addressOnly,
  combine,
} from "../dist/combine.js";

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
  // dangerous by the address is never lowered to safe
  assert.equal(combine({ ...base, model: model(DANGEROUS) }, noCreds, pageModel(SAFE)).verdict, SUSPICIOUS);
});

test("the address model alone blocks only a page that asks for credentials or that the page model agrees on", () => {
  const before = combine({ ...base, model: model(DANGEROUS, ["addr"]) });
  assert.deepEqual([before.verdict, addressOnly(before)], [DANGEROUS, true]);
  // a page that asks for nothing gets the banner, with the address reasons and a note
  const banner = combine({ ...base, model: model(DANGEROUS, ["addr"]) }, noCreds, pageModel(SUSPICIOUS, true, ["p"]));
  assert.equal(banner.verdict, SUSPICIOUS);
  assert.deepEqual(banner.notes, [ADDRESS_ONLY_NOTE]);
  assert.ok(banner.reasons.includes("addr"));
  const unread = combine({ ...base, model: model(DANGEROUS) }, noCreds, pageModel(SAFE, false, []));
  assert.equal(unread.verdict, SUSPICIOUS);
  // a login page, or a page model that also says dangerous, keeps the block
  assert.equal(combine({ ...base, model: model(DANGEROUS) }, login, pageModel(SAFE)).verdict, DANGEROUS);
  const pageSays = { ...pageModel(DANGEROUS), pageDangerous: true };
  assert.equal(combine({ ...base, model: model(DANGEROUS) }, noCreds, pageSays).verdict, DANGEROUS);
  // a page verdict that only echoes the dangerous address is no second opinion
  assert.equal(combine({ ...base, model: model(DANGEROUS) }, noCreds, pageModel(DANGEROUS)).verdict, SUSPICIOUS);
  // a second layer can still raise the banner back: high domain risk, an LLM brand opinion
  const domain = { risk: "high", signals: [{ severity: "high", text: "young" }] };
  assert.equal(combine({ ...base, model: model(DANGEROUS), domain }, noCreds, pageModel(SAFE)).verdict, DANGEROUS);
  const llm = { raise: true, brand: "X", brand_domain: "x.com" };
  const raised = combine({ ...base, model: model(DANGEROUS), domain, llm }, noCreds, pageModel(SAFE));
  assert.equal(raised.verdict, DANGEROUS);
  assert.equal(addressOnly(raised), false);
  assert.equal(addressOnly(combine({ ...base, blocked: "url" })), false);
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

test("a local address is not judged, but a blocklist hit still warns", async () => {
  const { combine, LOCAL_NOTE, SAFE, DANGEROUS } = await import("../dist/combine.js");
  const base = { trusted: false, allow: false, shortener: false, blocked: null, model: null, domain: null, local: true };
  const r = combine(base, { hasPassword: true, asksCredentials: true }, null);
  assert.deepEqual([r.verdict, r.layer, r.notes], [SAFE, "local", [LOCAL_NOTE]]);
  assert.equal(combine({ ...base, blocked: "url" }).verdict, DANGEROUS);
});

// --- LLM brand opinion (escalate only) ----------------------------------------------------
const llm = { raise: true, brand: "PayPal", brand_domain: "paypal.com" };
const REASON = "This address looks like it imitates PayPal, whose real site is paypal.com.";

test("an LLM brand opinion raises safe to suspicious, and to dangerous only on a credential page", () => {
  const r = combine({ ...base, llm });
  assert.deepEqual([r.verdict, r.layer, r.reasons], [SUSPICIOUS, "llm", [REASON]]);
  const sus = combine({ ...base, model: model(SUSPICIOUS, ["m"]), llm });
  assert.deepEqual([sus.verdict, sus.reasons], [SUSPICIOUS, [REASON, "m"]]);
  const login = combine({ ...base, model: model(SUSPICIOUS, ["m"]), llm }, { asksCredentials: true });
  assert.deepEqual([login.verdict, login.layer], [DANGEROUS, "llm"]);
});

test("an LLM phishing opinion raises one step with its own reason", () => {
  const r = combine({ ...base, llm: { raise: true, kind: "phishing", brand: null, brand_domain: null, phishing: 0.9 } });
  assert.deepEqual([r.verdict, r.layer, r.reasons], [SUSPICIOUS, "llm", ["An AI check of the address thinks it looks like a phishing site (90% likely)."]]);
});

test("the LLM opinion never lowers, and no opinion or raise:false changes nothing", () => {
  assert.equal(combine({ ...base, model: model(DANGEROUS), llm }).verdict, DANGEROUS);
  assert.equal(combine({ ...base, llm: { ...llm, raise: false } }).verdict, SAFE);
  assert.equal(combine({ ...base, llm: null }).verdict, SAFE);
});

test("the LLM opinion never acts on trusted, blocklisted, allowlisted or short-link addresses", () => {
  assert.equal(combine({ ...base, trusted: true, llm }).verdict, SAFE);
  assert.equal(combine({ ...base, blocked: "url", model: null, llm }).layer, "blocklist");
  assert.equal(combine({ ...base, allow: true, llm }).verdict, SAFE);
  assert.equal(combine({ ...base, shortener: true, llm }).verdict, SAFE);
});

// the picture-only rule (pagefacts.js pictureOnly): raises safe to suspicious on a somewhat suspicious address
const picture = { hasPassword: false, credFormCrossDomain: false, credFormInsecure: false, asksCredentials: false, pictureOnly: true };
const withProb = (prob, verdict = SAFE) => ({ ...base, model: { verdict, prob, reasons: [] } });

test("a picture-only page on an address the model finds somewhat suspicious is raised to suspicious", () => {
  const r = combine(withProb(PICTURE_MIN_PROB), picture);
  assert.deepEqual([r.verdict, r.layer, r.reasons], [SUSPICIOUS, "page", [PICTURE_REASON]]);
});

test("a picture-only page on an address that looks fine, or an ordinary page, is not raised", () => {
  assert.equal(combine(withProb(PICTURE_MIN_PROB - 0.01), picture).verdict, SAFE);
  assert.equal(combine(withProb(0.8), { ...picture, pictureOnly: false }).verdict, SAFE);
  assert.equal(combine(withProb(PICTURE_MIN_PROB), null).verdict, SAFE);
});

test("the picture-only rule never lowers and never acts on trusted, allowlisted, blocklisted, short-link or local addresses", () => {
  assert.equal(combine(withProb(0.9, DANGEROUS), { ...picture, asksCredentials: true }).verdict, DANGEROUS);
  assert.equal(combine(withProb(0.8, SUSPICIOUS), picture).verdict, SUSPICIOUS);
  for (const layers of [{ trusted: true }, { allow: true }, { shortener: true }, { local: true }]) {
    assert.equal(combine({ ...withProb(0.9), ...layers }, picture).verdict, SAFE);
  }
  assert.equal(combine({ ...withProb(0.9), blocked: "url" }, picture).layer, "blocklist");
});

test("a picture-only page restores a suspicious address verdict the page model cleared", () => {
  const pageModel = { hasHtml: false, blended: 0.2, verdict: SAFE, pageDangerous: false, reasons: [] };
  const r = combine(withProb(0.95, SUSPICIOUS), picture, pageModel);
  assert.deepEqual([r.verdict, r.layer], [SUSPICIOUS, "page"]);
});

// --- offline look-alike check (escalate only) ----------------------------------------------
const lookalike = { rule: "homograph", brand: "paypal", text: 'This address looks like "paypal" but is written with look-alike characters.' };

test("a look-alike hit raises safe to suspicious, and to dangerous only on a credential page", () => {
  const r = combine({ ...base, lookalike });
  assert.deepEqual([r.verdict, r.layer, r.reasons], [SUSPICIOUS, "lookalike", [lookalike.text]]);
  const sus = combine({ ...base, model: model(SUSPICIOUS, ["m"]), lookalike });
  assert.deepEqual([sus.verdict, sus.reasons], [SUSPICIOUS, [lookalike.text, "m"]]);
  const login = combine({ ...base, model: model(SUSPICIOUS, ["m"]), lookalike }, { asksCredentials: true });
  assert.deepEqual([login.verdict, login.layer], [DANGEROUS, "lookalike"]);
});

test("a look-alike hit never lowers a verdict and never acts on trusted, listed or short-link addresses", () => {
  assert.equal(combine({ ...base, model: model(DANGEROUS), lookalike }).verdict, DANGEROUS);
  assert.equal(combine({ ...base, lookalike: null }).verdict, SAFE);
  assert.equal(combine({ ...base, trusted: true, lookalike }).verdict, SAFE);
  assert.equal(combine({ ...base, blocked: "url", model: null, lookalike }).layer, "blocklist");
  assert.equal(combine({ ...base, allow: true, lookalike }).verdict, SAFE);
  assert.equal(combine({ ...base, shortener: true, lookalike }).verdict, SAFE);
  assert.equal(combine({ ...base, local: true, lookalike }).layer, "local");
});

test("a download from a suspicious address gets a file-worded banner; other verdicts get none", async () => {
  const { downloadWarning, SAFE, SUSPICIOUS, DANGEROUS } = await import("../src/combine.js");
  const warn = downloadWarning({ verdict: SUSPICIOUS, domain: "evil.example", reasons: ["r"], url: "http://evil.example/x" });
  assert.equal(warn.verdict, SUSPICIOUS);
  assert.match(warn.headline, /file was just downloaded from evil\.example/);
  assert.deepEqual(warn.reasons, ["r"]);
  assert.equal(downloadWarning({ verdict: SAFE, reasons: [] }), null);
  assert.equal(downloadWarning({ verdict: DANGEROUS, layer: "blocklist", reasons: [] }), null); // the warning page handles it
  assert.equal(downloadWarning(null), null);
});
