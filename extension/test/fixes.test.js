// Unit tests for the 2026-10-15 page-check fixes (red-team and stress-test gaps).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { effectiveUrl } from "../dist/address.js";
import { DOMAIN_FAILURE_MS, domainTtl, usableAnswer } from "../dist/domain.js";
import { safeExit, worse } from "../dist/navigation.js";
import { TRUST_DAYS, addTrust, liveTrust } from "../dist/trust.js";
import { loadHybrid } from "../dist/lib/hybrid.js";
import { loadPage, scorePage } from "../dist/lib/page.js";
import { psl, readDist } from "./helpers.js";

const DAY = 24 * 60 * 60 * 1000;

test("trust entries expire after TRUST_DAYS; old bare keys are kept with a fresh time", () => {
  const now = 1_000 * DAY;
  const stored = [{ key: "old.com", at: now - (TRUST_DAYS + 1) * DAY }, { key: "new.com", at: now - DAY }, "legacy.com", null, { at: 5 }];
  const live = liveTrust(stored, now);
  assert.deepEqual([...live.keys()].sort(), ["legacy.com", "new.com"]);
  assert.equal(live.get("legacy.com"), now);
  const added = addTrust(stored, "site.org", now);
  assert.deepEqual(added.map((e) => e.key).sort(), ["legacy.com", "new.com", "site.org"]);
  assert.ok(added.every((e) => typeof e.at === "number"));
  assert.equal(liveTrust(added, now + TRUST_DAYS * DAY).size, 0);
});

test("effectiveUrl: web addresses as they are; blob and about pages stand for their origin; others have none", () => {
  assert.equal(effectiveUrl("https://a.com/x?y=1"), "https://a.com/x?y=1");
  assert.equal(effectiveUrl("blob:https://evil.example/1234-5678"), "https://evil.example/");
  assert.equal(effectiveUrl("about:blank", "https://opener.example"), "https://opener.example/");
  assert.equal(effectiveUrl("about:srcdoc", "https://site.example"), "https://site.example/");
  for (const [url, origin] of [
    ["about:blank", "null"],
    ["about:blank", null],
    ["data:text/html,<b>x</b>", null],
    ["file:///C:/invoice.html", "null"],
    ["", null],
    ["http://", null],
    ["not a url", null],
    ["javascript:alert(1)", null],
    ["blob:null/1234", null],
  ]) {
    assert.equal(effectiveUrl(url, origin), null, url);
  }
});

test("unparseable addresses are no longer scored (the model gave them all 0.98)", () => {
  // effectiveUrl is applied before scoreAddress in background.js evaluate(); a null target is
  // "unscored" in combine.js. Here: no malformed input reaches the model.
  for (const url of ["", "http://", "http://%%%/", "file:///C:/x.html", "blob:https://evil.example/1"]) {
    const t = effectiveUrl(url);
    assert.ok(t === null || t === "https://evil.example/", url);
  }
});

test("backend failures are never an answer and are cached only briefly", () => {
  assert.equal(usableAnswer(null), null);
  assert.equal(usableAnswer({ risk: "low", signals: [], error: "timeout" }), null);
  assert.equal(usableAnswer({ risk: "unknown", signals: [] }), null);
  assert.equal(usableAnswer({ risk: "low" }), null);
  const ok = { risk: "high", signals: [{ severity: "high", text: "x" }] };
  assert.equal(usableAnswer(ok), ok);
  assert.equal(domainTtl({ answer: null }, 3_600_000), DOMAIN_FAILURE_MS);
  assert.equal(domainTtl({ answer: ok }, 3_600_000), 3_600_000);
  assert.ok(DOMAIN_FAILURE_MS <= 60_000);
});

test("'Take me back to safety' goes to the last safe page on another site, else a new tab", () => {
  const domainOf = (u) => (u ? new URL(u).hostname.split(".").slice(-2).join(".") : null);
  const seen = [
    { url: "https://mail.example.com/inbox", domain: "example.com" },
    { url: "https://evil.test/start", domain: "evil.test" }, // the phishing site's own earlier page
  ];
  assert.equal(safeExit(seen, "https://login.evil.test/x", domainOf), "https://mail.example.com/inbox");
  assert.equal(safeExit([seen[1]], "https://evil.test/x", domainOf), "chrome://newtab/");
  assert.equal(safeExit(null, null, domainOf), "chrome://newtab/");
});

test("worse keeps the higher verdict", () => {
  assert.equal(worse({ verdict: 1 }, { verdict: 0 }).verdict, 1);
  assert.equal(worse(null, { verdict: 2 }).verdict, 2);
});

test("a bare login form (too little text for training) is read only when asked for", () => {
  const address = loadHybrid(readDist("data/tier_a_hybrid.json"), psl());
  const page = loadPage(readDist("data/tier_b_page.json"));
  const html = '<html><body><form action="/p" method="post"><input name="u"><input type="password" name="p"><button>Sign in</button></form></body></html>';
  const url = "https://secure-login.example.net/signin";
  const plain = scorePage(address, page, url, html);
  assert.deepEqual([plain.hasHtml, plain.short], [false, false]);
  const tiny = scorePage(address, page, url, html, { allowShort: true });
  assert.deepEqual([tiny.hasHtml, tiny.short], [true, true]);
  assert.ok(tiny.probPage > 0 && tiny.probPage < 1);
  // a normal page is unchanged by the option
  const long = `<html><body><p>${"Ordinary text about our bakery and its opening hours. ".repeat(10)}</p></body></html>`;
  const a = scorePage(address, page, "https://bakery.example.org/about", long);
  const b = scorePage(address, page, "https://bakery.example.org/about", long, { allowShort: true });
  assert.deepEqual([a.hasHtml, a.short, a.blended], [b.hasHtml, b.short, b.blended]);
});

test("content script counts one-time code, card and PIN inputs as credentials", () => {
  const src = readFileSync(new URL("../dist/content.js", import.meta.url), "utf8");
  const isCred = new Function(`${src}; return isCredentialInput;`)();
  const input = (attrs) => ({ getAttribute: (k) => attrs[k] ?? null });
  assert.equal(isCred(input({ name: "otp" })), true);
  assert.equal(isCred(input({ autocomplete: "one-time-code" })), true);
  assert.equal(isCred(input({ id: "card-number" })), true);
  assert.equal(isCred(input({ placeholder: "CVV" })), true);
  assert.equal(isCred(input({ name: "upi_pin" })), true);
  assert.equal(isCred(input({ name: "email" })), false);
  assert.equal(isCred(input({ name: "search", placeholder: "Search topics" })), false);
  assert.equal(isCred(input({ name: "otp", type: "hidden" })), false);
});
