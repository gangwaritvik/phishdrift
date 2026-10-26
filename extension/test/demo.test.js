// The demo page's address check (demo/check.js) on the built extension modules.
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

import { checkUrl, loadChecker, normaliseInput } from "../../demo/check.js";

const root = new URL("../../", import.meta.url);
const read = async (path) => {
  const file = new URL(path, root);
  return existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : null;
};
const checker = loadChecker({ base: new URL("extension/dist/", root), read });

test("bare hosts get a scheme, other schemes are kept", () => {
  assert.equal(normaliseInput(" example.com/x "), "https://example.com/x");
  assert.equal(normaliseInput("localhost:8000/a"), "https://localhost:8000/a");
  assert.equal(normaliseInput("http://a.com"), "http://a.com");
  assert.equal(normaliseInput("javascript:alert(1)"), "javascript:alert(1)");
});

test("allowlisted site is safe even when the model alone would flag it", async () => {
  const r = await checkUrl(await checker, "web.whatsapp.com");
  assert.equal(r.verdict, "safe");
  assert.equal(r.layer, "allowlist");
  assert.ok(r.modelAlone && typeof r.modelAlone.prob === "number");
});

test("verdict matches the address model when no other layer applies", async () => {
  const c = await checker;
  const { scoreUrl } = c.hybrid;
  for (const url of ["http://secure-login-verify-account.xyz/wp-admin/office365/index.php", "https://myshop-handmade-pottery.com/about"]) {
    const r = await checkUrl(c, url);
    if (r.layer !== "url-model") continue;
    assert.equal(r.verdict, ["safe", "suspicious", "dangerous"][scoreUrl(c.model, url).verdict]);
  }
});

test("short links and non-web addresses are not scored by the model", async () => {
  const c = await checker;
  assert.equal((await checkUrl(c, "https://bit.ly/abc")).layer, "shortener");
  assert.equal((await checkUrl(c, "javascript:alert(1)")).verdict, "unscored");
});

test("trace lists every layer in order, with the deciding tone", async () => {
  const c = await checker;
  const ids = ["allowlist", "blocklist", "model", "llm", "combine", "page"];
  const safe = await checkUrl(c, "web.whatsapp.com");
  assert.deepEqual(safe.trace.map((t) => t.id), ids);
  assert.equal(safe.trace[0].tone, "safe");
  assert.equal(safe.trace[2].tone, "skip");
  assert.equal(safe.trace[4].tone, "safe");
  const bad = await checkUrl(c, "http://secure-login-verify-account.xyz/wp-admin/office365/index.php");
  assert.equal(bad.trace[0].tone, "clear");
  assert.equal(bad.trace[4].tone, "bad");
  assert.equal(bad.trace[5].tone, "na");
});

test("a popular tenant site on a hosting platform is allowlisted by its host", async () => {
  const c = await checker;
  const r = await checkUrl(c, "https://stitch.withgoogle.com/projects/5662571052682527?pli=1");
  assert.equal(r.verdict, "safe");
  assert.equal(r.layer, "allowlist");
  const other = await checkUrl(c, "https://codetolearn.withgoogle.com/projects/5662571052682527?pli=1");
  assert.equal(other.layer === "allowlist", false);
});

test("evidence shows what each layer looked at for this address", async () => {
  const c = await checker;
  const bad = (await checkUrl(c, "http://secure-login-verify-account.xyz/wp-admin/office365/index.php")).evidence;
  assert.equal(bad.allowlist.domain, "secure-login-verify-account.xyz");
  assert.equal(bad.allowlist.found, false);
  assert.equal(bad.allowlist.hash.length, bad.allowlist.bytes * 2);
  assert.ok(bad.blocklist.keys.length > 0 && bad.blocklist.keys.every((k) => k.hash));
  const m = bad.model;
  const sum = m.base + m.items.reduce((s, r) => s + r.delta, 0) + m.other;
  assert.ok(Math.abs(sum - m.raw) < 1e-6);
  assert.equal(bad.combine.start, bad.combine.end);
  const ok = (await checkUrl(c, "web.whatsapp.com")).evidence;
  assert.equal(ok.allowlist.found, true);
  assert.equal(ok.model.used, false);
  assert.equal(ok.combine.end, 0);
});

test("an AI answer from the backend raises the verdict and shows in the trace", async () => {
  const base = await checker;
  const url = "https://myshop-handmade-pottery.com/about";
  const plain = await checkUrl(base, url);
  assert.equal(plain.trace[3].tone, "na");
  const asked = [];
  const c = { ...base, askLlm: async (host) => (asked.push(host), { raise: true, brand: "PayPal", brand_domain: "paypal.com", confidence: 0.9, reason: "x", error: null }) };
  const r = await checkUrl(c, url);
  assert.deepEqual(asked, ["myshop-handmade-pottery.com"]);
  if (plain.verdict === "safe") assert.deepEqual([r.verdict, r.layer], ["suspicious", "llm"]);
  else assert.notEqual(r.verdict, "safe");
  assert.equal(r.trace[3].tone, "warn");
  const down = await checkUrl({ ...base, askLlm: async () => null }, url);
  assert.equal(down.trace[3].label, "AI check not reachable");
  assert.equal(down.verdict, plain.verdict);
  const allow = await checkUrl(c, "web.whatsapp.com");
  assert.equal(allow.trace[3].tone, "skip");
  assert.equal(asked.length, 1);
});

test("a followed short link is judged at its destination", async () => {
  const c = Object.create(await checker);
  c.expand = async (url) => ({ final: "https://web.whatsapp.com/", complete: true, hops: [{ url, status: 301, method: "HEAD" }], error: null });
  const r = await checkUrl(c, "https://bit.ly/abc");
  assert.deepEqual([r.layer, r.url, r.shortLink.from], ["allowlist", "https://web.whatsapp.com/", "https://bit.ly/abc"]);
  c.expand = async () => ({ complete: false, error: "no_redirect" });
  const stuck = await checkUrl(c, "https://bit.ly/abc");
  assert.equal(stuck.layer, "shortener");
  assert.ok(stuck.notes[0].includes("no_redirect"));
});

test("shorteners from js/data/lists.json count, not only the model's own 25", async () => {
  const c = await checker;
  assert.equal(c.model.lists.shorteners.has("aka.ms"), false);
  assert.equal((await checkUrl(c, "https://aka.ms/xyz")).layer, "shortener");
});
