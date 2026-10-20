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

test("look-alike address is warned with a look-alike reason", async () => {
  const r = await checkUrl(await checker, "https://paypa1.com/signin");
  assert.notEqual(r.verdict, "safe");
  assert.ok(r.lookalike.some((t) => t.includes("paypal")));
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
  const ids = ["allowlist", "blocklist", "model", "lookalike", "combine", "page"];
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
