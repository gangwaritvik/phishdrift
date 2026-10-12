// Browser smoke test (not part of CI): loads extension/dist in Chromium, with a stub backend on
// 127.0.0.1:8000 and a local page server; every host name resolves to the local page server.
// Needs Playwright (global or local) and a Chromium. Run: node build.mjs && node e2e/smoke.mjs
//
// Pages (verdicts from the shipped model, thresholds 0.865 suspicious / 0.9855 dangerous):
//   http://www.wikipedia.org:8123/wiki/Phishing  safe
//   http://evil-blocked.com:8123/a               suspicious -> banner
//   http://evil-blocked.com:8123/b               suspicious + password form to another site -> dangerous
//   http://secure-paypal-login.xyz:8123/         dangerous -> warning page, "proceed anyway"
//   http://example.com:8123/                     safe by the model, on the stub blocklist -> warning page

import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { hashPrefix } from "../dist/keys.js";

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE ?? "playwright");
const dist = join(dirname(fileURLToPath(import.meta.url)), "..", "dist");

const listen = (server, port) => new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
const BYTES = 6;
const feedback = [];
const scoreCalls = [];

const backend = createServer(async (req, res) => {
  let body = "";
  for await (const chunk of req) body += chunk;
  const json = (obj) => {
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify(obj));
  };
  if (req.url === "/lists/manifest") return json({ version: "stub1", prefix_bytes: BYTES });
  if (req.url === "/lists/blocklist.json") {
    return json({ version: "stub1", prefix_bytes: BYTES, domains: [await hashPrefix("example.com", BYTES)], urls: [] });
  }
  if (req.url === "/lists/allowlist.json") return json({ version: "stub1", prefix_bytes: BYTES, domains: [] });
  if (req.url === "/score") {
    scoreCalls.push(JSON.parse(body));
    return json({ domain: JSON.parse(body).domain, risk: "low", signals: [], tier_c_model: false, cached: false });
  }
  if (req.url === "/feedback") {
    feedback.push(JSON.parse(body));
    return json({ ok: true });
  }
  res.statusCode = 404;
  res.end();
});

const pages = createServer((req, res) => {
  res.setHeader("Content-Type", "text/html");
  if (req.url === "/b") {
    res.end('<form action="http://collector.test:8123/p" method="post"><input type="password" name="p"></form>');
  } else {
    res.end(`<html><body><h1 id="ok">page ${req.url}</h1></body></html>`);
  }
});

await listen(backend, 8000);
await listen(pages, 8123);

const context = await chromium.launchPersistentContext("", {
  channel: "chromium",
  headless: true,
  args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`, "--host-resolver-rules=MAP * 127.0.0.1,EXCLUDE localhost"],
});
let failed = false;
try {
  let [worker] = context.serviceWorkers();
  worker ??= await context.waitForEvent("serviceworker");
  const extId = new URL(worker.url()).host;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const tabState = (tabId) => worker.evaluate(async (k) => (await chrome.storage.session.get(k))[k], `tab:${tabId}`);
  const tabIdOf = (page) => worker.evaluate(async (url) => (await chrome.tabs.query({})).find((t) => t.url === url || t.pendingUrl === url)?.id, page.url());
  const settle = async (page, pred, what) => {
    for (let i = 0; i < 60; i++) {
      if (await pred().catch(() => false)) return;
      await sleep(250);
    }
    throw new Error(`timed out: ${what} (now at ${page.url()})`);
  };
  const open = async (url) => {
    const page = await context.newPage();
    await page.goto(url).catch(() => {}); // a redirect to the warning page aborts the navigation
    return page;
  };

  // The list sync runs at install; wait for it.
  await settle(worker, async () => (await worker.evaluate(async () => (await chrome.storage.local.get("lists")).lists?.version)) === "stub1", "list sync");

  // 1. safe page: no banner, no warning, no backend call
  let page = await open("http://www.wikipedia.org:8123/wiki/Phishing");
  await sleep(1500);
  assert.match(page.url(), /wikipedia/);
  assert.equal(await page.locator("#phishdrift-banner-host").count(), 0);
  assert.equal(scoreCalls.length, 0, "no domain is sent for an address the model passes");
  console.log("ok  safe page untouched, nothing sent to the backend");

  // 2. suspicious: banner, and only the domain went to the backend
  page = await open("http://evil-blocked.com:8123/a");
  await settle(page, async () => (await page.locator("#phishdrift-banner-host").count()) === 1, "banner");
  assert.deepEqual(scoreCalls.at(-1), { domain: "evil-blocked.com", local_verdict: 1 });
  console.log("ok  suspicious page shows the banner; backend got", JSON.stringify(scoreCalls.at(-1)));

  // 3. page check: password form to another site escalates to the warning page
  page = await open("http://evil-blocked.com:8123/b");
  await settle(page, async () => page.url().startsWith(`chrome-extension://${extId}/warning.html`), "warning page");
  assert.match(await page.locator("#reasons").innerText(), /different website/);
  console.log("ok  cross-site password form escalates to the warning page");

  // 4. dangerous by the model: warning page, report, proceed anyway
  page = await open("http://secure-paypal-login.xyz:8123/");
  await settle(page, async () => page.url().startsWith(`chrome-extension://${extId}/warning.html`), "warning page");
  assert.ok((await page.locator("#reasons li").count()) >= 1);
  await page.click("#report");
  await settle(page, async () => feedback.length === 1, "feedback");
  assert.deepEqual(Object.keys(feedback[0]).sort(), ["domain", "kind", "verdict"]);
  assert.equal(feedback[0].domain, "secure-paypal-login.xyz");
  await page.click("#proceed");
  await settle(page, async () => page.url().startsWith("http://secure-paypal-login.xyz:8123/"), "proceed anyway");
  await page.waitForSelector("#ok");
  console.log("ok  dangerous page: reasons shown, false-positive report sends domain only, proceed anyway works");

  // 5. blocklist hit on an address the model passes
  page = await open("http://example.com:8123/");
  await settle(page, async () => page.url().startsWith(`chrome-extension://${extId}/warning.html`), "blocklist warning");
  assert.match(await page.locator("#reasons").innerText(), /list of known phishing/);
  console.log("ok  blocklist hit blocks an address the model passes");

  // 6. fail open: backend gone, a flagged page still opens and gets its banner
  await new Promise((r) => backend.close(r));
  backend.closeAllConnections?.();
  page = await open("http://evil-blocked.com:8123/a?x=1");
  await settle(page, async () => (await page.locator("#phishdrift-banner-host").count()) === 1, "banner without backend");
  console.log("ok  backend down: page still loads and is checked with the address model only");
} catch (err) {
  failed = true;
  console.error("FAIL", err);
} finally {
  await context.close();
  pages.close();
  backend.close();
}
process.exit(failed ? 1 : 0);
