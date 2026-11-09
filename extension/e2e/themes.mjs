// Real-browser check of the five themes and the tier C domain check.
// Usage: node themes.mjs DIST OUTDIR      (build first: node extension/build.mjs)
// Env: CHROME = path of a Chrome binary (default: Playwright's Chromium); PLAYWRIGHT_MODULE.
// Loads DIST unpacked, serves local pages on 127.0.0.1 (every host name resolves there, so no real
// site is contacted) and stands in for the hosted domain check with stubs: plain HTTP for the
// overridden address, HTTPS (self-signed) for the DEFAULT address, so the real default URL, the CORS
// preflight and the request body are exercised. Screenshots go to OUTDIR. Exit code 1 on any FAIL.
import { execFileSync } from "node:child_process";
import { createServer as createHttp } from "node:http";
import { createServer as createHttps } from "node:https";
import { createRequire } from "node:module";
import { mkdirSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { calibrate, candidates } from "./attack/calibrate.mjs";

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE ?? "playwright");
const [dist, out] = [process.argv[2], process.argv[3]];
mkdirSync(out, { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const listen = (s, port) => new Promise((r, j) => { s.once("error", j); s.listen(port, "127.0.0.1", r); });

const NEWS = readFileSync(new URL("./attack/pages/news.html", import.meta.url), "utf8");
const LOGIN = readFileSync(new URL("./attack/pages/news_login.html", import.meta.url), "utf8"); // asks for a password: the page model cannot clear it
const cal = await calibrate(dist, NEWS, { need: { mid: 1, high: 1, safe: 1, edge: 1 } });
// One suspicious address per test (verdicts and domain-check answers are cached per domain). "Suspicious"
// here means what the shipped page path says for this page (it asks for a password, so the page model
// cannot clear it; on a plain page it usually does).
const { loadHybrid } = await import(`${dist}/lib/hybrid.js`);
const { loadPage, scorePage } = await import(`${dist}/lib/page.js`);
const j = (f) => JSON.parse(readFileSync(`${dist}/${f}`, "utf8"));
const addressModel = loadHybrid(j("data/tier_a_hybrid.json"), j("data/psl_icann.json"));
const pageModel = loadPage(j("data/tier_b_page.json"));
const HOSTS = candidates().mid.filter((h) => scorePage(addressModel, pageModel, `http://${h}:8123/a`, LOGIN, { allowShort: true }).verdict === 1).slice(0, 6);
if (HOSTS.length < 6) throw new Error(`only ${HOSTS.length} of 6 test addresses stay suspicious on the login page; extend the candidate names`);
const SAFE = cal.picked.safe[0].host;
const { DEFAULTS } = await import(`${dist}/config.js`);
const DEFAULT_HOST = new URL(DEFAULTS.tierCUrl).hostname;
console.log(`suspicious addresses ${HOSTS.join(", ")}, safe ${SAFE}; default domain check ${DEFAULTS.tierCUrl}`);

// ---- stubs ----
const answers = { mode: "safe" }; // safe | dangerous | hang | error
const seen = { http: [], https: [] };
function tierCStub(log) {
  return async (req, res) => {
    let body = "";
    for await (const c of req) body += c;
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    log.push({ method: req.method, url: req.url, body });
    if (req.method === "OPTIONS") { res.statusCode = 204; return res.end(); }
    if (answers.mode === "hang") return;
    if (answers.mode === "error") { res.statusCode = 500; return res.end("{}"); }
    res.setHeader("Content-Type", "application/json");
    const dangerous = answers.mode === "dangerous";
    res.end(JSON.stringify({
      checked: true, verdict: dangerous ? "dangerous" : "safe", probability: dangerous ? 0.97 : 0.01,
      reasons: dangerous ? [{ feature: "domain_age_days", contribution: 2, text: "The domain was registered only 3 days ago." }] : [],
    }));
  };
}
const dir = mkdtempSync(join(tmpdir(), "pd-themes-"));
execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", join(dir, "k.pem"), "-out", join(dir, "c.pem"), "-days", "2", "-subj", "/CN=stub", "-addext", `subjectAltName=DNS:${DEFAULT_HOST}`], { stdio: "ignore" });
const httpsStub = createHttps({ key: readFileSync(join(dir, "k.pem")), cert: readFileSync(join(dir, "c.pem")) }, tierCStub(seen.https));
const httpStub = createHttp(tierCStub(seen.http));
const backend = createHttp((req, res) => { // the extension's own backend: unreachable would only add a note
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify({ domain: "x", risk: "low", signals: [], cached: false }));
});
const pages = createHttp((req, res) => { res.setHeader("Content-Type", "text/html"); res.setHeader("Cache-Control", "no-store"); res.end(req.url.startsWith("/plain") ? NEWS : LOGIN); });
await listen(httpsStub, 8443); await listen(httpStub, 8444); await listen(backend, 8000); await listen(pages, 8123);

const context = await chromium.launchPersistentContext("", {
  ...(process.env.CHROME ? { executablePath: process.env.CHROME } : { channel: "chromium" }),
  headless: true,
  viewport: { width: 1100, height: 760 },
  args: [
    `--disable-extensions-except=${dist}`, `--load-extension=${dist}`, "--ignore-certificate-errors", "--no-proxy-server",
    `--host-resolver-rules=MAP ${DEFAULT_HOST} 127.0.0.1:8443,MAP * 127.0.0.1,EXCLUDE localhost`,
  ],
});
let worker = context.serviceWorkers().find((w) => w.url().startsWith("chrome-extension://"));
worker ??= await context.waitForEvent("serviceworker", { predicate: (w) => w.url().startsWith("chrome-extension://") });
await sleep(1000);
const extId = new URL(worker.url()).host;
if (process.env.DEBUG) worker.on("console", (m) => console.log("  [worker]", m.text().slice(0, 200)));
const version = context.browser()?.version() ?? "?";
console.log(`browser ${version}`);
const setSettings = (patch) => worker.evaluate(async (p) => {
  const cur = (await chrome.storage.local.get("settings")).settings ?? {};
  await chrome.storage.local.set({ settings: { ...cur, ...p } });
}, patch);
const getSetting = (k) => worker.evaluate(async (key) => (await chrome.storage.local.get("settings")).settings?.[key], k);

const results = [];
async function record(id, fn) {
  if (process.env.ONLY && !id.includes(process.env.ONLY)) return;
  let r;
  try { r = await fn(); } catch (e) { r = { pass: false, actual: `error: ${e.message.split("\n")[0]}` }; }
  results.push({ id, ...r });
  console.log(`${r.pass ? "PASS" : "FAIL"}  ${id}  ${r.actual}`);
  for (const p of context.pages()) await p.close().catch(() => {});
}
const isWarning = (p) => p.url().startsWith(`chrome-extension://${extId}/warning.html`);
const bannerShown = (p) => p.evaluate(() => {
  const el = document.elementFromPoint(innerWidth / 2, 6);
  return el?.tagName === "PHISHDRIFT-BANNER";
}).catch(() => false);
async function waitFor(fn, ms) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) { if (await fn()) return true; await sleep(250); }
  return false;
}
const bg = (p) => p.evaluate(() => getComputedStyle(document.body).backgroundColor);
const THEMES = ["paper", "midnight", "pop", "clinic", "terminal"];

// Counts View Transition calls and waits for each to finish, so the ripple is proven to run.
const spyTransitions = `(() => {
  const orig = document.startViewTransition?.bind(document);
  window.__vt = { calls: 0, finished: 0, missing: !orig };
  if (orig) document.startViewTransition = (cb) => { window.__vt.calls++; const t = orig(cb); t.finished.then(() => window.__vt.finished++, () => {}); return t; };
})();`;

// ---- 1. popup: five themes, ripple, saved choice ----
await setSettings({ theme: undefined });
await record("popup-themes", async () => {
  const page = await context.newPage();
  await page.addInitScript(spyTransitions);
  await page.goto(`chrome-extension://${extId}/popup.html`);
  await sleep(500);
  const seenBg = {};
  for (const id of THEMES) {
    await page.click(`.lens button[data-id=${id}]`);
    await sleep(1100); // the ripple lasts 700 ms
    const theme = await page.evaluate(() => document.documentElement.dataset.theme);
    seenBg[id] = await bg(page);
    await page.screenshot({ path: join(out, `popup_${id}.png`) });
    if (theme !== id) return { pass: false, actual: `clicked ${id}, page shows ${theme}` };
    if ((await getSetting("theme")) !== id) return { pass: false, actual: `${id} not saved` };
  }
  const vt = await page.evaluate(() => window.__vt);
  const distinct = new Set(Object.values(seenBg)).size;
  await page.keyboard.press("ArrowRight"); // keyboard: terminal -> paper
  await sleep(1100);
  const wrapped = await page.evaluate(() => document.documentElement.dataset.theme);
  // reopen: the saved theme is used
  await page.reload();
  await sleep(500);
  const reopened = await page.evaluate(() => document.documentElement.dataset.theme);
  const ok = distinct === 5 && vt.calls === 5 && vt.finished === 5 && wrapped === "paper" && reopened === "paper";
  return { pass: ok, actual: `${distinct} distinct backgrounds, ${vt.calls} view transitions started and ${vt.finished} finished (missing=${vt.missing}), arrow key wrapped to ${wrapped}, reopened as ${reopened}` };
});

// ---- 2. banner on a live suspicious page (tier C says safe) ----
answers.mode = "safe";
await setSettings({ tierC: true, tierCUrl: "http://127.0.0.1:8444/api/domain-check" });
await record("banner-suspicious-page", async () => {
  const page = await context.newPage();
  await page.goto(`http://${HOSTS[0]}:8123/a`);
  const first = await waitFor(() => bannerShown(page), 12000);
  await sleep(4000); // the page check and the domain check have answered by now; the banner must not be a stale one
  const ok = first && (await bannerShown(page));
  await page.screenshot({ path: join(out, "banner_page.png") });
  const text = ok ? await page.evaluate(() => document.querySelector("phishdrift-banner")?.matches(":popover-open")) : null;
  return { pass: ok, actual: `banner on top of the page: ${ok}, in the top layer: ${text}` };
});

// ---- 3. tier C dangerous -> warning page, in all five themes ----
answers.mode = "dangerous";
await record("warning-page-themes", async () => {
  const page = await context.newPage();
  await page.addInitScript(spyTransitions);
  await page.goto(`http://${HOSTS[1]}:8123/a`).catch(() => {});
  if (!(await waitFor(async () => isWarning(page), 15000))) return { pass: false, actual: `no warning page; url ${page.url().slice(0, 60)}` };
  await sleep(800);
  const reasons = await page.evaluate(() => [...document.querySelectorAll("#reasons li")].map((l) => l.textContent));
  const seenBg = {};
  for (const id of THEMES) {
    await page.click(`.lens button[data-id=${id}]`);
    await sleep(1100);
    seenBg[id] = await bg(page);
    await page.screenshot({ path: join(out, `warning_${id}.png`) });
    if ((await page.evaluate(() => document.documentElement.dataset.theme)) !== id) return { pass: false, actual: `theme ${id} not applied` };
  }
  const vt = await page.evaluate(() => window.__vt);
  const hasTierC = reasons.some((r) => /registered only 3 days/.test(r));
  const ok = new Set(Object.values(seenBg)).size === 5 && vt.finished === 5 && hasTierC;
  return { pass: ok, actual: `warning page (tier C raised it), ${new Set(Object.values(seenBg)).size} distinct backgrounds, ${vt.finished} ripples, tier C reason shown: ${hasTierC}` };
});
await setSettings({ theme: "paper" });

// ---- 4. tier C fails: the page is never held up, the suspicious banner stays ----
for (const [i, mode] of ["hang", "error"].entries()) {
  answers.mode = mode;
  await setSettings({ tierCTimeoutMs: 1500 });
  await record(`tier-c-${mode}-fails-open`, async () => {
    const page = await context.newPage();
    const t0 = Date.now();
    await page.goto(`http://${HOSTS[2 + i]}:8123/a`);
    const loadMs = Date.now() - t0;
    const banner = await waitFor(() => bannerShown(page), 12000);
    await sleep(2500); // past the 1.5 s timeout
    const stillBanner = await bannerShown(page);
    return { pass: banner && stillBanner && !isWarning(page), actual: `page loaded in ${loadMs} ms, banner ${banner}, still a banner after the timeout ${stillBanner}, no warning page` };
  });
}
await setSettings({ tierCTimeoutMs: undefined });

// ---- 5. what is sent: the DEFAULT address, domain only, only for suspicious unlisted sites ----
answers.mode = "safe";
await setSettings({ tierC: true, tierCUrl: undefined });
seen.https.length = 0;
await record("default-address-domain-only", async () => {
  const page = await context.newPage();
  await page.goto(`http://${HOSTS[4]}:8123/a#secret`);
  await waitFor(async () => seen.https.some((r) => r.method === "POST"), 12000);
  const posts = seen.https.filter((r) => r.method === "POST");
  const pre = seen.https.some((r) => r.method === "OPTIONS");
  const body = posts[0] ? JSON.parse(posts[0].body) : null;
  const ok = posts.length === 1 && posts[0].url === new URL(DEFAULTS.tierCUrl).pathname && JSON.stringify(Object.keys(body)) === '["domain"]' && !JSON.stringify(body).includes("secret");
  return { pass: ok, actual: `${posts.length} POST to ${posts[0]?.url}, preflight ${pre}, body ${posts[0]?.body}` };
});
seen.https.length = 0;
await record("safe-address-sends-nothing", async () => {
  const page = await context.newPage();
  await page.goto(`http://${SAFE}:8123/`);
  await sleep(4000);
  return { pass: seen.https.length === 0, actual: `${seen.https.length} requests to the domain check for a safe address` };
});
await setSettings({ tierC: false });
seen.https.length = 0;
await record("switch-off-sends-nothing", async () => {
  const page = await context.newPage();
  await page.goto(`http://${HOSTS[5]}:8123/a`);
  const banner = await waitFor(() => bannerShown(page), 12000);
  await sleep(2000);
  return { pass: banner && seen.https.length === 0, actual: `banner ${banner}, ${seen.https.length} requests with the switch off` };
});

await context.close();
const failed = results.filter((r) => !r.pass);
console.log(`\n${results.length - failed.length} passed, ${failed.length} failed (browser ${version})`);
process.exit(failed.length ? 1 : 0);
