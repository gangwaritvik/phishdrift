// Hands-on attack harness for the PhishDrift extension. Usage: node harness.mjs DIST OUTDIR [case-filter]
// (run.sh makes DIST from extension/dist with the test-only "tabs" permission added.)
// Loads DIST unpacked in Chromium (persistent context), stub backend on 127.0.0.1:8000, local page
// server on :8123; every host name resolves to 127.0.0.1. No real site is contacted.
// The test addresses are chosen at run time from the shipped model's score and cut-offs
// (calibrate.mjs), so the harness follows every retrain and stops if no address fits a band.
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { calibrate } from "./calibrate.mjs";

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE ?? "playwright");
const [dist, out, filter] = [process.argv[2], process.argv[3], process.argv[4]];
mkdirSync(out, { recursive: true });
const cal = await calibrate(dist, readFileSync(new URL("./pages/news.html", import.meta.url), "utf8"));
// H, TRUST: addresses the model calls suspicious; DANGER: dangerous; SAFE: safe; BLOCKED: safe by the
// model, so only the stub blocklist can warn on it.
const [HOST, TRUSTHOST] = cal.picked.mid.map((c) => c.host);
const DANGERHOST = cal.picked.high[0].host;
const SAFEHOSTNAME = cal.picked.safe[0].host;
const BLOCKEDHOST = cal.picked.safe[1].host;
const EDGEHOST = cal.picked.edge[0].host;
console.log(`calibrated for cut-offs ${cal.thresholds.suspicious.toFixed(4)} / ${cal.thresholds.dangerous.toFixed(4)}: suspicious ${HOST}, ${TRUSTHOST}; dangerous ${DANGERHOST}, dangerous-by-address-only ${EDGEHOST}; safe ${SAFEHOSTNAME}, ${BLOCKEDHOST}`);
const { hashPrefix } = await import(`${dist}/keys.js`);
const P = (f) => readFileSync(new URL(`./pages/${f}`, import.meta.url), "utf8");
const LURE = P("lure.html"), NEWS = P("news.html"), NEWS_LOGIN = P("news_login.html"), BLOG = P("blog.html");
const lureBody = LURE.match(/<body>([\s\S]*)<\/body>/)[1].replace(/<script>[\s\S]*?<\/script>/, "");
const TINY = '<form><input type="password" name="p"><button>Go</button></form>';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const listen = (s, port, host = "127.0.0.1") => new Promise((r, j) => { s.once("error", j); s.listen(port, host, r); });

// ---------- stub backend ----------
const BYTES = 6;
const be = { slowMs: 0, down: false, blockDomains: [BLOCKEDHOST], version: "stub1", scoreCalls: [] };
const sha256Hex = (t) => createHash("sha256").update(t).digest("hex");
async function stubLists() {
  const bundled = JSON.parse(readFileSync(join(dist, "data", "allowlist.json"), "utf8"));
  const blocklist = JSON.stringify({ version: be.version, prefix_bytes: BYTES, domains: await Promise.all(be.blockDomains.map((d) => hashPrefix(d, BYTES))), urls: [] });
  const blocked = new Set(await Promise.all(be.blockDomains.map((d) => hashPrefix(d, bundled.prefix_bytes))));
  const allowlist = JSON.stringify({ ...bundled, version: be.version, domains: bundled.domains.filter((d) => !blocked.has(d)) });
  return { manifest: { version: be.version, prefix_bytes: BYTES, sha256: { blocklist: sha256Hex(blocklist), allowlist: sha256Hex(allowlist) } }, blocklist, allowlist };
}
const backend = createServer(async (req, res) => {
  let body = "";
  for await (const c of req) body += c;
  if (be.down) { req.socket.destroy(); return; }
  const json = (o) => { res.setHeader("Content-Type", "application/json"); res.end(JSON.stringify(o)); };
  // Lists as the real backend serves them (PR #24 signed sync): manifest with each file's sha256,
  // full allowlist (the bundled one) minus blocklisted domains.
  const L = await stubLists();
  if (req.url === "/lists/manifest") return json(L.manifest);
  if (req.url === "/lists/blocklist.json") { res.setHeader("Content-Type", "application/json"); return res.end(L.blocklist); }
  if (req.url === "/lists/allowlist.json") { res.setHeader("Content-Type", "application/json"); return res.end(L.allowlist); }
  if (req.url === "/score") {
    be.scoreCalls.push(JSON.parse(body));
    if (be.slowMs) await sleep(be.slowMs);
    return json({ domain: JSON.parse(body).domain, risk: "low", signals: [], tier_c_model: false, cached: false });
  }
  if (req.url === "/feedback") return json({ ok: true });
  res.statusCode = 404; res.end();
});

// ---------- attack pages (path decides the page; host is whatever the test uses) ----------
const swapScript = (trigger) => `<script>
function toLure(){ document.body.innerHTML = ${JSON.stringify(lureBody)}; document.title = "Sign in to your account"; }
${trigger}</script>`;
const inject = (html, snippet) => html.replace("</body>", snippet + "</body>");
const head = (html, snippet) => html.replace("<head>", "<head>" + snippet);
const routes = {
  "/news": () => NEWS,
  "/news-login": () => NEWS_LOGIN,
  "/blog": () => BLOG,
  "/lure": () => LURE,
  "/tiny": () => TINY,
  "/delayed": () => inject(NEWS, swapScript("setTimeout(toLure, 2500);")),
  "/click": () => inject(NEWS, `<button id="go">Continue to your documents</button>` + swapScript(`document.getElementById("go").onclick = toLure;`)),
  "/overcap": () => inject(NEWS, swapScript(`let n=0; const t=setInterval(()=>{ n++; if(n<=3){ const i=document.createElement("input"); i.type="password"; i.name="d"+n; document.querySelector("main").append(i);} else { clearInterval(t); toLure(); } }, 1600);`)),
  "/shadow": () => inject(NEWS, `<div id="sh"></div><script>const r=document.getElementById("sh").attachShadow({mode:"closed"}); r.innerHTML=${JSON.stringify(lureBody)};</script>`),
  "/frame-outer": () => inject(NEWS, `<iframe src="http://${HOST}:8123/lure-frame" width="600" height="400"></iframe>`),
  "/lure-frame": () => LURE,
  "/srcdoc-outer": () => inject(NEWS, `<iframe width="600" height="400" srcdoc="${LURE.replace(/&/g, "&amp;").replace(/"/g, "&quot;")}"></iframe>`),
  "/spa": () => inject(NEWS, swapScript(`setTimeout(()=>{ history.pushState({}, "", "/a"); toLure(); }, 2000);`)),
  "/spa-hash": () => inject(NEWS, swapScript(`setTimeout(()=>{ location.hash = "#/login"; toLure(); }, 2000);`)),
  "/opener-blob": () => inject(NEWS, `<button id="go">open</button><script src="/static/blob.js"></script>`),
  "/opener-blank": () => inject(NEWS, `<button id="go">open</button><script src="/static/blank.js"></script>`),
  "/opener-data": () => inject(NEWS, `<a id="go" href="data:text/html;base64,${Buffer.from(LURE).toString("base64")}">open</a>`),
  "/rewrite": () => head(BLOG, `<script>history.replaceState({}, "", "/");</script>`),
  "/rewrite-lure": () => head(LURE, `<script>history.replaceState({}, "", "/");</script>`),
  "/css-hide-tag": () => head(BLOG, `<style>phishdrift-banner, html > *:not(body):not(head){opacity:0!important;visibility:hidden!important;clip-path:inset(50%)!important;transform:translateY(-500px)!important}</style>`),
  "/plant-id": () => inject(BLOG, `<div id="phishdrift-banner-host" style="display:none"></div>`),
  "/css-hide": () => head(BLOG, `<style>#phishdrift-banner-host{display:none!important}</style>`),
  "/remover": () => inject(BLOG, `<script src="/static/r.js"></script>`),
  "/static/r.js": () => `new MutationObserver(ms=>{for(const m of ms) for(const n of m.addedNodes) if(n.parentNode===document.documentElement && n!==document.body && n!==document.head) n.remove();}).observe(document.documentElement,{childList:true});`,
  "/static/blob.js": () => `document.getElementById("go").onclick=()=>{ const b=new Blob([${JSON.stringify(LURE)}],{type:"text/html"}); window.open(URL.createObjectURL(b)); };`,
  "/static/blank.js": () => `document.getElementById("go").onclick=()=>{ const w=window.open("about:blank"); w.document.write(${JSON.stringify(LURE)}); w.document.close(); };`,
};
// The case page: the next navigation to a case address serves srv.current, so the address (and
// with it the address model's verdict) stays fixed while the page changes.
const srv = { current: null, file: null };
const CASE_PATHS = new Set(["/a", "/", "/app", "/login", "/b-other-page", "/again", "/home"]);
const pages = createServer({ maxHeaderSize: 1 << 20 }, (req, res) => {
  const u = new URL(req.url, "http://x");
  let path = u.pathname;
  res.setHeader("Cache-Control", "no-store");
  if (CASE_PATHS.has(path) && srv.file) {
    for (const [k, v] of Object.entries(srv.file.headers)) res.setHeader(k, v);
    return res.end(srv.file.body);
  }
  if (CASE_PATHS.has(path) && srv.current && req.headers["sec-fetch-dest"] !== "iframe") {
    res.setHeader("Content-Type", "text/html");
    return res.end(srv.current);
  }
  const r = routes[path] ?? (() => `<html><head><title>ok</title></head><body><h1 id="ok">page ${req.url.slice(0, 80)}</h1><p>Plain page.</p></body></html>`);
  res.setHeader("Content-Type", path.endsWith(".js") ? "text/javascript" : "text/html");
  res.end(r(u.searchParams));
});

await listen(backend, 8000);
await listen(pages, 8123);
const pages6 = createServer({ maxHeaderSize: 1 << 20 }, (q, s) => pages.emit("request", q, s));
await listen(pages6, 8123, "::1").catch(() => {});

const context = await chromium.launchPersistentContext("", {
  channel: "chromium",
  headless: true,
  args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`, "--host-resolver-rules=MAP * 127.0.0.1,EXCLUDE localhost"],
});
let worker = context.serviceWorkers().find((w) => w.url().startsWith("chrome-extension://"));
worker ??= await context.waitForEvent("serviceworker", { predicate: (w) => w.url().startsWith("chrome-extension://") });
await sleep(1000);
const extId = new URL(worker.url()).host;
const results = [];

const isWarning = (page) => !page.isClosed() && page.url().startsWith(`chrome-extension://${extId}/warning.html`);
async function tabs() { return worker.evaluate(async () => (await chrome.tabs.query({})).map((t) => ({ id: t.id, url: t.url, pending: t.pendingUrl }))); }
async function tabIdOf(page) {
  const url = page.url();
  const all = await tabs();
  return (all.find((t) => t.url === url || t.pending === url) ?? all.find((t) => url.length > 200 && (t.url ?? "").startsWith(url.slice(0, 200))))?.id;
}
async function state(page) {
  const id = await tabIdOf(page);
  if (id === undefined) return null;
  return worker.evaluate(async (k) => (await chrome.storage.session.get(k))[k] ?? null, `tab:${id}`);
}
async function bannerVisible(page) {
  return page.evaluate(() => { const el = document.elementFromPoint(window.innerWidth / 2, 6); return (el?.id === "phishdrift-banner-host" || el?.tagName === "PHISHDRIFT-BANNER"); }).catch(() => false);
}
// what the user sees: "warning" (interstitial), "banner", or "none"; plus stored verdict
async function seen(page) {
  if (page.isClosed()) return { ui: "closed", verdict: null };
  if (isWarning(page)) return { ui: "warning", verdict: 2 };
  const st = await state(page);
  return { ui: (await bannerVisible(page)) ? "banner" : "none", verdict: st?.verdict ?? null, layer: st?.layer, reasons: st?.reasons, notes: st?.notes };
}
// warned = the user sees a warning AND the extension's own verdict for the tab agrees (a banner
// left over from an earlier, higher verdict while the tab's verdict is "safe" does not count).
const warned = (s) => s.ui === "warning" || (s.ui === "banner" && s.verdict >= 1);
const rank = { none: 0, closed: 0, banner: 1, warning: 2 };
async function waitSeen(page, minUi, ms = 8000) {
  // Judge what the user sees once the page has settled: a warning page is final; otherwise wait the
  // full time (late forms, rechecks and the page check can still change the verdict) and judge then.
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    if (isWarning(page) || page.isClosed()) break;
    await sleep(250);
  }
  return seen(page);
}
async function open(url, route = null) {
  srv.current = route ? routes[route]() : null;
  srv.file = null;
  const page = await context.newPage();
  await page.goto(url, { timeout: 15000 }).catch(() => {});
  return page;
}
async function shot(page, name) {
  if (page.isClosed()) return undefined;
  const p = join(out, `${name}.png`);
  await page.screenshot({ path: p }).catch(() => {});
  return p;
}
async function record(id, gap, expected, fn) {
  if (filter && !id.includes(filter)) return;
  let r;
  try { r = await fn(); } catch (e) { r = { pass: false, actual: `harness error: ${e.message.split("\n")[0]}` }; }
  results.push({ id, gap, expected, ...r });
  console.log(`${r.pass === null ? "INFO" : r.pass ? "PASS" : "FAIL"}  ${id}  ${r.actual}${r.shot ? "  [" + r.shot + "]" : ""}`);
  for (const p of context.pages()) await p.close().catch(() => {});
}
async function extMessage(msg) {
  const ext = await context.newPage();
  await ext.goto(`chrome-extension://${extId}/popup.html`).catch(() => {});
  const r = await ext.evaluate((m) => chrome.runtime.sendMessage(m), msg);
  await ext.close();
  return r;
}
const H = `http://${HOST}:8123`;
const SAFEHOST = `http://${SAFEHOSTNAME}:8123`;
const desc = (s) => `ui=${s.ui} verdict=${s.verdict}${s.layer ? " layer=" + s.layer : ""}${s.ui === "banner" && s.verdict === 0 ? " (STALE banner: tab verdict is safe)" : ""}`;

// wait for install-time list sync
for (let i = 0; i < 60; i++) {
  if (await worker.evaluate(async () => Boolean((await chrome.storage.local.get("lists")).lists?.version))) break;
  await sleep(250);
}

// ---------------- cases ----------------
await record("G1-cred-page-clears-suspicious", "page model can clear a suspicious address", "banner or warning (page asks for a password)", async () => {
  const page = await open(`${H}/a`, "/news-login");
  await sleep(2500);
  const s = await waitSeen(page, "banner", 3000);
  return { pass: warned(s), actual: desc(s), shot: await shot(page, "G1-cred") };
});
await record("G1-control-no-cred", "page model can clear a suspicious address", "info: page without credential fields may be cleared", async () => {
  const page = await open(`${H}/a`, "/news");
  await sleep(2500);
  const s = await seen(page);
  return { pass: null, actual: desc(s) };
});
await record("G3-delayed-form", "late login form (2.5 s timer)", "warning or banner after the lure appears", async () => {
  const page = await open(`${H}/a`, "/delayed");
  const s = await waitSeen(page, "banner", 9000);
  return { pass: warned(s), actual: desc(s), shot: await shot(page, "G3-delayed") };
});
await record("G3-click-revealed-form", "login form revealed by a click", "warning or banner after the click", async () => {
  const page = await open(`${H}/a`, "/click");
  await sleep(2000);
  await page.click("#go").catch(() => {});
  const s = await waitSeen(page, "banner", 8000);
  return { pass: warned(s), actual: desc(s), shot: await shot(page, "G3-click") };
});
await record("G3-over-recheck-cap", "3 decoy password fields, then the lure", "warning or banner after the lure", async () => {
  const page = await open(`${H}/a`, "/overcap");
  const s = await waitSeen(page, "banner", 14000);
  return { pass: warned(s), actual: desc(s), shot: await shot(page, "G3-overcap") };
});
await record("G3-closed-shadow-form", "lure form in a closed shadow root", "warning or banner", async () => {
  const page = await open(`${H}/a`, "/shadow");
  const s = await waitSeen(page, "banner", 6000);
  return { pass: warned(s), actual: desc(s), shot: await shot(page, "G3-shadow") };
});
await record("G4-cross-site-iframe-login", "login form in a cross-site iframe on a safe page", "warning or banner on the tab", async () => {
  const page = await open(`${SAFEHOST}/`, "/frame-outer");
  const s = await waitSeen(page, "banner", 6000);
  const id = await tabIdOf(page);
  console.log("   doc:", JSON.stringify(await worker.evaluate(async (k) => (await chrome.storage.session.get(k))[k], `doc:${id}`)), "frames:", page.frames().map((f) => f.url()).join(" "));
  return { pass: warned(s), actual: desc(s), shot: await shot(page, "G4-iframe") };
});
await record("G4-srcdoc-iframe-login", "login form in a srcdoc iframe on a safe page", "warning or banner on the tab", async () => {
  const page = await open(`${SAFEHOST}/`, "/srcdoc-outer");
  const s = await waitSeen(page, "banner", 6000);
  return { pass: warned(s), actual: desc(s), shot: await shot(page, "G4-srcdoc") };
});
await record("G4-spa-pushstate", "single-page app route change to a lure", "warning or banner after the route change", async () => {
  const page = await open(`${H}/`, "/spa");
  const s = await waitSeen(page, "banner", 9000);
  return { pass: warned(s), actual: desc(s) + ` url=${page.isClosed() ? "" : page.url()}`, shot: await shot(page, "G4-spa") };
});
await record("G4-spa-hash", "hash route change to a lure", "warning or banner after the route change", async () => {
  const page = await open(`${H}/`, "/spa-hash");
  const s = await waitSeen(page, "banner", 9000);
  return { pass: warned(s), actual: desc(s), shot: await shot(page, "G4-hash") };
});
let clickErr = null;
async function popupCase(path, name) {
  clickErr = null;
  const page = await open(`${H}/`, `/${path}`);
  await sleep(1500);
  const [pop] = await Promise.all([context.waitForEvent("page", { timeout: 5000 }).catch(() => null), page.click("#go", { timeout: 4000 }).catch((e) => { clickErr = e.message.split("\n")[0]; })]);
  if (!pop) return { pass: false, actual: `no new tab opened (opener ${await seen(page).then(desc)}, at ${page.isClosed() ? "closed" : page.url()}, click: ${clickErr})` };
  await sleep(500);
  const s = await waitSeen(pop, "banner", 6000);
  return { pass: warned(s), actual: `${desc(s)} url=${pop.isClosed() ? "" : pop.url().slice(0, 60)}`, shot: await shot(pop, name) };
}
await record("X-blob-page", "lure opened as a blob: URL", "warning or banner in the new tab", () => popupCase("opener-blob", "X-blob"));
await record("X-about-blank-page", "lure written into about:blank", "warning or banner in the new tab", () => popupCase("opener-blank", "X-blank"));
await record("X-data-url", "link to a data: URL lure", "blocked by Chrome or warned", async () => {
  const page = await open(`${H}/`, "/opener-data");
  await sleep(1000);
  await page.click("#go").catch(() => {});
  await sleep(2500);
  const blocked = !page.url().startsWith("data:");
  const s = await seen(page);
  return { pass: blocked || s.ui !== "none", actual: blocked ? `Chrome refused the navigation (still at ${page.url()})` : desc(s) };
});
await record("X-address-rewrite", "page rewrites its address to / (replaceState)", "banner stays (verdict does not get better)", async () => {
  const page = await open(`${H}/a`, "/rewrite");
  const s = await waitSeen(page, "banner", 6000);
  return { pass: warned(s), actual: desc(s) + ` url=${page.isClosed() ? "" : page.url()}`, shot: await shot(page, "X-rewrite") };
});
await record("X-address-rewrite-lure", "lure page rewrites its address to /", "warning", async () => {
  const page = await open(`${H}/a`, "/rewrite-lure");
  const s = await waitSeen(page, "warning", 6000);
  return { pass: s.ui === "warning", actual: desc(s) };
});
await record("X-banner-same-id", "page plants an element with the banner's id", "banner visible", async () => {
  const page = await open(`${H}/a`, "/plant-id");
  const s = await waitSeen(page, "banner", 6000);
  return { pass: warned(s), actual: desc(s), shot: await shot(page, "X-plant") };
});
await record("X-banner-css-hidden", "page CSS hides #phishdrift-banner-host", "banner visible", async () => {
  const page = await open(`${H}/a`, "/css-hide");
  const s = await waitSeen(page, "banner", 6000);
  return { pass: warned(s), actual: desc(s), shot: await shot(page, "X-csshide") };
});
await record("X-banner-css-hidden-tag", "page CSS hides the banner element by tag (opacity, visibility, clip, transform)", "banner visible", async () => {
  const page = await open(`${H}/a`, "/css-hide-tag");
  const s = await waitSeen(page, "banner", 6000);
  return { pass: warned(s), actual: desc(s), shot: await shot(page, "X-csshide-tag") };
});
await record("X-banner-removed", "page script removes the banner", "banner visible", async () => {
  const page = await open(`${H}/a`, "/remover");
  const s = await waitSeen(page, "banner", 6000);
  return { pass: warned(s), actual: desc(s), shot: await shot(page, "X-remover") };
});
await record("X-back-to-safety-history", "'Take me back to safety' after browsing from a safe page", "lands on the previous safe page and stays", async () => {
  // the dangerous page asks for a password: since 2026-10-20 an address-only dangerous verdict on a
  // page that asks for nothing is a banner, and the warning page needs a second reason
  srv.current = routes["/tiny"]();
  const page = await context.newPage();
  await page.goto(`${SAFEHOST}/articles/today`).catch(() => {});
  await page.goto(`http://${DANGERHOST}:8123/`).catch(() => {});
  for (let i = 0; i < 30 && !isWarning(page); i++) await sleep(250);
  if (!isWarning(page)) return { pass: false, actual: `no warning page (at ${page.url()})` };
  await page.click("#back").catch(() => {});
  await sleep(3000);
  const u = page.isClosed() ? "closed" : page.url();
  return { pass: u.startsWith(SAFEHOST), actual: `ended at ${u}`, shot: await shot(page, "X-back-history") };
});
await record("X-back-to-safety-new-tab", "'Take me back to safety' in a tab opened straight to the dangerous page", "tab closes or leaves the dangerous site", async () => {
  const page = await open(`http://${DANGERHOST}:8123/home`, "/tiny"); // asks for a password, see above
  for (let i = 0; i < 30 && !isWarning(page); i++) await sleep(250);
  if (!isWarning(page)) return { pass: false, actual: `no warning page (at ${page.url()})` };
  await page.click("#back").catch(() => {});
  await sleep(3000);
  const u = page.isClosed() ? "closed" : page.url();
  return { pass: u === "closed" || !(u.includes(DANGERHOST) || u.includes("warning.html")), actual: `ended at ${u}`, shot: await shot(page, "X-back-newtab") };
});
await record("D-address-only-dangerous-is-banner", "dangerous address, ordinary content page that asks for nothing (by design since 2026-10-20)", "banner, not the warning page", async () => {
  const page = await open(`http://${EDGEHOST}:8123/app`, "/news");
  await sleep(7500); // past the 5 s hold: the warning page would have replaced the banner by now
  const s = await seen(page);
  return { pass: s.ui === "banner" && s.verdict === 1, actual: desc(s), shot: await shot(page, "D-address-only") };
});
await record("G2-trust-then-blocklisted", "'Trust this site', then the domain is blocklisted by a later sync", "warning shown", async () => {
  be.blockDomains = [BLOCKEDHOST];
  const page = await open(`http://${TRUSTHOST}:8123/a`, "/blog");
  await waitSeen(page, "banner", 5000);
  const t = await extMessage({ type: "trust", tabId: await tabIdOf(page) });
  be.blockDomains = [BLOCKEDHOST, TRUSTHOST]; be.version = "stub2";
  const syncRes = await extMessage({ type: "sync" });
  const p2 = await open(`http://${TRUSTHOST}:8123/b-other-page`);
  const s = await waitSeen(p2, "warning", 5000);
  return { pass: s.ui === "warning", actual: `trust=${JSON.stringify(t)} sync=${JSON.stringify(syncRes)} then ${desc(s)}`, shot: await shot(p2, "G2-trust-block") };
});
await record("G2-trust-on-blocklisted-page", "'Trust this site' pressed on a blocklisted page", "warning still shown on the next visit", async () => {
  const page = await open(`http://${BLOCKEDHOST}:8123/`);
  for (let i = 0; i < 30 && !isWarning(page); i++) await sleep(250);
  if (!isWarning(page)) return { pass: false, actual: `no warning first (at ${page.url()})` };
  const id = (await tabs()).find((t) => t.url?.startsWith(`chrome-extension://${extId}/warning.html`))?.id;
  const t = await extMessage({ type: "trust", tabId: id });
  const p2 = await open(`http://${BLOCKEDHOST}:8123/again`);
  const s = await waitSeen(p2, "warning", 5000);
  return { pass: s.ui === "warning", actual: `trust=${JSON.stringify(t)} then ${desc(s)}` };
});
await record("G2-trust-expiry", "trust entry older than the expiry", "warning comes back", async () => {
  const stored = await worker.evaluate(async () => (await chrome.storage.local.get("trusted")).trusted);
  const fmt = JSON.stringify(stored)?.slice(0, 200);
  if (stored === undefined) return { pass: false, actual: "nothing was trusted earlier in the run, so expiry could not be tested" };
  if (Array.isArray(stored) && stored.every((x) => typeof x === "string")) {
    return { pass: false, actual: `trust stored as plain keys with no time: ${fmt}` };
  }
  // age every entry by 400 days, whatever the shape: any number that looks like a ms timestamp
  const aged = JSON.parse(JSON.stringify(stored), (k, v) => (typeof v === "number" && v > 1e12 ? v - 400 * 864e5 : v));
  await worker.evaluate(async (v) => chrome.storage.local.set({ trusted: v }), aged);
  be.blockDomains = [BLOCKEDHOST]; be.version = "stub3";
  await extMessage({ type: "sync" });
  const p2 = await open(`http://${TRUSTHOST}:8123/a?again=1`);
  const s = await waitSeen(p2, "banner", 5000);
  return { pass: warned(s), actual: `stored=${fmt} after ageing 400 days: ${desc(s)}` };
});
await record("G-tiny-login-suspicious", "tiny login page on a suspicious address", "banner", async () => {
  const page = await open(`${H}/a`, "/tiny");
  const s = await waitSeen(page, "banner", 5000);
  return { pass: warned(s), actual: desc(s), shot: await shot(page, "tiny") };
});
await record("G-tiny-login-unknown", "tiny login page on an address the model passes", "info", async () => {
  const page = await open(`http://shop-blue.com:8123/login`, "/tiny");
  await sleep(2500);
  const s = await seen(page);
  return { pass: null, actual: desc(s) };
});
const weird = [
  "http://0x7f.0.0.1:8123/login",
  "http://2130706433:8123/a/blog",
  "http://[::1]:8123/a/blog",
  `http://user:pass@${HOST}:8123/a/blog`,
  "http://xn--pypal-4ve.com:8123/a/blog",
  `http://${HOST}:8123/a/%zz%/blog`,
  `http://${HOST}:8123/a/` + "x".repeat(40000),
  `http://${HOST}.:8123/a/blog`,
  `http://${HOST.toUpperCase()}:8123/A/Blog`,
];
for (const [i, u] of weird.entries()) {
  await record(`X-odd-address-${i}`, `unusual address ${u.slice(0, 60)}`, "page loads, a verdict is stored, no crash", async () => {
    const page = await open(u);
    await sleep(2500);
    const st = await state(page);
    if (!st) console.log("   tabs:", JSON.stringify((await tabs()).map((t) => [t.id, (t.url ?? "").slice(0, 70), (t.url ?? "").length])));
    const loaded = isWarning(page) || (await page.evaluate(() => document.readyState).catch(() => "?")) === "complete";
    const s = await seen(page);
    return { pass: loaded && (st !== null || isWarning(page)), actual: `loaded=${loaded} stored=${st ? "yes" : "no"} ${desc(s)} reasons=${JSON.stringify(s.reasons ?? []).slice(0, 120)}` };
  });
}
await record("X-backend-slow", "backend answers after 15 s", "page loads at once; banner within about 3 s", async () => {
  be.slowMs = 15000;
  srv.current = routes["/blog"]();
  const page = await context.newPage();
  const t0 = Date.now();
  await page.goto(`${H}/app`, { waitUntil: "domcontentloaded" }).catch(() => {});
  const loadMs = Date.now() - t0;
  let bannerMs = null;
  while (Date.now() - t0 < 8000) {
    const cur = await seen(page);
    if (warned(cur)) { bannerMs = Date.now() - t0; break; }
    await sleep(100);
  }
  const s = await seen(page);
  be.slowMs = 0;
  return { pass: loadMs < 3000 && bannerMs !== null && bannerMs < 4000, actual: `loaded in ${loadMs} ms, ${desc(s)} first warned at ${bannerMs} ms, notes=${JSON.stringify(s.notes)}` };
});
await record("X-backend-down", "backend refuses connections", "page loads; banner from the address check", async () => {
  be.down = true;
  const page = await open(`${H}/login`, "/blog");
  const s = await waitSeen(page, "banner", 6000);
  be.down = false;
  return { pass: warned(s), actual: `${desc(s)} notes=${JSON.stringify(s.notes)}` };
});


// ---------------- file types: PDFs and downloads ----------------
// The body is chosen by the Content-Type / Content-Disposition headers, not by the path, so the address
// (and its model score) is the same as for the page cases.
const pdfBytes = (link) => {
  const objs = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> /Annots [6 0 R] >>`,
    "<< /Length 60 >>\nstream\nBT /F1 18 Tf 20 100 Td (Click here to sign in) Tj ET\nendstream",
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    `<< /Type /Annot /Subtype /Link /Rect [0 0 300 200] /Border [0 0 0] /A << /S /URI /URI (${link}) >> >>`,
  ];
  let out = "%PDF-1.4\n"; const offs = [];
  objs.forEach((o, i) => { offs.push(out.length); out += `${i + 1} 0 obj\n${o}\nendobj\n`; });
  const xref = out.length;
  out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n` + offs.map((o) => String(o).padStart(10, "0") + " 00000 n \n").join("");
  return out + `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
};
const FILES = {
  pdf: () => ({ headers: { "Content-Type": "application/pdf" }, body: pdfBytes("http://example.test/") }),
  exe: () => ({ headers: { "Content-Type": "application/octet-stream", "Content-Disposition": 'attachment; filename="setup.exe"' }, body: "MZ fake" }),
  zip: () => ({ headers: { "Content-Type": "application/zip" }, body: "PK fake" }),
  htmlAttachment: () => ({ headers: { "Content-Type": "text/html", "Content-Disposition": 'attachment; filename="invoice.html"' }, body: LURE }),
  image: () => ({ headers: { "Content-Type": "image/svg+xml" }, body: '<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40"><rect width="40" height="40"/></svg>' }),
};
async function openFile(url, kind) {
  srv.current = null;
  srv.file = FILES[kind]();
  const page = await context.newPage();
  const id = (await tabs()).find((t) => (t.url ?? "") === "" || t.url === "about:blank" || t.pending === "about:blank")?.id ?? null;
  const nav = await page.goto(url, { timeout: 10000 }).then(() => "loaded", (e) => (/Download is starting/.test(e.message) ? "download" : "error"));
  return { page, nav, id };
}
async function fileSeen(f) {
  const { page, id } = f;
  const tabId = (page.url().startsWith("http") ? await tabIdOf(page) : null) ?? id;
  const st = tabId == null ? null : await worker.evaluate(async (k) => (await chrome.storage.session.get(k))[k] ?? null, `tab:${tabId}`);
  const badge = tabId == null ? "" : await worker.evaluate((t) => chrome.action.getBadgeText({ tabId: t }), tabId);
  const ui = isWarning(page) ? "warning" : (await bannerVisible(page)) ? "banner" : "none";
  return { ui, verdict: ui === "warning" ? 2 : st?.verdict ?? null, layer: st?.layer, badge, nav: f.nav, at: page.isClosed() ? "closed" : page.url().slice(0, 50) };
}
const fdesc = (s) => `nav=${s.nav} ui=${s.ui} stored verdict=${s.verdict}${s.layer ? " layer=" + s.layer : ""} badge="${s.badge}" tab at ${s.at}`;
const fileCase = (id, gap, expected, host, path, kind, okFn, wait = 8000) =>
  record(id, gap, expected, async () => {
    const f = await openFile(`http://${host}:8123${path}`, kind);
    await sleep(wait);
    const s = await fileSeen(f);
    return { pass: okFn(s), actual: fdesc(s), shot: await shot(f.page, id) };
  });
const anyWarn = (s) => s.ui !== "none" || s.verdict >= 1;
await record("F-pdf-control-safe-address", "PDF on an address the model passes", "no warning", async () => {
  const f = await openFile(`${SAFEHOST}/`, "pdf"); await sleep(4000); const s = await fileSeen(f);
  return { pass: s.ui === "none", actual: fdesc(s) };
});
await fileCase("F-pdf-suspicious-address", "PDF on a suspicious address", "banner (like a web page)", HOST, "/a", "pdf", (s) => s.ui === "banner" || s.ui === "warning");
await fileCase("F-pdf-dangerous-address", "PDF on a dangerous address", "warning page or banner", DANGERHOST, "/home", "pdf", anyWarn);
await fileCase("F-pdf-blocklisted", "PDF on a blocklisted address", "warning page", BLOCKEDHOST, "/", "pdf", (s) => s.ui === "warning");
await fileCase("F-download-dangerous-address", "download (.exe) from a dangerous address, new tab with no page (toolbar badge only: nowhere to put a banner)", "info", DANGERHOST, "/home", "exe", () => null, 6000);
await fileCase("F-download-blocklisted", "download (.exe) from a blocklisted address", "warning page", BLOCKEDHOST, "/", "exe", (s) => s.ui === "warning", 6000);
await fileCase("F-download-zip-suspicious", "zip from a suspicious address", "info (badge only, new tab)", HOST, "/a", "zip", () => null, 6000);
await fileCase("F-html-attachment-dangerous", "HTML file sent as a download from a dangerous address", "info (badge only, new tab)", DANGERHOST, "/home", "htmlAttachment", () => null, 6000);
await fileCase("F-svg-image-dangerous", "image on a dangerous address (no HTML, no content script)", "info", DANGERHOST, "/home", "image", () => null, 6000);
async function downloadFromSafePage(host, path) {
  srv.current = routes["/news"](); srv.file = null;
  const page = await context.newPage();
  await page.goto(`${SAFEHOST}/`).catch(() => {});
  await sleep(2500);
  const before = await seen(page);
  srv.file = FILES.exe();
  const dl = page.waitForEvent("download", { timeout: 6000 }).catch(() => null);
  await page.evaluate((u) => { const a = document.createElement("a"); a.href = u; a.textContent = "get"; document.body.append(a); a.click(); }, `http://${host}:8123${path}`);
  const d = await dl;
  await sleep(3500);
  const after = await seen(page);
  return { page, before, after, started: d !== null };
}
await record("F-download-link-from-safe-page-flagged", "safe page, the user clicks a download link to a dangerous address", "the page keeps its own verdict (safe) and shows a banner about the file", async () => {
  const { page, before, after, started } = await downloadFromSafePage(DANGERHOST, "/home");
  const text = await page.evaluate(() => document.querySelector("phishdrift-banner") ? "banner element present" : "no banner element").catch(() => "?");
  return { pass: started && before.verdict === 0 && after.verdict === 0 && after.ui === "banner", actual: `download started=${started}; before: ${desc(before)} | after: ui=${after.ui} stored verdict=${after.verdict} (${text})`, shot: await shot(page, "F-download-from-page") };
});
await record("F-download-link-from-safe-page-control", "safe page, the user clicks a download link to a safe address", "no banner, the page keeps its verdict", async () => {
  const { page, before, after, started } = await downloadFromSafePage(SAFEHOSTNAME + "", "/");
  return { pass: started && after.verdict === before.verdict && after.ui === "none", actual: `download started=${started}; before: ${desc(before)} | after: ${desc(after)}` };
});
await record("F-download-link-blocklisted", "safe page, the user clicks a download link to a blocklisted address", "warning page (the download itself is not stopped)", async () => {
  const { page, after, started } = await downloadFromSafePage(BLOCKEDHOST, "/");
  return { pass: after.ui === "warning", actual: `download started=${started}; ${desc(after)}` };
});
await record("F-pdf-link-click", "link inside a PDF on a safe address, opened in the same tab, leads to a dangerous address", "the link target is checked like any navigation: warning page (the page it leads to asks for a password)", async () => {
  srv.current = null;
  srv.file = { headers: { "Content-Type": "application/pdf" }, body: pdfBytes(`http://${DANGERHOST}:8123/home`) };
  const page = await context.newPage();
  await page.goto(`${SAFEHOST}/`, { timeout: 10000 }).catch(() => {});
  await sleep(4000);
  srv.file = { headers: { "Content-Type": "text/html" }, body: TINY }; // what the link leads to
  await page.mouse.click(790, 200);
  for (let i = 0; i < 40 && !isWarning(page) && !page.url().includes(DANGERHOST); i++) await sleep(250);
  await sleep(1500);
  const u = page.isClosed() ? "closed" : page.url();
  const s = await seen(page);
  return { pass: isWarning(page) || (u.includes(DANGERHOST) && warned(s)), actual: `after click tab at ${u.slice(0, 60)} ${desc(s)}`, shot: await shot(page, "F-pdf-link") };
});

writeFileSync(join(out, "results.json"), JSON.stringify(results, null, 2));
const f = results.filter((r) => r.pass === false).length;
console.log(`\n${results.filter((r) => r.pass).length} pass, ${f} fail, ${results.filter((r) => r.pass === null).length} info -> ${out}/results.json`);
await context.close();
pages.close(); backend.close(); pages6.close();
process.exit(0);
