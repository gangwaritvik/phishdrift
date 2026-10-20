// Offline rendering of stored pages: each page's stored HTML is served at its real address inside
// headless Chromium (every other request is aborted, so inline scripts run but external scripts,
// styles, frames and XHR fail), and after load and a short settle the live DOM is serialised the way
// the content script's `pageHtml` does, with the content script's page facts read from that DOM.
// No network request leaves the browser. A lower bound on the raw-vs-rendered difference on real
// sites, where external scripts also run.
//   node js/bench/render_pages.mjs IN.jsonl OUT.jsonl [--workers 4] [--settle-ms 1500] [--timeout-ms 15000]
//     IN.jsonl: {url, html}; OUT.jsonl: {url, ok, error, html, facts, ms} per page, appended; pages
//     already in OUT.jsonl are skipped (resumable).
// Playwright is resolved from the global node_modules (npm root -g) when the project has none.

import { createReadStream, existsSync, appendFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { createRequire } from "node:module";
import { execSync } from "node:child_process";
import path from "node:path";

const [inFile, outFile, ...rest] = process.argv.slice(2);
if (!inFile || !outFile) throw new Error("usage: render_pages.mjs IN.jsonl OUT.jsonl [--workers N] [--settle-ms MS] [--timeout-ms MS]");
const opt = (name, dflt) => {
  const i = rest.indexOf(name);
  return i >= 0 ? Number(rest[i + 1]) : dflt;
};
const WORKERS = opt("--workers", 4);
const SETTLE_MS = opt("--settle-ms", 1500);
const TIMEOUT_MS = opt("--timeout-ms", 15000);

function loadPlaywright() {
  const req = createRequire(import.meta.url);
  try {
    return req("playwright");
  } catch {
    const root = execSync("npm root -g", { encoding: "utf8" }).trim();
    return createRequire(path.join(root, "noop.js"))("playwright");
  }
}
const { chromium } = loadPlaywright();

const done = new Set();
if (existsSync(outFile)) {
  for await (const line of createInterface({ input: createReadStream(outFile), crlfDelay: Infinity })) {
    if (line.trim()) done.add(JSON.parse(line).url);
  }
}
const queue = [];
for await (const line of createInterface({ input: createReadStream(inFile), crlfDelay: Infinity })) {
  if (!line.trim()) continue;
  const row = JSON.parse(line);
  if (!done.has(row.url)) queue.push(row);
}
process.stderr.write(`render: ${queue.length} to do, ${done.size} done\n`);

// Closed shadow roots: the extension reads them with chrome.dom.openOrClosedShadowRoot; a page script
// cannot, so attachShadow is wrapped to keep a reference to every root (read by `shadowRootOf`).
const INIT = `(() => {
  const orig = Element.prototype.attachShadow;
  const key = Symbol.for("phishdrift.shadow");
  Element.prototype.attachShadow = function (init) {
    const root = orig.call(this, init);
    try { Object.defineProperty(this, key, { value: root, enumerable: false }); } catch {}
    return root;
  };
})();`;

// Copied from extension/src/content.js (shadowRoots, collectPageFacts, pageHtml), with
// chrome.dom.openOrClosedShadowRoot replaced by the reference kept by INIT.
function serialise() {
  const key = Symbol.for("phishdrift.shadow");
  const CREDENTIAL_INPUT = /\b(otp|one[-_ ]?time|passcode|cvv|cvc|csc|card[-_ ]?(number|no)|cc[-_ ]?(num|number)|upi[-_ ]?pin|atm[-_ ]?pin|pin[-_ ]?code)\b/i;
  const CREDENTIAL_AUTOCOMPLETE = /\b(one-time-code|cc-number|cc-csc)\b/i;
  const MAX_SHADOW_ROOTS = 200;
  const MAX_HTML_CHARS = 5_000_000;
  function isCredentialInput(input) {
    const type = (input.getAttribute("type") || "text").toLowerCase();
    if (type === "hidden" || type === "password" || type === "submit" || type === "button") return false;
    if (CREDENTIAL_AUTOCOMPLETE.test(input.getAttribute("autocomplete") || "")) return true;
    const text = ["name", "id", "placeholder", "aria-label"].map((a) => input.getAttribute(a) || "").join(" ");
    return CREDENTIAL_INPUT.test(text);
  }
  const shadowRootOf = (el) => el[key] ?? el.shadowRoot ?? null;
  function shadowRoots(doc) {
    const found = [];
    const stack = [doc];
    while (stack.length && found.length < MAX_SHADOW_ROOTS) {
      const root = stack.pop();
      for (const el of Array.from(root.querySelectorAll?.("*") ?? [])) {
        if (el.tagName === "PHISHDRIFT-BANNER") continue;
        const shadow = shadowRootOf(el);
        if (!shadow) continue;
        found.push(shadow);
        stack.push(shadow);
        if (found.length >= MAX_SHADOW_ROOTS) break;
      }
    }
    return found;
  }
  function collectPageFacts(doc, base, shadows) {
    const forms = [];
    const allForms = [...Array.from(doc.forms ?? []), ...shadows.flatMap((r) => Array.from(r.querySelectorAll("form")))];
    for (const form of allForms) {
      const hasPassword = Boolean(form.querySelector('input[type="password"]'));
      let action = null;
      try {
        action = new URL(form.getAttribute("action") || "", base).href;
      } catch {
        action = null;
      }
      forms.push({ hasPassword, action });
    }
    let passwordFields = 0;
    let credentialFields = 0;
    for (const root of [doc, ...shadows]) {
      passwordFields += root.querySelectorAll('input[type="password"]').length;
      const inputs = Array.from(root.querySelectorAll("input") ?? []);
      credentialFields += inputs.filter((i) => typeof i.getAttribute === "function" && isCredentialInput(i)).length;
    }
    return { passwordFields, credentialFields, forms };
  }
  function pageHtml(doc, shadowList) {
    const doctype = doc.doctype ? new XMLSerializer().serializeToString(doc.doctype) : "";
    const shadows = shadowList.map((r) => `<div data-phishdrift-shadow>${r.innerHTML}</div>`).join("");
    const html = doc.documentElement.outerHTML;
    const end = html.lastIndexOf("</body>");
    const joined = end < 0 ? html + shadows : html.slice(0, end) + shadows + html.slice(end);
    return (doctype + joined).slice(0, MAX_HTML_CHARS);
  }
  const shadows = shadowRoots(document);
  return {
    html: pageHtml(document, shadows),
    facts: collectPageFacts(document, location.href, shadows),
    href: location.href,
    shadows: shadows.length,
  };
}

const noHash = (u) => u.split("#")[0];
const withTimeout = (p, ms, what) =>
  Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error(`timeout: ${what}`)), ms))]);

async function renderOne(browser, row) {
  const t0 = Date.now();
  const context = await browser.newContext({ serviceWorkers: "block", javaScriptEnabled: true, ignoreHTTPSErrors: true });
  try {
    await context.addInitScript(INIT);
    const target = noHash(row.url);
    let served = 0;
    await context.route("**/*", (route) => {
      const req = route.request();
      if (req.isNavigationRequest() && req.frame().parentFrame() === null && noHash(req.url()) === target && served < 3) {
        served += 1;
        return route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: Buffer.from(row.html, "utf8") });
      }
      return route.abort();
    });
    const page = await context.newPage();
    const work = (async () => {
      await page.goto(row.url, { waitUntil: "load", timeout: TIMEOUT_MS });
      await page.waitForTimeout(SETTLE_MS);
      return page.evaluate(serialise);
    })();
    const out = await withTimeout(work, TIMEOUT_MS, "render");
    return { url: row.url, ok: true, error: null, html: out.html, facts: out.facts, href: out.href, shadows: out.shadows, ms: Date.now() - t0 };
  } catch (e) {
    return { url: row.url, ok: false, error: String(e?.message ?? e).split("\n")[0].slice(0, 200), html: null, facts: null, ms: Date.now() - t0 };
  } finally {
    await withTimeout(context.close(), 5000, "close").catch(() => {});
  }
}

let next = 0;
let finished = 0;
async function worker() {
  let browser = await chromium.launch({ headless: true });
  while (next < queue.length) {
    const row = queue[next++];
    const res = await renderOne(browser, row);
    if (!res.ok && /timeout|closed|crash/i.test(res.error)) {
      // a hung page may leave the browser unusable: restart it before the next page
      await withTimeout(browser.close(), 5000, "browser close").catch(() => {});
      browser = await chromium.launch({ headless: true });
    }
    appendFileSync(outFile, `${JSON.stringify(res)}\n`);
    finished += 1;
    if (finished % 100 === 0) process.stderr.write(`render: ${finished}/${queue.length}\n`);
  }
  await withTimeout(browser.close(), 5000, "browser close").catch(() => {});
}
await Promise.all(Array.from({ length: Math.max(1, WORKERS) }, worker));
process.stderr.write(`render: finished ${finished}\n`);
process.exit(0);
