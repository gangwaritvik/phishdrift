// Picture-only rule on stored pages: how many natural legitimate pages look like "one picture and no
// readable text, no fields" (pagefacts.js pictureOnly), and what the address model says about them.
// Each page's stored HTML is served at its real address in headless Chromium (viewport 1280x720, every
// other request aborted, so inline scripts run but external scripts, styles and images do not), then
// the content script's `visualFacts` (extension/src/content.js, the block between the visual-facts
// markers, run as it is) is read from the live DOM. No network request leaves the browser.
//   node js/bench/picture_facts.mjs IN.jsonl OUT.jsonl [--workers 4] [--settle-ms 1000] [--timeout-ms 15000]
//     IN.jsonl: {url, html}; OUT.jsonl: {url, ok, error, visual} per page, appended; resumable.
// Images never load here, so an <img> without width/height attributes has no size: the area figures
// are a lower bound, the picture counts an upper bound.

import { createReadStream, existsSync, appendFileSync, readFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import path from "node:path";

const [inFile, outFile, ...rest] = process.argv.slice(2);
if (!inFile || !outFile) throw new Error("usage: picture_facts.mjs IN.jsonl OUT.jsonl [--workers N] [--settle-ms MS] [--timeout-ms MS]");
const opt = (name, dflt) => {
  const i = rest.indexOf(name);
  return i >= 0 ? Number(rest[i + 1]) : dflt;
};
const WORKERS = opt("--workers", 4);
const SETTLE_MS = opt("--settle-ms", 1000);
const TIMEOUT_MS = opt("--timeout-ms", 15000);

const here = path.dirname(fileURLToPath(import.meta.url));
const content = readFileSync(path.join(here, "..", "..", "extension", "src", "content.js"), "utf8");
const block = content.match(/\/\/ <visual-facts>[\s\S]*?\/\/ <\/visual-facts>/)?.[0];
if (!block) throw new Error("visual-facts block not found in extension/src/content.js");
const SOURCE = `(() => { ${block}\n return visualFacts(document, window); })()`;

const { chromium } = createRequire(import.meta.url)(process.env.PLAYWRIGHT_MODULE ?? "playwright");

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
process.stderr.write(`picture_facts: ${queue.length} to do, ${done.size} done\n`);

const noHash = (u) => u.split("#")[0];
const withTimeout = (p, ms, what) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error(`timeout: ${what}`)), ms))]);

async function renderOne(browser, row) {
  const context = await browser.newContext({ serviceWorkers: "block", viewport: { width: 1280, height: 720 }, ignoreHTTPSErrors: true });
  try {
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
    const visual = await withTimeout(
      (async () => {
        await page.goto(row.url, { waitUntil: "load", timeout: TIMEOUT_MS });
        await page.waitForTimeout(SETTLE_MS);
        return page.evaluate(SOURCE);
      })(),
      TIMEOUT_MS,
      "render",
    );
    return { url: row.url, ok: true, error: null, visual };
  } catch (e) {
    return { url: row.url, ok: false, error: String(e?.message ?? e).split("\n")[0].slice(0, 200), visual: null };
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
      await withTimeout(browser.close(), 5000, "browser close").catch(() => {});
      browser = await chromium.launch({ headless: true });
    }
    appendFileSync(outFile, `${JSON.stringify(res)}\n`);
    finished += 1;
    if (finished % 100 === 0) process.stderr.write(`picture_facts: ${finished}/${queue.length}\n`);
  }
  await withTimeout(browser.close(), 5000, "browser close").catch(() => {});
}
await Promise.all(Array.from({ length: Math.max(1, WORKERS) }, worker));
process.stderr.write(`picture_facts: finished ${finished}\n`);
process.exit(0);
