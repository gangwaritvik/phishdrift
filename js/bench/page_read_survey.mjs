// Why does the URL check page say "Page empty"? Fetches popular legitimate sites with the hosted
// function's own code and reports, for each, where reading stopped. For a machine with open internet
// (workflow page-read-survey.yml). Legitimate sites only; pages are never run.
//   node js/bench/page_read_survey.mjs URL...
// Each address is fetched twice: as the function does (honest user agent) and with a browser user agent.
import { readFileSync } from "node:fs";

import { fetchPage } from "../../netlify/functions/fetch-page.mjs";
import { loadHybrid } from "../src/hybrid.js";
import { analyzeHtml } from "../src/html_features.js";

const read = (f) => JSON.parse(readFileSync(new URL(`../data/${f}`, import.meta.url), "utf8"));
const model = loadHybrid(read("tier_a_hybrid.json"), read("psl_icann.json"));

const BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";
// same limits as the function, but plain fetch with a browser user agent
async function browserRequest(url, ms) {
  const res = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(ms), headers: { "User-Agent": BROWSER_UA, Accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1", "Accept-Language": "en-US,en;q=0.9" } });
  const contentType = res.headers.get("content-type") ?? "";
  const location = res.headers.get("location");
  const body = location ? Buffer.alloc(0) : Buffer.from(await res.arrayBuffer()).subarray(0, 1_500_000);
  return { status: res.status, location, contentType, body, truncated: false };
}

function describe(r) {
  if (!r.ok) return { stage: "fetch", why: r.error + (r.status ? ` HTTP ${r.status}` : "") };
  const a = analyzeHtml(r.final, r.html, model.lists);
  // visible characters the parser saw (a floor of 0 lets short pages through; junk pages stay null)
  const visible = analyzeHtml(r.final, r.html, model.lists, null, { minVisibleChars: 0 }).values?.visible_text_len ?? null;
  const scripts = (r.html.match(/<script\b/gi) ?? []).length;
  const title = /<title[^>]*>([^<]{0,80})/i.exec(r.html)?.[1]?.trim() ?? "";
  return { stage: "read", status: a.status, http: r.status, bytes: r.bytes, scripts, title, noscript: /<noscript/i.test(r.html), visible };
}

const urls = process.argv.slice(2);

// With SITE set (the live demo site), also ask its /api/fetch-page for every address, as the URL check page
// does, and say which card the page would show. Paced under the function's 10 fetches a minute per address.
if (process.env.SITE) {
  const tally = {};
  for (const url of urls) {
    let line;
    try {
      const res = await fetch(`${process.env.SITE}/api/fetch-page`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url }), signal: AbortSignal.timeout(20000) });
      const r = res.ok ? await res.json() : null;
      let card;
      if (!r) card = `no answer (function HTTP ${res.status})`;
      else if (!r.ok) card = `Page not read (${r.error}${r.status ? ` HTTP ${r.status}` : ""})`;
      else if (r.status < 200 || r.status >= 300) card = `Page not read (HTTP ${r.status})`;
      else {
        const a = analyzeHtml(r.final, r.html, model.lists);
        card = a.status === "ok" ? "scored" : `Page empty (${a.status}, ${r.bytes} bytes)`;
      }
      line = card;
    } catch (e) {
      line = `no answer (${e.message})`;
    }
    const key = line.replace(/\(.*$/, "").trim();
    tally[key] = (tally[key] ?? 0) + 1;
    console.log(`LIVE ${url}\n  ${line}`);
    await new Promise((r) => setTimeout(r, 7000));
  }
  console.log("\nLIVE SUMMARY n=" + urls.length, JSON.stringify(tally));
}

const rows = [];
for (const url of urls) {
  const honest = describe(await fetchPage(url));
  const browser = describe(await fetchPage(url, { requestFn: browserRequest }));
  rows.push({ url, honest, browser });
  const f = (d) => (d.stage === "fetch" ? `NOFETCH ${d.why}` : `${d.status} http=${d.http} bytes=${d.bytes} scripts=${d.scripts} visible=${d.visible} title="${d.title.slice(0, 30)}"`);
  console.log(`${url}\n  honest : ${f(honest)}\n  browser: ${f(browser)}`);
}
const tally = (key) => {
  const t = {};
  for (const r of rows) {
    const d = r[key];
    const k = d.stage === "fetch" ? `fetch:${d.why}` : d.status;
    t[k] = (t[k] ?? 0) + 1;
  }
  return t;
};
console.log("\nSUMMARY n=" + rows.length);
console.log("honest UA :", JSON.stringify(tally("honest")));
console.log("browser UA:", JSON.stringify(tally("browser")));
