// Fetches real pages with the hosted function's own code (netlify/functions/fetch-page.mjs) and reads them
// with the page model, for a machine with open internet (the GitHub workflow page-fetch-probe.yml).
// Use legitimate addresses only: the fetch is a plain GET and the pages are never run.
//   node js/bench/fetch_page_probe.mjs URL...
import { readFileSync } from "node:fs";

import { handle } from "../../netlify/functions/fetch-page.mjs";
import { loadHybrid } from "../src/hybrid.js";
import { loadPage, scorePage } from "../src/page.js";

const read = (f) => JSON.parse(readFileSync(new URL(`../data/${f}`, import.meta.url), "utf8"));
const model = loadHybrid(read("tier_a_hybrid.json"), read("psl_icann.json"));
const page = loadPage(read("tier_b_page.json"));

for (const url of process.argv.slice(2)) {
  const t = Date.now();
  const res = await handle(new Request("https://probe/api/fetch-page", { method: "POST", body: JSON.stringify({ url }) }));
  const r = await res.json();
  const ms = Date.now() - t;
  if (!r.ok) {
    console.log(`${url}\n  not fetched: ${r.error ?? res.status}${r.status ? ` (HTTP ${r.status})` : ""} final=${r.final ?? "-"} ${ms} ms`);
    continue;
  }
  const s = scorePage(model, page, r.final, r.html);
  console.log(
    `${url}\n  HTTP ${r.status} final=${r.final} redirects=${r.redirects.length} bytes=${r.bytes}${r.truncated ? " (cut)" : ""} ${ms} ms\n` +
      `  page model: ${s.hasHtml ? `read, page ${s.probPage.toFixed(3)} blended ${s.blended.toFixed(3)} verdict=${["safe", "suspicious", "dangerous"][s.verdict]}` : "could not read (empty or too little text)"}`,
  );
}
