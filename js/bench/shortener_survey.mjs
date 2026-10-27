// Follows a sample of real short links per shortener with the hosted function's own code and prints
// one line per link and a summary per shortener. For a machine with open internet (the GitHub
// workflow short-link-probe.yml). Only shortener addresses are requested; destinations are never opened.
//   node js/bench/shortener_survey.mjs FEED.txt [per_host=3] [max_hosts=30] [extra URL...]
// FEED.txt: one URL per line (e.g. Phishing.Database phishing-links-ACTIVE.txt). Shorteners are taken
// from js/data/lists.json; the hosts with the most links in the feed are sampled (seeded, no typing of hosts).
import { readFileSync } from "node:fs";
import { handle, isShortener, hostOf } from "../../netlify/functions/expand.mjs";
import { makeTrie, registrable } from "../src/llm_check.js";
import pslRules from "../data/psl_icann.json" with { type: "json" };

const [feedFile, perHost = "3", maxHosts = "30", ...extra] = process.argv.slice(2);
const psl = makeTrie(pslRules);
const byHost = new Map();
for (const line of readFileSync(feedFile, "utf8").split("\n")) {
  const url = line.trim();
  if (!/^https?:\/\//i.test(url) || !isShortener(url)) continue;
  const h = registrable(hostOf(url), psl);
  if (!byHost.has(h)) byHost.set(h, []);
  byHost.get(h).push(url);
}
let seed = 1;
const rnd = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648;
const picks = [...byHost.entries()].sort((a, b) => b[1].length - a[1].length).slice(0, Number(maxHosts))
  .map(([h, urls]) => [h, urls.length, urls.sort(() => rnd() - 0.5).slice(0, Number(perHost))]);
for (const u of extra) picks.push(["(extra)", 0, [u]]);

const summary = new Map();
for (const [host, total, urls] of picks) {
  for (const url of urls) {
    const res = await handle(new Request("https://probe/api/expand", { method: "POST", body: JSON.stringify({ url }) }));
    const b = await res.json();
    const hops = (b.hops ?? []).map((x) => `${x.method} ${x.status}`).join(", ");
    console.log(`${host}\t${b.complete ? "FOLLOWED" : "stopped:" + b.error}\t${url}\t-> ${b.final ?? "-"}\t[${hops}]`);
    const s = summary.get(host) ?? { total, tried: 0, followed: 0 };
    s.tried++; if (b.complete) s.followed++;
    summary.set(host, s);
  }
}
console.log("\nshortener\tlinks in feed\ttried\tfollowed");
let t = 0, f = 0;
for (const [h, s] of summary) { console.log(`${h}\t${s.total}\t${s.tried}\t${s.followed}`); t += s.tried; f += s.followed; }
console.log(`TOTAL tried ${t} followed ${f}`);
