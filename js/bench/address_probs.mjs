// The address layer's score for a list of URLs: bundled allowlist, then the address model.
//   node js/bench/address_probs.mjs DIST URLS.jsonl > OUT.jsonl
//     URLS.jsonl: {url[, set]} per line -> {url, set, allow, shortener, prob, verdict, unreadable} per line
//     (`unreadable`: the page path's verdict if the page model cannot read the page, e.g. a picture)
// Used to choose where the picture-only rule starts (experiments/picture_only.py).

import { createReadStream, readFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";

const [distArg, urlsFile] = process.argv.slice(2);
if (!distArg || !urlsFile) throw new Error("usage: address_probs.mjs DIST URLS.jsonl");
const dist = pathToFileURL(`${distArg.replace(/\/$/, "")}/`);
const mod = (p) => import(new URL(p, dist).href);
const read = (p) => JSON.parse(readFileSync(new URL(p, dist), "utf8"));

const { loadHybrid } = await mod("lib/hybrid.js");
const { ListSet } = await mod("lists.js");
const { scoreAddress } = await mod("address.js");

const { loadPage } = await mod("lib/page.js");
const { interp } = await mod("lib/model.js");

const model = loadHybrid(read("data/tier_a_hybrid.json"), read("data/psl_icann.json"));
const page = loadPage(read("data/tier_b_page.json"));
// The verdict the page path gives a page the page model cannot read (as in lib/page.js scorePage):
// the calibrated address score against the blend's thresholds.
const unreadable = (prob) => {
  const blended = interp(prob, page.isoAddress.x, page.isoAddress.y) + page.tie * prob;
  if (prob >= model.thresholds.dangerous || blended >= page.thresholds.dangerous) return 2;
  return blended >= page.thresholds.suspicious ? 1 : 0;
};
const lists = new ListSet(
  { allowlist: read("data/allowlist.json") },
  { platforms: model.lists.platforms, psl: model.lists.psl, shorteners: model.lists.shorteners },
);

const out = [];
for await (const line of createInterface({ input: createReadStream(urlsFile), crlfDelay: Infinity })) {
  if (!line.trim()) continue;
  const { url, set = null } = JSON.parse(line);
  const listed = await lists.check(url);
  const scored = !listed.allow && !listed.shortener && !listed.blocked ? scoreAddress(model, url) : null;
  out.push(JSON.stringify({ url, set, allow: Boolean(listed.allow), shortener: Boolean(listed.shortener), prob: scored?.prob ?? null, verdict: scored?.verdict ?? 0, unreadable: scored?.prob == null ? 0 : unreadable(scored.prob) }));
}
console.log(out.join("\n"));
