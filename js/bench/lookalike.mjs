// What the offline look-alike check adds, per URL, without a browser: the verdict of the shipped
// address layers (bundled allowlist, tier A model) before and after the look-alike rule is applied
// through the extension's own combiner (needs `node extension/build.mjs` first).
//   node js/bench/lookalike.mjs URLS.txt [ALLOWLIST.json]
//   -> JSON array of {url, allowlisted, before, after, rule, brand} on stdout.

import { readFileSync } from "node:fs";

const { ListSet } = await import("../../extension/dist/lists.js").catch(() => {
  throw new Error("extension/dist is missing: run node extension/build.mjs first");
});
const { combine } = await import("../../extension/dist/combine.js");
import { loadHybrid, scoreUrl } from "../src/hybrid.js";
import { loadLookalike, lookalikeSignal } from "../src/lookalike.js";

const root = new URL("../../", import.meta.url);
const read = (path) => JSON.parse(readFileSync(new URL(path, root), "utf8"));
const [urlsFile, allowFile = "extension/data/allowlist.json"] = process.argv.slice(2);
if (!urlsFile) throw new Error("usage: lookalike.mjs URLS.txt [ALLOWLIST.json]");

const psl = read("js/data/psl_icann.json");
const model = loadHybrid(read("js/data/tier_a_hybrid.json"), psl);
const rules = loadLookalike(read("js/data/lookalike.json"), model.lists.psl, model.lists.platforms);
const lists = new ListSet(
  { allowlist: JSON.parse(readFileSync(allowFile, "utf8")) },
  { platforms: model.lists.platforms, psl: model.lists.psl },
);
const urls = readFileSync(urlsFile, "utf8").split("\n").map((u) => u.trim()).filter(Boolean);

const name = ["safe", "suspicious", "dangerous"];
const rows = [];
for (const url of urls) {
  const { allow, shortener, blocked } = await lists.check(url);
  const scored = allow || shortener ? null : scoreUrl(model, url);
  const layers = { allow, shortener, blocked, model: scored && { ...scored, reasons: scored.reasons ?? [] }, unscored: false };
  const before = combine(layers).verdict;
  const hit = lookalikeSignal(rules, url); // reported for every URL; applied only where the allowlist does not decide
  const after = combine({ ...layers, lookalike: allow || shortener ? null : hit }).verdict;
  rows.push({ url, allowlisted: Boolean(allow), before: name[before], after: name[after], rule: hit?.rule ?? null, brand: hit?.brand ?? null });
}
console.log(JSON.stringify(rows));
