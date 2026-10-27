// Verdicts for addresses on shared hosting, before and after the shared-host cap in
// extension/src/combine.js: the shipped address layers (bundled allowlist, tier A model) through
// the extension's own combiner, with `shared` off (old behaviour) and as listed (needs
// `node extension/build.mjs` first). No page, backend or blocklist.
//   node js/bench/shared_hosts.mjs URLS.txt [ALLOWLIST.json]
//   -> JSON array of {url, shared, allowlisted, prob, before, after} on stdout.

import { readFileSync } from "node:fs";

const { ListSet } = await import("../../extension/dist/lists.js").catch(() => {
  throw new Error("extension/dist is missing: run node extension/build.mjs first");
});
const { combine } = await import("../../extension/dist/combine.js");
import { loadHybrid, scoreUrl } from "../src/hybrid.js";

const root = new URL("../../", import.meta.url);
const read = (path) => JSON.parse(readFileSync(new URL(path, root), "utf8"));
const [urlsFile, allowFile = "extension/data/allowlist.json"] = process.argv.slice(2);
if (!urlsFile) throw new Error("usage: shared_hosts.mjs URLS.txt [ALLOWLIST.json]");

const model = loadHybrid(read("js/data/tier_a_hybrid.json"), read("js/data/psl_icann.json"));
const lists = new ListSet(
  { allowlist: JSON.parse(readFileSync(allowFile, "utf8")) },
  { platforms: model.lists.platforms, psl: model.lists.psl },
);
const urls = readFileSync(urlsFile, "utf8").split("\n").map((u) => u.trim()).filter(Boolean);

const name = ["safe", "suspicious", "dangerous"];
const rows = [];
for (const url of urls) {
  const listed = await lists.check(url);
  const s = scoreUrl(model, url);
  const layers = { trusted: false, allow: listed.allow, shortener: listed.shortener, blocked: listed.blocked, model: s };
  rows.push({
    url,
    shared: listed.shared,
    allowlisted: Boolean(listed.allow),
    prob: s.prob,
    before: name[combine({ ...layers, shared: false }).verdict],
    after: name[combine({ ...layers, shared: listed.shared }).verdict],
  });
}
console.log(JSON.stringify(rows));
