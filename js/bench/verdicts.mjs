// Verdicts the extension gives to a list of URLs, without a browser: the bundled allowlist, then
// the tier A model (suspicious and dangerous thresholds). Mirrors the order in
// extension/src/background.js (needs `node extension/build.mjs` first); the blocklist, backend and page layers are not applied.
//   node js/bench/verdicts.mjs URLS.txt [ALLOWLIST.json]  -> JSON array of {url, allowlisted, model, shipped} on stdout.

import { readFileSync } from "node:fs";

// extension/src imports ./lib/psl.js, which only exists in the assembled extension/dist.
const { ListSet } = await import("../../extension/dist/lists.js").catch(() => {
  throw new Error("extension/dist is missing: run node extension/build.mjs first");
});
import { loadHybrid, scoreUrl } from "../src/hybrid.js";

const root = new URL("../../", import.meta.url);
const read = (path) => JSON.parse(readFileSync(new URL(path, root), "utf8"));
const [urlsFile, allowFile = "extension/data/allowlist.json"] = process.argv.slice(2);
if (!urlsFile) throw new Error("usage: verdicts.mjs URLS.txt [ALLOWLIST.json]");

const model = loadHybrid(read("js/data/tier_a_hybrid.json"), read("js/data/psl_icann.json"));
const lists = new ListSet(
  { allowlist: JSON.parse(readFileSync(allowFile, "utf8")) },
  { platforms: model.lists.platforms, psl: model.lists.psl },
);
const urls = readFileSync(urlsFile, "utf8").split("\n").map((u) => u.trim()).filter(Boolean);

const name = ["safe", "suspicious", "dangerous"];
const rows = [];
for (const url of urls) {
  const verdict = scoreUrl(model, url).verdict;
  const { allow } = await lists.check(url);
  rows.push({ url, allowlisted: Boolean(allow), model: name[verdict], shipped: name[allow ? 0 : verdict] });
}
console.log(JSON.stringify(rows));
