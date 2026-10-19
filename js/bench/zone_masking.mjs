// Address-model scores of URLs inside learned open-hosting zones, read as they are and with the zone
// masked like a platform-list domain (the zone part of the host replaced by the neutral platform
// token, which then counts as a platform). Used by experiments/zone_masking.py; needs
// `node extension/build.mjs` first.
//   node js/bench/zone_masking.mjs CASES.json  (CASES: [{set, url}])  -> JSON on stdout.

import { readFileSync } from "node:fs";

const { ListSet } = await import("../../extension/dist/lists.js").catch(() => {
  throw new Error("extension/dist is missing: run node extension/build.mjs first");
});
import { loadHybrid, scoreUrl } from "../src/hybrid.js";
import { PLATFORM_TOKEN } from "../src/urlparts.js";

const root = new URL("../../", import.meta.url);
const read = (path) => JSON.parse(readFileSync(new URL(path, root), "utf8"));
const model = loadHybrid(read("js/data/tier_a_hybrid.json"), read("js/data/psl_icann.json"));
const masked = { ...model, lists: { ...model.lists, platforms: new Set([...model.lists.platforms, PLATFORM_TOKEN]) } };
const lists = new ListSet(
  { allowlist: read("extension/data/allowlist.json") },
  { platforms: model.lists.platforms, psl: model.lists.psl },
);

function zoneOf(host, zones) {
  for (let h = host; h; h = h.includes(".") ? h.slice(h.indexOf(".") + 1) : "") if (zones.has(h)) return h;
  return null;
}

const rows = [];
for (const c of JSON.parse(readFileSync(process.argv[2], "utf8"))) {
  const { domain, shared } = await lists.check(c.url);
  const u = new URL(c.url);
  const host = u.hostname.toLowerCase().replace(/^www\./, "");
  const zone = shared && !model.lists.platforms.has(domain) ? zoneOf(host, lists.openHosting) : null;
  if (!zone) continue;
  u.hostname = host.slice(0, host.length - zone.length) + PLATFORM_TOKEN;
  rows.push({
    ...c, zone, below_zone: host !== zone,
    p_plain: scoreUrl(model, c.url).prob, p_masked: scoreUrl(masked, u.href).prob,
  });
}
console.log(JSON.stringify({ thresholds: model.thresholds, rows }));
