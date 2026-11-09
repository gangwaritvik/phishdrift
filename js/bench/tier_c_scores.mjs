// Scores every captured host of a tier C data folder with the shipped bundle (js/data/tier_c.json),
// the same code the hosted /api/domain-check runs. Host and domain records are picked as
// features/build_c.py does (latest host record; latest domain record with RDAP data, else latest).
//   node js/bench/tier_c_scores.mjs DOMAIN_INFO_DIR OUT.tsv
import { readFileSync, readdirSync, writeFileSync } from "node:fs";

import { NAMES_C, computeC, loadTierC, scoreFeatures } from "../src/tier_c.js";

const root = new URL("../../", import.meta.url);
const read = (path) => JSON.parse(readFileSync(new URL(path, root), "utf8"));
const [dir, out] = process.argv.slice(2);
if (!dir || !out) throw new Error("usage: tier_c_scores.mjs DOMAIN_INFO_DIR OUT.tsv");

const model = loadTierC(read("js/data/tier_c.json"), read("js/data/psl_icann.json"));
const hosts = new Map();
const domains = new Map();
for (const f of readdirSync(dir).filter((n) => n.endsWith(".jsonl")).sort()) {
  for (const line of readFileSync(`${dir}/${f}`, "utf8").split("\n")) {
    if (!line.trim()) continue;
    let rec;
    try {
      rec = JSON.parse(line);
    } catch {
      continue;
    }
    if (rec.kind === "host" && rec.host) {
      const old = hosts.get(rec.host.toLowerCase());
      if (!old || String(rec.captured_at || "") >= String(old.captured_at || "")) hosts.set(rec.host.toLowerCase(), rec);
    } else if (rec.kind === "domain" && rec.domain) {
      const key = rec.domain.toLowerCase();
      if (!domains.has(key)) domains.set(key, []);
      domains.get(key).push(rec);
    }
  }
}
const pick = (recs) => {
  if (!recs) return null;
  const sorted = [...recs].sort((a, b) => String(a.captured_at || "").localeCompare(String(b.captured_at || "")));
  const good = sorted.filter((r) => r.rdap);
  return good.length ? good[good.length - 1] : sorted[sorted.length - 1];
};

const cols = ["host", "domain", "label", "source", "first_seen", "captured_at", "prob", "calibrated", "verdict", "rdap_error", "rdap_found", "domain_age_days", "resolves", "tls_verified"];
const lines = [cols.join("\t")];
for (const [host, rec] of hosts) {
  const dom = pick(domains.get(String(rec.domain || "").toLowerCase()));
  const features = computeC(rec, dom, model.lists);
  const s = scoreFeatures(model, features);
  lines.push(
    [host, rec.domain, rec.label, rec.source ?? "", rec.first_seen ?? "", rec.captured_at ?? "", s.prob, s.calibrated, s.verdict, dom?.rdap_error ?? "", features.rdap_found, features.domain_age_days, rec.dns?.resolves ?? "", rec.tls?.verified ?? ""].join("\t"),
  );
}
writeFileSync(out, lines.join("\n") + "\n");
console.log(`${hosts.size} hosts scored, ${NAMES_C.length} features`);
