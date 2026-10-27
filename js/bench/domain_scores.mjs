// The shipped address model's score for a bare domain, as the tier C experiment's address baseline.
//   node js/bench/domain_scores.mjs DOMAINS.txt > scores.csv     (one domain per line)
// Scores `https://<domain>/` with js/data/tier_a_hybrid.json; output is `domain,score` (probability).

import { createReadStream, readFileSync } from "node:fs";
import { createInterface } from "node:readline";

import { loadHybrid, scoreUrl } from "../src/hybrid.js";

const read = (p) => JSON.parse(readFileSync(new URL(p, import.meta.url), "utf8"));
const model = loadHybrid(read("../data/tier_a_hybrid.json"), read("../data/psl_icann.json"));
const file = process.argv[2];
if (!file) throw new Error("usage: domain_scores.mjs DOMAINS.txt");

const out = ["domain,score"];
for await (const line of createInterface({ input: createReadStream(file), crlfDelay: Infinity })) {
  const domain = line.trim().toLowerCase();
  if (domain) out.push(`${domain},${scoreUrl(model, `https://${domain}/`).prob}`);
}
console.log(out.join("\n"));
