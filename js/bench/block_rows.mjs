// Full blocks ("dangerous") the combiner gives to rows with stored page features, without a
// browser: the address model on the row's URL, the page model on its stored tier B features (as
// js/src/page.js scorePage), then combine() of the given assembled extension, so an older build
// can be compared with a newer one. Credential facts are read from the page features (password,
// one-time code, card, CVV and UPI PIN field counts), not a live DOM. No allowlist, blocklist,
// backend, look-alike or brand rules; no password-form rule (no form actions in the features).
//   node js/bench/block_rows.mjs DIST ROWS.jsonl
//     ROWS.jsonl: {url, label, source, b: {tier B feature: value | null}} per line
// -> JSON {n, rows: [{label, source, address, page, asks, verdict}]} on stdout.

import { createReadStream, readFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";

const [distArg, rowsFile] = process.argv.slice(2);
if (!distArg || !rowsFile) throw new Error("usage: block_rows.mjs DIST ROWS.jsonl");
const dist = pathToFileURL(`${distArg.replace(/\/$/, "")}/`);
const mod = (p) => import(new URL(p, dist).href);
const read = (p) => JSON.parse(readFileSync(new URL(p, dist), "utf8"));

const { featureValues, loadHybrid } = await mod("lib/hybrid.js");
const { loadPage } = await mod("lib/page.js");
const { DANGEROUS, SAFE, SUSPICIOUS, interp, rawScore } = await mod("lib/model.js");
const { combine } = await mod("combine.js");

const address = loadHybrid(read("data/tier_a_hybrid.json"), read("data/psl_icann.json"));
const page = loadPage(read("data/tier_b_page.json"));
const calibrated = (p, iso) => interp(p, iso.x, iso.y) + page.tie * p;
// tier B counts of the fields the content script treats as a credential request
const ASK_COUNTS = ["password", "otp", "card", "cvv", "upi_pin"].map((k) => `n_${k}_fields`);
const level = (p, t) => (p >= t.dangerous ? DANGEROUS : p >= t.suspicious ? SUSPICIOUS : SAFE);

const rows = [];
for await (const line of createInterface({ input: createReadStream(rowsFile), crlfDelay: Infinity })) {
  if (!line.trim()) continue;
  const { url, label, source, b } = JSON.parse(line);
  const aValues = featureValues(address, url);
  const probAddress = 1 / (1 + Math.exp(-rawScore(address, aValues)));
  const byName = Object.fromEntries(address.names.map((n, i) => [n, aValues[i]]));
  const hasHtml = Object.values(b).some((v) => v !== null);
  const values = page.names.map((n) => (n in b ? (b[n] ?? NaN) : byName[n]));
  const blended = hasHtml ? calibrated(1 / (1 + Math.exp(-rawScore(page, values))), page.isoPage) : calibrated(probAddress, page.isoAddress);
  // scorePage's verdict ("agree" rule)
  let pageVerdict = SAFE;
  if (probAddress >= address.thresholds.dangerous || blended >= page.thresholds.dangerous) pageVerdict = DANGEROUS;
  else if (blended >= page.thresholds.suspicious && (!hasHtml || probAddress >= address.thresholds.suspicious)) pageVerdict = SUSPICIOUS;
  const asks = ASK_COUNTS.some((k) => (b[k] ?? 0) > 0);
  const layers = { trusted: false, allow: false, shortener: false, blocked: null, unscored: false, domain: null, backendFailed: false };
  layers.model = { verdict: level(probAddress, address.thresholds), prob: probAddress, reasons: [] };
  const facts = { hasPassword: (b.n_password_fields ?? 0) > 0, credFormCrossDomain: false, credFormInsecure: false, asksCredentials: asks };
  const pageModel = { hasHtml, short: false, blended, verdict: pageVerdict, reasons: [], pageDangerous: hasHtml && blended >= page.thresholds.dangerous };
  const r = combine(layers, facts, pageModel);
  rows.push({ label, source, address: layers.model.verdict, page: pageModel.pageDangerous, asks, verdict: r.verdict });
}
console.log(JSON.stringify({ n: rows.length, rows }));
