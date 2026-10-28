// Latency of the in-browser tier A model, measured in Node (V8, the engine Chrome uses).
// node js/bench/latency.mjs [--runs N]  -> one JSON object on stdout.
// Reads the bundle, the PSL and the URLs of tests/fixtures/hybrid_parity.json.
// --bundle FILE --parity FILE: measure another bundle (an experiment's) and its own parity file;
// the output then also says how far JavaScript's probabilities are from Python's for that bundle.

import { readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { performance } from "node:perf_hooks";

import { loadHybrid, scoreUrl } from "../src/hybrid.js";

const root = new URL("../../", import.meta.url);
const read = (path) => JSON.parse(readFileSync(new URL(path, root), "utf8"));
const runs = Number(process.argv[process.argv.indexOf("--runs") + 1]) || 5;

const arg = (name) => {
  const i = process.argv.indexOf(name);
  return i > 0 ? process.argv[i + 1] : null;
};
const bundlePath = arg("--bundle")
  ? new URL(`file://${resolve(arg("--bundle"))}`)
  : new URL("js/data/tier_a_hybrid.json", root);
const parityPath = arg("--parity")
  ? new URL(`file://${resolve(arg("--parity"))}`)
  : new URL("tests/fixtures/hybrid_parity.json", root);
const t0 = performance.now();
const bundle = JSON.parse(readFileSync(bundlePath, "utf8"));
const psl = read("js/data/psl_icann.json");
const parseMs = performance.now() - t0;
const t1 = performance.now();
const model = loadHybrid(bundle, psl);
const loadMs = performance.now() - t1;

const parity = JSON.parse(readFileSync(parityPath, "utf8"));
const urls = parity.cases.map((c) => c.url);
let maxDiff = 0;
let reasonMismatch = 0;
for (const c of parity.cases) {
  const got = scoreUrl(model, c.url, { withReasons: true });
  maxDiff = Math.max(maxDiff, Math.abs(got.prob - c.prob));
  const a = JSON.stringify(got.reasons.map((r) => r.text));
  if (a !== JSON.stringify(c.reasons.map((r) => r.text))) reasonMismatch++;
}

function timePerUrl(opts, warm) {
  for (let i = 0; i < warm; i++) scoreUrl(model, urls[i % urls.length], opts);
  const per = [];
  for (const url of urls) {
    const s = performance.now();
    scoreUrl(model, url, opts);
    per.push(performance.now() - s);
  }
  return per;
}

const quantile = (xs, q) => {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor(q * s.length))];
};
const summary = (xs) => ({
  median_ms: quantile(xs, 0.5),
  p95_ms: quantile(xs, 0.95),
  max_ms: Math.max(...xs),
});

const score = [];
const reasons = [];
for (let r = 0; r < runs; r++) {
  score.push(...timePerUrl({}, r === 0 ? 50 : 0));
  reasons.push(...timePerUrl({ withReasons: true }, r === 0 ? 10 : 0));
}
console.log(
  JSON.stringify({
    node: process.version,
    urls: urls.length,
    runs,
    bundle_mb: statSync(bundlePath).size / 1e6,
    parity_cases: urls.length,
    parity_max_abs_diff: maxDiff,
    parity_reason_mismatches: reasonMismatch,
    json_parse_ms: parseMs,
    model_build_ms: loadMs,
    score: summary(score),
    score_with_reasons: summary(reasons),
  }),
);
