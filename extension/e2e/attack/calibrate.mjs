// Chooses the test addresses of the attack harness from the shipped model, so the harness
// recalibrates itself after every retrain. A host is "suspicious" when the address model's score
// for every path the cases use lies between its suspicious and dangerous cut-offs, "dangerous" when
// every score is at or above the dangerous cut-off, "safe" when every score is below the suspicious
// cut-off. Fails loudly when no candidate falls in a band. The candidate names are only raw
// material for the search; the model decides.
import { readFileSync } from "node:fs";

const WORDS = ["evil", "secure", "login", "verify", "account", "update", "signin", "bank", "wallet", "support", "docs", "portal"];
const TLDS = ["com", "info", "xyz", "top", "net", "online", "org", "site", "shop", "club"];
const SAFE_WORDS = ["localnews-daily", "bakery-hours", "garden-notes", "city-library", "weather-today", "recipe-box"];
const PORT = 8123;

export function candidates() {
  const out = { mid: [], high: [], safe: [] };
  for (const w of WORDS) for (const t of TLDS) {
    out.mid.push(`${w}-blocked.${t}`);
    out.high.push(`${w}-paypal-login.${t}`, `${w}-verify.${t}`);
  }
  for (const w of SAFE_WORDS) for (const t of ["com", "org", "net"]) out.safe.push(`${w}.${t}`);
  return out;
}

// paths each role is used with in harness.mjs
export const PATHS = {
  mid: ["/", "/a", "/app", "/login"],
  high: ["/", "/home", "/app", "/verify-account"],
  safe: ["/", "/articles/today"],
};

// edge: the address model alone says dangerous but the page model, reading an ordinary content page
// (`html`), does not (the combiner then shows a banner, not the warning page; combine.js `addressOnly`)
export async function calibrate(dist, html, { need = { mid: 2, high: 1, safe: 2, edge: 1 } } = {}) {
  const { loadHybrid, scoreUrl } = await import(`${dist}/lib/hybrid.js`);
  const { loadPage, scorePage } = await import(`${dist}/lib/page.js`);
  const j = (p) => JSON.parse(readFileSync(`${dist}/${p}`, "utf8"));
  const model = loadHybrid(j("data/tier_a_hybrid.json"), j("data/psl_icann.json"));
  const pageModel = loadPage(j("data/tier_b_page.json"));
  const { suspicious: lo, dangerous: hi } = model.thresholds;
  const score = (host, path) => scoreUrl(model, `http://${host}:${PORT}${path}`).prob;
  const fits = {
    mid: (p) => p >= lo && p < hi,
    high: (p) => p >= hi,
    safe: (p) => p < lo,
  };
  const edgeFits = (host) => {
    const url = `http://${host}:${PORT}/app`;
    const a = scoreUrl(model, url).prob;
    if (a < hi) return null;
    const p = scorePage(model, pageModel, url, html);
    return p.hasHtml && !p.pageDangerous ? [a] : null;
  };
  const picked = {};
  const cands = candidates();
  cands.edge = [...cands.mid, ...cands.high];
  for (const role of ["mid", "high", "safe", "edge"]) {
    const found = [];
    for (const host of cands[role]) {
      const ps = role === "edge" ? edgeFits(host) : PATHS[role].map((p) => score(host, p));
      if (ps && (role === "edge" || ps.every(fits[role]))) found.push({ host, scores: ps.map((x) => +x.toFixed(4)) });
      if (found.length >= need[role]) break;
    }
    if (found.length < need[role]) {
      throw new Error(`calibration failed: only ${found.length} of ${need[role]} ${role} test addresses found among ${cands[role].length} candidates (cut-offs ${lo}, ${hi}); extend the candidate names in calibrate.mjs`);
    }
    picked[role] = found;
  }
  return { thresholds: { suspicious: lo, dangerous: hi }, picked };
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  console.log(JSON.stringify(await calibrate(process.argv[2], readFileSync(new URL("./pages/news.html", import.meta.url), "utf8")), null, 1));
}
