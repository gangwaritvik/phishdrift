// Combined three-tier measurement on live addresses: for every address the tier A address model, the tier B page
// model (the page fetched live with the hosted function's own code) and the tier C domain check (live RDAP, DNS
// over HTTPS, TLS with the hosted function's own code) are run, then the extension's own combiner
// (extension/src/combine.js, loaded through demo/check.js `loadChecker`) turns them into a verdict. The same
// addresses are also combined with fewer tiers (A, A+B, A+C, A+B+C), so every difference is on identical addresses.
//
//   node js/bench/combined_live.mjs --out DIR [--phish N] [--legit N] [--seed S] [--stub]
//
// Needs `node extension/build.mjs` first and open internet (the GitHub workflow combined-live.yml).
// Phishing addresses come from the live feeds (OpenPhish, Phishing.Database "NEW today"), one per registrable
// domain; legitimate addresses are the naturally browsed pages of configs/eval/ood_urls.csv, one per site.
// Pages are fetched with one plain GET (nothing is run, no cookies); phishing HTML is never written to disk.
// Not applied: blocklist (the feeds supply the test addresses), backend domain rules, user trust, AI check,
// frames, picture-only facts (they need a live DOM).
// Writes DIR/rows.csv; the analysis is experiments/combined_live.py.

import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";

import { loadChecker } from "../../demo/check.js";
import { pageFlags } from "../../extension/dist/pagefacts.js";
import { handle as domainCheck } from "../../netlify/functions/domain-check.mjs";
import { fetchPage } from "../../netlify/functions/fetch-page.mjs";

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith("--") ? [...acc, [a.slice(2), all[i + 1]?.startsWith("--") || all[i + 1] === undefined ? "1" : all[i + 1]]] : acc), []),
);
const OUT = args.out ?? "out/combined_live";
const N_PHISH = Number(args.phish ?? 700);
const N_LEGIT = Number(args.legit ?? 600);
const SEED = Number(args.seed ?? 1);
const STUB = Boolean(args.stub);
const WORKERS = Number(args.workers ?? 12);
const PER_URL_MS = 40_000;

const root = new URL("../../", import.meta.url);
const read = async (path) => {
  const file = new URL(path, root);
  return existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : null;
};

// ---- sampling ---------------------------------------------------------------------------------------------
function rng(seed) {
  let s = seed >>> 0;
  return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32);
}
function shuffle(list, rand) {
  const a = [...list];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}
async function feed(url, ms = 30_000) {
  const res = await fetch(url, { signal: AbortSignal.timeout(ms), headers: { "User-Agent": "PhishDrift-research (academic project)" } });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return (await res.text()).split(/\r?\n/).map((l) => l.trim()).filter((l) => /^https?:\/\//i.test(l));
}

async function sample(c) {
  const rand = rng(SEED);
  const domainOf = async (url) => (await c.lists.check(url)).domain;
  const pick = async (items, n) => {
    // one address per registrable domain, in a seeded random order
    const seen = new Set();
    const out = [];
    for (const it of shuffle(items, rand)) {
      const d = await domainOf(it.url);
      if (!d || seen.has(d)) continue;
      seen.add(d);
      out.push({ ...it, domain: d });
      if (out.length >= n) break;
    }
    return out;
  };
  if (STUB) {
    const stub = [
      { url: "https://secure-login.paypa1-verify.example.top/signin", label: 1, source: "stub" },
      { url: "https://en.wikipedia.org/wiki/Phishing", label: 0, source: "stub" },
      { url: "https://some-new-bank-login.example.xyz/", label: 1, source: "stub" },
      { url: "https://www.python.org/about/", label: 0, source: "stub" },
    ];
    return stub.map((s) => ({ ...s, domain: s.url.split("/")[2] }));
  }
  // OpenPhish is left out of this run: its terms ask for one poll per 12 h and the capture workflow already polls it.
  const gh = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master";
  const feeds = [
    ["phishing_database_new", () => feed(`${gh}/phishing-links-NEW-today.txt`)],
    ["phishunt", () => feed("https://phishunt.io/feed.txt")],
    ["phishstats", async () => {
      const urls = [];
      for (let p = 0; p < 5; p++) {
        const res = await fetch(`https://api.phishstats.info/api/phishing?_sort=-id&_size=100&_p=${p}`, { signal: AbortSignal.timeout(30_000) });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        urls.push(...(await res.json()).map((r) => r.url).filter((u) => /^https?:\/\//i.test(u)));
      }
      return urls;
    }],
    ["phishtank", async () => {
      const res = await fetch("http://data.phishtank.com/data/online-valid.csv", { signal: AbortSignal.timeout(120_000), headers: { "User-Agent": "phishdrift-research" } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return (await res.text()).split(/\r?\n/).map((l) => /^\d+,"?(https?:\/\/.*?)"?,https?:\/\/(www\.)?phishtank/.exec(l)?.[1]).filter(Boolean);
    }],
    // older entries (active, but listing time unknown): used only to top up
    ["phishing_database_active", () => feed(`${gh}/phishing-links-ACTIVE.txt`, 120_000)],
  ];
  const perFeed = [];
  for (const [source, get] of feeds) {
    try {
      const urls = await get();
      console.error(`feed ${source}: ${urls.length} addresses`);
      perFeed.push({ source, urls });
    } catch (e) {
      console.error(`feed ${source} failed: ${e.message}`);
    }
  }
  // fresh feeds first (up to a quarter of the target each), then the older list fills the rest; one per domain overall
  let phish = [];
  const taken = new Set();
  const fillFrom = async (f, n) => {
    const got = await pick(f.urls.map((u) => ({ url: u, label: 1, source: f.source })), n + taken.size * 0 + 400);
    let k = 0;
    for (const it of got) {
      if (taken.has(it.domain) || k >= n) continue;
      taken.add(it.domain);
      phish.push(it);
      k++;
    }
  };
  for (const f of perFeed.filter((x) => x.source !== "phishing_database_active")) await fillFrom(f, Math.ceil(N_PHISH / 3));
  const active = perFeed.find((x) => x.source === "phishing_database_active");
  if (active && phish.length < N_PHISH) await fillFrom(active, N_PHISH - phish.length);
  phish = phish.slice(0, N_PHISH);
  const csv = readFileSync(new URL("configs/eval/ood_urls.csv", root), "utf8").split(/\r?\n/).slice(1).filter(Boolean);
  const natural = csv.map((l) => l.split(",")).filter((p) => p[2] === "True").map((p) => ({ url: p[0], label: 0, source: "natural" }));
  const legit = await pick(natural, N_LEGIT);
  console.error(`sampled ${phish.length} phishing and ${legit.length} legitimate addresses`);
  return [...phish, ...legit];
}

// ---- the layers -------------------------------------------------------------------------------------------
const CREDENTIAL_INPUT = /\b(otp|one[-_ ]?time|passcode|cvv|cvc|csc|card[-_ ]?(number|no)|cc[-_ ]?(num|number)|upi[-_ ]?pin|atm[-_ ]?pin|pin[-_ ]?code)\b/i;
const CREDENTIAL_AUTOCOMPLETE = /\b(one-time-code|cc-number|cc-csc)\b/i;
const attr = (tag, name) => tag.match(new RegExp(`\\s${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, "i"))?.slice(2).find((v) => v !== undefined) ?? null;
// the content script's facts, read from the raw HTML with a tag scan (as js/bench/page_verdicts.mjs does)
function facts(html, base) {
  let passwordFields = 0;
  let credentialFields = 0;
  for (const [tag] of html.matchAll(/<input\b[^>]*>/gi)) {
    const type = (attr(tag, "type") || "text").toLowerCase();
    if (type === "password") passwordFields += 1;
    else if (!["hidden", "submit", "button"].includes(type)) {
      const text = ["name", "id", "placeholder", "aria-label"].map((a) => attr(tag, a) || "").join(" ");
      if (CREDENTIAL_AUTOCOMPLETE.test(attr(tag, "autocomplete") || "") || CREDENTIAL_INPUT.test(text)) credentialFields += 1;
    }
  }
  const forms = [];
  for (const [, open, body] of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    let action = null;
    try {
      action = new URL(attr(`<f ${open}>`, "action") || "", base).href;
    } catch {
      action = null;
    }
    forms.push({ hasPassword: /<input\b[^>]*type\s*=\s*["']?password/i.test(body), action });
  }
  return { passwordFields, credentialFields, forms };
}

const withTimeout = (p, ms) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), ms))]);
const NAMES = ["safe", "suspicious", "dangerous"];

async function tierCFor(c, domain) {
  if (STUB) return { checked: true, verdict: domain.includes("example") ? "dangerous" : "safe", prob: 0.9, reasons: [{ text: "stub reason" }] };
  const res = await domainCheck(new Request("https://probe/api/domain-check", { method: "POST", body: JSON.stringify({ domain }) }));
  return res.json();
}
async function pageFor(url) {
  if (STUB) {
    const html = url.includes("wikipedia") || url.includes("python") ? "<html><head><title>Docs</title></head><body>" + "<p>Some readable text about a topic.</p>".repeat(30) + "</body></html>" : "<html><head><title>Sign in</title></head><body><form action='https://evil.example/p'><input type='password' name='pw'><input name='user'></form><p>Verify your account now to keep access.</p></body></html>";
    return { ok: true, status: 200, final: url, redirects: [], bytes: html.length, html };
  }
  return fetchPage(url);
}

async function one(c, pageModelBundle, item) {
  const { url } = item;
  const row = { ...item };
  const listed = await c.lists.check(url);
  row.allow = Boolean(listed.allow);
  row.shared = Boolean(listed.shared);
  row.shortener = Boolean(listed.shortener);
  const model = c.address.scoreAddress(c.model, url);
  row.addr_prob = model?.prob ?? null;
  row.addr_verdict = model ? NAMES[model.verdict] : "none";

  // tier B: the page, fetched live, read by the page model at the address it ended on
  const t0 = Date.now();
  let got = null;
  try {
    got = await withTimeout(pageFor(url), PER_URL_MS);
  } catch (e) {
    got = { ok: false, error: String(e.message).slice(0, 60) };
  }
  row.fetch_ok = Boolean(got.ok && got.status >= 200 && got.status < 300);
  row.fetch_status = got.status ?? "";
  row.fetch_error = got.ok ? (row.fetch_ok ? "" : `http_${got.status}`) : (got.error ?? "failed");
  row.fetch_ms = Date.now() - t0;
  row.final = got.final ?? url;
  row.redirected_cross_domain = false;
  let flags = null;
  const pageScore = {};
  if (row.fetch_ok) {
    const f = facts(got.html, got.final);
    flags = pageFlags(f, got.final, c.model.lists.psl);
    row.asks_credentials = Boolean(flags.asksCredentials);
    row.bytes = got.bytes;
    const finalDomain = (await c.lists.check(got.final)).domain;
    row.redirected_cross_domain = Boolean(finalDomain && finalDomain !== listed.domain);
    for (const trusted of [false, true]) {
      const s = c.pageMod.scorePage(c.model, pageModelBundle, got.final, got.html, { withReasons: false, allowShort: !trusted && f.passwordFields > 0 });
      s.allowedPageWarning = trusted && s.hasHtml && s.blended >= pageModelBundle.thresholds.dangerous && f.passwordFields > 0;
      pageScore[trusted ? "trusted" : "plain"] = s;
    }
    const s = pageScore.plain;
    row.page_state = s.hasHtml ? "scored" : "unreadable";
    row.page_prob = s.hasHtml ? s.blended : "";
    row.page_prob_raw = s.hasHtml ? s.probPage : "";
    row.page_verdict = s.hasHtml ? NAMES[s.verdict] : "";
  } else {
    row.page_state = "unavailable";
  }

  // tier C: the domain check on the registrable domain of the address
  const tcJson = await withTimeout(tierCFor(c, listed.domain), PER_URL_MS).catch((e) => ({ error: String(e.message) }));
  const tcAnswer = c.domainMod.usableTierCAnswer(tcJson);
  row.c_state = tcAnswer ? "scored" : tcJson?.checked === false ? `not_checked:${tcJson.reason ?? "failed"}` : "unreachable";
  row.c_prob = tcAnswer ? tcJson.prob : "";
  row.c_verdict = tcAnswer ? tcJson.verdict : "";
  row.c_age_days = tcJson?.facts?.domain_age_days ?? "";
  row.c_resolves = tcJson?.facts?.resolves ?? "";

  // the combiner, per allowlist mode and tier set
  for (const mode of ["off", "on"]) {
    const allow = mode === "on" && listed.allow;
    const base = { trusted: false, domainName: listed.domain, shared: listed.shared, allow, shortener: listed.shortener, blocked: null, model: allow || listed.shortener ? null : model, unscored: false, local: false, domain: null, backendFailed: false };
    const trustedAddr = allow || listed.shortener;
    const pm = row.page_state === "scored" || row.page_state === "unreadable" ? pageScore[trustedAddr ? "trusted" : "plain"] : null;
    const addressVerdict = c.combine.combine(base, null, null).verdict;
    // as shipped: tier C is asked only about addresses the address layers call suspicious (background.js)
    const asked = addressVerdict === 1 && !allow && !listed.shortener;
    const withC = (gate) => (tcAnswer && (gate ? asked : true) ? { ...base, tierC: tcAnswer } : base);
    const v = (layers, withPage) => NAMES[c.combine.combine(layers, withPage ? flags : null, withPage ? pm : null).verdict];
    row[`v_A_${mode}`] = v(base, false);
    row[`v_AB_${mode}`] = v(base, true);
    row[`v_AC_${mode}`] = v(withC(true), false);
    row[`v_ABC_${mode}`] = v(withC(true), true);
    row[`v_ABC_all_${mode}`] = v(withC(false), true);
    row[`layer_ABC_${mode}`] = c.combine.combine(withC(true), flags, pm).layer;
  }
  return row;
}

// ---- run --------------------------------------------------------------------------------------------------
const c = await loadChecker({ base: new URL("extension/dist/", root), read });
const pageModelBundle = c.pageMod.loadPage(await read("js/data/tier_b_page.json"));
const items = await sample(c);
const rows = [];
let next = 0;
let done = 0;
async function worker() {
  for (;;) {
    const i = next++;
    if (i >= items.length) return;
    try {
      rows[i] = await withTimeout(one(c, pageModelBundle, items[i]), PER_URL_MS * 2);
    } catch (e) {
      rows[i] = { ...items[i], error: String(e.message).slice(0, 80) };
    }
    if (++done % 50 === 0) console.error(`${done}/${items.length}`);
  }
}
await Promise.all(Array.from({ length: WORKERS }, worker));

const good = rows.filter((r) => r && !r.error);
console.error(`done: ${good.length} rows, ${rows.length - good.length} errors`);
const cols = [...new Set(good.flatMap((r) => Object.keys(r)))];
const esc = (v) => (v === undefined || v === null ? "" : /[",\n]/.test(String(v)) ? `"${String(v).replace(/"/g, '""')}"` : String(v));
mkdirSync(OUT, { recursive: true });
const csv = [cols.join(","), ...good.map((r) => cols.map((k) => esc(r[k])).join(","))].join("\n");
writeFileSync(`${OUT}/rows.csv`, csv + "\n");
console.log(`wrote ${OUT}/rows.csv (${good.length} rows)`);
