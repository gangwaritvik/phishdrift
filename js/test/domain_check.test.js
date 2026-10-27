// The hosted tier C check with fake network parts: refusals, the capture records it builds, the
// verdict from a small hand-made model, the function wrapper (cache, bad input, no model).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { handle } from "../../netlify/functions/domain-check.mjs";
import { checkDomain, dohQuery, gather, parseBootstrap, refusal } from "../src/domain_check.js";
import { buildTrie } from "../src/psl.js";
import { NAMES_C, loadTierC } from "../src/tier_c.js";

const read = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8"));
const pslRules = read("../data/psl_icann.json");
const psl = buildTrie(pslRules);
const lists = read("../data/lists.json");
const refuseLists = { psl, platforms: new Set(lists.platforms), shorteners: new Set(lists.shorteners) };
const NOW = Date.parse("2026-10-27T12:00:00Z");

// one stump: registered 30 days ago or less -> +3 log-odds, older -> -3
const age = NAMES_C.indexOf("domain_age_days");
const bundle = {
  names: NAMES_C,
  trees: [{ f: [age], t: [30], l: [-1], r: [-2], d: [1], m: [2], v: [3, -3], c: [100], n: [20, 80] }],
  thresholds: { suspicious: 0.5, dangerous: 0.9 },
  isotonic: { x: [0, 1], y: [0, 1] },
  reasons: Object.fromEntries(NAMES_C.map((n) => [n, { text: `${n} {v}`, lo: null, hi: null }])),
  explain: { top: 3, min_logodds: 0.1 },
  brands: ["paypal"],
  free_issuers: ["let's encrypt"],
  serving: {
    cache_ttl_s: 3600, cache_max_entries: 10, rdap_timeout_ms: 1000, total_timeout_ms: 2000,
    rdap_bootstrap_url: "https://boot.example/dns.json", doh_urls: ["https://doh.example/resolve"],
    dns_timeout_s: 1, tls_timeout_s: 1,
  },
};
const model = loadTierC(bundle, pslRules);

const rdapBody = (daysAgo) => ({
  events: [
    { eventAction: "registration", eventDate: new Date(NOW - daysAgo * 86400e3).toISOString() },
    { eventAction: "expiration", eventDate: new Date(NOW + 300 * 86400e3).toISOString() },
  ],
  status: ["active"],
});
const reply = (body, status = 200) => ({ ok: status < 400, status, json: async () => body });

// fake internet: DoH answers an A record for the domain (or only for www.), RDAP says `daysAgo`
function fakeFetch({ daysAgo = 5, resolves = "apex", rdapStatus = 200 } = {}) {
  const calls = [];
  const fn = async (url) => {
    calls.push(String(url));
    const u = new URL(url);
    if (u.host === "boot.example") return reply({ services: [[["com", "net"], ["https://rdap.example/"]]] });
    if (u.host === "rdap.example") return rdapStatus === 200 ? reply(rdapBody(daysAgo)) : reply({}, rdapStatus);
    const name = u.searchParams.get("name");
    const type = u.searchParams.get("type");
    const hit = (resolves === "apex" && name === "fresh-site.com") || (resolves === "www" && name === "www.fresh-site.com");
    if (type === "A" && hit) return reply({ Status: 0, Answer: [{ type: 1, TTL: 300, data: "93.184.216.34" }] });
    return reply({ Status: 0, Answer: [] });
  };
  fn.calls = calls;
  return fn;
}
const okTls = async () => ({ ok: true, verified: true, issuer_o: "Let's Encrypt", issuer_cn: "R3", subject_cn: "fresh-site.com", not_before: "2026-10-20T00:00:00+00:00", not_after: "2027-01-18T00:00:00+00:00", san_count: 1, sans: ["fresh-site.com"] });
const deps = (fetchFn, tlsFn = okTls) => ({ fetchFn, tlsFn, bases: parseBootstrap({ services: [[["com"], ["https://rdap.example/"]]] }), cfg: bundle.serving, now: () => NOW });

test("refusal: IPs, local names, platforms, shorteners", () => {
  assert.equal(refusal("93.184.216.34", refuseLists), "ip_or_empty");
  assert.equal(refusal("printer.local", refuseLists), "local_name");
  assert.equal(refusal("intranet", refuseLists), "local_name");
  assert.equal(refusal("my-shop.web.app", refuseLists), "hosting_platform");
  assert.equal(refusal("bit.ly", refuseLists), "shortener");
  assert.equal(refusal("fresh-site.com", refuseLists), null);
});

test("bootstrap map and DoH answers", async () => {
  assert.deepEqual(parseBootstrap({ services: [[["COM"], ["https://x.example/"]], [["zz"], []]] }), { com: "https://x.example" });
  const query = dohQuery(["https://doh.example/resolve"], fakeFetch(), 500);
  assert.deepEqual(await query("fresh-site.com", "A"), [["93.184.216.34", 300]]);
  const failing = dohQuery(["https://doh.example/resolve"], async () => reply({}, 500), 500);
  await assert.rejects(failing("x.com", "A"), /DoH A x.com/);
});

test("gather builds the capture records, www. as the fallback", async () => {
  const { hostRec, domainRec } = await gather("fresh-site.com", deps(fakeFetch({ resolves: "www" })));
  assert.equal(hostRec.probe_host, "www.fresh-site.com");
  assert.equal(hostRec.dns.resolves, true);
  assert.equal(hostRec.tls.verified, true);
  assert.ok(domainRec.rdap.registered);
  const none = await gather("fresh-site.com", deps(fakeFetch({ resolves: "none" })));
  assert.equal(none.hostRec.tls.error, "gaierror");
});

test("a young domain is dangerous with reasons, an old one safe", async () => {
  const young = await checkDomain("fresh-site.com", model, deps(fakeFetch({ daysAgo: 5 })));
  assert.equal(young.verdict, "dangerous");
  assert.equal(young.facts.domain_age_days, 5);
  assert.ok(young.reasons.some((r) => r.feature === "domain_age_days"));
  const old = await checkDomain("fresh-site.com", model, deps(fakeFetch({ daysAgo: 4000 })));
  assert.equal(old.verdict, "safe");
});

test("a failed registry answer is a gap (NaN), not a young domain", async () => {
  const r = await checkDomain("fresh-site.com", model, deps(fakeFetch({ rdapStatus: 429 })));
  assert.equal(r.facts.rdap_error, "http_429");
  assert.equal(r.facts.domain_age_days, null);
});

const post = (body) => new Request("https://site.example/api/domain-check", { method: "POST", body: typeof body === "string" ? body : JSON.stringify(body) });

test("function: answers, caches, refuses, and says so without a model", async () => {
  const fetchFn = fakeFetch({ daysAgo: 5 });
  const opts = { fetchFn, tlsFn: okTls, now: () => NOW, getModel: () => model };
  const first = await (await handle(post({ domain: "Fresh-Site.com" }), opts)).json();
  assert.equal(first.checked, true);
  assert.equal(first.verdict, "dangerous");
  assert.equal(first.cached, false);
  const n = fetchFn.calls.length;
  const second = await (await handle(post({ domain: "fresh-site.com" }), opts)).json();
  assert.equal(second.cached, true);
  assert.equal(fetchFn.calls.length, n);
  assert.deepEqual(await (await handle(post({ domain: "bit.ly" }), opts)).json(), { domain: "bit.ly", checked: false, reason: "shortener" });
  assert.equal((await handle(post({ domain: "not a host" }), opts)).status, 422);
  assert.equal((await handle(post("{"), opts)).status, 400);
  assert.equal((await handle(new Request("https://site.example/api/domain-check"), opts)).status, 405);
  const none = await (await handle(post({ domain: "fresh-site.com" }), { ...opts, getModel: () => null })).json();
  assert.equal(none.reason, "no_model");
});
