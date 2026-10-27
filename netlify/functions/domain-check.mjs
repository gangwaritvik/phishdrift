// Hosted tier C domain check (Netlify Function): POST /api/domain-check { domain } -> the domain's
// verdict from its age, DNS and certificate, for the extension (it sends the registrable domain only)
// and the URL check page. Tier C can only add to a verdict, never lower one; that rule lives in the
// combiner (extension/src/combine.js), this function just answers.
// Safety: only registrable domains are checked (no IP addresses, local names, hosting platforms or
// link shorteners); the TLS handshake goes to an address we looked up ourselves over DNS-over-HTTPS
// and is refused unless that address is public; no page is fetched. Limits: Netlify's per-IP rate
// limit (config below), a per-instance cache, a total time limit.
// The model is js/data/tier_c.json (python -m models.tier_c train); without it the answer is
// { model: false } and nothing is guessed.

import fs from "node:fs";
import tls from "node:tls";

import lists from "../../js/data/lists.json" with { type: "json" };
import pslRules from "../../js/data/psl_icann.json" with { type: "json" };
import { checkDomain, parseBootstrap, refusal } from "../../js/src/domain_check.js";
import { cleanHost, makeTrie } from "../../js/src/llm_check.js";
import { loadTierC, parseCert, registrable } from "../../js/src/tier_c.js";
import { isPublicIp } from "./expand.mjs";

const psl = makeTrie(pslRules);
const refuseLists = { psl, platforms: new Set(lists.platforms), shorteners: new Set(lists.shorteners) };
const cache = new Map(); // domain -> { at, result }
let model; // undefined = not loaded yet, null = no bundle
let bases = null;

const CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type" };
const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...CORS } });

// Read at run time (not imported) so a build without the bundle still deploys; netlify.toml ships it.
export function loadModel(paths = [new URL("../../js/data/tier_c.json", import.meta.url), "js/data/tier_c.json"]) {
  for (const p of paths) {
    try {
      return loadTierC(JSON.parse(fs.readFileSync(p, "utf8")), pslRules);
    } catch {
      /* try the next place */
    }
  }
  return null;
}

// The handshake to one public address, with the host name as server name; mirrors tls_facts.
export function tlsProbe(host, address, ms) {
  return new Promise((resolve) => {
    if (!isPublicIp(address)) return resolve({ ok: false, verified: false, error: "not_public_address" });
    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve(value);
    };
    const sock = tls.connect({ host: address, port: 443, servername: host, rejectUnauthorized: false }, () => {
      const cert = sock.getPeerCertificate();
      if (!sock.authorized) return finish({ ok: true, verified: false, error: String(sock.authorizationError || "unverified") });
      finish({ ok: true, verified: true, version: sock.getProtocol(), ...parseCert(cert) });
    });
    sock.setTimeout(ms, () => finish({ ok: false, verified: false, error: "timeout" }));
    sock.on("error", (e) => finish({ ok: false, verified: false, error: e.code || e.name || "Error" }));
  });
}

export async function handle(req, { fetchFn = fetch, tlsFn = tlsProbe, now = Date.now, getModel = () => (model === undefined ? (model = loadModel()) : model) } = {}) {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
  if (req.method !== "POST") return json(405, { error: "method" });
  const raw = await req.text();
  if (raw.length > 1024) return json(413, { error: "too_large" });
  let host;
  try {
    host = cleanHost(JSON.parse(raw)?.domain);
  } catch {
    return json(400, { error: "bad_json" });
  }
  if (!host) return json(422, { error: "domain must be a bare hostname such as example.com" });
  const why = refusal(host, refuseLists);
  if (why) return json(200, { domain: host, checked: false, reason: why });
  const m = getModel();
  if (!m) return json(200, { domain: host, checked: false, reason: "no_model" });
  const cfg = m.serving;
  const domain = registrable(host, m.lists.psl)[1];
  const hit = cache.get(domain);
  if (hit && now() - hit.at < cfg.cache_ttl_s * 1000) return json(200, { ...hit.result, cached: true });
  const work = async () => {
    bases ??= parseBootstrap(await (await fetchFn(cfg.rdap_bootstrap_url, { signal: AbortSignal.timeout(cfg.rdap_timeout_ms) })).json());
    return checkDomain(domain, m, { fetchFn, tlsFn: (h, a) => tlsFn(h, a, cfg.tls_timeout_s * 1000), bases, cfg, now });
  };
  let result;
  try {
    result = await Promise.race([
      work(),
      new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), cfg.total_timeout_ms)),
    ]);
  } catch (e) {
    return json(200, { domain, checked: false, reason: "failed", detail: String(e?.message || e).slice(0, 120) });
  }
  if (cache.size >= cfg.cache_max_entries) cache.delete(cache.keys().next().value);
  cache.set(domain, { at: now(), result });
  return json(200, { ...result, checked: true, cached: false });
}

export default (req) => handle(req);

// Netlify reads this statically: at most 20 checks a minute from one IP address.
export const config = {
  path: ["/api/domain-check"],
  rateLimit: { windowLimit: 20, windowSize: 60, aggregateBy: ["ip", "domain"] },
};
