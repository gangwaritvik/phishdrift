// Short-link expansion (Netlify Function) for the online URL check page: POST /api/expand
// { url } -> { final, complete, hops, error }. A web page cannot follow another site's redirect
// itself (CORS), so this function does, with the limits of js/data/short_links.json.
// Safety: only addresses on a link shortener (js/data/lists.json) are requested, so this is not an
// open proxy; the destination itself is never requested; redirects are not followed by the
// request library and nothing on a page is run; only ports 80 and 443; every connection is
// refused when its host resolves to a private, loopback, link-local or other non-public address
// (checked at connect time, so a DNS answer cannot change between the check and the request).

import dns from "node:dns";
import http from "node:http";
import https from "node:https";
import net from "node:net";

import cfg from "../../js/data/short_links.json" with { type: "json" };
import lists from "../../js/data/lists.json" with { type: "json" };
import pslRules from "../../js/data/psl_icann.json" with { type: "json" };
import { makeTrie, registrable } from "../../js/src/llm_check.js";
import { expand } from "../../js/src/short_links.js";

const psl = makeTrie(pslRules);
const shorteners = new Set(lists.shorteners);
const cache = new Map(); // url -> { at, result }

// separate lists: a BlockList also matches IPv4 addresses against IPv4-mapped IPv6 ranges
const blocked4 = new net.BlockList();
const blocked6 = new net.BlockList();
for (const [addr, bits] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
  ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24],
  ["203.0.113.0", 24], ["224.0.0.0", 3],
]) blocked4.addSubnet(addr, bits, "ipv4");
for (const [addr, bits] of [["::", 127], ["::ffff:0:0", 96], ["64:ff9b::", 96], ["100::", 64], ["2001:db8::", 32], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8]]) {
  blocked6.addSubnet(addr, bits, "ipv6");
}
// ::ffff:a.b.c.d is refused as a whole (DNS answers plain IPv4 for those)
export const isPublicIp = (ip) => (net.isIP(ip) === 4 ? !blocked4.check(ip, "ipv4") : net.isIP(ip) === 6 && !blocked6.check(ip, "ipv6"));

export function hostOf(url) {
  try {
    return new URL(url).hostname.replace(/\.$/, "").toLowerCase();
  } catch {
    return "";
  }
}

export const isShortener = (url) => {
  const host = hostOf(url);
  return Boolean(host) && !net.isIP(host.replace(/^\[|\]$/g, "")) && shorteners.has(registrable(host, psl));
};

// dns.lookup that answers only with public addresses
function safeLookup(hostname, options, callback) {
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err);
    const ok = addresses.filter((a) => isPublicIp(a.address));
    if (!ok.length) return callback(new Error("not_public_address"));
    return options.all ? callback(null, ok) : callback(null, ok[0].address, ok[0].family);
  });
}

// One request, no redirects followed, at most max_body_bytes of a GET body read.
export function request(url, method, ms) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const port = u.port || (u.protocol === "https:" ? "443" : "80");
    if (port !== "443" && port !== "80") return reject(new Error("port_not_allowed"));
    const lib = u.protocol === "https:" ? https : http;
    const req = lib.request(u, { method, lookup: safeLookup, headers: { "User-Agent": "PhishDrift-link-check", Accept: "text/html,*/*" } }, (res) => {
      const location = res.headers.location ?? null;
      if (method === "HEAD" || location) {
        res.destroy();
        return resolve({ status: res.statusCode, location, body: "" });
      }
      let body = "";
      res.setEncoding("latin1");
      res.on("data", (chunk) => {
        body += chunk;
        if (body.length >= cfg.max_body_bytes) res.destroy();
      });
      res.on("close", () => resolve({ status: res.statusCode, location, body: body.slice(0, cfg.max_body_bytes) }));
    });
    req.setTimeout(ms, () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    req.end();
  });
}

const CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type" };
const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...CORS } });

export async function handle(req, { requestFn = request, now = Date.now } = {}) {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
  if (req.method !== "POST") return json(405, { error: "method" });
  const raw = await req.text();
  if (raw.length > 4096) return json(413, { error: "too_large" });
  let url;
  try {
    const u = new URL(JSON.parse(raw)?.url);
    if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("scheme");
    url = u.href;
  } catch {
    return json(422, { error: "url must be an http(s) address" });
  }
  if (!isShortener(url)) return json(422, { error: "not_shortener" });
  const hit = cache.get(url);
  if (hit && now() - hit.at < cfg.cache_ttl_s * 1000) return json(200, { ...hit.result, cached: true });
  const result = await expand(url, { isShortener, request: requestFn, cfg, now });
  if (result.complete) {
    if (cache.size >= cfg.cache_max_entries) cache.delete(cache.keys().next().value);
    cache.set(url, { at: now(), result });
  }
  return json(200, { ...result, cached: false });
}

export default (req) => handle(req);

// Netlify reads this statically: at most 20 expansions a minute from one IP address.
export const config = {
  path: ["/api/expand"],
  rateLimit: { windowLimit: 20, windowSize: 60, aggregateBy: ["ip", "domain"] },
};
