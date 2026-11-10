// Page fetch (Netlify Function) for the online URL check page: POST /api/fetch-page { url } ->
// { ok, status, final, redirects, contentType, bytes, truncated, html, error }. A web page cannot read
// another site's HTML (CORS), so this function does one plain GET and hands the text back; the browser
// then scores it with the same page model as the extension (js/src/page.js, tier B).
// Nothing on the page is run, no cookies are sent or kept, and no other file of the page is fetched.
// Safety: only http(s) on ports 80 and 443; every hop (the first address and each redirect) must be a
// public address, checked when the connection is made (so a DNS answer cannot change between the check
// and the request) and for an address written as an IP; at most max_redirects hops; one time limit for
// the whole fetch; at most max_body_bytes read (after decompression); only an HTML answer is returned;
// Netlify's per-IP rate limit (config below). It is a fetch of one address the user typed, not a crawl.
// Limits that are not safety: a server can show this function a different page than a visitor (an
// honest user agent is sent), and a page built by scripts arrives nearly empty.

import http from "node:http";
import https from "node:https";
import net from "node:net";
import zlib from "node:zlib";

import cfg from "../../js/data/page_fetch.json" with { type: "json" };
import { isPublicIp, safeLookup } from "./expand.mjs";

const CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type" };
const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...CORS } });
const DECODERS = { gzip: zlib.createGunzip, deflate: zlib.createInflate, br: zlib.createBrotliDecompress };

// The address written as an IP (net.connect skips the DNS lookup for those, so safeLookup never sees them).
function refuseAddress(u) {
  if (u.protocol !== "http:" && u.protocol !== "https:") return "bad_scheme";
  const port = u.port || (u.protocol === "https:" ? "443" : "80");
  if (port !== "443" && port !== "80") return "port_not_allowed";
  const host = u.hostname.replace(/^\[|\]$/g, "");
  if (net.isIP(host) && !isPublicIp(host)) return "not_public_address";
  return null;
}

// One GET, redirects not followed: { status, location, contentType, body (Buffer), truncated }.
export function request(url, ms) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === "https:" ? https : http;
    const req = lib.request(
      u,
      { method: "GET", lookup: safeLookup, headers: { "User-Agent": "PhishDrift-page-check (URL check page)", Accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1", "Accept-Encoding": "gzip, deflate, br" } },
      (res) => {
        const base = { status: res.statusCode, location: res.headers.location ?? null, contentType: String(res.headers["content-type"] ?? "") };
        if (base.location) {
          res.destroy();
          return resolve({ ...base, body: Buffer.alloc(0), truncated: false });
        }
        const encoding = String(res.headers["content-encoding"] ?? "identity").toLowerCase();
        const decoder = encoding === "identity" ? null : DECODERS[encoding]?.();
        if (encoding !== "identity" && !decoder) {
          res.destroy();
          return reject(new Error("unsupported_encoding"));
        }
        const chunks = [];
        let size = 0;
        let truncated = false;
        const out = decoder ? res.pipe(decoder) : res;
        const finish = () => resolve({ ...base, body: Buffer.concat(chunks).subarray(0, cfg.max_body_bytes), truncated });
        out.on("data", (chunk) => {
          size += chunk.length;
          chunks.push(chunk);
          if (size > cfg.max_body_bytes) {
            truncated = true;
            res.destroy();
            decoder?.destroy();
            finish();
          }
        });
        out.on("end", finish);
        out.on("error", (e) => (truncated ? undefined : reject(e)));
        res.on("error", (e) => (truncated ? undefined : reject(e)));
      },
    );
    req.setTimeout(ms, () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    req.end();
  });
}

const isHtml = (type) => /^(text\/html|application\/xhtml\+xml)\b/i.test(type);

function decode(buffer, contentType) {
  const charset = /charset\s*=\s*["']?([\w-]+)/i.exec(contentType)?.[1] ?? "utf-8";
  try {
    return new TextDecoder(charset).decode(buffer);
  } catch {
    return new TextDecoder("utf-8").decode(buffer);
  }
}

// The fetch itself, with `requestFn` replaceable for tests.
export async function fetchPage(start, { requestFn = request, now = Date.now } = {}) {
  const deadline = now() + cfg.timeout_ms;
  const redirects = [];
  let url = start;
  for (let hop = 0; hop <= cfg.max_redirects; hop++) {
    const refusal = refuseAddress(new URL(url));
    if (refusal) return { ok: false, final: url, redirects, error: refusal };
    const left = deadline - now();
    if (left <= 0) return { ok: false, final: url, redirects, error: "timeout" };
    let res;
    try {
      res = await requestFn(url, left);
    } catch (e) {
      return { ok: false, final: url, redirects, error: String(e?.code ?? e?.message ?? e).slice(0, 80) };
    }
    if (res.location) {
      let next;
      try {
        next = new URL(res.location, url).href;
      } catch {
        return { ok: false, final: url, redirects, status: res.status, error: "bad_redirect" };
      }
      redirects.push({ from: url, to: next, status: res.status });
      url = next;
      continue;
    }
    if (!isHtml(res.contentType)) return { ok: false, final: url, redirects, status: res.status, contentType: res.contentType, error: "not_html" };
    return {
      ok: true,
      status: res.status,
      final: url,
      redirects,
      contentType: res.contentType,
      bytes: res.body.length,
      truncated: res.truncated,
      html: decode(res.body, res.contentType),
      error: null,
    };
  }
  return { ok: false, final: url, redirects, error: "too_many_redirects" };
}

export async function handle(req, deps = {}) {
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
  return json(200, await fetchPage(url, deps));
}

export default (req) => handle(req);

// Netlify reads this statically: at most 10 page fetches a minute from one IP address.
export const config = {
  path: ["/api/fetch-page"],
  rateLimit: { windowLimit: 10, windowSize: 60, aggregateBy: ["ip", "domain"] },
};
