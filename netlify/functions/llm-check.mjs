// Hosted LLM brand check (Netlify Function): the same answer as the backend's POST /llm-check,
// for the online URL check page (same site, /api/llm-check) and the extension (setting llmUrl).
// The Gemini key is the site's GEMINI_API_KEY environment variable; it never leaves this function.
// Limits: Netlify's own per-IP rate limit (config below), a per-instance cache and daily cap.

import cfg from "../../js/data/llm_check.json" with { type: "json" };
import pslRules from "../../js/data/psl_icann.json" with { type: "json" };
import { askGemini, checkHost, cleanHost, makeTrie } from "../../js/src/llm_check.js";

const psl = makeTrie(pslRules);
const cache = new Map(); // host -> { at, result }
let day = "";
let calls = 0;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};
const json = (status, body) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...CORS } });
const OFF = { raise: false, kind: null, brand: null, brand_domain: null, confidence: 0.0, phishing: 0.0 };

export async function handle(request, { env = process.env, fetchFn = fetch, now = Date.now } = {}) {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
  if (request.method !== "POST") return json(405, { error: "method" });
  const raw = await request.text();
  if (raw.length > 4096) return json(413, { error: "too_large" });
  let body;
  try {
    body = JSON.parse(raw);
  } catch {
    return json(400, { error: "bad_json" });
  }
  const host = cleanHost(body?.domain);
  const words = body?.path_words ?? [];
  if (!host || !Array.isArray(words) || words.length > 40 || words.some((w) => typeof w !== "string" || w.length > 200)) {
    return json(422, { error: "domain must be a bare hostname such as example.com" });
  }
  const key = env[cfg.api_key_env] ?? "";
  if (!key) return json(200, { ...OFF, cached: false, error: "disabled" });
  const cacheKey = `${host}|${words.join(" ")}`;
  const hit = cache.get(cacheKey);
  if (hit && now() - hit.at < cfg.cache_ttl_s * 1000) return json(200, { ...hit.result, cached: true });
  const today = new Date(now()).toISOString().slice(0, 10);
  if (today !== day) [day, calls] = [today, 0];
  if (calls >= cfg.max_calls_per_day) return json(200, { ...OFF, cached: false, error: "daily_cap" });
  calls += 1;
  const result = await checkHost(host, words, { cfg, psl, provider: (user) => askGemini(cfg, key, user, fetchFn) });
  if (result.error === null) {
    if (cache.size >= cfg.cache_max_entries) cache.delete(cache.keys().next().value);
    cache.set(cacheKey, { at: now(), result });
  }
  return json(200, { ...result, cached: false });
}

export default (request) => handle(request);

// Netlify reads this object statically, so the numbers must be literals here: at most 20 checks
// per minute from one IP address; more are answered 429 by Netlify before the function runs.
export const config = {
  path: ["/api/llm-check", "/llm-check"],
  rateLimit: { windowLimit: 20, windowSize: 60, aggregateBy: ["ip", "domain"] },
};
