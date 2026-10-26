// LLM brand check, a JavaScript copy of backend/llm.py for hosts without the Python backend (the
// Netlify Function in netlify/functions/llm-check.mjs). The prompt, answer schema and settings
// come from js/data/llm_check.json (python -m backend export-llm-js), and
// tests/fixtures/llm_parity.json holds Python's own prompts, parses and verdicts for both suites.
// The model only names a brand and that brand's domain; the verdict is decided here in code.

import { buildTrie, splitHost } from "./psl.js";
import { cpHead, pyLower, pyStrip } from "./pystr.js";

const KEYS = ["brand", "brand_domain", "confidence", "reason"];
const HOST_RE = /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\.[a-z]{2,}$/;
const LABEL = "[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?";
const HOSTNAME_RE = new RegExp(`^${LABEL}(?:\\.${LABEL})+$`); // backend/app.py clean_domain
const IPV4 = /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$/;
const NONE = () => ({ raise: false, brand: null, brand_domain: null, confidence: 0.0 });

// backend/app.py clean_domain: a lowercased bare hostname, or null.
export function cleanHost(value) {
  if (typeof value !== "string") return null;
  let host = value.toLowerCase();
  if (host.endsWith(".")) host = host.slice(0, -1);
  return host.length <= 253 && HOSTNAME_RE.test(host) ? host : null;
}

export function cleanWords(words, limit) {
  const out = [];
  for (const word of words) out.push(...(pyLower(String(word)).match(/[a-z0-9]{1,30}/g) ?? []));
  return out.slice(0, limit);
}

// json.dumps({"host": ..., "path_words": [...]}, ensure_ascii=True).
export function buildPrompt(host, words) {
  const dump = (s) => JSON.stringify(s).replace(/[\u0080-\uffff]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
  return `{"host": ${dump(host)}, "path_words": [${words.map(dump).join(", ")}]}`;
}

export function parse(text) {
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    return null;
  }
  if (data === null || typeof data !== "object" || Array.isArray(data)) return null;
  const got = Object.keys(data);
  if (got.length !== KEYS.length || !KEYS.every((k) => Object.hasOwn(data, k))) return null;
  const { brand, brand_domain: dom, confidence: conf, reason } = data;
  if (typeof conf !== "number" || !(conf >= 0 && conf <= 1)) return null;
  if (typeof reason !== "string" || !(brand === null || typeof brand === "string")) return null;
  if (dom !== null && (typeof dom !== "string" || !HOST_RE.test(pyLower(pyStrip(dom))))) return null;
  return {
    brand: brand ? cpHead(pyStrip(brand), 60) : null,
    brand_domain: dom ? pyLower(pyStrip(dom)) : null,
    confidence: conf,
    reason: cpHead(pyStrip(reason), 140),
  };
}

// phishdrift.domains.registered_domain for a bare host (public-suffix-only).
export function registrable(host, psl) {
  if (!host) return "";
  if (IPV4.test(host)) return host;
  const [, label, suffix] = splitHost(host, psl);
  return label && suffix ? `${label}.${suffix}` : host;
}

export function judge(host, answer, minConfidence, psl) {
  if (answer === null || !answer.brand || !answer.brand_domain) return NONE();
  const out = { ...NONE(), brand: answer.brand, brand_domain: answer.brand_domain, confidence: answer.confidence };
  if (answer.confidence < minConfidence) return out;
  const claimed = registrable(answer.brand_domain, psl);
  const visited = registrable(host, psl);
  out.raise = Boolean(claimed) && Boolean(visited) && claimed !== visited;
  return out;
}

export function makeTrie(rules) {
  return buildTrie(rules);
}

// One Gemini generateContent call; resolves to the answer text or throws (message safe to log).
export async function askGemini(cfg, key, user, fetchFn = fetch) {
  const res = await fetchFn(cfg.url.replace("{model}", cfg.model), {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-goog-api-key": key },
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: cfg.system }] },
      contents: [{ role: "user", parts: [{ text: user }] }],
      generationConfig: {
        temperature: 0,
        maxOutputTokens: cfg.max_output_tokens,
        responseMimeType: "application/json",
        responseSchema: cfg.schema,
      },
    }),
    signal: AbortSignal.timeout(cfg.timeout_ms),
  });
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${String(data?.error?.message ?? "no error message").slice(0, 200)}`);
  const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
  if (typeof text !== "string") throw new Error(`no answer text (finishReason=${data?.candidates?.[0]?.finishReason || "none"})`);
  return text;
}

// backend/llm.py LlmChecker: ask, parse, judge. Never throws: a failure is `error`, no opinion.
export async function checkHost(host, words, { cfg, psl, provider }) {
  let text;
  try {
    text = await provider(buildPrompt(host, cleanWords(words, cfg.max_path_words)));
  } catch (err) {
    const detail = `${err?.name}: ${String(err?.message).slice(0, 200)}`;
    console.warn(`llm check failed: ${detail}`);
    // the message is Google's own error text or ours, never the request, so the key cannot be in it
    return { ...NONE(), error: "provider_failed", detail };
  }
  const answer = parse(text);
  if (answer === null) return { ...NONE(), error: "bad_answer", detail: String(text).slice(0, 160) };
  return { ...judge(host, answer, cfg.min_confidence, psl), error: null };
}
