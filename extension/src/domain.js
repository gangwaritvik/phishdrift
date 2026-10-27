// Backend domain answers. A lookup that failed (network error, timeout, an error status, or an
// answer the backend itself marks as failed) is not evidence: it is never read as "low risk", and
// it is remembered only briefly so a backend that comes back is asked again soon.

export const DOMAIN_FAILURE_MS = 30 * 1000;

// The backend's JSON -> the answer the combiner uses, or null when the lookup failed.
export function usableAnswer(json) {
  if (!json || typeof json !== "object") return null;
  if (json.error || json.risk === "unknown" || !Array.isArray(json.signals)) return null;
  return json;
}

// The backend's /llm-check JSON -> {raise, brand, brand_domain}, or null when it gave no opinion.
export function usableLlmAnswer(json) {
  if (!json || typeof json !== "object" || json.error || typeof json.raise !== "boolean") return null;
  if (json.raise && (typeof json.brand !== "string" || typeof json.brand_domain !== "string")) return null;
  return { raise: json.raise, brand: json.brand, brand_domain: json.brand_domain };
}

// The hosted domain check's JSON (netlify/functions/domain-check.mjs) -> {verdict: 0|1|2, reasons:[{text}]},
// or null when it did not check the domain (refused, no model, failed): that is no evidence either way.
const TIER_C_VERDICTS = { safe: 0, suspicious: 1, dangerous: 2 };
export function usableTierCAnswer(json) {
  if (!json || typeof json !== "object" || json.error || json.checked !== true) return null;
  const verdict = TIER_C_VERDICTS[json.verdict];
  if (verdict === undefined || !Array.isArray(json.reasons)) return null;
  return { verdict, reasons: json.reasons.filter((r) => typeof r?.text === "string").map((r) => ({ text: r.text })) };
}

// How long a cached lookup stays fresh.
export function domainTtl(entry, okMs, failMs = DOMAIN_FAILURE_MS) {
  return entry.answer ? okMs : failMs;
}
