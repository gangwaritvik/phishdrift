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

// How long a cached lookup stays fresh.
export function domainTtl(entry, okMs, failMs = DOMAIN_FAILURE_MS) {
  return entry.answer ? okMs : failMs;
}
