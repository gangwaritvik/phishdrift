// "Trust this site": the user's own exceptions, stored as { key, at } with an expiry, so one click
// does not silence a site for good (it may change hands or start hosting phishing later). Trust only
// silences the models; a blocklist hit always warns (combine.js). Older versions stored bare keys
// with no time; those are kept and given the time they are first read.

export const TRUST_DAYS = 30;
const DAY_MS = 24 * 60 * 60 * 1000;

// stored: array of strings (old format) or { key, at } -> Map key -> at, expired entries dropped.
export function liveTrust(stored, now = Date.now(), days = TRUST_DAYS) {
  const out = new Map();
  for (const entry of stored ?? []) {
    const { key, at } = typeof entry === "string" ? { key: entry, at: now } : entry ?? {};
    if (typeof key !== "string" || !key) continue;
    if (typeof at !== "number" || now - at >= days * DAY_MS) continue;
    out.set(key, Math.max(out.get(key) ?? 0, at));
  }
  return out;
}

export function addTrust(stored, key, now = Date.now(), days = TRUST_DAYS) {
  const live = liveTrust(stored, now, days);
  live.set(key, now);
  return [...live].map(([k, at]) => ({ key: k, at }));
}
