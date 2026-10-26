// Defaults; a `settings` object in chrome.storage.local overrides them, after `sanitizeSettings`
// (a bad stored value falls back to its default instead of breaking the extension).

export const DEFAULTS = {
  backendUrl: "http://127.0.0.1:8000",
  backendTimeoutMs: 2500, // fail open after this: the page is never held up by the backend
  verdictCacheMs: 10 * 60 * 1000,
  verdictCacheMax: 500,
  domainCacheMs: 60 * 60 * 1000,
  llmCheck: false, // opt-in: ask the backend's LLM about borderline addresses (host name only)
  llmGrayLow: 0.5, // untuned: safe addresses with a model score from here up are borderline
  llmTimeoutMs: 20_000,
  llmUrl: "", // full address of a hosted LLM check (e.g. https://<site>.netlify.app/llm-check); empty = backendUrl + /llm-check
  listSyncMinutes: 60, // the backend's remote config (list_sync_minutes) can change it, 15-1440
};

const RANGES = {
  backendTimeoutMs: [500, 10_000],
  verdictCacheMs: [0, 60 * 60 * 1000],
  verdictCacheMax: [10, 10_000],
  domainCacheMs: [0, 24 * 60 * 60 * 1000],
  llmGrayLow: [0.05, 0.99],
  llmTimeoutMs: [500, 30_000],
  listSyncMinutes: [15, 24 * 60],
};

export function sanitizeSettings(stored) {
  const out = { ...DEFAULTS };
  for (const [key, [lo, hi]] of Object.entries(RANGES)) {
    const v = stored?.[key];
    if (Number.isFinite(v) && v >= lo && v <= hi) out[key] = v;
  }
  if (typeof stored?.llmCheck === "boolean") out.llmCheck = stored.llmCheck;
  for (const key of ["backendUrl", "llmUrl"]) {
    const url = webUrl(stored?.[key]);
    if (url !== null) out[key] = url;
  }
  return out;
}

// An http(s) address without credentials and trailing "/", or null.
function webUrl(url) {
  if (typeof url !== "string") return null;
  try {
    const u = new URL(url);
    if ((u.protocol === "https:" || u.protocol === "http:") && !u.username && !u.password) {
      return url.replace(/\/+$/, "");
    }
  } catch {
    // not an address
  }
  return null;
}

// Where the LLM brand check is asked: the hosted check when set, else the backend's endpoint.
export function llmEndpoint(settings) {
  return settings.llmUrl || `${settings.backendUrl}/llm-check`;
}
