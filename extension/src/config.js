// Defaults; a `settings` object in chrome.storage.local overrides them.

export const DEFAULTS = {
  backendUrl: "http://127.0.0.1:8000",
  backendTimeoutMs: 2500, // fail open after this: the page is never held up by the backend
  verdictCacheMs: 10 * 60 * 1000,
  verdictCacheMax: 500,
  domainCacheMs: 60 * 60 * 1000,
  listSyncMinutes: 24 * 60,
};
