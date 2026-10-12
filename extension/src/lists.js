// Allowlist and blocklist lookups against the synced hashed lists (backend/lists.py builds them).
// Matching never leaves the device. On shared hosting platforms the blocklist is matched on the
// full URL, never the domain, and the allowlist does not apply.

import { hashPrefix, listDomainKey, listUrlKey } from "./keys.js";

function toSet(list) {
  return new Set(list ?? []);
}

export class ListSet {
  // payload: { blocklist: {prefix_bytes, domains, urls}, allowlist: {prefix_bytes, domains} } | null
  constructor(payload, { platforms, psl }) {
    this.version = payload?.blocklist?.version ?? null;
    this.blockBytes = payload?.blocklist?.prefix_bytes ?? 0;
    this.allowBytes = payload?.allowlist?.prefix_bytes ?? 0;
    this.blockDomains = toSet(payload?.blocklist?.domains);
    this.blockUrls = toSet(payload?.blocklist?.urls);
    this.allowDomains = toSet(payload?.allowlist?.domains);
    this.platforms = platforms;
    this.psl = psl;
  }

  // { domain, shared, trustKey, allow, blocked: null | "domain" | "url" }
  async check(url) {
    const domain = listDomainKey(url, this.psl);
    if (!domain) return { domain: null, shared: false, trustKey: null, allow: false, blocked: null };
    const shared = this.platforms.has(domain);
    let blocked = null;
    let allow = false;
    if (shared) {
      if (this.blockBytes && this.blockUrls.size) {
        if (this.blockUrls.has(await hashPrefix(listUrlKey(url), this.blockBytes))) blocked = "url";
      }
    } else {
      if (this.blockBytes && this.blockDomains.size) {
        if (this.blockDomains.has(await hashPrefix(domain, this.blockBytes))) blocked = "domain";
      }
      if (this.allowBytes && this.allowDomains.size) {
        allow = this.allowDomains.has(await hashPrefix(domain, this.allowBytes));
      }
    }
    // A user's own "trust this site" is keyed by domain, or by the exact host on shared platforms.
    const trustKey = shared ? listUrlKey(url).split(/[/?:]/)[0] : domain;
    return { domain, shared, trustKey, allow, blocked };
  }
}
