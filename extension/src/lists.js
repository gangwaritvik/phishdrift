// Allowlist and blocklist lookups against the synced hashed lists (backend/lists.py builds them).
// Matching never leaves the device. On shared hosting platforms the blocklist is matched on the
// full URL, never the domain, and the allowlist does not apply. Shared hosting is the platform list
// (configs/platforms.yaml, bundled with the model) plus the "open hosting" zones the list builder
// learned from phishing hosts below allowlisted domains (allowlist.open_hosting, for example
// cloudapp.azure.com or drive.google.com; backend/lists.py `open_hosting_zones`). There the
// allowlist is looked up by exact host instead: the builder lists popular tenant sites on
// platforms (stitch.withgoogle.com) by host (backend/lists.py `tenant_sites`).

import { hashPrefix, listDomainKey, listUrlExpressions, listUrlKey } from "./keys.js";

function toSet(list) {
  return new Set(list ?? []);
}

// Mirrors backend/lists.py `in_zone`: the host is a zone or lies below one.
export function inZone(host, zones) {
  if (zones.has(host)) return true;
  for (let i = host.indexOf("."); i !== -1; i = host.indexOf(".", i + 1)) {
    if (zones.has(host.slice(i + 1))) return true;
  }
  return false;
}

// The extension ships with an allowlist built at packaging time (extension/data/allowlist.json, from
// `python -m backend build-lists`), so the most visited sites are allowlisted even before the
// first sync or when no backend runs. A synced allowlist replaces it once there is one, and a
// domain on the synced blocklist is never allowed by the bundled list (as in backend/lists.py).
export function withBundledAllowlist(payload, bundled) {
  if (payload?.allowlist?.domains?.length || !bundled?.domains?.length) return payload ?? null;
  const block = payload?.blocklist;
  let allowlist = bundled;
  if (block?.domains?.length && block.prefix_bytes <= bundled.prefix_bytes) {
    // the blocklist may use shorter hashes than the allowlist: compare on its prefix length
    const blocked = new Set(block.domains);
    const cut = 2 * block.prefix_bytes;
    allowlist = { ...bundled, domains: bundled.domains.filter((d) => !blocked.has(d.slice(0, cut))) };
  }
  return { ...(payload ?? {}), allowlist };
}

export class ListSet {
  // payload: { blocklist: {prefix_bytes, domains, urls},
  //            allowlist: {prefix_bytes, domains, open_hosting} } | null
  constructor(payload, { platforms, psl, shorteners = new Set() }) {
    this.version = payload?.blocklist?.version ?? null;
    this.blockBytes = payload?.blocklist?.prefix_bytes ?? 0;
    this.allowBytes = payload?.allowlist?.prefix_bytes ?? 0;
    this.blockDomains = toSet(payload?.blocklist?.domains);
    this.blockUrls = toSet(payload?.blocklist?.urls);
    this.allowDomains = toSet(payload?.allowlist?.domains);
    this.openHosting = toSet(payload?.allowlist?.open_hosting);
    this.platforms = platforms;
    this.psl = psl;
    this.shorteners = shorteners;
  }

  // { domain, shared, shortener, trustKey, allow, blocked: null | "domain" | "url" }
  // A shortener is never allowlisted: the address that matters is where it redirects to.
  async check(url) {
    const domain = listDomainKey(url, this.psl);
    if (!domain) return { domain: null, shared: false, shortener: false, trustKey: null, allow: false, blocked: null };
    const shortener = this.shorteners.has(domain);
    const host = listUrlKey(url).split(/[/?:]/)[0];
    const shared = this.platforms.has(domain) || inZone(host, this.openHosting);
    let blocked = null;
    let allow = false;
    // URL entries: platform and open-hosting URLs, and bad URLs on allowlisted sites. Every
    // host-suffix / path-prefix expression is looked up, so a tenant or a URL listed without its
    // query still matches when a per-victim token in the query or path changes.
    if (this.blockBytes && this.blockUrls.size) {
      for (const key of listUrlExpressions(url)) {
        if (this.blockUrls.has(await hashPrefix(key, this.blockBytes))) {
          blocked = "url";
          break;
        }
      }
    }
    if (shared) {
      if (!shortener && !blocked && this.allowBytes && this.allowDomains.size) {
        allow = this.allowDomains.has(await hashPrefix(host, this.allowBytes));
      }
    } else {
      if (!blocked && this.blockBytes && this.blockDomains.size) {
        if (this.blockDomains.has(await hashPrefix(domain, this.blockBytes))) blocked = "domain";
      }
      if (!shortener && this.allowBytes && this.allowDomains.size) {
        allow = this.allowDomains.has(await hashPrefix(domain, this.allowBytes));
      }
    }
    // A user's own "trust this site" is keyed by domain, or by the exact host on shared platforms.
    const trustKey = shared ? host : domain;
    return { domain, shared, shortener, trustKey, allow, blocked };
  }
}
