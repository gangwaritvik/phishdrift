// Keys and hashes for the synced lists. Mirrors backend/lists.py (list_url_key, list_domain_key,
// hash prefix); tests/fixtures/list_key_parity.json is checked by both test suites.

import { splitHost } from "./lib/psl.js";

const SCHEME = /^[a-zA-Z][a-zA-Z0-9+.\-]*:\/\//;
const IPV4 = /^(?:(?:0|[1-9][0-9]{0,2})\.){3}(?:0|[1-9][0-9]{0,2})$/;

// Shared normalisation (backend/lists.py `_split`): returns [host, portSuffix, rest].
function split(url) {
  let s = url.replace(/^[ \t\n\r\f\v]+|[ \t\n\r\f\v]+$/g, "");
  const hash = s.indexOf("#");
  if (hash >= 0) s = s.slice(0, hash);
  s = s.replace(SCHEME, "");
  const cuts = [s.indexOf("/"), s.indexOf("?")].filter((i) => i >= 0);
  const cut = cuts.length ? Math.min(...cuts) : s.length;
  let authority = s.slice(0, cut);
  const rest = s.slice(cut);
  authority = authority.slice(authority.lastIndexOf("@") + 1).replace(/[A-Z]/g, (c) => c.toLowerCase());
  let host = authority;
  let port = "";
  if (authority.startsWith("[")) {
    const end = authority.indexOf("]");
    if (end !== -1) [host, port] = [authority.slice(0, end + 1), authority.slice(end + 1)];
  } else {
    const colon = authority.indexOf(":");
    if (colon !== -1) [host, port] = [authority.slice(0, colon), authority.slice(colon)];
  }
  host = host.replace(/\.+$/, "");
  if (host.startsWith("www.")) host = host.slice(4);
  return [host, port, rest];
}

export function listUrlKey(url) {
  const [host, port, rest] = split(url);
  const q = rest.indexOf("?");
  const path = (q >= 0 ? rest.slice(0, q) : rest).replace(/\/+$/, "");
  return host + port + path + (q >= 0 ? rest.slice(q) : "");
}

// Registrable domain (public-suffix-only) of the URL's host; IP literals and hosts without a
// public suffix give the host itself. `psl` is the trie from lib/psl.js buildTrie.
export function listDomainKey(url, psl) {
  const [host] = split(url);
  if (IPV4.test(host)) return host;
  if (host.startsWith("[") && host.endsWith("]")) return host.slice(1, -1);
  const [, label, suffix] = splitHost(host, psl);
  return label && suffix ? `${label}.${suffix}` : host;
}

export async function hashPrefix(key, bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key)));
  return Array.from(digest.slice(0, bytes), (b) => b.toString(16).padStart(2, "0")).join("");
}
