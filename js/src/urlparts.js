// Canonical URL parts, mirroring features/urlparts.py step by step (plain string operations).
// Lengths and indexing in the features use code points (Array.from), like Python strings.

import { splitHost } from "./psl.js";
import { pyStrip } from "./pystr.js";

export const PLATFORM_TOKEN = "hostingplatform.com";
const SCHEME = /^[a-zA-Z][a-zA-Z0-9+.\-]*:\/\//;

export function isDigitStr(s) {
  return s.length > 0 && /^\p{Nd}+$/u.test(s); // Python str.isdigit (decimal digits)
}

export function words(text) {
  return text.toLowerCase().split(/[^a-z0-9]+/).filter((w) => w);
}

function parseIPv4(s) {
  const parts = s.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => /^[0-9]{1,3}$/.test(p) && !(p.length > 1 && p[0] === "0") && Number(p) <= 255);
}

// Python ipaddress.IPv6Address rules (scope id allowed).
function parseIPv6(input) {
  let s = input;
  const pct = s.indexOf("%");
  if (pct >= 0) {
    if (pct === s.length - 1) return false;
    s = s.slice(0, pct);
  }
  if (!s) return false;
  let parts = s.split(":");
  if (parts.length < 3) return false;
  if (parts[parts.length - 1].includes(".")) {
    if (!parseIPv4(parts[parts.length - 1])) return false;
    parts = parts.slice(0, -1).concat(["0", "0"]);
  }
  if (parts.length > 9) return false;
  let skip = null;
  for (let i = 1; i < parts.length - 1; i++) {
    if (!parts[i]) {
      if (skip !== null) return false;
      skip = i;
    }
  }
  if (skip !== null) {
    let hi = skip;
    let lo = parts.length - skip - 1;
    if (!parts[0]) {
      hi -= 1;
      if (hi) return false;
    }
    if (!parts[parts.length - 1]) {
      lo -= 1;
      if (lo) return false;
    }
    if (8 - (hi + lo) < 1) return false;
    parts = parts.slice(0, hi).concat(parts.slice(parts.length - lo));
  } else {
    if (parts.length !== 8 || !parts[0] || !parts[parts.length - 1]) return false;
  }
  return parts.every((p) => /^[0-9a-fA-F]{1,4}$/.test(p));
}

export function isIpHost(host) {
  const bare = host.replace(/^[\[\]]+|[\[\]]+$/g, "");
  return parseIPv4(bare) || parseIPv6(bare);
}

// Returns null when there is no host (Python returns None).
export function parse(url, platforms, pslRoot) {
  let s = pyStrip(url); // Python str.strip(), not JS trim()
  const hash = s.indexOf("#");
  if (hash >= 0) s = s.slice(0, hash);
  const m = s.match(SCHEME);
  if (m) s = s.slice(m[0].length);
  const cuts = [s.indexOf("/"), s.indexOf("?")].filter((i) => i >= 0);
  const cut = cuts.length ? Math.min(...cuts) : s.length;
  let authority = s.slice(0, cut);
  const rest = s.slice(cut);
  let userinfo = "";
  const at = authority.lastIndexOf("@");
  if (at >= 0) {
    userinfo = authority.slice(0, at);
    authority = authority.slice(at + 1);
  }
  let host;
  let port = "";
  if (authority.startsWith("[")) {
    const end = authority.indexOf("]");
    host = end >= 0 ? authority.slice(0, end + 1) : authority;
    const tail = end >= 0 ? authority.slice(end + 1) : "";
    port = tail.startsWith(":") && isDigitStr(tail.slice(1)) ? tail.slice(1) : "";
  } else {
    const colon = authority.lastIndexOf(":");
    if (colon >= 0 && isDigitStr(authority.slice(colon + 1))) {
      host = authority.slice(0, colon);
      port = authority.slice(colon + 1);
    } else {
      host = authority;
    }
  }
  host = host.toLowerCase().replace(/\.+$/, "");
  if (!/[\p{L}\p{N}]/u.test(host)) return null;
  if (host.startsWith("www.")) host = host.slice(4);
  let path;
  let query;
  if (rest.startsWith("?")) {
    path = "";
    query = rest.slice(1);
  } else {
    const q = rest.indexOf("?");
    path = q >= 0 ? rest.slice(0, q) : rest;
    query = q >= 0 ? rest.slice(q + 1) : "";
  }
  path = path.replace(/\/+$/, "");

  const isIp = isIpHost(host);
  let [subdomain, label, suffix] = isIp ? ["", host, ""] : splitHost(host, pslRoot);
  let isPlatform = false;
  if (!isIp && suffix && platforms.has(`${label}.${suffix}`)) {
    isPlatform = true;
    host = subdomain ? `${subdomain}.${PLATFORM_TOKEN}` : PLATFORM_TOKEN;
    [subdomain, label, suffix] = splitHost(host, pslRoot);
  }
  let canon = (userinfo ? `${userinfo}@` : "") + host + (port ? `:${port}` : "");
  canon += path + (query ? `?${query}` : "");
  return {
    canon, host, port, userinfo, path, query, subdomain, label, suffix, isIp, isPlatform,
    domain: suffix ? `${label}.${suffix}` : label,
  };
}
