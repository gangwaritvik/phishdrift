// Google Safe Browsing check against the synced 4-byte hash prefixes (backend/safebrowsing.py).
// URLs are canonicalised and turned into host-suffix / path-prefix expressions as in Google's
// "URLs and Hashing" spec. A prefix hit is only a candidate: the backend returns the full hashes
// Google lists under that one prefix and the match is decided here, so no URL or domain leaves the
// device. Shortcut: IPs written in octal, hex or as one integer are not normalised (Chrome hands
// the extension normalised hosts); upgrade by parsing them in `canonicalize`.

const PREFIX = 4;
const MAX_HOST_SUFFIXES = 5;
const MAX_DIRS = 3;

// Work on UTF-8 bytes held one per char, so %XX escapes and non-ASCII behave as in the spec.
const toBinary = (s) => String.fromCharCode(...new TextEncoder().encode(s));
const toBytes = (b) => Uint8Array.from(b, (c) => c.charCodeAt(0));
const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

function unescapeAll(s) {
  for (;;) {
    const next = s.replace(/%([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
    if (next === s) return s;
    s = next;
  }
}

const escapeBytes = (s) => s.replace(/[\x00-\x20#%\x7f-\xff]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0")}`);

function resolvePath(path) {
  const segs = path.split("/");
  const out = [];
  let trailing = false;
  segs.forEach((seg, i) => {
    const last = i === segs.length - 1;
    if (seg === "..") {
      out.pop();
      trailing = last;
    } else if (seg === "." || seg === "") {
      trailing = last;
    } else {
      out.push(seg);
      trailing = false;
    }
  });
  return `/${out.join("/")}${trailing && out.length ? "/" : ""}`;
}

// { host, path, query } of a URL: query is null when the URL has no "?".
export function canonicalize(url) {
  let s = url.replace(/^[ \t\n\r\f\v]+|[ \t\n\r\f\v]+$/g, "").replace(/[\t\r\n]/g, "");
  const hash = s.indexOf("#");
  if (hash >= 0) s = s.slice(0, hash);
  s = unescapeAll(toBinary(s)).replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "");
  const cut = s.search(/[/?]/);
  let authority = cut < 0 ? s : s.slice(0, cut);
  let rest = cut < 0 ? "" : s.slice(cut);
  authority = authority.slice(authority.lastIndexOf("@") + 1);
  const host = authority.replace(/:\d*$/, "").replace(/^\.+|\.+$/g, "").replace(/\.{2,}/g, ".").replace(/[A-Z]/g, (c) => c.toLowerCase());
  const q = rest.indexOf("?");
  const query = q >= 0 ? rest.slice(q + 1) : null;
  if (q >= 0) rest = rest.slice(0, q);
  return { host: escapeBytes(host), path: escapeBytes(resolvePath(rest || "/")), query: query === null ? null : escapeBytes(query) };
}

const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;

// Every "host/path" string Safe Browsing hashes for a URL: up to 5 hosts x up to 6 paths.
export function expressions(url) {
  const { host, path, query } = canonicalize(url);
  const hosts = [host];
  if (!IPV4.test(host)) {
    const labels = host.split(".");
    for (let n = Math.min(MAX_HOST_SUFFIXES, labels.length - 1); n >= 2; n--) hosts.push(labels.slice(-n).join("."));
  }
  const dirs = path.split("/").slice(1, -1);
  const paths = [...(query === null ? [] : [`${path}?${query}`]), path, "/"];
  for (let n = 1; n <= Math.min(dirs.length, MAX_DIRS); n++) paths.push(`/${dirs.slice(0, n).join("/")}/`);
  const out = [];
  for (const h of hosts) for (const p of [...new Set(paths)]) if (!out.includes(h + p)) out.push(h + p);
  return out;
}

export class SafeBrowsing {
  // prefixes: Uint8Array of sorted 4-byte prefixes (the backend's safebrowsing.bin)
  constructor(prefixes) {
    this.prefixes = prefixes;
    this.count = Math.floor(prefixes.length / PREFIX);
  }

  has(p) {
    let lo = 0;
    let hi = this.count - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      let cmp = 0;
      for (let i = 0; i < PREFIX && cmp === 0; i++) cmp = this.prefixes[mid * PREFIX + i] - p[i];
      if (cmp === 0) return true;
      if (cmp < 0) lo = mid + 1;
      else hi = mid - 1;
    }
    return false;
  }

  // The listed expression for `url`, or null. `confirm(prefixHex)` resolves to the full hashes
  // (hex) the backend got from Google for that prefix; it may throw, which counts as "not listed".
  async match(url, confirm) {
    const byPrefix = new Map();
    for (const expr of expressions(url)) {
      const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", toBytes(expr)));
      if (!this.has(digest.subarray(0, PREFIX))) continue;
      const key = hex(digest.subarray(0, PREFIX));
      byPrefix.set(key, [...(byPrefix.get(key) ?? []), [hex(digest), expr]]);
    }
    for (const [prefix, candidates] of byPrefix) {
      let full;
      try {
        full = new Set(await confirm(prefix));
      } catch {
        continue;
      }
      const hit = candidates.find(([h]) => full.has(h));
      if (hit) return hit[1];
    }
    return null;
  }
}

// --- sync ----------------------------------------------------------------------------------------

const MIN_KEEP = 0.5; // a new file may not lose more than this share of a stored one of >= MIN_FOR_SHRINK
const MIN_FOR_SHRINK = 10000;

export function toBase64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

export const fromBase64 = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

// One sync round for GET /lists/safebrowsing.bin. `stored` is {etag, b64} or null. Returns
// {status: "unchanged" | "updated" | "none" | "rejected" | "failed", stored?, problems?}: "none" is
// a backend without a Safe Browsing key (404). The ETag and the length check stand in for the signed
// manifest: a wrong file can only cause candidate hits, and every hit is confirmed by Google's full hash.
export async function syncSafeBrowsing({ backendUrl, fetchFn = fetch, stored = null, timeoutMs = 10000 }) {
  try {
    const res = await fetchFn(`${backendUrl}/lists/safebrowsing.bin`, {
      headers: stored?.etag ? { "If-None-Match": stored.etag } : {},
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (res.status === 304) return { status: "unchanged" };
    if (res.status === 404) return { status: "none" };
    if (!res.ok) return { status: "failed", problems: [`safebrowsing.bin: HTTP ${res.status}`] };
    const bytes = new Uint8Array(await res.arrayBuffer());
    const had = stored ? fromBase64(stored.b64).length / PREFIX : 0;
    if (bytes.length % PREFIX) return { status: "rejected", problems: ["safebrowsing.bin length is not a multiple of 4"] };
    if (had >= MIN_FOR_SHRINK && bytes.length / PREFIX < MIN_KEEP * had) {
      return { status: "rejected", problems: [`safebrowsing.bin shrank to ${bytes.length / PREFIX} of ${had}`] };
    }
    return { status: "updated", stored: { etag: res.headers.get("ETag"), b64: toBase64(bytes) } };
  } catch (err) {
    return { status: "failed", problems: [String(err.message ?? err)] };
  }
}
