// Safe list sync (backend/lists.py builds and signs the lists). Pure functions: the service worker
// passes `fetch`, the stored lists and the bundled allowlist, and stores what `syncLists` returns.
//
// A synced list is applied only when
//   1. the manifest's signature verifies against the bundled public key (lists_pubkey.js; skipped
//      while that key is null, in development),
//   2. each list file's sha256 equals the one in the manifest (after a delta, the rebuilt file's),
//   3. every hash has the size the list declares and the versions agree, and
//   4. it passes the sanity limits below: the allowlist keeps most of its size, the blocklist does
//      not suddenly lose most entries, and none of the most visited sites (the bundled allowlist's
//      `top` hashes, trusted because they ship with the extension) is blocked or dropped.
// Otherwise the stored lists stay as they are and the problems are returned.

export const LIMITS = {
  minAllowFraction: 0.8, // new allowlist >= this share of the larger of the stored and bundled ones
  maxBlockShrink: 0.5, // a blocklist of >= minBlockForShrink entries may lose at most this share
  minBlockForShrink: 100,
  minTopPresent: 0.95, // this share of the bundled top sites must stay allowlisted
};

const HEX = /^[0-9a-f]+$/;

export async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

// Exact bytes the backend served for a list document (Python json.dumps with separators (",",":")
// and ensure_ascii=False, keys in the order the backend wrote them).
export function canonical(doc) {
  return JSON.stringify(doc);
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// True when `doc.signature` is a valid ECDSA P-256 / SHA-256 signature (raw r||s, base64) over the
// canonical JSON of `doc` without its signature field.
export async function verifySignature(doc, pubkey) {
  if (!pubkey?.spki || typeof doc?.signature !== "string") return false;
  const { signature, ...body } = doc;
  try {
    const key = await crypto.subtle.importKey(
      "spki",
      b64ToBytes(pubkey.spki),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      b64ToBytes(signature),
      new TextEncoder().encode(canonical(body)),
    );
  } catch {
    return false;
  }
}

function hashList(list, bytes, name, problems) {
  if (!Array.isArray(list)) {
    problems.push(`${name} is not a list`);
    return;
  }
  for (const h of list) {
    if (typeof h !== "string" || h.length !== 2 * bytes || !HEX.test(h)) {
      problems.push(`${name} has a malformed hash`);
      return;
    }
  }
}

function sizeOf(lists, name, field) {
  return lists?.[name]?.[field]?.length ?? 0;
}

// Problems with a candidate `{blocklist, allowlist}` (empty array: fine to apply).
export function checkLists(next, { stored = null, bundled = null, limits = LIMITS } = {}) {
  const problems = [];
  const block = next?.blocklist;
  const allow = next?.allowlist;
  if (!block || !allow) return ["blocklist or allowlist missing"];
  for (const [name, doc] of [["blocklist", block], ["allowlist", allow]]) {
    if (!Number.isInteger(doc.prefix_bytes) || doc.prefix_bytes < 4 || doc.prefix_bytes > 32) {
      problems.push(`${name}.prefix_bytes out of range`);
    }
  }
  if (problems.length) return problems;
  hashList(block.domains, block.prefix_bytes, "blocklist.domains", problems);
  hashList(block.urls, block.prefix_bytes, "blocklist.urls", problems);
  hashList(allow.domains, allow.prefix_bytes, "allowlist.domains", problems);
  if (!Array.isArray(allow.open_hosting ?? [])) problems.push("allowlist.open_hosting is not a list");
  if (block.version !== allow.version) problems.push("blocklist and allowlist versions differ");
  if (problems.length) return problems;

  const refAllow = Math.max(sizeOf(stored, "allowlist", "domains"), bundled?.domains?.length ?? 0);
  if (allow.domains.length < limits.minAllowFraction * refAllow) {
    problems.push(`allowlist shrank to ${allow.domains.length} of ${refAllow}`);
  }
  const oldBlock = sizeOf(stored, "blocklist", "domains") + sizeOf(stored, "blocklist", "urls");
  const newBlock = block.domains.length + block.urls.length;
  if (oldBlock >= limits.minBlockForShrink && newBlock < (1 - limits.maxBlockShrink) * oldBlock) {
    problems.push(`blocklist shrank to ${newBlock} of ${oldBlock}`);
  }
  // The most visited sites: never blocked by domain, and (almost all) still allowlisted.
  const top = bundled?.top ?? [];
  if (top.length) {
    const blocked = new Set(block.domains);
    const allowed = new Set(allow.domains);
    const cut = 2 * block.prefix_bytes;
    const hits = top.filter((h) => h.length >= cut && blocked.has(h.slice(0, cut)));
    if (hits.length) problems.push(`blocklist blocks ${hits.length} of the most visited sites`);
    if (allow.prefix_bytes === bundled.prefix_bytes) {
      const kept = top.filter((h) => allowed.has(h)).length;
      if (kept < limits.minTopPresent * top.length) {
        problems.push(`allowlist keeps only ${kept} of ${top.length} most visited sites`);
      }
    }
  }
  return problems;
}

function applySet(old, change) {
  const out = new Set(old ?? []);
  for (const x of change?.del ?? []) out.delete(x);
  for (const x of change?.add ?? []) out.add(x);
  return [...out].sort();
}

// Python sorts str with code-point order; JS sort() on these ASCII/hex strings agrees.
export function applyDelta(stored, delta) {
  const b = delta.blocklist;
  const a = delta.allowlist;
  return {
    blocklist: {
      version: b.version,
      prefix_bytes: b.prefix_bytes,
      domains: applySet(stored.blocklist.domains, b.domains),
      urls: applySet(stored.blocklist.urls, b.urls),
    },
    allowlist: {
      version: a.version,
      prefix_bytes: a.prefix_bytes,
      domains: applySet(stored.allowlist.domains, a.domains),
      open_hosting: applySet(stored.allowlist.open_hosting, a.open_hosting),
      top: a.top ?? [],
    },
  };
}

async function matchesManifest(lists, manifest) {
  const want = manifest?.sha256 ?? {};
  if (!want.blocklist || !want.allowlist) return false;
  return (
    (await sha256Hex(canonical(lists.blocklist))) === want.blocklist &&
    (await sha256Hex(canonical(lists.allowlist))) === want.allowlist
  );
}

// One sync round. Returns {status: "unchanged" | "updated" | "rejected" | "failed", lists?,
// via?, problems?}. `stored` is {version, blocklist, allowlist} or null; the caller stores
// `lists` on "updated" and should then clear any cached verdicts.
export async function syncLists({ backendUrl, fetchFn = fetch, stored = null, bundled = null, pubkey = null, timeoutMs = 10000, limits = LIMITS }) {
  const get = async (path, asText = false) => {
    const res = await fetchFn(`${backendUrl}${path}`, { signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) {
      const err = new Error(`${path}: HTTP ${res.status}`);
      err.status = res.status;
      throw err;
    }
    return asText ? res.text() : res.json();
  };
  let manifest;
  try {
    manifest = await get("/lists/manifest");
  } catch (err) {
    return { status: "failed", problems: [String(err.message ?? err)] };
  }
  if (pubkey && !(await verifySignature(manifest, pubkey))) {
    return { status: "rejected", problems: ["manifest signature does not verify"] };
  }
  if (stored?.version && stored.version === manifest.version) return { status: "unchanged" };

  let next = null;
  let via = "full";
  if (stored?.version && stored.blocklist && stored.allowlist) {
    try {
      const delta = await get(`/lists/delta?from=${encodeURIComponent(stored.version)}`);
      const candidate = applyDelta(stored, delta);
      if (delta.to === manifest.version && (await matchesManifest(candidate, manifest))) {
        next = candidate;
        via = "delta";
      }
    } catch {
      // no delta from that version (or it did not check out): download the full lists
    }
  }
  if (!next) {
    try {
      const [blockText, allowText] = await Promise.all([
        get("/lists/blocklist.json", true),
        get("/lists/allowlist.json", true),
      ]);
      const want = manifest.sha256 ?? {};
      if ((await sha256Hex(blockText)) !== want.blocklist || (await sha256Hex(allowText)) !== want.allowlist) {
        return { status: "rejected", problems: ["list file hash does not match the manifest"] };
      }
      next = { blocklist: JSON.parse(blockText), allowlist: JSON.parse(allowText) };
    } catch (err) {
      return { status: "failed", problems: [String(err.message ?? err)] };
    }
  }
  const problems = checkLists(next, { stored, bundled, limits });
  if (next.blocklist.version !== manifest.version) problems.push("list version differs from the manifest");
  if (problems.length) return { status: "rejected", problems };
  return { status: "updated", via, lists: { version: manifest.version, ...next } };
}

// --- remote config (GET /config, backend/remote_config.py) -----------------------------------

export const CONFIG_BOUNDS = { min: 0.5, max: 0.9999, maxNeverWarn: 200, syncMin: 15, syncMax: 1440 };
const DOMAIN = /^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/;

// Problems with a parsed /config document (empty array: fine to apply).
export function checkConfig(cfg, bounds = CONFIG_BOUNDS) {
  const problems = [];
  if (!cfg || typeof cfg !== "object") return ["config is not an object"];
  if (!Number.isInteger(cfg.version) || cfg.version < 1) problems.push("version");
  const m = cfg.list_sync_minutes;
  if (!Number.isInteger(m) || m < bounds.syncMin || m > bounds.syncMax) problems.push("list_sync_minutes");
  for (const model of ["address", "page"]) {
    const t = cfg.thresholds?.[model];
    if (!t) {
      problems.push(`thresholds.${model}`);
      continue;
    }
    for (const k of ["suspicious", "dangerous"]) {
      const v = t[k];
      if (v !== null && (typeof v !== "number" || v < bounds.min || v > bounds.max)) problems.push(`thresholds.${model}.${k}`);
    }
    if (t.suspicious != null && t.dangerous != null && !(t.suspicious < t.dangerous)) {
      problems.push(`thresholds.${model}: suspicious must be below dangerous`);
    }
  }
  const nw = cfg.never_warn;
  if (!Array.isArray(nw) || nw.length > bounds.maxNeverWarn || nw.some((d) => typeof d !== "string" || !DOMAIN.test(d))) {
    problems.push("never_warn");
  }
  return problems;
}

// Fetch, verify (sha256 field, and the signature when a key is bundled) and check /config.
// Returns {status: "updated" | "rejected" | "failed", config?, problems?}.
export async function fetchConfig({ backendUrl, fetchFn = fetch, pubkey = null, timeoutMs = 10000, bounds = CONFIG_BOUNDS }) {
  let doc;
  try {
    const res = await fetchFn(`${backendUrl}/config`, { signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) return { status: "failed", problems: [`/config: HTTP ${res.status}`] };
    doc = await res.json();
  } catch (err) {
    return { status: "failed", problems: [String(err.message ?? err)] };
  }
  if (pubkey && !(await verifySignature(doc, pubkey))) {
    return { status: "rejected", problems: ["config signature does not verify"] };
  }
  const { signature, sha256, ...body } = doc;
  if (sha256 !== (await sha256Hex(canonical(body)))) {
    return { status: "rejected", problems: ["config sha256 does not match"] };
  }
  const problems = checkConfig(body, bounds);
  if (problems.length) return { status: "rejected", problems };
  return { status: "updated", config: body };
}
