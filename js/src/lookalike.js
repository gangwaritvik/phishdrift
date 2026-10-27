// Offline look-alike check: a site whose name is a brand's name written with look-alike characters
// (paypa1, a Cyrillic "а" in apple) or one edit away from it (paypai), and which is not one of the
// brand's own sites. Escalate-only signal next to the models (extension/src/combine.js); it needs no
// network and sends nothing anywhere. Payload: js/data/lookalike.json (python -m features lookalike).

import { pyLower } from "./pystr.js";
import { parse } from "./urlparts.js";

const DIGITS = { 0: "o", 1: "l", 3: "e", 4: "a", 5: "s", 7: "t", 8: "b", 9: "g" };
const SEQUENCES = [["rn", "m"], ["vv", "w"]];
const cps = (s) => Array.from(s);

// ---- punycode (RFC 3492 decoder) ---------------------------------------------------------------

const BASE = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700, BIAS = 72, N0 = 128;

function adapt(delta0, numpoints, first) {
  let delta = first ? Math.floor(delta0 / DAMP) : Math.floor(delta0 / 2);
  delta += Math.floor(delta / numpoints);
  let k = 0;
  while (delta > Math.floor(((BASE - TMIN) * TMAX) / 2)) {
    delta = Math.floor(delta / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * delta) / (delta + SKEW));
}

function digitOf(ch) {
  const c = ch.codePointAt(0);
  if (c >= 48 && c <= 57) return c - 22;
  if (c >= 65 && c <= 90) return c - 65;
  if (c >= 97 && c <= 122) return c - 97;
  return BASE;
}

export function punycodeDecode(input) {
  const text = cps(input);
  let cut = -1;
  for (let j = text.length - 1; j >= 0; j--) if (text[j] === "-") { cut = j; break; }
  const out = cut > 0 ? text.slice(0, cut) : [];
  if (out.some((ch) => ch.codePointAt(0) >= 0x80)) return null;
  let i = 0, n = N0, bias = BIAS;
  let pos = cut > 0 ? cut + 1 : 0;
  while (pos < text.length) {
    const old = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (pos >= text.length) return null;
      const d = digitOf(text[pos]);
      pos += 1;
      if (d >= BASE) return null;
      i += d * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (d < t) break;
      w *= BASE - t;
      if (i > 0x10ffff * 4) return null;
    }
    const size = out.length + 1;
    bias = adapt(i - old, size, old === 0);
    n += Math.floor(i / size);
    i %= size;
    if (n > 0x10ffff || (n >= 0xd800 && n <= 0xdfff)) return null;
    out.splice(i, 0, String.fromCodePoint(n));
    i += 1;
  }
  return out.join("");
}

export function decodeLabel(label) {
  if (label.startsWith("xn--")) {
    const decoded = punycodeDecode(label.slice(4));
    if (decoded) return pyLower(decoded);
  }
  return label;
}

// Restricted Damerau-Levenshtein distance exactly 1 (insertion, deletion, substitution or swap of
// neighbouring letters), on code points.
export function withinOne(a0, b0) {
  if (a0 === b0) return false;
  const a = cps(a0);
  const b = cps(b0);
  const la = a.length, lb = b.length;
  if (Math.abs(la - lb) > 1) return false;
  let i = 0;
  while (i < la && i < lb && a[i] === b[i]) i++;
  const eq = (x, y) => x.length === y.length && x.every((c, j) => c === y[j]);
  if (la === lb) {
    if (eq(a.slice(i + 1), b.slice(i + 1))) return true;
    return i + 1 < la && a[i] === b[i + 1] && a[i + 1] === b[i] && eq(a.slice(i + 2), b.slice(i + 2));
  }
  if (la > lb) return eq(a.slice(i + 1), b.slice(i));
  return eq(a.slice(i), b.slice(i + 1));
}

// ---- the rule ----------------------------------------------------------------------------------

// platforms: Set of hosting-platform domains (their sites belong to tenants, not to a brand).
export function loadLookalike(payload, pslRoot, platforms = new Set()) {
  const rules = {
    skeletonMap: payload.skeleton_map,
    brandSet: new Set(payload.brands),
    official: new Set(payload.domains),
    on: new Set(payload.rules),
    minEditLen: payload.min_edit_len,
    platforms,
    psl: pslRoot,
    targets: new Map(), // skeleton of a brand name -> brand names
  };
  for (const b of [...payload.brands].sort()) {
    const k = skeleton(rules, b);
    if (!rules.targets.has(k)) rules.targets.set(k, []);
    rules.targets.get(k).push(b);
  }
  rules.targetKeys = [...rules.targets.keys()].sort();
  return rules;
}

export function skeleton(rules, text) {
  let out = cps(pyLower(text))
    .map((c) => rules.skeletonMap[c] ?? DIGITS[c] ?? c)
    .join("");
  for (const [src, dst] of SEQUENCES) out = out.replaceAll(src, dst);
  return out;
}

// null, or { rule: "homograph" | "edit1", brand, text } for the address's registrable name.
export function lookalikeSignal(rules, url) {
  const p = typeof url === "string" ? parse(url, rules.platforms, rules.psl) : null;
  if (p === null || p.isIp || p.isPlatform || !p.suffix) return null;
  const { domain, label } = p;
  if (rules.official.has(domain) || rules.brandSet.has(label) || rules.brandSet.has(label.replaceAll("-", ""))) return null;
  const dlabel = decodeLabel(label);
  const skel = skeleton(rules, dlabel);
  if (rules.on.has("homograph") && skel !== dlabel) {
    // "1" stands for "l" (app1e) or "i" (c1tibank): try both readings
    const alt = dlabel.includes("1") ? skeleton(rules, dlabel.replaceAll("1", "i")) : skel;
    const found = [skel, alt].find((k) => rules.targets.has(k));
    if (found !== undefined) {
      const brand = rules.targets.get(found)[0];
      return { rule: "homograph", brand, text: `This address looks like "${brand}" but is written with look-alike characters.` };
    }
  }
  if (rules.on.has("edit1") && cps(skel).length >= rules.minEditLen - 1) {
    const n = cps(skel).length;
    for (const t of rules.targetKeys) {
      const m = cps(t).length;
      // one letter added to a short name often spells another real name
      if (m < rules.minEditLen || (n > m && m <= rules.minEditLen) || cps(t)[0] !== cps(skel)[0]) continue;
      if (withinOne(skel, t)) {
        const brand = rules.targets.get(t)[0];
        return { rule: "edit1", brand, text: `This address is one letter away from "${brand}".` };
      }
    }
  }
  return null;
}
