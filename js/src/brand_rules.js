// Brand and look-alike rules in the browser, mirroring features/brand_rules.py step by step.
// Escalate-only signals next to the models (extension/src/combine.js): address rules
// (homograph, embedded, edit1, combo) and the brand-page rule (brand shown + credential field +
// not the brand's domain). Payload: js/data/brand_rules.json (python -m features export-rules).
// Parity with Python: tests/fixtures/brand_rules_parity.json.

import { splitHost } from "./psl.js";
import { pyLower } from "./pystr.js";
import { parse } from "./urlparts.js";

const MIN_BRAND_LEN = 4;
const DIGITS = { 0: "o", 1: "l", 3: "e", 4: "a", 5: "s", 7: "t", 8: "b", 9: "g" };
const SEQUENCES = [["rn", "m"], ["vv", "w"]];
const NO_PLATFORMS = new Set();
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

// Restricted Damerau-Levenshtein distance exactly 1 (on code points).
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

// payload: js/data/brand_rules.json; pslRoot: the model's public-suffix trie; platforms: Set.
export function loadBrandRules(payload, pslRoot, platforms = NO_PLATFORMS) {
  const brands = [...new Set(payload.brands.filter((b) => cps(b).length >= MIN_BRAND_LEN))].sort();
  const brandDomains = {};
  for (const [b, ds] of Object.entries(payload.brand_domains)) if (ds.length) brandDomains[b] = [...new Set(ds)].sort();
  const rules = {
    skeletonMap: payload.skeleton_map,
    brandDomains,
    brands,
    brandSet: new Set(brands),
    lures: new Set(payload.lures),
    minEditLen: payload.min_edit_len,
    minComboLen: payload.min_combo_len,
    enabled: new Set(payload.enabled),
    catcher: payload.catcher,
    platforms,
    psl: pslRoot,
    official: new Map(),
    targets: new Map(),
  };
  for (const b of Object.keys(brandDomains).sort()) {
    for (const d of brandDomains[b]) {
      const lab = d.split(".")[0];
      if (lab === b || !rules.official.has(d)) {
        rules.official.set(d, lab === b || !(lab in brandDomains) ? b : lab);
      }
    }
  }
  for (const b of brands) {
    const k = skeleton(rules, b);
    if (!rules.targets.has(k)) rules.targets.set(k, []);
    rules.targets.get(k).push(b);
  }
  for (const v of rules.targets.values()) v.sort();
  rules.targetKeys = [...rules.targets.keys()].sort(); // Python sorted() (keys are BMP text)
  return rules;
}

export function skeleton(rules, text) {
  let out = cps(pyLower(text))
    .map((c) => rules.skeletonMap[c] ?? DIGITS[c] ?? c)
    .join("");
  for (const [src, dst] of SEQUENCES) out = out.replaceAll(src, dst);
  return out;
}

export function owns(rules, brand, domain, label) {
  return label === brand || (rules.brandDomains[brand] ?? []).includes(domain) || rules.official.get(domain) === brand;
}

function hit(rule, brand, domain, extra = "") {
  const text = {
    homograph: `This address looks like "${brand}" but is written with look-alike characters.`,
    embedded: `This address puts ${extra} in front of a different website (${domain}).`,
    edit1: `This address is one letter away from "${brand}".`,
    combo: `This address joins the name "${brand}" with "${extra}", but ${domain} does not belong to ${brand}.`,
  }[rule];
  return { rule, brand, text };
}

function embedded(rules, front) {
  const labels = front.replaceAll("-", ".").split(".").filter((x) => x);
  for (let i = 0; i < labels.length; i++) {
    for (let j = i + 2; j <= Math.min(labels.length, i + 4); j++) {
      const cand = labels.slice(i, j).join(".");
      if (rules.official.has(cand)) return [rules.official.get(cand), cand];
      const [sub, lab, suf] = splitHost(cand, rules.psl);
      if (!sub && suf && rules.brandSet.has(lab)) return [lab, cand];
    }
  }
  return null;
}

function lureWords(rules, text) {
  if (rules.lures.has(text)) return true;
  const c = cps(text);
  for (let i = 1; i < c.length; i++) {
    if (rules.lures.has(c.slice(0, i).join("")) && rules.lures.has(c.slice(i).join(""))) return true;
  }
  return false;
}

function combo(rules, skel) {
  for (const b of rules.brands) {
    if (cps(b).length < rules.minComboLen || !skel.includes(b) || skel === b) continue;
    const rest = skel.replace(b, "-").split("-").filter((x) => x);
    if (rest.length && rest.every((x) => lureWords(rules, x))) return [b, rest.join(" ")];
  }
  return null;
}

export function addressSignals(rules, url) {
  const p = typeof url === "string" ? parse(url, NO_PLATFORMS, rules.psl) : null;
  if (p === null || p.isIp || !p.suffix) return [];
  const { domain, label } = p;
  if (rules.official.has(domain) || rules.brandSet.has(label) || rules.brandSet.has(label.replaceAll("-", ""))) return [];
  const dlabel = decodeLabel(label);
  const skel = skeleton(rules, dlabel);
  const hits = [];
  const on = rules.enabled;
  if (on.has("homograph") && skel !== dlabel) {
    // "1" stands for "l" (app1e) or "i" (c1tibank): try both readings
    const alt = dlabel.includes("1") ? skeleton(rules, dlabel.replaceAll("1", "i")) : skel;
    const found = [skel, alt].find((k) => rules.targets.has(k));
    if (found !== undefined) hits.push(hit("homograph", rules.targets.get(found)[0], domain));
  }
  if (on.has("embedded") && p.subdomain) {
    const b = embedded(rules, `${p.subdomain}.${label}`);
    if (b) hits.push(hit("embedded", b[0], domain, b[1]));
  }
  if (on.has("edit1") && cps(skel).length >= rules.minEditLen - 1 && !hits.length) {
    const n = cps(skel).length;
    for (const t of rules.targetKeys) {
      // one letter added to a short name often spells another real name (vivacom)
      if (n > cps(t).length && cps(t).length <= rules.minEditLen) continue;
      if (cps(t).length >= rules.minEditLen && cps(t)[0] === cps(skel)[0] && withinOne(skel, t)) {
        hits.push(hit("edit1", rules.targets.get(t)[0], domain));
        break;
      }
    }
  }
  if (on.has("combo") && !hits.length) {
    let b = combo(rules, skel);
    if (!b && rules.platforms.has(domain) && p.subdomain) {
      const parts = p.subdomain.split(".");
      b = combo(rules, skeleton(rules, decodeLabel(parts[parts.length - 1])));
    }
    if (b) hits.push(hit("combo", b[0], domain, b[1]));
  }
  return hits;
}

// Brands the page presents itself as (page_claims in Python).
export function pageClaims(facts) {
  const site = [...(facts.site_brands ?? [])];
  if (facts.site_named && !site.length) return [];
  const claimed = [...site];
  const title = facts.title_brands ?? [];
  if (title.length && (facts.title_login || title.includes(facts.title_norm))) {
    for (const b of title) if (!claimed.includes(b)) claimed.push(b);
  }
  for (const b of facts.copyright_brands ?? []) if (!claimed.includes(b)) claimed.push(b);
  return claimed;
}

export function credentialFields(facts) {
  return (facts.password_fields ?? 0) + (facts.otp_fields ?? 0) + (facts.card_fields ?? 0) + (facts.pin_fields ?? 0);
}

export function pageSignal(rules, url, facts) {
  if (!facts || !credentialFields(facts)) return null;
  const p = typeof url === "string" ? parse(url, NO_PLATFORMS, rules.psl) : null;
  if (p === null || (!p.suffix && !p.isIp)) return null;
  const [domain, label] = p.isIp ? [p.host, p.host] : [p.domain, p.label];
  const claimed = pageClaims(facts);
  if (!claimed.length || claimed.some((b) => owns(rules, b, domain, label))) return null;
  const b = claimed[0];
  return {
    rule: "brand_page",
    brand: b,
    text: `This page shows the name "${b}" and asks for a password or code, but ${domain} does not belong to ${b}.`,
  };
}

// phishing_catcher-style host score (a baseline, not a model feature); catcher_score in Python.
export function catcherScore(rules, url, suspiciousTlds) {
  const p = typeof url === "string" ? parse(url, NO_PLATFORMS, rules.psl) : null;
  if (p === null) return NaN;
  const cfg = rules.catcher;
  const w = cfg.weights;
  const host = p.host;
  let score = 0;
  for (const word of host.replaceAll("-", ".").split(".").filter((x) => x)) {
    if (rules.lures.has(word)) score += w.lure;
    if (rules.brandSet.has(word) && !owns(rules, word, p.domain, p.label)) score += w.brand;
  }
  const skel = skeleton(rules, decodeLabel(p.label));
  if (cps(skel).length >= rules.minEditLen && !rules.official.has(p.domain) && !rules.brandSet.has(p.label)) {
    for (const t of rules.targets.keys()) {
      if (cps(t).length >= rules.minEditLen && withinOne(skel, t)) {
        score += w.brand_typo;
        break;
      }
    }
  }
  const chars = cps(host);
  const counts = new Map();
  for (const c of chars) counts.set(c, (counts.get(c) || 0) + 1);
  let entropy = 0;
  for (const c of counts.values()) entropy -= (c / chars.length) * Math.log2(c / chars.length);
  score += w.entropy * (chars.length ? entropy : 0);
  if (!host.includes("xn--")) score += w.hyphen * (host.split("-").length - 1);
  else score += w.punycode;
  if (p.subdomain) score += w.dot * Math.max(0, p.subdomain.split(".").length - cfg.free_levels);
  const tld = p.suffix ? p.suffix.split(".").pop() : "";
  if (suspiciousTlds.has(tld)) score += w.tld;
  return score;
}
