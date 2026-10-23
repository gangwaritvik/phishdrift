// Offline look-alike check: does the registrable name imitate a brand from the model's brand list?
// Escalate-only evidence for the combiner (extension/src/combine.js `lookalikeEscalate`); it works
// without the backend or the language model. A name that IS a brand (on any suffix) is never a hit.
//   homoglyph: "paypa1", "rnicrosoft", "g00gle" fold to a brand once look-alike characters are mapped
//   hyphen:    "paypal-secure-login": a brand word next to a lure word (login, secure, verify, ...)
//   subdomain: "paypal.com.evil.net", "paypal.login.evil.net" put a brand where the site name goes

import { parse } from "./urlparts.js";

const MIN_EMBEDDED_LEN = 5; // shorter brand names occur inside ordinary words and subdomains
const SINGLE = { 0: "o", 3: "e", 4: "a", 5: "s", 8: "b", "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ѕ": "s", "ӏ": "l", "ο": "o", "ν": "v" };

// All readings of a label with look-alike characters mapped ("1" may be l or i).
function folds(label) {
  const base = [...label.normalize("NFKD").replace(/\p{M}/gu, "")].map((ch) => SINGLE[ch] ?? ch).join("").replaceAll("rn", "m").replaceAll("vv", "w");
  return [...new Set([base.replaceAll("1", "l"), base.replaceAll("1", "i")])];
}

// -> { brand, kind } | null
export function lookalikeHit(model, url) {
  let p;
  try {
    p = parse(url, model.lists.platforms, model.lists.psl);
  } catch {
    return null;
  }
  if (!p || p.isIp || p.isPlatform || !p.label) return null;
  const brands = model.lists.brandSet;
  if (brands.has(p.label)) return null;
  for (const f of folds(p.label)) {
    if (brands.has(f)) return { brand: f, kind: "homoglyph" };
  }
  const brandIn = (text) => {
    for (const w of text.split(/[^\p{L}\p{N}]+/u)) for (const f of folds(w)) if (f.length >= MIN_EMBEDDED_LEN && brands.has(f)) return f;
    return null;
  };
  const words = p.label.split("-");
  const lure = model.lists.keywords.some((k) => words.includes(k));
  const inLabel = words.length > 1 && lure ? brandIn(p.label) : null;
  if (inLabel) return { brand: inLabel, kind: "hyphen" };
  const sub = p.subdomain ? brandIn(p.subdomain) : null;
  return sub ? { brand: sub, kind: "subdomain" } : null;
}

export const lookalikeReason = (hit) =>
  hit.kind === "homoglyph"
    ? `This address spells "${hit.brand}" with look-alike characters, a common phishing trick.`
    : hit.kind === "hyphen"
      ? `This address puts "${hit.brand}" in a made-up site name, a common phishing trick.`
      : `This address puts "${hit.brand}" in front of a different site's name, a common phishing trick.`;
