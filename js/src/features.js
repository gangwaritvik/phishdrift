// Tier A URL features, a line-by-line port of features/url_features.py.
// Strings are handled as arrays of code points (Array.from) wherever Python uses len() or
// indexing, so non-ASCII URLs give the same numbers. Missing values are NaN, never 0.

import { buildTrie } from "./psl.js";
import { isDigitStr, parse, words } from "./urlparts.js";

const CHARS = {
  dot: ".", hyphen: "-", underscore: "_", slash: "/", at: "@", qmark: "?", and: "&", eq: "=",
  percent: "%", tilde: "~", plus: "+", star: "*", colon: ":", comma: ",", semicolon: ";",
  dollar: "$", pipe: "|", space: " ",
};
const VOWELS = "aeiou";
const PCT = /%[0-9a-fA-F]{2}/g;
const EMAIL = /[a-z0-9._+\-]+@[a-z0-9\-]+\.[a-z]{2,}/;
const EMBEDDED = /https?(?::\/\/|%3a%2f%2f|%253a%252f%252f)/;
const EXT = /\.([a-z0-9]{1,5})$/;
const SCRIPT_EXT = new Set(["php", "asp", "aspx", "jsp", "cgi"]);
const HTML_EXT = new Set(["html", "htm", "shtml"]);
const HOMOGLYPHS = {
  0: "o", 1: "l", 3: "e", 4: "a", 5: "s", 7: "t", 8: "b", 9: "g",
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
  "ı": "i", "ɡ": "g", "ɑ": "a", "ο": "o", "ν": "v",
};
const HOMOGLYPH_SEQ = [["rn", "m"], ["vv", "w"], ["cl", "d"]];
export const MIN_BRAND_LEN = 4;

const cps = (s) => Array.from(s);
const len = (s) => cps(s).length;
const isDigit = (c) => c >= "0" && c <= "9";
const isLetter = (c) => {
  const l = c.toLowerCase();
  return l >= "a" && l <= "z";
};
const ratio = (count, total) => (total ? count / total : NaN);
const count = (text, ch) => text.split(ch).length - 1;
const hits = (text, vocab) => vocab.reduce((n, w) => n + (text.includes(w) ? 1 : 0), 0);

function entropy(text) {
  const chars = cps(text);
  if (!chars.length) return NaN;
  const counts = new Map();
  for (const c of chars) counts.set(c, (counts.get(c) || 0) + 1);
  let h = 0;
  for (const c of counts.values()) h -= (c / chars.length) * Math.log2(c / chars.length);
  return h;
}

function wordStats(ws) {
  if (!ws.length) return [NaN, NaN, NaN];
  const lens = ws.map((w) => w.length);
  return [Math.min(...lens), Math.max(...lens), lens.reduce((a, b) => a + b, 0) / lens.length];
}

function longestRun(text, same) {
  let best = 0;
  let run = 0;
  let prev = null;
  for (const ch of cps(text)) {
    run = prev !== null && same(prev, ch) ? run + 1 : 1;
    best = Math.max(best, run);
    prev = ch;
  }
  return best;
}

const charClass = (c) => (isLetter(c) ? 0 : isDigit(c) ? 1 : 2);

export function editDistance(a, b) {
  const x = cps(a);
  const y = cps(b);
  let prev = Array.from({ length: y.length + 1 }, (_, j) => j);
  for (let i = 1; i <= x.length; i++) {
    const cur = [i];
    for (let j = 1; j <= y.length; j++) {
      cur.push(Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (x[i - 1] !== y[j - 1] ? 1 : 0)));
    }
    prev = cur;
  }
  return prev[prev.length - 1];
}

export function normaliseHomoglyphs(label) {
  let out = cps(label).map((c) => HOMOGLYPHS[c] ?? c).join("");
  for (const [src, dst] of HOMOGLYPH_SEQ) out = out.replaceAll(src, dst);
  return out;
}

// Lists as Lists.build() makes them in Python, from the payload of js/data/lists.json.
export function buildLists(payload, pslRules) {
  const brands = [...new Set(payload.brands.filter((b) => len(b) >= MIN_BRAND_LEN))].sort();
  return {
    platforms: new Set(payload.platforms),
    brands,
    brandSet: new Set(brands),
    keywords: [...new Set(payload.keywords)].sort(),
    shorteners: new Set(payload.shorteners),
    suspiciousTlds: new Set(payload.suspicious_tlds),
    redirectParams: new Set(payload.redirect_params),
    fitted: payload.fitted,
    psl: buildTrie(pslRules),
  };
}

function lengthGroup(p) {
  const out = {
    url_len: len(p.canon), host_len: len(p.host), domain_len: len(p.domain),
    subdomain_len: len(p.subdomain), path_len: len(p.path), query_len: len(p.query),
    tld_len: len(p.suffix),
  };
  for (const [scope, text] of [["url", p.canon], ["host", p.host], ["path", p.path]]) {
    const [lo, hi, avg] = wordStats(words(text));
    out[`shortest_word_${scope}`] = lo;
    out[`longest_word_${scope}`] = hi;
    out[`avg_word_${scope}`] = avg;
  }
  return out;
}

function countsGroup(p) {
  const out = {};
  for (const [key, ch] of Object.entries(CHARS)) out[`n_${key}`] = count(p.canon, ch);
  out.host_n_dot = count(p.host, ".");
  out.host_n_hyphen = count(p.host, "-");
  out.n_digits = cps(p.canon).filter(isDigit).length;
  out.n_letters = cps(p.canon).filter(isLetter).length;
  out.n_subdomain_levels = p.subdomain ? p.subdomain.split(".").length : 0;
  out.path_depth = p.path.split("/").filter((s) => s).length;
  out.n_query_params = p.query.split("&").filter((s) => s).length;
  const tokens = words(p.host).concat(words(p.path));
  out.n_www_tokens = tokens.filter((t) => t === "www").length;
  out.n_com_tokens = tokens.filter((t) => t === "com").length;
  return out;
}

function ratiosGroup(p) {
  const out = {};
  for (const [scope, text] of [["url", p.canon], ["host", p.host]]) {
    const chars = cps(text);
    const digits = chars.filter(isDigit).length;
    const letters = chars.filter(isLetter).length;
    out[`digit_ratio_${scope}`] = ratio(digits, chars.length);
    out[`letter_ratio_${scope}`] = ratio(letters, chars.length);
    out[`special_ratio_${scope}`] = ratio(chars.length - digits - letters, chars.length);
  }
  return out;
}

function ipObfuscated(host) {
  const tail = host.slice(2);
  if (host.startsWith("0x") && tail && cps(tail).every((c) => "0123456789abcdef".includes(c))) return true;
  if (isDigitStr(host) && len(host) >= 8) return true;
  const parts = host.split(".");
  if (parts.length === 4 && parts.every((x) => isDigitStr(x) || x.startsWith("0x"))) {
    return parts.some((x) => len(x) > 1 && x.startsWith("0"));
  }
  return false;
}

function hostFormGroup(p) {
  const subLabels = p.subdomain ? p.subdomain.split(".") : [];
  const lastTld = p.suffix ? p.suffix.split(".").pop() : "";
  const pathWords = words(p.path);
  const seg = p.path.split("/").pop();
  const m = seg.toLowerCase().match(EXT);
  const ext = m ? m[1] : "";
  const hostLabels = p.host.split(".");
  const pathLower = p.path.toLowerCase();
  return {
    host_is_ip: +p.isIp,
    host_ip_obfuscated: +ipObfuscated(p.host),
    has_port: +(p.port !== ""),
    nonstandard_port: +!["", "80", "443"].includes(p.port),
    has_userinfo: +(p.userinfo !== ""),
    has_punycode: +p.host.includes("xn--"),
    has_non_ascii_host: +cps(p.host).some((c) => c.codePointAt(0) > 127),
    https_in_host: +p.host.includes("https"),
    http_in_path: +pathLower.includes("http"),
    www_in_path: +pathLower.includes("www"),
    www_misplaced_host: +hostLabels.includes("www"),
    double_slash_in_path: +p.path.includes("//"),
    tld_in_path: +(Boolean(lastTld) && pathWords.includes(lastTld)),
    tld_in_subdomain: +(Boolean(lastTld) && subLabels.includes(lastTld)),
    abnormal_subdomain: +(subLabels.length > 3 || subLabels.some((x) => len(x) > 25)),
    prefix_suffix_hyphen: +p.label.includes("-"),
    path_ext_present: +(ext !== ""),
    path_ext_is_script: +SCRIPT_EXT.has(ext),
    path_ext_is_html: +HTML_EXT.has(ext),
  };
}

function obfuscationGroup(p) {
  const n = len(p.canon);
  const nPct = (p.canon.match(PCT) || []).length;
  return {
    n_pct_encoded: nPct,
    pct_encoded_ratio: ratio(3 * nPct, n),
    longest_repeat_run: longestRun(p.canon, (a, b) => a === b),
    char_continuation_rate: ratio(longestRun(p.canon, (a, b) => charClass(a) === charClass(b)), n),
    n_non_ascii_url: cps(p.canon).filter((c) => c.codePointAt(0) > 127).length,
  };
}

function bigramLoglik(label, fitted) {
  const chars = cps(label);
  const table = fitted.bigram_logprob || {};
  if (!Object.keys(table).length || chars.length < 2) return NaN;
  let total = 0;
  for (let i = 0; i < chars.length - 1; i++) {
    const pair = chars[i] + chars[i + 1];
    total += Object.hasOwn(table, pair) ? table[pair] : fitted.bigram_floor;
  }
  return total / (chars.length - 1);
}

function randomnessGroup(p, fitted) {
  const label = cps(p.label);
  const letters = label.filter(isLetter);
  let consonantRun = 0;
  let run = 0;
  for (const c of label) {
    run = isLetter(c) && !VOWELS.includes(c) ? run + 1 : 0;
    consonantRun = Math.max(consonantRun, run);
  }
  let switches = 0;
  for (let i = 0; i + 1 < label.length; i++) {
    const [a, b] = [label[i], label[i + 1]];
    if ((isDigit(a) && isLetter(b)) || (isLetter(a) && isDigit(b))) switches += 1;
  }
  return {
    entropy_url: entropy(p.canon),
    entropy_domain: entropy(p.label),
    bigram_loglik_domain: bigramLoglik(p.label, fitted),
    domain_longest_consonant_run: letters.length ? consonantRun : 0,
    domain_vowel_ratio: ratio(letters.filter((c) => VOWELS.includes(c)).length, letters.length),
    domain_digit_switches: switches,
  };
}

function wordsGroup(p, lists) {
  const host = p.host;
  const path = p.path.toLowerCase();
  const query = p.query.toLowerCase();
  const kw = lists.keywords;
  const exact = lists.brandSet.has(p.label);
  return {
    n_suspicious_keywords: hits(`${host}/${path}?${query}`, kw),
    kw_in_host: hits(host, kw),
    kw_in_path: hits(path, kw),
    kw_in_query: hits(query, kw),
    brand_in_subdomain: hits(p.subdomain, lists.brands),
    brand_in_path: hits(path, lists.brands),
    domain_is_brand: +exact,
    domain_contains_brand: +(Boolean(p.label) && !exact && lists.brands.some((b) => p.label.includes(b))),
  };
}

const SQUAT_NAMES = [
  "min_brand_edit_distance", "homoglyph_brand_match", "combosquat_prefix", "combosquat_suffix",
  "combosquat_middle",
];

function squattingGroup(p, lists) {
  const label = p.label;
  if (p.isIp || !label || !lists.brands.length) {
    return Object.fromEntries(SQUAT_NAMES.map((n) => [n, NaN]));
  }
  // Python checks only brands within edit distance 2 (symmetric-delete index) and caps at 3;
  // scanning every brand with the same cap gives the same number.
  let dist = 3;
  const n = len(label);
  for (const b of lists.brands) {
    if (Math.abs(len(b) - n) > 2) continue;
    dist = Math.min(dist, editDistance(label, b));
  }
  const parts = label.replaceAll("_", "-").split("-").filter((x) => x);
  const fixed = parts.map(normaliseHomoglyphs);
  const homoglyph = parts.some((x, i) => fixed[i] !== x && lists.brandSet.has(fixed[i]));
  const brandParts = [];
  parts.forEach((x, i) => {
    if (lists.brandSet.has(x) || lists.brandSet.has(fixed[i])) brandParts.push(i);
  });
  const combo = parts.length > 1;
  return {
    min_brand_edit_distance: dist,
    homoglyph_brand_match: +homoglyph,
    combosquat_prefix: +(combo && brandParts.includes(0)),
    combosquat_suffix: +(combo && brandParts.includes(parts.length - 1)),
    combosquat_middle: +brandParts.some((i) => i > 0 && i < parts.length - 1),
  };
}

function tldRisk(p, fitted) {
  const table = fitted.tld_risk || {};
  if (p.isIp || !p.suffix || !Object.keys(table).length) return NaN;
  return Object.hasOwn(table, p.suffix) ? table[p.suffix] : fitted.tld_default;
}

function otherGroup(p, lists, fitted) {
  const keys = new Set(p.query.split("&").filter((kv) => kv).map((kv) => kv.split("=")[0].toLowerCase()));
  const tail = `${p.path}?${p.query}`.toLowerCase();
  const tld = p.suffix ? p.suffix.split(".").pop() : "";
  return {
    is_shortener: +lists.shorteners.has(p.domain),
    has_redirect_param: +[...keys].some((k) => lists.redirectParams.has(k)),
    has_embedded_url: +EMBEDDED.test(tail),
    has_embedded_email: +EMAIL.test(tail),
    suspicious_tld: +lists.suspiciousTlds.has(tld),
    tld_risk: tldRisk(p, fitted),
    is_hosting_platform: +p.isPlatform,
  };
}

// All tier A features of one URL, keyed by name. `names` (the registry order) fills NaN for an
// unparsable URL.
export function extract(url, lists, names) {
  const p = typeof url === "string" ? parse(url, lists.platforms, lists.psl) : null;
  if (p === null) return Object.fromEntries(names.map((n) => [n, NaN]));
  return {
    ...lengthGroup(p), ...countsGroup(p), ...ratiosGroup(p), ...hostFormGroup(p),
    ...obfuscationGroup(p), ...randomnessGroup(p, lists.fitted), ...wordsGroup(p, lists),
    ...squattingGroup(p, lists), ...otherGroup(p, lists, lists.fitted),
  };
}

