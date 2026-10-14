// Python str and re behaviour that JavaScript does not share, for the tier B port.
//
// - Lengths and slices are in code points (Python len), not UTF-16 units (JS .length).
// - Whitespace is Python's str.isspace set (= re \s): it has \x1c-\x1f and \x85 and lacks
//   ﻿, unlike JS trim() and \s.
// - re \w, \W, \b and \s are Unicode-aware in Python; pyRegex() rewrites a Python pattern
//   into a JS one using the code-point sets exported from Python (js/src/pydata.js).
// - re.IGNORECASE: Python also matches U+0130 and U+0131 with "i"; JS (flag iu) folds U+017F
//   and U+212A like Python but not those two, so foldI() maps them to "i" before matching
//   (same length, so match offsets stay valid on the original string).
// - str.lower(): code points unassigned in Python's Unicode database stay as they are.

import { SPACE_RANGES, UNASSIGNED_RANGES, WORD_RANGES } from "./pydata.js";

const hex = (n) => `\\u{${n.toString(16)}}`;
const classBody = (ranges) => ranges.map(([a, b]) => (a === b ? hex(a) : `${hex(a)}-${hex(b)}`)).join("");

export const SPACE = classBody(SPACE_RANGES); // body of a character class (no brackets)
export const WORD = classBody(WORD_RANGES);
const UNASSIGNED = new RegExp(`[${classBody(UNASSIGNED_RANGES)}]`, "u");
const UNASSIGNED_G = new RegExp(`[${classBody(UNASSIGNED_RANGES)}]`, "gu");
const NON_ASCII = /[^\x00-\x7f]/;
const SURROGATE = /[\ud800-\udfff]/;
const SPACE_RUNS = new RegExp(`[${SPACE}]+`, "gu");
const SPACE_CODES = new Set();
for (const [a, b] of SPACE_RANGES) for (let c = a; c <= b; c++) SPACE_CODES.add(c); // all BMP

// Python len(s).
export function cpLen(s) {
  if (!SURROGATE.test(s)) return s.length;
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) i++;
    }
    n++;
  }
  return n;
}

// UTF-16 index of the code point `n` places after unit index `from` (clamped to the end).
export function cpForward(s, from, n) {
  let i = from;
  for (let k = 0; k < n && i < s.length; k++) {
    const c = s.charCodeAt(i);
    i += c >= 0xd800 && c <= 0xdbff && i + 1 < s.length && (s.charCodeAt(i + 1) & 0xfc00) === 0xdc00 ? 2 : 1;
  }
  return i;
}

// UTF-16 index of the code point `n` places before unit index `from` (clamped to 0).
export function cpBack(s, from, n) {
  let i = from;
  for (let k = 0; k < n && i > 0; k++) {
    const c = s.charCodeAt(i - 1);
    i -= (c & 0xfc00) === 0xdc00 && i - 2 >= 0 && (s.charCodeAt(i - 2) & 0xfc00) === 0xd800 ? 2 : 1;
  }
  return i;
}

// Python s[:n] for n >= 0.
export function cpHead(s, n) {
  if (s.length <= n) return s; // at most n units means at most n code points
  if (!SURROGATE.test(s)) return s.slice(0, n);
  return s.slice(0, cpForward(s, 0, n));
}

// Python s.strip() with no argument.
export function pyStrip(s) {
  let a = 0;
  let b = s.length;
  while (a < b && SPACE_CODES.has(s.charCodeAt(a))) a++;
  while (b > a && SPACE_CODES.has(s.charCodeAt(b - 1))) b--;
  return a === 0 && b === s.length ? s : s.slice(a, b);
}

// Python s.strip(chars) for a set of BMP characters.
export function stripChars(s, chars) {
  let a = 0;
  let b = s.length;
  while (a < b && chars.includes(s[a])) a++;
  while (b > a && chars.includes(s[b - 1])) b--;
  return s.slice(a, b);
}

// Python " ".join(s.split()).
export function pyJoinSplit(s) {
  return pyStrip(s.replace(SPACE_RUNS, " "));
}

// Python s.lower().
export function pyLower(s) {
  if (!NON_ASCII.test(s)) return s.toLowerCase();
  if (!UNASSIGNED.test(s)) return s.toLowerCase();
  let out = "";
  let last = 0;
  for (const m of s.matchAll(UNASSIGNED_G)) {
    out += s.slice(last, m.index).toLowerCase() + m[0];
    last = m.index + m[0].length;
  }
  return out + s.slice(last).toLowerCase();
}

// String to run an re.IGNORECASE pattern on (see the header).
export function foldI(s) {
  return s.replace(/[İı]/g, "i");
}

// A Python pattern as a JS RegExp (always flag u). Outside character classes \s \S \w \W \b
// become Python's sets, "." becomes [^\n] and "$" becomes (?=\n?$); inside classes \s and \w
// are expanded. Other escapes are kept (\- only inside classes).
export function pyRegex(source, flags = "") {
  let out = "";
  let inClass = false;
  for (let i = 0; i < source.length; i++) {
    const ch = source[i];
    if (ch === "\\") {
      const nx = source[i + 1];
      i++;
      if (nx === "s") out += inClass ? SPACE : `[${SPACE}]`;
      else if (nx === "w") out += inClass ? WORD : `[${WORD}]`;
      else if (nx === "S" && !inClass) out += `[^${SPACE}]`;
      else if (nx === "W" && !inClass) out += `[^${WORD}]`;
      else if (nx === "b" && !inClass) out += `(?:(?<=[${WORD}])(?![${WORD}])|(?<![${WORD}])(?=[${WORD}]))`;
      else if ("SWbBdD".includes(nx)) throw new Error(`pyRegex: unsupported \\${nx}`);
      else out += `\\${nx}`;
      continue;
    }
    if (inClass) {
      if (ch === "]") inClass = false;
      out += ch;
    } else if (ch === "[") {
      inClass = true;
      out += ch;
      if (source[i + 1] === "^") out += source[++i];
      if (source[i + 1] === "]") out += `\\${source[++i]}`; // a leading ] is literal in Python
    } else if (ch === ".") out += "[^\\n]";
    else if (ch === "$") out += "(?=\\n?$)";
    else out += ch;
  }
  return new RegExp(out, `u${flags}`);
}
