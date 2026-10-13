// Public-suffix split of a host, mirroring tldextract (ICANN rules only), which is what
// phishdrift.domains.split_host uses in Python. The rules come from js/data/psl_icann.json
// (python -m features export-js); non-ASCII rules are also listed in punycode, so xn-- labels
// match without an IDNA decoder.

import { pyStrip } from "./pystr.js";

const IPV4 =
  /^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/;

export function buildTrie(rules) {
  const root = { matches: new Map(), end: false };
  for (const rule of rules) {
    let node = root;
    for (const label of rule.split(".").reverse()) {
      if (!node.matches.has(label)) node.matches.set(label, { matches: new Map(), end: false });
      node = node.matches.get(label);
    }
    node.end = true;
  }
  return root;
}

// tldextract's suffix_index: index of the first public-suffix label, or null.
function suffixIndex(labels, root) {
  let node = root;
  let suffixIdx = labels.length;
  let labelIdx = labels.length;
  for (let i = labels.length - 1; i >= 0; i--) {
    const label = labels[i].toLowerCase();
    if (node.matches.has(label)) {
      labelIdx -= 1;
      node = node.matches.get(label);
      if (node.end) suffixIdx = labelIdx;
      continue;
    }
    if (node.matches.has("*")) {
      return node.matches.has("!" + label) ? labelIdx : labelIdx - 1;
    }
    break;
  }
  return suffixIdx === labels.length ? null : suffixIdx;
}

// tldextract.remote.lenient_netloc applied to a bare host.
function lenientHost(text) {
  let s = text;
  const dbl = s.indexOf("//");
  if (dbl === 0) s = s.slice(2);
  else if (dbl >= 2 && s[dbl - 1] === ":" && /^[A-Za-z0-9+\-.]*$/.test(s.slice(0, dbl - 1))) {
    s = s.slice(dbl + 2);
  }
  for (const sep of ["/", "?", "#"]) {
    const i = s.indexOf(sep);
    if (i >= 0) s = s.slice(0, i);
  }
  const at = s.lastIndexOf("@");
  if (at >= 0) s = s.slice(at + 1);
  if (s.startsWith("[")) {
    const close = s.indexOf("]");
    if (close >= 0) return s.slice(0, close + 1);
  }
  const colon = s.indexOf(":");
  if (colon >= 0) s = s.slice(0, colon);
  s = pyStrip(s); // Python str.strip()
  return s.replace(/[.。．｡]+$/u, "");
}

// [subdomain, domain label, public suffix]; a host without a known suffix gives ["", host, ""]
// only when it has one label (tldextract keeps the left labels as the subdomain).
export function splitHost(host, root) {
  const netloc = lenientHost(host).replace(/[。．｡]/gu, ".");
  if (netloc.length >= 4 && netloc[0] === "[" && netloc[netloc.length - 1] === "]") {
    return ["", netloc, ""];
  }
  const labels = netloc.split(".");
  const idx = suffixIndex(labels, root);
  if (idx === null) {
    if (labels.length === 4 && /^\p{Nd}/u.test(netloc) && IPV4.test(netloc)) return ["", netloc, ""];
    return [labels.slice(0, -1).join("."), labels[labels.length - 1], ""];
  }
  const subdomain = idx >= 2 ? labels.slice(0, idx - 1).join(".") : "";
  const domain = idx > 0 ? labels[idx - 1] : "";
  return [subdomain, domain, labels.slice(idx).join(".")];
}
