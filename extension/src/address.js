// The address model's verdict for one URL, with the cases the model must never decide alone:
// an address too long to score in time, a scoring error, and a page with no web address of its own.
// The first two give a soft warning instead of leaving the page unchecked (a page could otherwise
// switch the check off by itself); the last is not scored at all, because a score for "blob:...",
// "about:blank" or a malformed address is meaningless (the model gave every unparseable address
// 0.98 and every blob: address over 0.99).

import { SAFE, SUSPICIOUS } from "./combine.js";
import { scoreUrl } from "./lib/hybrid.js";

export const MAX_URL_CHARS = 32_768;
export const LONG_URL_REASON = "This address is extremely long, a trick used to hide where it leads.";
export const ERROR_REASON = "PhishDrift could not check this address.";

function webUrl(text) {
  try {
    const u = new URL(text);
    return (u.protocol === "http:" || u.protocol === "https:") && u.hostname ? u : null;
  } catch {
    return null;
  }
}

// The web address a document stands for, or null when it has none.
// - http(s) addresses are used as they are;
// - "blob:https://site/uuid" (a page built in memory by a site) stands for that site;
// - about:blank, about:srcdoc and other documents without an address of their own (a pop-up a page
//   writes into, an inline frame) stand for the origin they inherit, which the content script reports;
// - data: pages, opaque origins (sandboxed frames), local files and malformed addresses have none.
export function effectiveUrl(url, origin = null) {
  if (typeof url !== "string") return null;
  if (url.length > MAX_URL_CHARS) return url; // scored as "too long" below, never parsed
  if (webUrl(url)) return url;
  if (url.startsWith("blob:")) {
    const inner = webUrl(url.slice(5));
    return inner ? `${inner.origin}/` : null;
  }
  if (/^about:/i.test(url) && origin && origin !== "null") {
    const o = webUrl(origin);
    return o ? `${o.origin}/` : null;
  }
  return null;
}

export function scoreAddress(model, url) {
  if (url.length > MAX_URL_CHARS) return { verdict: SUSPICIOUS, prob: null, reasons: [{ text: LONG_URL_REASON }] };
  try {
    const first = scoreUrl(model, url);
    // Reasons (TreeSHAP, about 100 ms) only for addresses that get a warning.
    const scored = first.verdict > SAFE ? scoreUrl(model, url, { withReasons: true }) : first;
    return { verdict: scored.verdict, prob: scored.prob, reasons: scored.reasons };
  } catch (err) {
    console.warn("PhishDrift address check failed:", err);
    return { verdict: SUSPICIOUS, prob: null, reasons: [{ text: ERROR_REASON }] };
  }
}
