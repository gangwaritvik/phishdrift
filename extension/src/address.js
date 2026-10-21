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

// Addresses on this computer or the local network (a router's admin page, a development server,
// an intranet name) cannot be phishing sites on the web, and the address model, trained on public
// URLs, calls most of them dangerous (http://192.168.0.1/ scored 0.99). They are not scored.
const LOCAL_SUFFIXES = [".localhost", ".local", ".lan", ".internal", ".home.arpa", ".localdomain", ".intranet"];

function privateIPv4(host) {
  const m = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return a === 127 || a === 10 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
}

function privateIPv6(host) {
  if (!host.startsWith("[")) return false;
  const h = host.slice(1, -1).toLowerCase();
  if (h === "::1") return true;
  const v4 = h.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) return privateIPv4(v4[1]);
  return /^f[cd][0-9a-f]{0,2}:/.test(h) || /^fe[89ab][0-9a-f]?:/.test(h);
}

export function isLocalAddress(url) {
  const u = webUrl(url);
  if (!u) return false;
  // the URL parser has already turned hex, octal and integer IPv4 forms into dotted decimal
  const host = u.hostname.toLowerCase().replace(/\.$/, "");
  if (host === "localhost" || LOCAL_SUFFIXES.some((s) => host.endsWith(s))) return true;
  if (privateIPv4(host) || privateIPv6(host)) return true;
  return !host.includes(".") && !host.startsWith("["); // a single-label intranet name
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
