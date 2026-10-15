// The address model's verdict for one URL, with the two cases the model must never decide alone:
// an address too long to score in time, and a scoring error. Both give a soft warning instead of
// leaving the page unchecked (a page could otherwise switch the check off by itself).

import { SAFE, SUSPICIOUS } from "./combine.js";
import { scoreUrl } from "./lib/hybrid.js";

export const MAX_URL_CHARS = 32_768;
export const LONG_URL_REASON = "This address is extremely long, a trick used to hide where it leads.";
export const ERROR_REASON = "PhishDrift could not check this address.";

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
