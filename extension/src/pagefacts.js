// Derive page-check flags from the raw facts the content script reports (forms and their targets).
// Runs in the service worker, where the public-suffix data is available.

import { listDomainKey } from "./keys.js";

// facts: { passwordFields, credentialFields (one-time code, card, CVV, PIN inputs),
//          forms: [{ hasPassword, action: absolute URL | null }],
//          frameCredentials (set by the service worker: a frame of this page asks for credentials) }
export function pageFlags(facts, pageUrl, psl) {
  const pageDomain = pageUrl ? listDomainKey(pageUrl, psl) : null;
  let credFormCrossDomain = false;
  let credFormInsecure = false;
  for (const form of facts.forms ?? []) {
    if (!form.hasPassword || !form.action || !pageUrl) continue;
    if (/^http:/i.test(form.action) && /^https?:/i.test(pageUrl)) credFormInsecure = true;
    const target = listDomainKey(form.action, psl);
    if (target && pageDomain && target !== pageDomain) credFormCrossDomain = true;
  }
  const hasPassword = (facts.passwordFields ?? 0) > 0;
  // A page that asks for a password, a one-time code, card details or a PIN, itself or in a frame:
  // on such a page the page model may raise a warning but never lower one (combine.js).
  const asksCredentials = hasPassword || (facts.credentialFields ?? 0) > 0 || Boolean(facts.frameCredentials);
  return { hasPassword, credFormCrossDomain, credFormInsecure, asksCredentials };
}
