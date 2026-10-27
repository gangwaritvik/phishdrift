// Derive page-check flags from the raw facts the content script reports (forms and their targets).
// Runs in the service worker, where the public-suffix data is available.

import { listDomainKey } from "./keys.js";

// A page that is one picture and nothing else: next to no readable text, no input fields, and a
// picture covering a good part of the window (a sign-in box drawn as an image or canvas). The
// numbers are the content script's `visual` facts (content.js visualFacts). The area share is a
// guess for a login-box-sized picture; text and fields are the definition of "nothing else".
export const PICTURE_MAX_TEXT = 100;
export const PICTURE_MIN_AREA = 0.1;

export function isPictureOnly(visual) {
  return Boolean(visual) && visual.textChars < PICTURE_MAX_TEXT && visual.fields === 0 && visual.largest >= PICTURE_MIN_AREA;
}

// facts: { passwordFields, credentialFields (one-time code, card, CVV, PIN inputs),
//          forms: [{ hasPassword, action: absolute URL | null }],
//          visual ({textChars, fields, pictures, largest} of the top page, content.js visualFacts),
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
  const pictureOnly = !asksCredentials && isPictureOnly(facts.visual);
  return { hasPassword, credFormCrossDomain, credFormInsecure, asksCredentials, pictureOnly };
}
