// Derive page-check flags from the raw facts the content script reports (forms and their targets).
// Runs in the service worker, where the public-suffix data is available.

import { listDomainKey } from "./keys.js";

// facts: { passwordFields, forms: [{ hasPassword, action: absolute URL | null }] }
export function pageFlags(facts, pageUrl, psl) {
  const pageDomain = listDomainKey(pageUrl, psl);
  let credFormCrossDomain = false;
  let credFormInsecure = false;
  for (const form of facts.forms ?? []) {
    if (!form.hasPassword || !form.action) continue;
    if (/^http:/i.test(form.action) && /^https:/i.test(pageUrl)) credFormInsecure = true;
    if (/^http:/i.test(form.action) && /^http:/i.test(pageUrl)) credFormInsecure = true;
    const target = listDomainKey(form.action, psl);
    if (target && pageDomain && target !== pageDomain) credFormCrossDomain = true;
  }
  return { hasPassword: (facts.passwordFields ?? 0) > 0, credFormCrossDomain, credFormInsecure };
}
