// Combiner: turns the layers' outputs into safe / suspicious / dangerous with plain-English reasons.
//
// Order follows CLAUDE.md (cheapest first): blocklist, user trust and allowlist, URL model, then
// backend domain checks and page checks. Before the page has loaded only the URL model has run.
// - A blocklist hit always warns: neither "trust this site" nor the allowlist overrides an exact
//   listed URL (a domain-level hit never co-occurs with an allowlist hit).
// - Once the content script sends the page, the page model (js/src/page.js, the "agree" rule of
//   reports/blend2_rules.md) can raise the address verdict. It can lower it only on a page that asks
//   for no credentials at all (no password, one-time code, card or PIN field, in the page or any of
//   its frames): the page's HTML belongs to whoever runs it, so on a login page the attacker's own
//   markup must not be able to clear an address warning.
// - The address model alone never blocks a page that asks for nothing: a dangerous address on a
//   page with no credential field, which the page model does not also call dangerous, gets the
//   banner instead of the warning page (an API endpoint, a redirect hop, an ordinary article).
//   Before the page has been read, such a verdict is held (`addressOnly`, see background.js).
// - Domain evidence (backend, tier C rules checked in reports/domain_rules.md) can only raise
//   suspicious to dangerous, never turn a safe verdict into a warning.
// - The password-form rule is used only when the page model could not read the page fully.
// - A page with no web address of its own (data:, sandboxed frames) is not scored by the address
//   model; it is suspicious only if it asks for credentials.

export const SAFE = 0;
export const SUSPICIOUS = 1;
export const DANGEROUS = 2;

export const BLOCKLIST_REASON = "This address is on a list of known phishing sites.";
export const NO_ADDRESS_REASON = "This page asks for a password or card details but has no web address of its own.";
export const NO_ADDRESS_NOTE = "This page has no web address to check.";
export const LOCAL_NOTE = "This is an address on your computer or local network, which PhishDrift does not check.";
export const ADDRESS_ONLY_NOTE =
  "The address looks like phishing, but this page does not ask for a password or payment details, so it was not blocked.";

export const SHARED_HOST_NOTE =
  "This site is on a shared hosting platform, where anyone can publish under a name of their choice, so its address alone is never called dangerous.";

// A dangerous verdict that rests on the address model alone (no list, look-alike rule, domain
// check or page agrees yet). The service worker shows it as suspicious until the page is read.
export const addressOnly = (result) => result?.verdict === DANGEROUS && result.layer === "url-model";

// layers: {
//   trusted: bool,               user pressed "trust this site"
//   allow: bool,                 allowlist hit
//   shortener: bool,             link shortener (judged by where it redirects, never by itself)
//   blocked: null|"domain"|"url",
//   model: {verdict, prob, reasons:[{text}]} | null,
//   domain: {risk, signals:[{severity,text}]} | null,   backend answer
//   backendFailed: bool,
//   shared: bool,                shared hosting platform or open-hosting zone (lists.js)
//   unscored: bool,              the document has no web address (address.js effectiveUrl)
//   local: bool,                 this computer or the local network (address.js isLocalAddress)
// }
// page: {hasPassword, credFormCrossDomain, credFormInsecure, asksCredentials} | null (pagefacts.js)
// pageModel: {hasHtml, blended, verdict, pageDangerous, reasons:[{text}], allowedPageWarning?} | null
//            (scorePage in page.js)
// lookalike: layers.lookalike = {rule, brand, text} | null, the offline look-alike check; it only
// raises (see lookalikeEscalate).
// llm: layers.llm = {raise, kind: "brand"|"phishing"|null, brand, brand_domain, phishing} | null, the
// backend's AI opinion on the address (backend/llm.py). It only raises (see llmEscalate).
export function combine(layers, page = null, pageModel = null) {
  const out = lookalikeEscalate(combineLayers(layers, page, pageModel), layers, page);
  return llmEscalate(out, layers, page);
}

export const llmReason = (llm) =>
  llm.kind === "phishing"
    ? `An AI check of the address thinks it looks like a phishing site (${Math.round(llm.phishing * 100)}% likely).`
    : `This address looks like it imitates ${llm.brand}, whose real site is ${llm.brand_domain}.`;

// One step up for a look-alike or AI-check hit: safe to suspicious, suspicious to dangerous only if
// the page asks for credentials. Never lowers a verdict, never acts on blocklisted, trusted,
// allowlisted, short-link, local or unscored addresses.
function stepUp(out, layers, page, reason, layer) {
  if (layers.trusted || layers.allow || layers.shortener) return out;
  if (["blocklist", "none", "local", "allowlist", "shortener", "user-trusted"].includes(out.layer)) return out;
  const cap = page?.asksCredentials ? DANGEROUS : SUSPICIOUS;
  const verdict = Math.min(out.verdict + 1, Math.max(cap, out.verdict));
  const reasons = [...new Set([reason, ...out.reasons])];
  if (verdict <= out.verdict) return { ...out, reasons };
  return { ...out, verdict, layer, reasons };
}

// layers.lookalike: the offline look-alike check (js/src/lookalike.js) says the address imitates a
// brand whose own site it is not.
export function lookalikeEscalate(out, layers, page) {
  return layers.lookalike ? stepUp(out, layers, page, layers.lookalike.text, "lookalike") : out;
}

// layers.llm says the address imitates a brand or looks like phishing on its own.
export function llmEscalate(out, layers, page) {
  return layers.llm?.raise ? stepUp(out, layers, page, llmReason(layers.llm), "llm") : out;
}

function combineLayers(layers, page = null, pageModel = null) {
  const out = { verdict: SAFE, layer: "url-model", reasons: [], notes: [], prob: null };
  const allowed = layers.allow && layers.blocked !== "url";
  if (layers.blocked && !allowed) {
    return { ...out, verdict: DANGEROUS, layer: "blocklist", reasons: [BLOCKLIST_REASON] };
  }
  if (layers.trusted) return { ...out, layer: "user-trusted" };
  if (layers.local) return { ...out, layer: "local", notes: [LOCAL_NOTE] };
  // Allowlisted pages and short links skip the address model, but not the page: a site anyone can
  // publish on (forms, file shares, link pages) is only as safe as the page it serves. The page
  // model warns there only on strong evidence (page.js `allowedPageWarning`), and never more than
  // suspicious, because the address itself is trusted or says nothing.
  if (allowed || layers.shortener) {
    if (pageModel?.allowedPageWarning) {
      const reasons = [...new Set(pageModel.reasons.map((r) => r.text))];
      return { ...out, verdict: SUSPICIOUS, layer: "page-model", reasons, prob: pageModel.blended };
    }
    return { ...out, layer: allowed ? "allowlist" : "shortener" };
  }

  if (layers.unscored) {
    if (page?.asksCredentials) return { ...out, verdict: SUSPICIOUS, layer: "page", reasons: [NO_ADDRESS_REASON] };
    return { ...out, layer: "none", notes: [NO_ADDRESS_NOTE] };
  }
  if (!layers.model) return { ...out, layer: "none", notes: ["The address could not be read."] };
  // Shared hosting: whoever publishes there picks the host name, and the model's prior for hosting
  // platforms makes many ordinary tenants look like phishing (reports/shared_host_cap.md). The
  // address alone is then capped at suspicious; a page that asks for credentials, the page model,
  // a list or domain evidence can still take it to dangerous.
  const capped = layers.shared && !page?.asksCredentials && layers.model.verdict > SUSPICIOUS;
  const model = capped ? { ...layers.model, verdict: SUSPICIOUS } : layers.model;
  if (capped) out.notes.push(SHARED_HOST_NOTE);
  out.verdict = model.verdict;
  out.prob = model.prob;
  out.reasons = model.reasons.map((r) => r.text);
  const pageRead = Boolean(pageModel?.hasHtml);
  // Lowering needs page facts that show no credential field (without facts, nothing is lowered),
  // and the address model's dangerous verdict always stands.
  const mayLower = page !== null && !page.asksCredentials && model.verdict < DANGEROUS;
  if (pageModel && (pageModel.verdict >= model.verdict || mayLower)) {
    out.verdict = pageModel.verdict;
    out.prob = pageModel.blended;
    if (pageRead) {
      out.layer = "page-model";
      const pageReasons = pageModel.reasons.map((r) => r.text);
      // address reasons first when the address alone is dangerous; page reasons otherwise
      out.reasons = model.verdict === DANGEROUS ? [...out.reasons, ...pageReasons] : [...pageReasons, ...out.reasons];
      out.reasons = [...new Set(out.reasons)];
    }
  }
  // The address alone says dangerous, but the page asks for nothing and the page model does not
  // agree: one step down, to the banner (never to safe; a login form added later is rechecked).
  if (out.verdict === DANGEROUS && model.verdict === DANGEROUS && page !== null && !page.asksCredentials) {
    // only the page model's own call counts (its verdict is dangerous whenever the address is), and
    // a page it could not read gives no second opinion
    if (!pageRead || !pageModel.pageDangerous) {
      out.verdict = SUSPICIOUS;
      out.notes.push(ADDRESS_ONLY_NOTE);
    }
  }
  if (out.verdict === SAFE) return { ...out, reasons: [] };

  // The URL or page model flagged it: add what the domain and the page say.
  if (layers.domain) {
    const flagged = layers.domain.signals.filter((s) => s.severity !== "info");
    out.reasons.push(...flagged.map((s) => s.text));
    if (layers.domain.risk === "high" && out.verdict === SUSPICIOUS) {
      out.verdict = DANGEROUS;
      out.layer = "domain";
    }
  } else if (layers.backendFailed) {
    out.notes.push("Domain checks were unavailable, so this uses the address check only.");
  }
  // The password-form rule, when the page model could not read the page or read it only as a bare
  // form (too little text for training pages).
  if ((!pageRead || pageModel.short) && page?.hasPassword && (page.credFormCrossDomain || page.credFormInsecure)) {
    out.reasons.push(
      page.credFormCrossDomain
        ? "This page asks for a password and sends it to a different website."
        : "This page asks for a password over an unencrypted connection.",
    );
    if (out.verdict === SUSPICIOUS) {
      out.verdict = DANGEROUS;
      out.layer = "page";
    }
  }
  return out;
}

// A frame that asks for credentials (a login form in an iframe, srcdoc or about:blank frame) is
// judged on its own page score alone: the address model's agreement is not required, because the
// frame's address (often the hosting page's) says little about the form inside it. Frames from
// allowlisted or trusted sites are skipped by the caller.
export const FRAME_PAGE_REASON = "This page shows a login form inside an embedded frame, and that form looks like phishing.";

export function framePageVerdict(scored, thresholds) {
  if (!scored?.hasHtml) return SAFE;
  if (scored.blended >= thresholds.dangerous) return DANGEROUS;
  if (scored.blended >= thresholds.suspicious) return SUSPICIOUS;
  return SAFE;
}
