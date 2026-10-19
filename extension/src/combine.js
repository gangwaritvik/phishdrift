// Combiner: turns the layers' outputs into safe / suspicious / dangerous with plain-English reasons.
//
// Order follows CLAUDE.md (cheapest first): user trust and allowlist, blocklist, URL model, then
// backend domain checks and page checks. Before the page has loaded only the URL model has run.
// Once the content script sends the page, the page model's verdict (js/src/page.js, the
// "shipped" rule measured in reports/blend2_rules.md) replaces the URL model's: it can lower a
// suspicious address to safe or raise it, and the address model's dangerous verdict stands.
// Domain evidence (backend, tier C rules checked in reports/domain_rules.md) can only raise
// suspicious to dangerous, never turn a safe verdict into a warning. The password-form rule is
// used only when the page model could not read the page (no usable HTML).

export const SAFE = 0;
export const SUSPICIOUS = 1;
export const DANGEROUS = 2;

export const BLOCKLIST_REASON = "This address is on a list of known phishing sites.";

// layers: {
//   trusted: bool,               user pressed "trust this site"
//   allow: bool,                 allowlist hit
//   shortener: bool,             link shortener (judged by where it redirects, never by itself)
//   blocked: null|"domain"|"url",
//   model: {verdict, prob, reasons:[{text}]} | null,
//   domain: {risk, signals:[{severity,text}]} | null,   backend answer
//   backendFailed: bool,
// }
// page: {hasPassword, credFormCrossDomain, credFormInsecure} | null
// pageModel: {hasHtml, blended, verdict, reasons:[{text}], allowedPageWarning?} | null
//            (scorePage in page.js)
// brand: {address: [{rule, brand, text}], page: {rule, brand, text} | null} from brand_rules.js.
// The brand and look-alike rules only raise a verdict (see brandEscalate).
export function combine(layers, page = null, pageModel = null, brand = null) {
  return brandEscalate(combineLayers(layers, page, pageModel), brand, layers);
}

// One step up for a look-alike address (homograph, embedded domain, one letter away, brand + lure
// word) and one for a page that shows a brand, asks for a credential and is not on the brand's
// domain. Never lowers a
// verdict, never acts on user-trusted or blocklisted addresses, and on an allowlisted page (or a
// short link) only the page rule applies and only up to suspicious.
export function brandEscalate(out, brand, layers) {
  if (!brand || layers.trusted || out.layer === "blocklist" || out.layer === "none") return out;
  const addressTrusted = out.layer === "allowlist" || out.layer === "shortener" || layers.allow || layers.shortener;
  const address = addressTrusted ? [] : (brand.address ?? []);
  const pageHit = brand.page ?? null;
  let verdict = out.verdict;
  if (address.length) verdict += 1;
  if (pageHit) verdict += 1;
  verdict = Math.min(verdict, addressTrusted ? SUSPICIOUS : DANGEROUS);
  const hits = [...(pageHit ? [pageHit] : []), ...address];
  if (!hits.length) return out;
  const reasons = [...new Set([...hits.map((h) => h.text), ...out.reasons])];
  if (verdict <= out.verdict) return out.verdict === SAFE ? out : { ...out, reasons };
  return { ...out, verdict, layer: pageHit ? "brand-page" : "lookalike", reasons };
}

function combineLayers(layers, page = null, pageModel = null) {
  const out = { verdict: SAFE, layer: "url-model", reasons: [], notes: [], prob: null };
  if (layers.trusted) return { ...out, layer: "user-trusted" };
  // An exact listed URL is evidence about that page, so it overrides the allowlist (a big site
  // can still host one bad file); a domain-level hit never co-occurs with an allowlist hit.
  // Allowlisted pages and short links skip the address model, but not the page: a site anyone can
  // publish on (forms, file shares, link pages) is only as safe as the page it serves. The page
  // model warns there only on strong evidence (page.js `allowedPageWarning`), and never more than
  // suspicious, because the address itself is trusted or says nothing.
  const addressTrusted = (layers.allow && layers.blocked !== "url") || (layers.shortener && !layers.blocked);
  if (addressTrusted) {
    if (pageModel?.allowedPageWarning) {
      const reasons = [...new Set(pageModel.reasons.map((r) => r.text))];
      return { ...out, verdict: SUSPICIOUS, layer: "page-model", reasons, prob: pageModel.blended };
    }
    return { ...out, layer: layers.allow ? "allowlist" : "shortener" };
  }
  if (layers.blocked) {
    return { ...out, verdict: DANGEROUS, layer: "blocklist", reasons: [BLOCKLIST_REASON] };
  }

  const model = layers.model;
  if (!model) return { ...out, layer: "none", notes: ["The address could not be read."] };
  out.verdict = model.verdict;
  out.prob = model.prob;
  out.reasons = model.reasons.map((r) => r.text);
  const pageRead = Boolean(pageModel?.hasHtml);
  if (pageModel) {
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
  if (out.verdict === SAFE) return { ...out, reasons: [] };

  // The URL model flagged it: add what the domain and the page say.
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
  if (!pageRead && page?.hasPassword && (page.credFormCrossDomain || page.credFormInsecure)) {
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
