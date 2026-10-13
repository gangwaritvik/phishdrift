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
//   blocked: null|"domain"|"url",
//   model: {verdict, prob, reasons:[{text}]} | null,
//   domain: {risk, signals:[{severity,text}]} | null,   backend answer
//   backendFailed: bool,
// }
// page: {hasPassword, credFormCrossDomain, credFormInsecure} | null
// pageModel: {hasHtml, blended, verdict, reasons:[{text}]} | null   (scorePage in page.js)
export function combine(layers, page = null, pageModel = null) {
  const out = { verdict: SAFE, layer: "url-model", reasons: [], notes: [], prob: null };
  if (layers.trusted) return { ...out, layer: "user-trusted" };
  // An exact listed URL is evidence about that page, so it overrides the allowlist (a big site
  // can still host one bad file); a domain-level hit never co-occurs with an allowlist hit.
  if (layers.allow && layers.blocked !== "url") return { ...out, layer: "allowlist" };
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
