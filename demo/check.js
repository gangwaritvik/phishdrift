// Address check for the demo page: the extension's own layers for a typed URL (allowlist and
// blocklist, the tier A model, look-alike rules, the combiner), in the order of layersFor() and
// evaluate() in extension/src/background.js. Nothing is reimplemented: the modules are loaded from
// `base`, a folder laid out like extension/dist (combine.js, lists.js, address.js and lib/).
// Not applied: the page model (a web page cannot read another site's HTML), backend domain checks,
// user trust and the remote config. A short link is not followed.
//
// `read(path)` returns parsed JSON for a path relative to the repository root, or null when the
// file does not exist.

const LABELS = ["safe", "suspicious", "dangerous"];

// Lists built by `python -m backend build-lists` (data/lists, on the PC) are fresher than the
// allowlist bundled with the extension; the bundled one is used when there are none.
async function loadLists(read) {
  const [allow, block, bundled] = await Promise.all([
    read("data/lists/allowlist.json"),
    read("data/lists/blocklist.json"),
    read("extension/data/allowlist.json"),
  ]);
  const synced = allow?.domains?.length || block ? { allowlist: allow ?? undefined, blocklist: block ?? undefined } : null;
  const allowSource = allow?.domains?.length ? "data/lists/allowlist.json" : bundled ? "extension/data/allowlist.json" : null;
  return { synced, bundled, allowSource, block };
}

export async function loadChecker({ base, read }) {
  const mod = (path) => import(new URL(path, base).href);
  const [combine, lists, address, hybrid, brand] = await Promise.all([
    mod("combine.js"),
    mod("lists.js"),
    mod("address.js"),
    mod("lib/hybrid.js"),
    mod("lib/brand_rules.js"),
  ]);
  const [bundle, psl, rulesPayload] = await Promise.all([
    read("js/data/tier_a_hybrid.json"),
    read("js/data/psl_icann.json"),
    read("js/data/brand_rules.json"),
  ]);
  if (!bundle || !psl || !rulesPayload) throw new Error("js/data is missing model files (tier_a_hybrid.json, psl_icann.json, brand_rules.json)");
  const model = hybrid.loadHybrid(bundle, psl);
  const rules = brand.loadBrandRules(rulesPayload, model.lists.psl, model.lists.platforms);
  const { synced, bundled, allowSource, block } = await loadLists(read);
  const listSet = new lists.ListSet(lists.withBundledAllowlist(synced, bundled), {
    platforms: model.lists.platforms,
    psl: model.lists.psl,
    shorteners: model.lists.shorteners,
  });
  return {
    combine,
    address,
    hybrid,
    brand,
    model,
    rules,
    lists: listSet,
    info: {
      modelCreated: bundle.created ?? null,
      thresholds: model.thresholds,
      allowlist: allowSource,
      allowDomains: listSet.allowDomains.size,
      blocklist: block ? "data/lists/blocklist.json" : null,
      blockDomains: listSet.blockDomains.size,
      blockUrls: listSet.blockUrls.size,
    },
  };
}

// Adds a scheme to a bare host ("example.com/x") as the address bar does.
export function normaliseInput(text) {
  const s = String(text ?? "").trim();
  if (!s) return "";
  return /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(s) && !/^[^/:]+:\d/.test(s) ? s : `https://${s}`;
}

// The extension's verdict for one address, plus the model's own score for display (the model is
// skipped for allowlisted, blocklisted and short-link addresses, as in the extension; its score is
// still shown so the page can say what it would have said).
export async function checkUrl(c, input) {
  const url = normaliseInput(input);
  const target = c.address.effectiveUrl(url);
  if (target === null) {
    return { url, verdict: "unscored", label: "not a web address", reasons: [], notes: ["Type a web address such as https://example.com/login."] };
  }
  const listed = await c.lists.check(target);
  const layers = {
    trusted: false,
    domainName: listed.domain,
    shared: listed.shared,
    allow: listed.allow,
    shortener: listed.shortener,
    blocked: listed.blocked,
    model: null,
    unscored: false,
    lookalike: [],
  };
  if (!layers.allow && !layers.shortener && !layers.blocked) {
    layers.model = c.address.scoreAddress(c.model, target);
    layers.lookalike = c.brand.addressSignals(c.rules, target);
  }
  const result = c.combine.combine(layers, null, null, { address: layers.lookalike, page: null });
  let modelAlone = null;
  if (target.length <= c.address.MAX_URL_CHARS) {
    const s = c.hybrid.scoreUrl(c.model, target, { withReasons: true });
    modelAlone = { prob: s.prob, calibrated: s.calibrated, verdict: LABELS[s.verdict], reasons: s.reasons.map((r) => r.text) };
  }
  const notes = [...(result.notes ?? [])];
  if (layers.shortener) notes.push("This is a link shortener. The extension judges the page it redirects to; this page does not follow the link.");
  if (layers.shared) notes.push("This domain is a shared hosting platform: the allowlist does not apply and only the full address is matched against the blocklist.");
  return {
    url: target,
    domain: listed.domain,
    verdict: LABELS[result.verdict],
    layer: result.layer,
    prob: result.prob,
    reasons: result.reasons,
    notes,
    allowlisted: Boolean(listed.allow),
    blocked: listed.blocked,
    lookalike: layers.lookalike.map((h) => h.text),
    modelAlone,
  };
}
