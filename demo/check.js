// Address check for the demo page: the extension's own layers for a typed URL (allowlist and
// blocklist, the tier A model, look-alike rules, the combiner), in the order of layersFor() and
// evaluate() in extension/src/background.js. Nothing is reimplemented: the modules are loaded from
// `base`, a folder laid out like extension/dist (combine.js, lists.js, address.js and lib/).
// Not applied: the page model (a web page cannot read another site's HTML), backend domain checks,
// user trust and the remote config. A short link is not followed.
//
// `read(path)` returns parsed JSON for a path relative to the repository root, or null when the
// file does not exist.

import { buildEvidence } from "./evidence.js";

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
  const [combine, lists, address, hybrid, brand, keys, pslMod, urlparts, explain, modelMod] = await Promise.all([
    mod("combine.js"),
    mod("lists.js"),
    mod("address.js"),
    mod("lib/hybrid.js"),
    mod("lib/brand_rules.js"),
    mod("keys.js"),
    mod("lib/psl.js"),
    mod("lib/urlparts.js"),
    mod("lib/explain.js"),
    mod("lib/model.js"),
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
    x: { keys, psl: pslMod, urlparts, explain, model: modelMod, hybrid, lists },
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

const TONE = ["safe", "warn", "bad"]; // verdict index -> tone
const VERDICT_WORD = { safe: "Looks safe", suspicious: "Suspicious", dangerous: "Dangerous" };
const LAYER_WORD = {
  allowlist: "The allowlist decided.",
  blocklist: "The blocklist decided.",
  "url-model": "The address model decided.",
  lookalike: "The look-alike rules raised the verdict.",
  shortener: "A short link has nothing to judge until it is followed.",
  none: "Nothing to check.",
};

// One entry per layer, in the order the extension runs them: what it found, for the page to
// animate. tone: safe | clear | warn | bad | skip | na.
function buildTrace(c, listed, layers, result, label) {
  const { info } = c;
  const decidedEarly = layers.allow || layers.shortener || layers.blocked;
  const earlyWhy = layers.blocked
    ? "The blocklist already decided, so this step isn't needed."
    : layers.shortener
      ? "Short links are judged by where they lead, not by their own address."
      : "The allowlist already decided, so this step isn't needed.";
  const d = listed.domain;
  const trace = [];

  if (listed.shortener) {
    trace.push({ id: "allowlist", tone: "skip", label: "Link shortener", detail: "Link shorteners are never trusted on their own. The extension judges the page the link leads to." });
  } else if (listed.shared && layers.allow) {
    trace.push({ id: "allowlist", tone: "safe", label: "On the list", detail: `${d} hosts many separate sites, and ${listed.trustKey} is one of them that people visit a lot, with no phishing ever reported on it. It is on the allowlist by its exact name.` });
  } else if (listed.shared) {
    trace.push({ id: "allowlist", tone: "skip", label: "Not applicable", detail: `${d} hosts many separate sites, so its popularity proves nothing about ${listed.trustKey}, which is not a widely used site of its own. The allowlist is skipped.` });
  } else if (layers.allow) {
    trace.push({ id: "allowlist", tone: "safe", label: "On the list", detail: `${d} is one of the ${info.allowDomains.toLocaleString()} widely used sites on the allowlist.` });
  } else {
    trace.push({ id: "allowlist", tone: "clear", label: "Not listed", detail: `${d} is not on the allowlist, so the check goes on.` });
  }

  if (!info.blocklist) {
    trace.push({ id: "blocklist", tone: "skip", label: "No list here", detail: "No blocklist is built on this machine yet. Run python -m backend build-lists to add one." });
  } else if (layers.blocked) {
    trace.push({
      id: "blocklist",
      tone: "bad",
      label: "Listed",
      detail: layers.blocked === "url" ? "This exact address is on the list of known phishing URLs." : `${d} is on the list of known phishing domains.`,
    });
  } else {
    trace.push({ id: "blocklist", tone: "clear", label: "Not listed", detail: `Not found among ${info.blockDomains.toLocaleString()} blocked domains and ${info.blockUrls.toLocaleString()} blocked URLs.` });
  }

  const m = layers.model;
  if (!m) {
    trace.push({ id: "model", tone: "skip", label: "Skipped", detail: earlyWhy });
  } else if (m.prob === null) {
    trace.push({ id: "model", tone: "warn", label: "Suspicious", detail: m.reasons[0]?.text ?? "The address could not be scored." });
  } else {
    trace.push({
      id: "model",
      tone: TONE[m.verdict],
      label: VERDICT_WORD[LABELS[m.verdict]],
      detail: `Score ${m.prob.toFixed(3)}. It warns from ${info.thresholds.suspicious.toFixed(3)} and calls an address dangerous from ${info.thresholds.dangerous.toFixed(3)}.`,
    });
  }

  if (!m && decidedEarly) {
    trace.push({ id: "lookalike", tone: "skip", label: "Skipped", detail: earlyWhy });
  } else if (layers.lookalike.length) {
    const n = layers.lookalike.length;
    trace.push({ id: "lookalike", tone: "warn", label: n === 1 ? "1 match" : `${n} matches`, detail: layers.lookalike.map((h) => h.text).join(" ") });
  } else {
    trace.push({ id: "lookalike", tone: "clear", label: "None found", detail: "The domain doesn't imitate a known brand." });
  }

  const short = result.layer === "shortener";
  trace.push({ id: "combine", tone: short ? "skip" : TONE[result.verdict], label: short ? "Short link" : label, detail: LAYER_WORD[result.layer] ?? "Combined the layers." });
  trace.push({ id: "page", tone: "na", label: "Extension only", detail: "Reading login forms on the page and the backend's domain checks need the page itself. A web page can't fetch another site, so only the extension runs them." });
  return trace;
}

// The extension's verdict for one address, plus the model's own score for display (the model is
// skipped for allowlisted, blocklisted and short-link addresses, as in the extension; its score is
// still shown so the page can say what it would have said), and the per-layer trace.
export async function checkUrl(c, input) {
  const url = normaliseInput(input);
  const target = c.address.effectiveUrl(url);
  if (target === null) {
    return { url, verdict: "unscored", label: "Not a web address", reasons: [], notes: ["Type a web address such as https://example.com/login."], trace: [] };
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
  if (layers.shared) notes.push("This domain hosts many separate sites: the allowlist applies only to an exact site name that is widely used, and only the full address is matched against the blocklist.");
  const verdict = LABELS[result.verdict];
  return {
    url: target,
    domain: listed.domain,
    verdict,
    label: VERDICT_WORD[verdict],
    layer: result.layer,
    prob: result.prob,
    reasons: result.reasons,
    notes,
    allowlisted: Boolean(listed.allow),
    blocked: listed.blocked,
    lookalike: layers.lookalike.map((h) => h.text),
    modelAlone,
    thresholds: c.info.thresholds,
    evidence: await buildEvidence(c, target, listed, layers, result),
    trace: buildTrace(c, listed, layers, result, VERDICT_WORD[verdict]),
  };
}
