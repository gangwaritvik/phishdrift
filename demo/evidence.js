// What each layer actually looked at for one address, for the page to play as a scene. Everything
// here is read from the same objects the extension uses (`c.x` holds the extension's modules); it
// never changes a verdict.

const EPS = 1e-9;
const logit = (p) => Math.log(Math.max(p, EPS) / Math.max(1 - p, EPS));

function humanise(name) {
  return name.replaceAll("_", " ");
}

// Edit-distance alignment of two code-point arrays: columns of {a, b, op} (match / sub / ins / del).
export function align(aText, bText) {
  const a = Array.from(aText);
  const b = Array.from(bText);
  const d = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) d[i][0] = i;
  for (let j = 0; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
  }
  const cols = [];
  let i = a.length;
  let j = b.length;
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && d[i][j] === d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)) {
      cols.push({ a: a[i - 1], b: b[j - 1], op: a[i - 1] === b[j - 1] ? "match" : "sub" });
      i--;
      j--;
    } else if (i > 0 && d[i][j] === d[i - 1][j] + 1) {
      cols.push({ a: a[i - 1], b: null, op: "del" });
      i--;
    } else {
      cols.push({ a: null, b: b[j - 1], op: "ins" });
      j--;
    }
  }
  return { distance: d[a.length][b.length], cols: cols.reverse() };
}

async function allowlistEvidence(c, target, listed, layers) {
  const { keys, psl } = c.x;
  const host = keys.listUrlKey(target).split(/[/?:]/)[0];
  let sub = "";
  let label = "";
  let suffix = "";
  try {
    [sub, label, suffix] = psl.splitHost(host, c.model.lists.psl);
  } catch {
    // an IP address or odd host: the domain chip below falls back to the whole host
  }
  const bytes = c.lists.allowBytes;
  const domain = listed.domain ?? host;
  let shared = null;
  if (listed.shortener) shared = "shortener";
  else if (c.model.lists.platforms.has(domain)) shared = "platform";
  else if (listed.shared) shared = "zone";
  return {
    host,
    sub,
    label,
    suffix,
    domain,
    bytes,
    hash: bytes ? await keys.hashPrefix(domain, bytes) : null,
    size: c.lists.allowDomains.size,
    found: Boolean(layers.allow),
    shared,
    zones: c.lists.openHosting.size,
  };
}

async function blocklistEvidence(c, target, layers) {
  const { keys } = c.x;
  const loaded = Boolean(c.info.blocklist);
  const bytes = c.lists.blockBytes || 8; // shown even without a list, so the keys are real
  const list = keys.listUrlExpressions(target);
  const rows = [];
  for (const key of list) {
    const hash = await keys.hashPrefix(key, bytes);
    rows.push({ key, hash, hit: loaded && c.lists.blockUrls.has(hash) });
  }
  const domain = layers.domainName;
  const domainHash = domain ? await keys.hashPrefix(domain, bytes) : null;
  return {
    loaded,
    bytes,
    domain,
    domainHash,
    domainHit: loaded && Boolean(domainHash && c.lists.blockDomains.has(domainHash)),
    keys: rows,
    domains: c.lists.blockDomains.size,
    urls: c.lists.blockUrls.size,
    blocked: layers.blocked,
  };
}

function modelEvidence(c, target, layers) {
  const { hybrid, model: m, explain } = c.x;
  if (target.length > c.address.MAX_URL_CHARS) return null;
  const values = hybrid.featureValues(c.model, target);
  const phi = explain.contributions(c.model.trees, values);
  const raw = m.rawScore(c.model, values);
  const sum = phi.reduce((s, v) => s + v, 0);
  const base = raw - sum;
  const sentences = new Map();
  const full = explain.reasons(phi, values, c.model.names, c.model.reasonRules, { top: 999, min_logodds: -999 });
  for (const r of full) sentences.set(r.feature, r.text);
  const items = phi
    .map((p, i) => ({ feature: c.model.names[i], value: values[i], delta: p }))
    .filter((r) => Math.abs(r.delta) >= 0.05)
    .sort((a, b) => Math.abs(b.delta) - Math.abs(a.delta))
    .slice(0, 6)
    .map((r) => ({
      ...r,
      label:
        r.delta > 0 && sentences.has(r.feature)
          ? sentences.get(r.feature)
          : `${humanise(r.feature)} = ${Number.isInteger(r.value) ? r.value : Number(r.value).toFixed(2)}`,
    }))
    .sort((a, b) => b.delta - a.delta);
  const shown = items.reduce((s, r) => s + r.delta, 0);
  const t = c.model.thresholds;
  return {
    used: Boolean(layers.model),
    base,
    items,
    other: raw - base - shown,
    raw,
    prob: 1 / (1 + Math.exp(-raw)),
    thresholds: t,
    logitThresholds: { suspicious: logit(t.suspicious), dangerous: logit(t.dangerous) },
  };
}

function lookalikeEvidence(c, target, layers) {
  const { urlparts } = c.x;
  const brand = c.brand;
  const rules = c.rules;
  let p = null;
  try {
    p = urlparts.parse(target, new Set(), rules.psl);
  } catch {
    p = null;
  }
  if (!p || p.isIp || !p.suffix) return { used: Boolean(layers.model), applicable: false, hits: [] };
  const decoded = brand.decodeLabel(p.label);
  const skel = brand.skeleton(rules, decoded);
  let nearest = null;
  for (const key of rules.targetKeys) {
    if (Math.abs(Array.from(key).length - Array.from(skel).length) > 3) continue;
    const a = align(skel, key);
    if (!nearest || a.distance < nearest.distance) nearest = { key, brand: rules.targets.get(key)[0], ...a };
  }
  const official = rules.official.get(p.domain) ?? null;
  return {
    used: Boolean(layers.model),
    applicable: true,
    domain: p.domain,
    label: p.label,
    decoded,
    skeleton: skel,
    changed: Array.from(decoded).map((ch, i) => ch !== Array.from(skel)[i]),
    nearest,
    official,
    isBrand: rules.brandSet.has(p.label) || rules.brandSet.has(p.label.replaceAll("-", "")),
    brandCount: rules.brands.length,
    hits: layers.lookalike.map((h) => ({ rule: h.rule, brand: h.brand, text: h.text })),
  };
}

// The steps the combiner took, as positions on the safe / suspicious / dangerous ladder.
function combineEvidence(layers, result) {
  const names = ["safe", "suspicious", "dangerous"];
  const steps = [];
  let start;
  if (layers.blocked && !(layers.allow && layers.blocked !== "url")) {
    start = 2;
    steps.push({ text: layers.blocked === "url" ? "This exact address is on the blocklist." : "This domain is on the blocklist.", to: 2 });
  } else if (layers.allow) {
    start = 0;
    steps.push({ text: "The domain is on the allowlist, so the model never runs.", to: 0 });
  } else if (layers.shortener) {
    start = 0;
    steps.push({ text: "A short link is judged by where it leads, which this page cannot follow.", to: 0 });
  } else {
    start = layers.model?.verdict ?? 0;
    steps.push({ text: `The address model says ${names[start]}.`, to: start });
    if (layers.lookalike.length && result.verdict > start) {
      steps.push({ text: "A look-alike match raises it one step.", to: result.verdict });
    } else if (layers.lookalike.length) {
      steps.push({ text: "A look-alike match is found, but the verdict is already at the top.", to: result.verdict });
    }
  }
  return { steps, start, end: result.verdict };
}

export async function buildEvidence(c, target, listed, layers, result) {
  const model = modelEvidence(c, target, layers);
  return {
    domain: listed.domain,
    allowlist: await allowlistEvidence(c, target, listed, layers),
    blocklist: await blocklistEvidence(c, target, layers),
    model,
    lookalike: lookalikeEvidence(c, target, layers),
    combine: combineEvidence(layers, result),
  };
}
