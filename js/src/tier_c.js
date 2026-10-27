// Tier C (domain age, DNS, certificate) in JavaScript: the raw-facts-to-features step of
// features/domain_features.py (`computeC` = compute_c), the fact parsers of collector/domain_capture.py
// (RDAP, DNS answers, certificate) and the LightGBM scoring of js/data/tier_c.json
// (written by `python -m models.tier_c`). Parity: tests/fixtures/tier_c_parity.json.
// A missing value is NaN, never 0, as in Python.

import { contributions, reasons } from "./explain.js";
import { DANGEROUS, SAFE, SUSPICIOUS, interp, rawScore } from "./model.js";
import { buildTrie, splitHost } from "./psl.js";

const NAN = Number.NaN;
const SECONDS_PER_DAY = 86400;
const HOLD_STATUSES = ["clienthold", "serverhold"];
const TLS_LOOKUP_ERRORS = new Set(["gaierror", "ENOTFOUND", "EAI_AGAIN"]);
export const SINKHOLES = new Set(["0.0.0.0", "127.0.0.1", "::", "::1"]);

// --- helpers ---------------------------------------------------------------------------

// Epoch milliseconds of an ISO-8601 string (a time without a zone is UTC); null if absent or unreadable.
export function parseTime(value) {
  if (!value || typeof value !== "string") return null;
  let text = value.trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(text)) text += "T00:00:00";
  if (!/(Z|[+-]\d{2}:?\d{2})$/.test(text)) text += "Z";
  const t = Date.parse(text);
  return Number.isNaN(t) ? null : t;
}

function days(later, earlier) {
  if (later === null || earlier === null) return NAN;
  return (later - earlier) / 1000 / SECONDS_PER_DAY;
}

const flag = (v) => (v === null || v === undefined ? NAN : Number(Boolean(v)));
const isNan = (v) => Number.isNaN(v);

export function isIpHost(host) {
  const h = String(host).replace(/^\[|\]$/g, "");
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(h) || (h.includes(":") && /^[0-9a-fA-F:.]+$/.test(h));
}

// [label, registrable domain] of a host (public suffixes only), as features.domain_features.registrable.
export function registrable(host, root) {
  const [, label, suffix] = splitHost(String(host).toLowerCase().replace(/\.$/, ""), root);
  return [label, suffix ? `${label}.${suffix}` : label];
}

export function sinkholeOnly(dns) {
  if (!dns) return false;
  if (dns.sinkhole !== undefined && dns.sinkhole !== null) return Boolean(dns.sinkhole);
  const addrs = [...(dns.a || []), ...(dns.aaaa || [])];
  return addrs.length > 0 && addrs.every((a) => SINKHOLES.has(a));
}

// --- groups ----------------------------------------------------------------------------

export const NAMES_C = [
  "domain_age_days", "days_to_expiry", "registration_length_days", "days_since_rdap_change", "rdap_found",
  "whois_redacted", "rdap_status_count", "rdap_client_hold",
  "n_a", "n_aaaa", "has_cname", "mx_count", "has_mx", "has_spf", "has_dmarc", "n_ns", "ns_in_own_domain",
  "ns_cloudflare", "min_ttl_s",
  "tls_ok", "tls_verified", "cert_free_issuer", "cert_validity_days", "cert_age_days", "cert_days_left",
  "cert_san_count", "cert_wildcard", "cert_cn_matches_host", "brand_in_cert_sans",
];

function registrationGroup(domainRec, now) {
  const rdap = domainRec?.rdap;
  const error = domainRec?.rdap_error;
  const found = rdap ? 1 : error === "not_found" || error === "no_server" ? 0 : NAN;
  const out = {};
  for (const n of ["domain_age_days", "days_to_expiry", "registration_length_days", "days_since_rdap_change",
    "whois_redacted", "rdap_status_count", "rdap_client_hold"]) out[n] = NAN;
  out.rdap_found = found;
  if (!rdap) return out;
  const registered = parseTime(rdap.registered);
  const expires = parseTime(rdap.expires);
  const status = (rdap.status || []).map((s) => String(s).toLowerCase().replaceAll(" ", ""));
  return {
    domain_age_days: days(now, registered),
    days_to_expiry: days(expires, now),
    registration_length_days: days(expires, registered),
    days_since_rdap_change: days(now, parseTime(rdap.last_changed)),
    rdap_found: found,
    whois_redacted: flag(rdap.redacted),
    rdap_status_count: status.length,
    rdap_client_hold: Number(status.some((s) => HOLD_STATUSES.some((h) => s.includes(h)))),
  };
}

function dnsGroup(dns, own, root) {
  const names = ["n_a", "n_aaaa", "has_cname", "mx_count", "has_mx", "has_spf", "has_dmarc", "n_ns",
    "ns_in_own_domain", "ns_cloudflare", "min_ttl_s"];
  if (!dns) return Object.fromEntries(names.map((n) => [n, NAN]));
  const failed = new Set((dns.errors || []).map((e) => String(e).split(":")[0].toUpperCase()));
  const count = (key, rdtype) => (failed.has(rdtype) ? NAN : (dns[key] || []).length);
  const nNs = count("ns", "NS");
  const ns = (dns.ns || []).map((n) => String(n).toLowerCase().replace(/\.$/, ""));
  const mx = failed.has("MX") || dns.mx_count === null || dns.mx_count === undefined ? NAN : dns.mx_count;
  const txtOk = !failed.has("TXT");
  const hasNs = !isNan(nNs) && nNs > 0;
  return {
    n_a: count("a", "A"),
    n_aaaa: count("aaaa", "AAAA"),
    has_cname: failed.has("CNAME") ? NAN : Number(Boolean((dns.cname || []).length)),
    mx_count: mx,
    has_mx: isNan(mx) ? NAN : Number(mx > 0),
    has_spf: txtOk ? flag(dns.spf) : NAN,
    has_dmarc: txtOk ? flag(dns.dmarc) : NAN,
    n_ns: nNs,
    ns_in_own_domain: hasNs ? Number(ns.some((n) => registrable(n, root)[1] === own)) : NAN,
    ns_cloudflare: hasNs ? Number(ns.some((n) => n.endsWith(".ns.cloudflare.com"))) : NAN,
    min_ttl_s: dns.min_ttl === null || dns.min_ttl === undefined ? NAN : Number(dns.min_ttl),
  };
}

const sanName = (san) => {
  const s = String(san).toLowerCase().replace(/\.$/, "");
  return s.startsWith("*.") ? s.slice(2) : s;
};

export function brandInSans(sans, brands, root) {
  for (const san of sans) {
    const name = sanName(san);
    if (!name || isIpHost(name)) continue;
    const ownLabel = registrable(name, root)[0];
    const labels = name.split(".").filter(Boolean);
    for (const b of brands) {
      if (b !== ownLabel && labels.some((x) => x.includes(b))) return true;
    }
  }
  return false;
}

export function cnMatches(cn, host) {
  const c = String(cn).toLowerCase().replace(/\.$/, "");
  const h = String(host).toLowerCase().replace(/\.$/, "");
  if (c === h) return true;
  if (c.startsWith("*.")) {
    const i = h.indexOf(".");
    const head = i < 0 ? h : h.slice(0, i);
    const rest = i < 0 ? "" : h.slice(i + 1);
    return Boolean(head) && rest === c.slice(2);
  }
  return false;
}

function tlsGroup(tls, host, now, lists) {
  const names = ["tls_ok", "tls_verified", "cert_free_issuer", "cert_validity_days", "cert_age_days",
    "cert_days_left", "cert_san_count", "cert_wildcard", "cert_cn_matches_host", "brand_in_cert_sans"];
  const out = Object.fromEntries(names.map((n) => [n, NAN]));
  if (!tls || (!tls.ok && TLS_LOOKUP_ERRORS.has(tls.error))) return out;
  out.tls_ok = flag(tls.ok);
  if (!tls.ok) return out;
  out.tls_verified = flag(tls.verified);
  const hasCert = ["issuer_o", "issuer_cn", "not_before", "subject_cn"].some((k) => tls[k]);
  if (!tls.verified || !hasCert) return out;
  const issuer = `${tls.issuer_o || ""} ${tls.issuer_cn || ""}`.toLowerCase();
  const start = parseTime(tls.not_before);
  const end = parseTime(tls.not_after);
  const sans = tls.sans || [];
  const subject = tls.subject_cn;
  return {
    ...out,
    cert_free_issuer: issuer.trim() ? Number(lists.freeIssuers.some((i) => issuer.includes(i))) : NAN,
    cert_validity_days: days(end, start),
    cert_age_days: days(now, start),
    cert_days_left: days(end, now),
    cert_san_count: tls.san_count === null || tls.san_count === undefined ? NAN : Number(tls.san_count),
    cert_wildcard: Number([...sans, subject || ""].some((s) => String(s).startsWith("*."))),
    cert_cn_matches_host: subject ? Number(cnMatches(subject, host)) : NAN,
    brand_in_cert_sans: Number(brandInSans(sans, lists.brands, lists.psl)),
  };
}

// Every tier C feature of one host record (`probe_host` is the name the handshake went to) with
// its registrable domain's record. `lists`: { brands, freeIssuers, psl }.
export function computeC(hostRec, domainRec, lists) {
  const now = parseTime(hostRec.captured_at);
  const host = String(hostRec.probe_host || hostRec.host || "").toLowerCase();
  const own = String(hostRec.domain || registrable(host, lists.psl)[1]).toLowerCase();
  const filtered = sinkholeOnly(hostRec.dns);
  const values = {
    ...registrationGroup(domainRec, now),
    ...dnsGroup(filtered ? null : hostRec.dns, own, lists.psl),
    ...tlsGroup(filtered ? null : hostRec.tls, host, now, lists),
  };
  return Object.fromEntries(NAMES_C.map((n) => [n, Number(values[n])]));
}

// --- fact parsers (the inputs of computeC, as collector/domain_capture.py writes them) ------

function vcardValue(vcard, field) {
  for (const entry of vcard?.[1] || []) if (entry?.[0] === field) return entry.length > 3 ? String(entry[3]) : null;
  return null;
}

export function parseRdap(obj) {
  const events = {};
  for (const e of obj.events || []) events[e.eventAction] = e.eventDate;
  let registrar = null;
  for (const ent of obj.entities || []) {
    if ((ent.roles || []).includes("registrar")) registrar = vcardValue(ent.vcardArray || [], "fn") || ent.handle || null;
  }
  const text = JSON.stringify(obj).toLowerCase();
  return {
    registered: events.registration ?? null,
    expires: events.expiration ?? null,
    last_changed: events["last changed"] ?? null,
    registrar,
    status: obj.status || [],
    nameservers: (obj.nameservers || []).map((ns) => (ns.ldhName || "").toLowerCase()).sort(),
    redacted: Boolean(obj.redacted) || text.includes("redacted for privacy") || (registrar || "").toLowerCase().includes("privacy"),
  };
}

// dnsFacts(host, domain, query): query(name, rdtype) -> Promise<[[value, ttl], ...]>, rejecting on failure.
export async function dnsFacts(host, domain, query) {
  const errors = [];
  const q = async (name, rdtype) => {
    try {
      return await query(name, rdtype);
    } catch (e) {
      errors.push(`${rdtype}:${e?.name || "Error"}`);
      return [];
    }
  };
  const [a, aaaa, cname, ns, mx, txt, dmarc] = await Promise.all([
    q(host, "A"), q(host, "AAAA"), q(host, "CNAME"), q(domain, "NS"), q(domain, "MX"), q(domain, "TXT"),
    q(`_dmarc.${domain}`, "TXT"),
  ]);
  const ttls = [a, aaaa, cname, ns, mx].flatMap((r) => r.map(([, t]) => t));
  const addresses = [...a, ...aaaa].map(([v]) => v);
  const real = addresses.filter((v) => !SINKHOLES.has(v));
  return {
    errors,
    a: a.map(([v]) => v).sort(),
    aaaa: aaaa.map(([v]) => v).sort(),
    cname: cname.map(([v]) => v.replace(/\.$/, "")),
    ns: ns.map(([v]) => v.replace(/\.$/, "").toLowerCase()).sort(),
    mx_count: mx.length,
    spf: txt.some(([v]) => v.toLowerCase().includes("v=spf1")),
    dmarc: dmarc.some(([v]) => v.toLowerCase().includes("v=dmarc1")),
    min_ttl: ttls.length ? Math.min(...ttls) : null,
    resolves: real.length > 0,
    sinkhole: addresses.length > 0 && real.length === 0,
  };
}

// Node's tls.TLSSocket.getPeerCertificate() -> the certificate fields of the capture record.
const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
function certTime(text) {
  const m = /^([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\d{4}) GMT$/.exec(text || "");
  if (!m) return null;
  return new Date(Date.UTC(+m[6], MONTHS[m[1]], +m[2], +m[3], +m[4], +m[5])).toISOString().replace(".000Z", "+00:00");
}
export function parseCert(cert) {
  const sans = String(cert.subjectaltname || "").split(",").map((s) => s.trim()).filter((s) => s.startsWith("DNS:")).map((s) => s.slice(4));
  return {
    issuer_o: cert.issuer?.O ?? null,
    issuer_cn: cert.issuer?.CN ?? null,
    subject_cn: cert.subject?.CN ?? null,
    not_before: certTime(cert.valid_from),
    not_after: certTime(cert.valid_to),
    san_count: sans.length,
    sans: sans.slice(0, 50),
  };
}

// --- model -----------------------------------------------------------------------------

export function loadTierC(bundle, pslRules) {
  return {
    names: bundle.names,
    trees: bundle.trees,
    thresholds: bundle.thresholds,
    isotonic: bundle.isotonic,
    reasonRules: bundle.reasons,
    explainOptions: bundle.explain,
    serving: bundle.serving,
    lists: { brands: bundle.brands, freeIssuers: bundle.free_issuers, psl: buildTrie(pslRules) },
  };
}

// verdict: 0 safe / 1 suspicious / 2 dangerous (dangerous only when the bundle has a 0.1% threshold).
export function scoreFeatures(model, features, { withReasons = false } = {}) {
  const values = model.names.map((n) => features[n]);
  const prob = 1 / (1 + Math.exp(-rawScore(model, values)));
  let verdict = SAFE;
  if (model.thresholds.dangerous !== null && prob >= model.thresholds.dangerous) verdict = DANGEROUS;
  else if (prob >= model.thresholds.suspicious) verdict = SUSPICIOUS;
  const calibrated = interp(prob, model.isotonic.x, model.isotonic.y);
  const why = withReasons
    ? reasons(contributions(model.trees, values), values, model.names, model.reasonRules, model.explainOptions)
    : [];
  return { prob, calibrated, verdict, reasons: why };
}

export function scoreFacts(model, hostRec, domainRec, opts) {
  return scoreFeatures(model, computeC(hostRec, domainRec, model.lists), opts);
}
