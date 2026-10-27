// Live domain check for tier C (the hosted copy of what collector/domain_capture.py records at first
// sight): RDAP from the registry's own server, DNS over HTTPS, a TLS handshake, then js/src/tier_c.js.
// Everything that touches the network is passed in, so the logic is tested with fakes
// (js/test/domain_check.test.js); netlify/functions/domain-check.mjs supplies the real ones.
// A part that fails is recorded the way the capture records it (an error string), so its features
// are NaN and the model sees the same kind of gap it saw in training.

import { SINKHOLES, computeC, dnsFacts, isIpHost, parseRdap, registrable, scoreFeatures } from "./tier_c.js";

const RDTYPES = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28 };
const LOCAL_SUFFIXES = ["localhost", "local", "lan", "internal", "home.arpa", "localdomain", "intranet", "corp", "home"];
const VERDICTS = ["safe", "suspicious", "dangerous"];

// Why a name is not checked (null = check it). `lists`: { platforms: Set, shorteners: Set, psl }.
export function refusal(host, lists) {
  if (!host || isIpHost(host)) return "ip_or_empty";
  if (!host.includes(".") || LOCAL_SUFFIXES.some((s) => host === s || host.endsWith(`.${s}`))) return "local_name";
  const [label, domain] = registrable(host, lists.psl);
  if (!label || !domain.includes(".")) return "no_public_suffix";
  if (lists.shorteners.has(domain)) return "shortener";
  if (lists.platforms.has(domain)) return "hosting_platform";
  return null;
}

// TLD -> RDAP base URL, from the IANA bootstrap file (same map as load_rdap_bootstrap).
export function parseBootstrap(body) {
  const bases = {};
  for (const [tlds, urls] of body.services || []) {
    if (urls?.length) for (const tld of tlds) bases[String(tld).toLowerCase()] = String(urls[0]).replace(/\/+$/, "");
  }
  return bases;
}

// { rdap, rdap_error } of a registrable domain, as fetch_rdap returns them.
export async function rdapFor(domain, bases, fetchFn, timeoutMs) {
  const base = bases[domain.slice(domain.lastIndexOf(".") + 1)];
  if (!base) return { rdap: null, rdap_error: "no_server" };
  try {
    const resp = await fetchFn(`${base}/domain/${domain}`, {
      headers: { Accept: "application/rdap+json" },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (resp.status === 404) return { rdap: null, rdap_error: "not_found" };
    if (!resp.ok) return { rdap: null, rdap_error: `http_${resp.status}` };
    return { rdap: parseRdap(await resp.json()), rdap_error: null };
  } catch (e) {
    return { rdap: null, rdap_error: e?.name || "Error" };
  }
}

// query(name, rdtype) -> [[value, ttl], ...] over DNS-over-HTTPS (doh_query in the collector).
export function dohQuery(urls, fetchFn, timeoutMs) {
  return async (name, rdtype) => {
    let error = "failed";
    for (const url of urls) {
      try {
        const resp = await fetchFn(`${url}?name=${encodeURIComponent(name)}&type=${rdtype}`, {
          headers: { Accept: "application/dns-json" },
          signal: AbortSignal.timeout(timeoutMs),
        });
        if (!resp.ok) throw new Error(`http_${resp.status}`);
        const body = await resp.json();
        if (body.Status !== 0 && body.Status !== 3) throw new Error(`DNS status ${body.Status}`);
        return (body.Answer || [])
          .filter((a) => a.type === RDTYPES[rdtype])
          .map((a) => [rdtype === "TXT" ? String(a.data ?? "").replace(/^"|"$/g, "") : String(a.data ?? ""), Number(a.TTL ?? 0)]);
      } catch (e) {
        error = e?.name || e?.message || "failed";
      }
    }
    const err = new Error(`DoH ${rdtype} ${name}: ${error}`);
    err.name = "TimeoutError";
    throw err;
  };
}

const firstReal = (dns) => [...(dns.a || []), ...(dns.aaaa || [])].find((v) => !SINKHOLES.has(v)) ?? null;

// The capture records of one registrable domain: apex probed first, www. when the apex does not resolve.
// deps: { fetchFn, tlsFn(host, address) -> tls facts, bases, cfg: serving settings, now() }.
export async function gather(domain, deps) {
  const { fetchFn, tlsFn, bases, cfg } = deps;
  const query = dohQuery(cfg.doh_urls, fetchFn, cfg.dns_timeout_s * 1000);
  const rdapPromise = rdapFor(domain, bases, fetchFn, cfg.rdap_timeout_ms);
  let probe = domain;
  let dns = await dnsFacts(domain, domain, query);
  if (!dns.resolves && !dns.sinkhole) {
    const alt = await dnsFacts(`www.${domain}`, domain, query);
    if (alt.resolves) [dns, probe] = [alt, `www.${domain}`];
  }
  const address = firstReal(dns);
  const [domainRec, tls] = await Promise.all([
    rdapPromise,
    address ? tlsFn(probe, address) : { ok: false, verified: false, error: "gaierror" },
  ]);
  const captured = new Date(deps.now()).toISOString();
  return {
    hostRec: { kind: "host", host: domain, probe_host: probe, domain, captured_at: captured, dns, tls },
    domainRec: { kind: "domain", domain, captured_at: captured, ...domainRec },
  };
}

// One checked domain: { domain, verdict, prob, calibrated, reasons, facts }.
export async function checkDomain(domain, model, deps) {
  const { hostRec, domainRec } = await gather(domain, deps);
  const features = computeC(hostRec, domainRec, model.lists);
  const scored = scoreFeatures(model, features, { withReasons: true });
  return {
    domain,
    verdict: VERDICTS[scored.verdict],
    prob: scored.prob,
    calibrated: scored.calibrated,
    reasons: scored.reasons,
    facts: {
      resolves: hostRec.dns.resolves,
      domain_age_days: Number.isNaN(features.domain_age_days) ? null : Math.round(features.domain_age_days),
      rdap_error: domainRec.rdap_error,
      tls_verified: hostRec.tls?.verified ?? null,
    },
  };
}
