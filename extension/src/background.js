// Service worker: checks every top-level navigation. Layers, cheapest first: blocklist, user trust
// and allowlist, URL model (on device), backend domain checks (only for pages already rated
// suspicious; only the domain name is sent), then the page model on the HTML the content script
// sends (on device), and the login forms of the page's frames.
// Webnavigation cannot hold a page back, so a slow check never delays loading (fail open); a
// dangerous verdict redirects the tab to the warning page once it is known. Before commit only a
// blocklist hit does that (the address before server redirects may be a form post or a redirect
// hop), and a dangerous verdict from the address model alone waits for the page check: it is shown
// as a banner, and becomes the warning page if the page asks for credentials, the page model
// agrees, or no page check arrives within HOLD_MS (combine.js `addressOnly`). The backend is never
// waited for: the verdict is shown at once and raised when (and if) the backend answers.

import { sanitizeSettings } from "./config.js";
import { addressOnly, combine, DANGEROUS, FRAME_PAGE_REASON, SAFE, SUSPICIOUS, framePageVerdict } from "./combine.js";
import { listDomainKey, listUrlKey } from "./keys.js";
import { MAX_URL_CHARS, effectiveUrl, isLocalAddress, scoreAddress } from "./address.js";
import { DOMAIN_FAILURE_MS, usableAnswer } from "./domain.js";
import { addTrust, liveTrust } from "./trust.js";
import { safeExit, worse } from "./navigation.js";
import { loadHybrid } from "./lib/hybrid.js";
import { addressSignals, loadBrandRules, pageSignal } from "./lib/brand_rules.js";
import { analyzeHtml } from "./lib/html_features.js";
import { loadPage, scorePage } from "./lib/page.js";
import { isIpHost } from "./lib/urlparts.js";
import { ListSet, withBundledAllowlist } from "./lists.js";
import { LIST_PUBKEY } from "./lists_pubkey.js";
import { fetchConfig, syncLists as fetchLists } from "./listsync.js";
import { pageFlags } from "./pagefacts.js";

const SYNC_ALARM = "sync-lists";
const BADGES = { [SAFE]: "", [SUSPICIOUS]: "!", [DANGEROUS]: "X" };
const BADGE_COLORS = { [SUSPICIOUS]: "#d97706", [DANGEROUS]: "#b91c1c" };

// --- storage helpers ------------------------------------------------------------------------

async function getSettings() {
  const { settings, remoteConfig } = await chrome.storage.local.get(["settings", "remoteConfig"]);
  const out = sanitizeSettings(settings);
  // the backend's validated remote config sets the sync interval unless the user set one
  if (remoteConfig?.list_sync_minutes && settings?.listSyncMinutes === undefined) {
    out.listSyncMinutes = remoteConfig.list_sync_minutes;
  }
  return out;
}

// Remote config (backend /config, checked by listsync.js): thresholds that replace the bundled
// ones and registrable domains that never get a model warning (a blocklist hit still warns).
let remotePromise;
function getRemote() {
  remotePromise ??= (async () => {
    const { remoteConfig } = await chrome.storage.local.get("remoteConfig");
    return { thresholds: remoteConfig?.thresholds ?? {}, neverWarn: new Set(remoteConfig?.never_warn ?? []) };
  })();
  return remotePromise;
}

function withThresholds(thresholds, remote) {
  const out = { ...thresholds };
  for (const k of ["suspicious", "dangerous"]) if (typeof remote?.[k] === "number") out[k] = remote[k];
  return out.suspicious < out.dangerous ? out : thresholds;
}

// Live "trust this site" entries (trust.js): key -> time trusted; expired ones are left out.
async function getTrusted() {
  const { trusted } = await chrome.storage.local.get("trusted");
  return liveTrust(trusted);
}

const session = {
  get: async (key) => (await chrome.storage.session.get(key))[key],
  set: (key, value) => chrome.storage.session.set({ [key]: value }),
  remove: (key) => chrome.storage.session.remove(key),
};

// --- model and lists -----------------------------------------------------------------------

let modelPromise;
function getModel() {
  modelPromise ??= (async () => {
    const read = async (path) => (await fetch(chrome.runtime.getURL(path))).json();
    const [bundle, psl] = await Promise.all([read("data/tier_a_hybrid.json"), read("data/psl_icann.json")]);
    const model = loadHybrid(bundle, psl);
    model.thresholds = withThresholds(model.thresholds, (await getRemote()).thresholds.address);
    return model;
  })();
  return modelPromise;
}

let pagePromise;
function getPage() {
  pagePromise ??= (async () => {
    const bundle = await (await fetch(chrome.runtime.getURL("data/tier_b_page.json"))).json();
    const page = loadPage(bundle);
    page.thresholds = withThresholds(page.thresholds, (await getRemote()).thresholds.page);
    return page;
  })();
  return pagePromise;
}

let rulesPromise;
function getRules() {
  rulesPromise ??= (async () => {
    const model = await getModel();
    const payload = await (await fetch(chrome.runtime.getURL("data/brand_rules.json"))).json();
    return loadBrandRules(payload, model.lists.psl, model.lists.platforms);
  })();
  return rulesPromise;
}

let listsPromise;
async function getBundled() {
  try {
    return await (await fetch(chrome.runtime.getURL("data/allowlist.json"))).json();
  } catch {
    return null; // built without a bundled allowlist: only the synced lists apply
  }
}

function getLists() {
  listsPromise ??= (async () => {
    const model = await getModel();
    const { lists } = await chrome.storage.local.get("lists");
    const payload = withBundledAllowlist(lists ?? null, await getBundled());
    return new ListSet(payload, { platforms: model.lists.platforms, psl: model.lists.psl, shorteners: model.lists.shorteners });
  })();
  return listsPromise;
}

// Lists and remote config are applied only after listsync.js checks them (signature, file hashes,
// sanity limits); a rejected update leaves the stored ones in place. Cached verdicts are dropped
// after any change, so a newly blocklisted site warns on the next visit.
export async function syncLists() {
  const settings = await getSettings();
  const { lists: stored } = await chrome.storage.local.get("lists");
  const common = { backendUrl: settings.backendUrl, pubkey: LIST_PUBKEY, timeoutMs: settings.backendTimeoutMs * 4 };
  const res = await fetchLists({ ...common, stored: stored ?? null, bundled: await getBundled() });
  const cfg = await fetchConfig(common);
  let changed = false;
  if (res.status === "updated") {
    await chrome.storage.local.set({ lists: res.lists });
    listsPromise = undefined;
    changed = true;
  }
  if (cfg.status === "updated") {
    const { remoteConfig } = await chrome.storage.local.get("remoteConfig");
    if (JSON.stringify(remoteConfig) !== JSON.stringify(cfg.config)) {
      await chrome.storage.local.set({ remoteConfig: cfg.config });
      remotePromise = modelPromise = pagePromise = undefined;
      changed = true;
      await ensureAlarm();
    }
  }
  if (changed) verdictCache.clear();
  const status = { at: Date.now(), lists: res.status, config: cfg.status, problems: [...(res.problems ?? []), ...(cfg.problems ?? [])] };
  if (status.problems.length) console.warn("PhishDrift list sync:", status);
  await chrome.storage.local.set({ listSync: status });
  return { updated: res.status === "updated", version: res.lists?.version ?? stored?.version ?? null, ...status };
}

// --- one URL -------------------------------------------------------------------------------

const verdictCache = new Map(); // listUrlKey -> { at, layers } (address layers only)
const domainCache = new Map(); // domain -> { at, answer | null }; failures kept DOMAIN_FAILURE_MS
const domainInflight = new Map(); // domain -> Promise of the running lookup

function cacheGet(map, key, ttl) {
  const hit = map.get(key);
  if (hit && Date.now() - hit.at < ttl) return hit;
  map.delete(key);
  return undefined;
}

function cacheSet(map, key, value, max) {
  if (map.size >= max) map.delete(map.keys().next().value);
  map.set(key, { at: Date.now(), ...value });
}

// Backend domain checks: send the domain only. A failed lookup is cached for a short time as a
// failure (never as "low risk"), and nobody waits for a running lookup.
async function fetchDomain(domain, localVerdict, settings) {
  let answer = null;
  try {
    const res = await fetch(`${settings.backendUrl}/score`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain, local_verdict: localVerdict }),
      signal: AbortSignal.timeout(settings.backendTimeoutMs),
    });
    if (res.ok) answer = usableAnswer(await res.json());
  } catch {
    // fall through: answer stays null
  }
  cacheSet(domainCache, domain, { answer }, settings.verdictCacheMax);
}

// { answer, failed } when a lookup is cached, else { pending: Promise } (lookup started).
function domainLookup(domain, localVerdict, settings) {
  const hit = domainCache.get(domain);
  if (hit && Date.now() - hit.at < (hit.answer ? settings.domainCacheMs : DOMAIN_FAILURE_MS)) {
    return { answer: hit.answer, failed: hit.answer === null };
  }
  if (!domainInflight.has(domain)) {
    const run = fetchDomain(domain, localVerdict, settings).finally(() => domainInflight.delete(domain));
    domainInflight.set(domain, run);
  }
  return { pending: domainInflight.get(domain) };
}

const askable = (layers) => Boolean(layers.domainName) && !layers.shared && !isIpHost(layers.domainName);

const UNSCORED = {
  trustKey: null, domainName: null, shared: false, allow: false, shortener: false, blocked: null,
  model: null, unscored: true, lookalike: [],
};

// Address layers (lists and the URL model) for a web address; cached per address.
async function layersFor(url) {
  const settings = await getSettings();
  const key = listUrlKey(url);
  const trusted = await getTrusted(); // read each time: a new "trust" takes effect at once
  const cached = cacheGet(verdictCache, key, settings.verdictCacheMs);
  if (cached) return { ...cached.layers, trusted: trusted.has(cached.layers.trustKey) };

  const [model, lists, remote] = await Promise.all([getModel(), getLists(), getRemote()]);
  const listed = await lists.check(url);
  // a never-warn domain from the remote config acts like the allowlist (never on shared hosts,
  // never over a blocklist hit)
  if (!listed.shared && !listed.blocked && remote.neverWarn.has(listed.domain)) listed.allow = true;
  const layers = {
    trustKey: listed.trustKey,
    domainName: listed.domain,
    shared: listed.shared,
    allow: listed.allow,
    shortener: listed.shortener,
    blocked: listed.blocked,
    model: null,
    unscored: false,
    local: isLocalAddress(url),
    lookalike: [],
  };
  // The model also runs on trusted addresses: trust can expire or be outweighed by a blocklist hit,
  // and the cached layers must not depend on it.
  if (!layers.allow && !layers.shortener && !layers.blocked && !layers.local) {
    layers.model = scoreAddress(model, url);
    try {
      layers.lookalike = addressSignals(await getRules(), url);
    } catch (err) {
      console.warn("PhishDrift look-alike check failed:", err);
    }
  }
  cacheSet(verdictCache, key, { layers }, settings.verdictCacheMax);
  return { ...layers, trusted: trusted.has(listed.trustKey) };
}

// Page model on the HTML the content script sent (on this device). Any failure leaves the
// address verdict in place. On allowlisted pages and short links the address is not judged, so the
// page alone must carry the warning: a usable page over the page model's dangerous threshold that
// asks for a password (reports/stress_test: 1 of 893 allowlisted legitimate pages with HTML).
// A page with a password field but too little text for the page model (a bare login-form clone)
// is still read; the combiner never lets the page model lower a verdict on such a page.
// `brandFacts` (an object) receives the brand-rule page facts from the same parse.
async function pageCheck(layers, url, html, facts, brandFacts = null) {
  if (html == null || layers.trusted || layers.blocked || layers.unscored || url.length > MAX_URL_CHARS) return null;
  const addressTrusted = layers.allow || layers.shortener;
  if (!addressTrusted && !layers.model) return null;
  try {
    const [model, page, rules] = await Promise.all([getModel(), getPage(), getRules()]);
    const allowShort = !addressTrusted && (facts?.passwordFields ?? 0) > 0;
    const first = scorePage(model, page, url, html, { allowShort, facts: brandFacts, factBrands: rules.brandSet });
    const scored =
      first.verdict > SAFE && first.hasHtml ? scorePage(model, page, url, html, { withReasons: true, allowShort }) : first;
    if (addressTrusted) {
      scored.allowedPageWarning =
        scored.hasHtml && scored.blended >= page.thresholds.dangerous && (facts?.passwordFields ?? 0) > 0;
    }
    return scored;
  } catch (err) {
    console.warn("PhishDrift page check failed (address verdict kept):", err);
    return null;
  }
}

// Page model on a credential frame's HTML, judged on the blended score alone. Frames on
// allowlisted, trusted, blocklisted (already dangerous) or shortener addresses are skipped.
async function frameCheck(target, html) {
  if (target === null || html == null || target.length > MAX_URL_CHARS) return null;
  const layers = await layersFor(target);
  if (layers.allow || layers.shortener || layers.trusted || layers.blocked || layers.local) return null;
  try {
    const [model, page] = await Promise.all([getModel(), getPage()]);
    const first = scorePage(model, page, target, html, { allowShort: true });
    const verdict = framePageVerdict(first, page.thresholds);
    if (verdict === SAFE) return null;
    const { reasons } = scorePage(model, page, target, html, { withReasons: true, allowShort: true });
    return { verdict, reasons };
  } catch (err) {
    console.warn("PhishDrift frame check failed:", err);
    return null;
  }
}

// The verdict for a document. `origin` (from the content script) gives about:blank pages and
// frames the address they inherit. Returns { result, pending }: `pending` is set when a backend
// lookup was started for a suspicious page; when it settles, evaluate again to use its answer.
export async function evaluate(url, { facts = null, html = null, origin = null } = {}) {
  const settings = await getSettings();
  const target = effectiveUrl(url, origin);
  const layers = target === null ? { ...UNSCORED, trusted: false } : { ...(await layersFor(target)) };
  const model = await getModel();
  const page = facts ? pageFlags(facts, target, model.lists.psl) : null;
  const brandFacts = {};
  const pageModel = target === null ? null : await pageCheck(layers, target, html, facts, brandFacts);
  const brand = await brandSignals(layers, target, html, brandFacts, model);
  let result = combine(layers, page, pageModel, brand);
  let pending = null;
  // Domain evidence can only raise suspicious to dangerous, so only suspicious pages ask for it.
  if (result.verdict === SUSPICIOUS && askable(layers) && !layers.allow && !layers.shortener) {
    const found = domainLookup(layers.domainName, result.verdict, settings);
    if (found.pending) {
      pending = found.pending;
    } else {
      layers.domain = found.answer;
      layers.backendFailed = found.failed;
      result = combine(layers, page, pageModel, brand);
    }
  }
  return { result: { ...result, url, domain: layers.domainName }, pending };
}

// Look-alike address hits (from the cached layers) and the brand-page rule on the page's HTML.
async function brandSignals(layers, target, html, brandFacts, model) {
  const brand = { address: layers.lookalike ?? [], page: null };
  if (target === null || html == null || layers.trusted || layers.blocked) return brand;
  try {
    const rules = await getRules();
    // the page check parses the page once; when it did not run, parse here for the facts only
    if (!Object.keys(brandFacts).length && target.length <= MAX_URL_CHARS) {
      analyzeHtml(target, html, model.lists, null, { facts: brandFacts, factBrands: rules.brandSet });
    }
    brand.page = pageSignal(rules, target, brandFacts);
  } catch (err) {
    console.warn("PhishDrift brand-page check failed:", err);
  }
  return brand;
}

// Evaluate, apply, and apply again once a backend lookup it started has settled.
async function check(url, options, apply) {
  const { result, pending } = await evaluate(url, options);
  await apply(result);
  if (pending) {
    pending
      .then(async () => apply((await evaluate(url, options)).result, result))
      .catch((err) => console.warn("PhishDrift follow-up failed:", err));
  }
  return result;
}

// --- tabs -----------------------------------------------------------------------------------

function warningUrl(tabId) {
  return chrome.runtime.getURL(`warning.html?tab=${tabId}`);
}

// The last few addresses in a tab that were checked and safe, for "Take me back to safety".
const SAFE_HISTORY = 5;

async function rememberSafe(tabId, result) {
  if (result.verdict !== SAFE || !/^https?:/i.test(result.url ?? "")) return;
  if (!["allowlist", "url-model", "page-model", "user-trusted"].includes(result.layer)) return;
  const seen = ((await session.get(`safe:${tabId}`)) ?? []).filter((e) => e.url !== result.url);
  seen.push({ url: result.url, domain: result.domain });
  await session.set(`safe:${tabId}`, seen.slice(-SAFE_HISTORY));
}

// `at` is the tab's navigation when the verdict was reached; the warning page is not opened if the
// tab has moved on since (the awaits below leave room for "Take me back to safety" to run).
async function applyResult(tabId, result, at = lastNav.get(tabId)) {
  await session.set(`tab:${tabId}`, result);
  await chrome.action.setBadgeText({ tabId, text: BADGES[result.verdict] });
  if (BADGE_COLORS[result.verdict]) {
    await chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS[result.verdict] });
  }
  const bypass = await session.get(`bypass:${tabId}`);
  if (result.verdict === DANGEROUS && bypass !== listUrlKey(result.url) && lastNav.get(tabId) === at) {
    await chrome.tabs.update(tabId, { url: warningUrl(tabId) });
  }
}

// Tell the page's content script (if it is there yet) to show the banner for a verdict the
// service worker reached on its own (after a redirect, an in-page address change, a frame or a late
// backend answer).
// `kind` is "commit" for the address verdict at commit (stale once the page check has answered)
// and "raise" for anything that raised the document later (frame, in-page address, backend, tamper).
function notifyTab(tabId, result, kind = "raise") {
  if (result.verdict !== SUSPICIOUS) return;
  chrome.tabs.sendMessage(tabId, { type: "phishdrift-verdict", result, kind }, { frameId: 0 }).catch(() => {});
}

// Every address a document has shown is scored, and the document keeps the worst verdict: a page
// cannot lower its own verdict by rewriting its address (history.replaceState). `doc:<tab>` holds
// the committed address (after server redirects), the worst verdict of later in-page addresses and
// frames (`floor`), whether the page check has reported, and whether a frame asks for credentials.
// Pages built in memory (blob:) and local files are covered too (address.js effectiveUrl).
const navFilter = { url: [{ schemes: ["http", "https", "blob", "file"] }] };

async function guarded(fn) {
  try {
    await fn();
  } catch (err) {
    console.warn("PhishDrift check failed (page left alone):", err);
  }
}

const sameDoc = async (tabId, url) => (await session.get(`doc:${tabId}`))?.url === url;

// Raise the tab's shown verdict to `result` if it is worse, and remember it for the document.
async function raiseTab(tabId, result) {
  const at = lastNav.get(tabId);
  const doc = await session.get(`doc:${tabId}`);
  if (doc) await session.set(`doc:${tabId}`, { ...doc, floor: worse(doc.floor, result) });
  const shown = worse(await session.get(`tab:${tabId}`), result);
  await applyResult(tabId, shown, at);
  notifyTab(tabId, shown);
}

// A dangerous verdict shown as suspicious for now (before commit, or until the page check).
const held = (result) => ({ ...result, verdict: SUSPICIOUS, held: true });
const HOLD_MS = 5000;

// Committed but not yet read: the address model's dangerous verdict alone becomes the warning page
// only if no page check has started by HOLD_MS (pages where the content script cannot run).
function holdForPage(tabId, url, result) {
  setTimeout(
    () =>
      guarded(async () => {
        const doc = await session.get(`doc:${tabId}`);
        if (doc?.url !== url || doc.pageSeen || !stillAt(tabId, url)) return;
        await raiseTab(tabId, result);
      }),
    HOLD_MS,
  );
}

// Before the request: the address as typed or clicked (earliest possible warning, but only a
// blocklist hit opens the warning page here). A late backend answer is applied after commit.
// The address each tab is navigating to now. A verdict reached for an older navigation (slow
// scoring, a late backend answer) is dropped, so it can never send the tab that has since moved on
// ("Take me back to safety", a new link) back to the warning page. Lost if the worker restarts;
// then every verdict is applied, as before.
const lastNav = new Map();
const stillAt = (tabId, url) => !lastNav.has(tabId) || lastNav.get(tabId) === url;

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  const { tabId, url } = details;
  lastNav.set(tabId, url);
  guarded(async () => {
    const { result } = await evaluate(url);
    const early = result.verdict === DANGEROUS && result.layer !== "blocklist" ? held(result) : result;
    if (stillAt(tabId, url)) await applyResult(tabId, early);
  });
}, navFilter);

// Committed: the address after server redirects (shorteners, tracking links), before the page
// renders.
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  const { tabId, url } = details;
  lastNav.set(tabId, url);
  guarded(async () => {
    await session.set(`doc:${tabId}`, { url, floor: null, pageDone: false, frameCredentials: false });
    await check(url, {}, async (result, earlier) => {
      const doc = await session.get(`doc:${tabId}`);
      if (doc?.url !== url || !stillAt(tabId, url)) {
        if (!earlier) await rememberSafe(tabId, result); // a newer navigation; still a safe place to go back to
        return;
      }
      if (earlier) return raiseTab(tabId, result); // late backend answer
      if (doc.pageDone) return; // the page check won
      const shown = addressOnly(result) ? held(result) : result;
      await applyResult(tabId, shown);
      await rememberSafe(tabId, shown);
      notifyTab(tabId, shown, "commit");
      if (shown !== result) holdForPage(tabId, url, result);
    });
  });
}, navFilter);

// In-page address changes (single-page apps, history.pushState / replaceState): score the new
// address, and ask the page to send its content again once the new view has rendered.
chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  if (details.frameId !== 0) return;
  const { tabId, url } = details;
  guarded(async () => {
    const committed = (await session.get(`doc:${tabId}`))?.url;
    if (!committed) await session.set(`doc:${tabId}`, { url, floor: null, pageDone: false, frameCredentials: false });
    const doc = committed ?? url;
    await check(url, {}, async (result) => {
      // the page is asked to send its content again below; that check decides an address-only block
      if (stillAt(tabId, doc) && (await sameDoc(tabId, doc))) await raiseTab(tabId, addressOnly(result) ? held(result) : result);
    });
    chrome.tabs.sendMessage(tabId, { type: "phishdrift-recheck" }, { frameId: 0 }).catch(() => {});
  });
}, navFilter);

chrome.tabs.onRemoved.addListener((tabId) => {
  lastNav.delete(tabId);
  for (const key of ["tab", "bypass", "doc", "safe"]) session.remove(`${key}:${tabId}`);
});

// --- messages from the content script, popup and warning page -------------------------------

async function feedback(kind, tabId) {
  const result = await session.get(`tab:${tabId}`);
  if (!result?.domain) return { ok: false };
  const { backendUrl, backendTimeoutMs } = await getSettings();
  try {
    const res = await fetch(`${backendUrl}/feedback`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: result.domain, kind, verdict: result.verdict }), // domain only
      signal: AbortSignal.timeout(backendTimeoutMs),
    });
    return { ok: res.ok };
  } catch {
    return { ok: false };
  }
}

async function trust(tabId) {
  const result = await session.get(`tab:${tabId}`);
  const target = result?.url ? effectiveUrl(result.url) : null;
  if (!target) return { ok: false };
  const layers = await layersFor(target);
  if (!layers.trustKey) return { ok: false };
  const { trusted } = await chrome.storage.local.get("trusted");
  await chrome.storage.local.set({ trusted: addTrust(trusted, layers.trustKey) });
  return { ok: true, key: layers.trustKey };
}

async function leave(tabId) {
  const [result, seen, model] = await Promise.all([session.get(`tab:${tabId}`), session.get(`safe:${tabId}`), getModel()]);
  const domainOf = (u) => {
    const t = u ? effectiveUrl(u) : null;
    return t ? listDomainKey(t, model.lists.psl) : null;
  };
  const url = safeExit(seen, result?.url ?? null, domainOf);
  await session.remove(`bypass:${tabId}`);
  lastNav.set(tabId, url); // verdicts still arriving for the dangerous page are dropped
  await chrome.tabs.update(tabId, { url });
  return { ok: true, url };
}

const TAMPER_REASON = "This page tried to hide PhishDrift's warning.";
const SAME_SITE_FRAME = "This page asks for a password inside an embedded frame.";
const CROSS_SITE_FRAME = "This page shows a login form from another website, and that website looks unsafe:";

const handlers = {
  // Content script, top frame: page facts in, final verdict out.
  // The page is scored at the address it reports and at the address it was committed at; the
  // worse verdict (and any worse in-page address or frame seen since) stands.
  async page(msg, sender) {
    const tabId = sender.tab?.id;
    const at = tabId === undefined ? undefined : lastNav.get(tabId); // before any await
    const doc = tabId === undefined ? null : await session.get(`doc:${tabId}`);
    if (doc) await session.set(`doc:${tabId}`, { ...doc, pageSeen: true }); // stops holdForPage
    const facts = { ...msg.facts, frameCredentials: Boolean(doc?.frameCredentials) };
    const options = { facts, html: msg.html ?? null, origin: msg.origin ?? null };
    // Returns { result, pending }; `pending` settles when a backend lookup it started is done.
    const score = async () => {
      const first = await evaluate(msg.url, options);
      let { result } = first;
      let pending = first.pending;
      if (doc?.url && listUrlKey(doc.url) !== listUrlKey(msg.url)) {
        const second = await evaluate(doc.url, options);
        result = worse(result, second.result);
        pending = pending && second.pending ? Promise.all([pending, second.pending]) : (pending ?? second.pending);
      }
      const now = tabId === undefined ? null : await session.get(`doc:${tabId}`);
      return { result: worse(result, now?.floor ?? doc?.floor ?? null), pending };
    };
    let { result, pending } = await score();
    // a page the tab has already left (the user went back to safety, the warning page replaced it)
    if (tabId !== undefined && (lastNav.get(tabId) !== at || !stillAt(tabId, doc?.url ?? msg.url))) {
      await rememberSafe(tabId, result); // still a safe place to go back to
      return result;
    }
    if (tabId !== undefined) {
      if (doc) await session.set(`doc:${tabId}`, { ...(await session.get(`doc:${tabId}`)), pageDone: true });
      await applyResult(tabId, result, at);
      // a frame or in-page change may have raised this document while it was being scored
      const raised = worse(result, (await session.get(`doc:${tabId}`))?.floor ?? null);
      if (raised !== result) {
        result = raised;
        await applyResult(tabId, result, at);
      }
      await rememberSafe(tabId, result);
      // A late backend answer is applied to the same document only.
      pending
        ?.then(async () => {
          if ((!doc || (await sameDoc(tabId, doc.url))) && stillAt(tabId, doc?.url ?? msg.url)) await raiseTab(tabId, (await score()).result);
        })
        .catch(() => {});
    }
    return result;
  },

  // Content script, any other frame that asks for credentials (password, one-time code, card, PIN).
  // Same-site and address-less frames (about:blank, srcdoc) count as the page asking for credentials,
  // so the page model can no longer lower the address verdict. A frame from another site is
  // judged at its own address and on its own HTML, like a page.
  async frame(msg, sender) {
    const tabId = sender.tab?.id;
    if (tabId === undefined) return null;
    const doc = await session.get(`doc:${tabId}`);
    const topUrl = doc?.url ?? sender.tab?.url ?? null;
    if (!topUrl) return null;
    const model = await getModel();
    const flags = pageFlags(msg.facts ?? {}, null, model.lists.psl);
    if (!flags.asksCredentials) return null;
    if (doc) await session.set(`doc:${tabId}`, { ...doc, frameCredentials: true });

    const topTarget = effectiveUrl(topUrl);
    const frameTarget = effectiveUrl(msg.url, msg.origin ?? null);
    const domainOf = (u) => (u ? listDomainKey(u, model.lists.psl) : null);
    const sameSite = frameTarget !== null && domainOf(frameTarget) === domainOf(topTarget);
    // The address verdict without any page-model lowering (the page now asks for credentials).
    let result = (await evaluate(topUrl, { facts: { passwordFields: 1, forms: [] } })).result;
    if (result.verdict > SAFE && sameSite) result = { ...result, reasons: [...result.reasons, SAME_SITE_FRAME] };
    if (!sameSite) {
      const options = { facts: msg.facts, html: msg.html ?? null, origin: msg.origin ?? null };
      const framed = (await evaluate(msg.url, options)).result;
      if (framed.verdict > result.verdict) {
        result = { ...framed, url: topUrl, domain: result.domain, reasons: [CROSS_SITE_FRAME, ...framed.reasons] };
      }
    }
    // The frame's own form, on its page score alone (the agree rule is not applied to frames).
    const framePage = await frameCheck(frameTarget ?? topTarget, msg.html ?? null);
    if (framePage && framePage.verdict > result.verdict) {
      result = { ...result, verdict: framePage.verdict, layer: "frame-page", reasons: [FRAME_PAGE_REASON, ...framePage.reasons] };
    }
    if (result.verdict > SAFE && stillAt(tabId, topUrl)) await raiseTab(tabId, result);
    return result;
  },

  // The page kept removing or hiding the suspicious banner: show the full warning page instead.
  async tamper(msg, sender) {
    const tabId = sender.tab?.id;
    const shown = tabId === undefined ? null : await session.get(`tab:${tabId}`);
    if (!shown || shown.verdict !== SUSPICIOUS || sender.frameId !== 0) return null;
    const result = { ...shown, verdict: DANGEROUS, layer: "tamper", reasons: [TAMPER_REASON, ...shown.reasons] };
    await raiseTab(tabId, result);
    return result;
  },

  status: async (msg) => (await session.get(`tab:${msg.tabId}`)) ?? null,
  async bypass(msg) {
    const result = await session.get(`tab:${msg.tabId}`);
    if (result) await session.set(`bypass:${msg.tabId}`, listUrlKey(result.url));
    return { ok: Boolean(result), url: result?.url };
  },
  leave: (msg) => leave(msg.tabId),
  feedback: (msg) => feedback(msg.kind, msg.tabId),
  trust: (msg) => trust(msg.tabId),
  sync: () => syncLists(),
};

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const handler = handlers[msg?.type];
  if (!handler) return false;
  handler(msg, sender).then(sendResponse, (err) => sendResponse({ error: String(err) }));
  return true; // async response
});

// --- list sync ------------------------------------------------------------------------------

async function ensureAlarm() {
  const { listSyncMinutes } = await getSettings();
  await chrome.alarms.create(SYNC_ALARM, { periodInMinutes: listSyncMinutes });
}
chrome.runtime.onInstalled.addListener(() => {
  ensureAlarm();
  syncLists();
});
chrome.runtime.onStartup.addListener(ensureAlarm);
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === SYNC_ALARM) syncLists();
});
