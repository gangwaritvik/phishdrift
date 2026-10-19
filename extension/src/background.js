// Service worker: checks every top-level navigation. Layers, cheapest first: user trust and
// allowlist, blocklist, URL model (on device), backend domain checks (only for addresses a model
// already flagged; only the domain name is sent), then the page model on the HTML the content
// script sends (on device).
// Webnavigation cannot hold a page back, so a slow check never delays loading (fail open); a
// dangerous verdict redirects the tab to the warning page once it is known.

import { sanitizeSettings } from "./config.js";
import { combine, DANGEROUS, SAFE, SUSPICIOUS } from "./combine.js";
import { listUrlKey } from "./keys.js";
import { MAX_URL_CHARS, scoreAddress } from "./address.js";
import { loadHybrid } from "./lib/hybrid.js";
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

async function getTrusted() {
  const { trusted } = await chrome.storage.local.get("trusted");
  return new Set(trusted ?? []);
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

const verdictCache = new Map(); // listUrlKey -> { at, layers }
const domainCache = new Map(); // domain -> { at, answer | null }

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

// Backend domain checks: send the domain only, fail open on any error or timeout.
async function domainChecks(domain, localVerdict, settings) {
  const hit = cacheGet(domainCache, domain, settings.domainCacheMs);
  if (hit) return hit.answer;
  let answer = null;
  try {
    const res = await fetch(`${settings.backendUrl}/score`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain, local_verdict: localVerdict }),
      signal: AbortSignal.timeout(settings.backendTimeoutMs),
    });
    if (res.ok) answer = await res.json();
  } catch {
    // fall through: answer stays null
  }
  if (answer) cacheSet(domainCache, domain, { answer }, settings.verdictCacheMax);
  return answer;
}

async function layersFor(url) {
  const settings = await getSettings();
  const key = listUrlKey(url);
  const cached = cacheGet(verdictCache, key, settings.verdictCacheMs);
  const trusted = await getTrusted(); // read each time: a new "trust" takes effect at once
  if (cached) return { ...cached.layers, trusted: trusted.has(cached.layers.trustKey) };

  const [model, lists, remote] = await Promise.all([getModel(), getLists(), getRemote()]);
  const listed = await lists.check(url);
  // a never-warn domain from the remote config acts like the allowlist (never on shared hosts,
  // never over a blocklist hit)
  if (!listed.shared && !listed.blocked && remote.neverWarn.has(listed.domain)) listed.allow = true;
  const layers = {
    trustKey: listed.trustKey,
    domain: null,
    domainName: listed.domain,
    shared: listed.shared,
    allow: listed.allow,
    shortener: listed.shortener,
    blocked: listed.blocked,
    model: null,
    answer: null,
    backendFailed: false,
  };
  layers.trusted = trusted.has(listed.trustKey);
  if (!layers.trusted && !layers.allow && !layers.shortener && !layers.blocked) {
    const scored = scoreAddress(model, url);
    layers.model = scored;
    // Domain evidence can only raise suspicious to dangerous, so a dangerous address never waits
    // for the backend.
    if (scored.verdict === SUSPICIOUS && listed.domain && !listed.shared && !isIpHost(listed.domain)) {
      layers.domain = await domainChecks(listed.domain, scored.verdict, settings);
      layers.backendFailed = layers.domain === null;
    }
  }
  cacheSet(verdictCache, key, { layers }, settings.verdictCacheMax);
  return layers;
}

// Page model on the HTML the content script sent (on this device). Any failure leaves the
// address verdict in place. On allowlisted pages and short links the address is not judged, so the
// page alone must carry the warning: a usable page over the page model's dangerous threshold that
// asks for a password (reports/stress_test: 1 of 893 allowlisted legitimate pages with HTML).
async function pageCheck(layers, url, html, facts, settings) {
  if (html == null || layers.trusted || layers.blocked || url.length > MAX_URL_CHARS) return null;
  const addressTrusted = layers.allow || layers.shortener;
  if (!addressTrusted && !layers.model) return null;
  try {
    const [model, page] = await Promise.all([getModel(), getPage()]);
    const first = scorePage(model, page, url, html);
    const scored = first.verdict > SAFE && first.hasHtml ? scorePage(model, page, url, html, { withReasons: true }) : first;
    if (addressTrusted) {
      scored.allowedPageWarning =
        scored.hasHtml && scored.blended >= page.thresholds.dangerous && (facts?.passwordFields ?? 0) > 0;
      return scored;
    }
    // the page model flagged an address the URL model passed: ask the backend about the domain too
    if (scored.verdict > SAFE && !layers.domain && !layers.backendFailed && layers.domainName && !layers.shared && !isIpHost(layers.domainName)) {
      layers.domain = await domainChecks(layers.domainName, scored.verdict, settings);
      layers.backendFailed = layers.domain === null;
    }
    return scored;
  } catch (err) {
    console.warn("PhishDrift page check failed (address verdict kept):", err);
    return null;
  }
}

export async function evaluate(url, facts = null, html = null) {
  const settings = await getSettings();
  const layers = { ...(await layersFor(url)) };
  const model = await getModel();
  const page = facts ? pageFlags(facts, url, model.lists.psl) : null;
  const pageModel = await pageCheck(layers, url, html, facts, settings);
  const result = combine(layers, page, pageModel);
  return { ...result, url, domain: layers.domainName };
}

// --- tabs -----------------------------------------------------------------------------------

function warningUrl(tabId) {
  return chrome.runtime.getURL(`warning.html?tab=${tabId}`);
}

async function applyResult(tabId, result) {
  await session.set(`tab:${tabId}`, result);
  await chrome.action.setBadgeText({ tabId, text: BADGES[result.verdict] });
  if (BADGE_COLORS[result.verdict]) {
    await chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS[result.verdict] });
  }
  const bypass = await session.get(`bypass:${tabId}`);
  if (result.verdict === DANGEROUS && bypass !== listUrlKey(result.url)) {
    await chrome.tabs.update(tabId, { url: warningUrl(tabId) });
  }
}

// The worse of two results (higher verdict; the first on a tie).
export function worse(a, b) {
  if (!a) return b;
  if (!b) return a;
  return b.verdict > a.verdict ? b : a;
}

// Tell the page's content script (if it is there yet) to show the banner for a verdict the
// service worker reached on its own (after a redirect or an in-page address change).
function notifyTab(tabId, result) {
  if (result.verdict !== SUSPICIOUS) return;
  chrome.tabs.sendMessage(tabId, { type: "phishdrift-verdict", result }).catch(() => {});
}

// Every address a document has shown is scored, and the document keeps the worst verdict: a page
// cannot lower its own verdict by rewriting its address (history.replaceState). `doc:<tab>` holds
// the committed address (after server redirects), the worst verdict of later in-page addresses,
// and whether the page check has reported.
const navFilter = { url: [{ schemes: ["http", "https"] }] };

async function guarded(fn) {
  try {
    await fn();
  } catch (err) {
    console.warn("PhishDrift check failed (page left alone):", err);
  }
}

// Before the request: the address as typed or clicked (earliest possible warning).
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  guarded(async () => applyResult(details.tabId, await evaluate(details.url)));
}, navFilter);

// Committed: the address after server redirects (shorteners, tracking links), before the page
// renders.
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  const { tabId, url } = details;
  guarded(async () => {
    await session.set(`doc:${tabId}`, { url, floor: null, pageDone: false });
    const result = await evaluate(url);
    const doc = await session.get(`doc:${tabId}`);
    if (doc?.url !== url || doc.pageDone) return; // a newer navigation or the page check won
    await applyResult(tabId, result);
    notifyTab(tabId, result);
  });
}, navFilter);

// In-page address changes (single-page apps, history.pushState / replaceState).
chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  if (details.frameId !== 0) return;
  const { tabId, url } = details;
  guarded(async () => {
    const result = await evaluate(url);
    const doc = (await session.get(`doc:${tabId}`)) ?? { url, floor: null, pageDone: false };
    await session.set(`doc:${tabId}`, { ...doc, floor: worse(doc.floor, result) });
    const shown = worse(await session.get(`tab:${tabId}`), result);
    await applyResult(tabId, shown);
    notifyTab(tabId, shown);
  });
}, navFilter);

chrome.tabs.onRemoved.addListener((tabId) => {
  session.remove(`tab:${tabId}`);
  session.remove(`bypass:${tabId}`);
  session.remove(`doc:${tabId}`);
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
  if (!result?.url) return { ok: false };
  const layers = await layersFor(result.url);
  if (!layers.trustKey) return { ok: false };
  const trusted = await getTrusted();
  trusted.add(layers.trustKey);
  await chrome.storage.local.set({ trusted: [...trusted] });
  return { ok: true, key: layers.trustKey };
}

const handlers = {
  // Content script: page facts in, final verdict out.
  // The page is scored at the address it reports and at the address it was committed at; the
  // worse verdict (and any worse in-page address seen since) stands.
  async page(msg, sender) {
    const tabId = sender.tab?.id;
    const html = msg.html ?? null;
    let result = await evaluate(msg.url, msg.facts, html);
    const doc = tabId === undefined ? null : await session.get(`doc:${tabId}`);
    if (doc?.url && listUrlKey(doc.url) !== listUrlKey(msg.url)) {
      result = worse(result, await evaluate(doc.url, msg.facts, html));
    }
    result = worse(result, doc?.floor ?? null);
    if (tabId !== undefined) {
      if (doc) await session.set(`doc:${tabId}`, { ...doc, pageDone: true });
      await applyResult(tabId, result);
    }
    return result;
  },
  status: async (msg) => (await session.get(`tab:${msg.tabId}`)) ?? null,
  async bypass(msg) {
    const result = await session.get(`tab:${msg.tabId}`);
    if (result) await session.set(`bypass:${msg.tabId}`, listUrlKey(result.url));
    return { ok: Boolean(result), url: result?.url };
  },
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
