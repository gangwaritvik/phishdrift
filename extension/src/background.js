// Service worker: checks every top-level navigation. Layers, cheapest first: user trust and
// allowlist, blocklist, URL model (on device), backend domain checks (only for addresses the
// model already flagged; only the domain name is sent), then page checks from the content script.
// Webnavigation cannot hold a page back, so a slow check never delays loading (fail open); a
// dangerous verdict redirects the tab to the warning page once it is known.

import { DEFAULTS } from "./config.js";
import { combine, DANGEROUS, SAFE, SUSPICIOUS } from "./combine.js";
import { listUrlKey } from "./keys.js";
import { loadHybrid, scoreUrl } from "./lib/hybrid.js";
import { isIpHost } from "./lib/urlparts.js";
import { ListSet, withBundledAllowlist } from "./lists.js";
import { pageFlags } from "./pagefacts.js";

const SYNC_ALARM = "sync-lists";
const BADGES = { [SAFE]: "", [SUSPICIOUS]: "!", [DANGEROUS]: "X" };
const BADGE_COLORS = { [SUSPICIOUS]: "#d97706", [DANGEROUS]: "#b91c1c" };

// --- storage helpers ------------------------------------------------------------------------

async function getSettings() {
  const { settings } = await chrome.storage.local.get("settings");
  return { ...DEFAULTS, ...settings };
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
    return loadHybrid(bundle, psl);
  })();
  return modelPromise;
}

let listsPromise;
function getLists() {
  listsPromise ??= (async () => {
    const model = await getModel();
    const { lists } = await chrome.storage.local.get("lists");
    let bundled = null;
    try {
      bundled = await (await fetch(chrome.runtime.getURL("data/allowlist.json"))).json();
    } catch {
      // built without a bundled allowlist: only the synced lists apply
    }
    const payload = withBundledAllowlist(lists ?? null, bundled);
    return new ListSet(payload, { platforms: model.lists.platforms, psl: model.lists.psl });
  })();
  return listsPromise;
}

export async function syncLists() {
  const { backendUrl, backendTimeoutMs } = await getSettings();
  const get = async (path) => {
    const res = await fetch(`${backendUrl}${path}`, { signal: AbortSignal.timeout(backendTimeoutMs * 4) });
    if (!res.ok) throw new Error(`${path}: ${res.status}`);
    return res.json();
  };
  try {
    const manifest = await get("/lists/manifest");
    const { lists } = await chrome.storage.local.get("lists");
    if (lists?.version === manifest.version) return { updated: false, version: manifest.version };
    const [blocklist, allowlist] = await Promise.all([get("/lists/blocklist.json"), get("/lists/allowlist.json")]);
    await chrome.storage.local.set({ lists: { version: manifest.version, blocklist, allowlist } });
    listsPromise = undefined;
    return { updated: true, version: manifest.version };
  } catch (err) {
    return { updated: false, error: String(err) };
  }
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

  const [model, lists] = await Promise.all([getModel(), getLists()]);
  const listed = await lists.check(url);
  const layers = {
    trustKey: listed.trustKey,
    domain: null,
    domainName: listed.domain,
    shared: listed.shared,
    allow: listed.allow,
    blocked: listed.blocked,
    model: null,
    answer: null,
    backendFailed: false,
  };
  layers.trusted = trusted.has(listed.trustKey);
  if (!layers.trusted && !layers.allow && !layers.blocked) {
    const first = scoreUrl(model, url);
    // Reasons (TreeSHAP, about 100 ms) only for addresses that get a warning.
    const scored = first.verdict > SAFE ? scoreUrl(model, url, { withReasons: true }) : first;
    layers.model = { verdict: scored.verdict, prob: scored.prob, reasons: scored.reasons };
    if (scored.verdict > SAFE && listed.domain && !listed.shared && !isIpHost(listed.domain)) {
      layers.domain = await domainChecks(listed.domain, scored.verdict, settings);
      layers.backendFailed = layers.domain === null;
    }
  }
  cacheSet(verdictCache, key, { layers }, settings.verdictCacheMax);
  return layers;
}

export async function evaluate(url, facts = null) {
  const layers = await layersFor(url);
  const model = await getModel();
  const page = facts ? pageFlags(facts, url, model.lists.psl) : null;
  const result = combine(layers, page);
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

chrome.webNavigation.onBeforeNavigate.addListener(
  async (details) => {
    if (details.frameId !== 0) return;
    try {
      await applyResult(details.tabId, await evaluate(details.url));
    } catch (err) {
      console.warn("PhishDrift check failed (page left alone):", err);
    }
  },
  { url: [{ schemes: ["http", "https"] }] },
);

chrome.tabs.onRemoved.addListener((tabId) => {
  session.remove(`tab:${tabId}`);
  session.remove(`bypass:${tabId}`);
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
  async page(msg, sender) {
    const tabId = sender.tab?.id;
    const result = await evaluate(msg.url, msg.facts);
    if (tabId !== undefined) await applyResult(tabId, result);
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
