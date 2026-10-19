// Verdicts the extension gives to legitimate pages with HTML, without a browser: the service worker's
// pipeline (allowlist, URL model, page model, combiner) run on stored HTML. Backend domain checks and
// the blocklist are not applied (both runs the same). Facts the content script would read from the
// live DOM are read from the stored HTML with a simple tag scan (an approximation of the live page).
//   node js/bench/page_verdicts.mjs DIST PAGES.jsonl [--no-allowlist] [--old]
//     DIST: an assembled extension/dist (node extension/build.mjs), possibly of an older commit
//     --old: the pipeline before 2026-10-15 (page model may lower any verdict; no short pages)
// -> JSON {n, rows: [{url, verdict, layer, address, frame, ...}]} on stdout (frame: the verdict
//    as a credential frame, for pages that ask for credentials; null otherwise or with --old).

import { createReadStream, readFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";

const [distArg, pagesFile, ...flags] = process.argv.slice(2);
if (!distArg || !pagesFile) throw new Error("usage: page_verdicts.mjs DIST PAGES.jsonl [--no-allowlist] [--old]");
const old = flags.includes("--old");
const useAllow = !flags.includes("--no-allowlist");
const dist = pathToFileURL(`${distArg.replace(/\/$/, "")}/`);
const mod = (p) => import(new URL(p, dist).href);
const read = (p) => JSON.parse(readFileSync(new URL(p, dist), "utf8"));

const { loadHybrid } = await mod("lib/hybrid.js");
const { loadPage, scorePage } = await mod("lib/page.js");
const { ListSet } = await mod("lists.js");
const { combine, framePageVerdict } = await mod("combine.js");
const { pageFlags } = await mod("pagefacts.js");
const { scoreAddress } = await mod("address.js");

const model = loadHybrid(read("data/tier_a_hybrid.json"), read("data/psl_icann.json"));
const page = loadPage(read("data/tier_b_page.json"));
const lists = new ListSet(useAllow ? { allowlist: read("data/allowlist.json") } : null, {
  platforms: model.lists.platforms,
  psl: model.lists.psl,
  shorteners: model.lists.shorteners,
});

// The content script's facts from raw HTML (password inputs, credential inputs, form actions).
const CREDENTIAL_INPUT = /\b(otp|one[-_ ]?time|passcode|cvv|cvc|csc|card[-_ ]?(number|no)|cc[-_ ]?(num|number)|upi[-_ ]?pin|atm[-_ ]?pin|pin[-_ ]?code)\b/i;
const CREDENTIAL_AUTOCOMPLETE = /\b(one-time-code|cc-number|cc-csc)\b/i;
const attr = (tag, name) => tag.match(new RegExp(`\\s${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, "i"))?.slice(2).find((v) => v !== undefined) ?? null;
function facts(html, base) {
  let passwordFields = 0;
  let credentialFields = 0;
  for (const [tag] of html.matchAll(/<input\b[^>]*>/gi)) {
    const type = (attr(tag, "type") || "text").toLowerCase();
    if (type === "password") passwordFields += 1;
    else if (!["hidden", "submit", "button"].includes(type)) {
      const text = ["name", "id", "placeholder", "aria-label"].map((a) => attr(tag, a) || "").join(" ");
      if (CREDENTIAL_AUTOCOMPLETE.test(attr(tag, "autocomplete") || "") || CREDENTIAL_INPUT.test(text)) credentialFields += 1;
    }
  }
  const forms = [];
  for (const [, open, body] of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    let action = null;
    try {
      action = new URL(attr(`<f ${open}>`, "action") || "", base).href;
    } catch {
      action = null;
    }
    forms.push({ hasPassword: /<input\b[^>]*type\s*=\s*["']?password/i.test(body), action });
  }
  return { passwordFields, credentialFields, forms };
}

const rows = [];
const MAX_HTML_CHARS = 5_000_000; // the content script's cap
for await (const line of createInterface({ input: createReadStream(pagesFile), crlfDelay: Infinity })) {
  if (!line.trim()) continue;
  const { url, html: full } = JSON.parse(line);
  const html = full.slice(0, MAX_HTML_CHARS);
  const listed = await lists.check(url);
  const layers = { ...listed, trusted: false, model: null, domain: null, backendFailed: false, unscored: false };
  if (!listed.allow && !listed.shortener && !listed.blocked) layers.model = scoreAddress(model, url);
  const f = facts(html, url);
  const flags = pageFlags(f, url, model.lists.psl);
  const addressTrusted = listed.allow || listed.shortener;
  let pageModel = null;
  if (addressTrusted || layers.model) {
    const allowShort = !old && !addressTrusted && f.passwordFields > 0;
    pageModel = scorePage(model, page, url, html, { withReasons: false, allowShort });
    if (addressTrusted) {
      pageModel.allowedPageWarning = pageModel.hasHtml && pageModel.blended >= page.thresholds.dangerous && f.passwordFields > 0;
    }
  }
  const r = combine(layers, flags, pageModel);
  const address = layers.model?.verdict ?? 0;
  // the verdict this page would get if it were a credential frame (judged on its page score alone)
  const asks = Boolean(flags.asksCredentials);
  const frame =
    !old && framePageVerdict && asks && !addressTrusted
      ? framePageVerdict(scorePage(model, page, url, html, { allowShort: true }), page.thresholds)
      : null;
  rows.push({ url, verdict: r.verdict, layer: r.layer, address, frame, hasHtml: Boolean(pageModel?.hasHtml), short: Boolean(pageModel?.short), creds: flags.asksCredentials ?? flags.hasPassword });
}
console.log(JSON.stringify({ n: rows.length, rows }));
