// Content script (classic script, no imports), in every frame. In the top frame, when the page has
// loaded it hands the page's HTML and its credential fields to the service worker, which scores the
// page on this device, gets the final verdict back, and shows a banner for "suspicious". In other
// frames it reports only frames that ask for credentials (a login form in an iframe, about:blank or
// srcdoc frame). Nothing leaves the device from here: the page model runs in the service worker and
// the backend only ever sees a domain name.

const CREDENTIAL_INPUT = /\b(otp|one[-_ ]?time|passcode|cvv|cvc|csc|card[-_ ]?(number|no)|cc[-_ ]?(num|number)|upi[-_ ]?pin|atm[-_ ]?pin|pin[-_ ]?code)\b/i;
const CREDENTIAL_AUTOCOMPLETE = /\b(one-time-code|cc-number|cc-csc)\b/i;

function isCredentialInput(input) {
  const type = (input.getAttribute("type") || "text").toLowerCase();
  if (type === "hidden" || type === "password" || type === "submit" || type === "button") return false;
  if (CREDENTIAL_AUTOCOMPLETE.test(input.getAttribute("autocomplete") || "")) return true;
  const text = ["name", "id", "placeholder", "aria-label"].map((a) => input.getAttribute(a) || "").join(" ");
  return CREDENTIAL_INPUT.test(text);
}

// Shadow roots, open and closed (a login form drawn inside a web component is invisible to
// document.querySelectorAll). Our own banner is skipped; at most MAX_SHADOW_ROOTS are read.
const MAX_SHADOW_ROOTS = 200;

function shadowRootOf(el) {
  try {
    const opened = typeof chrome !== "undefined" ? chrome.dom?.openOrClosedShadowRoot?.(el) : null;
    return opened ?? el.shadowRoot ?? null;
  } catch {
    return el.shadowRoot ?? null;
  }
}

function shadowRoots(doc) {
  const found = [];
  const stack = [doc];
  while (stack.length && found.length < MAX_SHADOW_ROOTS) {
    const root = stack.pop();
    for (const el of Array.from(root.querySelectorAll?.("*") ?? [])) {
      if (el.tagName === "PHISHDRIFT-BANNER") continue;
      const shadow = shadowRootOf(el);
      if (!shadow) continue;
      found.push(shadow);
      stack.push(shadow);
      if (found.length >= MAX_SHADOW_ROOTS) break;
    }
  }
  return found;
}

function collectPageFacts(doc, base, shadows = shadowRoots(doc)) {
  const forms = [];
  const allForms = [...Array.from(doc.forms ?? []), ...shadows.flatMap((r) => Array.from(r.querySelectorAll("form")))];
  for (const form of allForms) {
    const hasPassword = Boolean(form.querySelector('input[type="password"]'));
    let action = null;
    try {
      action = new URL(form.getAttribute("action") || "", base).href;
    } catch {
      action = null;
    }
    forms.push({ hasPassword, action });
  }
  let passwordFields = 0;
  let credentialFields = 0;
  for (const root of [doc, ...shadows]) {
    passwordFields += root.querySelectorAll('input[type="password"]').length;
    const inputs = Array.from(root.querySelectorAll("input") ?? []);
    credentialFields += inputs.filter((i) => typeof i.getAttribute === "function" && isCredentialInput(i)).length;
  }
  return { passwordFields, credentialFields, forms };
}

// <visual-facts> (js/bench/picture_facts.mjs runs this block as it is)
// What a page looks like, for the picture-only rule (pagefacts.js): the readable text, the input
// fields, and the share of the window the largest picture (img, canvas, svg or a CSS background
// image) covers. A fake sign-in box drawn as one image has next to no text and no fields.
const MAX_BACKGROUND_CANDIDATES = 100;

function visualFacts(doc, win) {
  const body = doc.body;
  if (!body) return null;
  const textChars = (body.innerText || "").replace(/\s+/g, " ").trim().length;
  const fields = body.querySelectorAll('input:not([type="hidden"]), textarea, select, [contenteditable]').length;
  const window_ = Math.max(1, win.innerWidth) * Math.max(1, win.innerHeight);
  const pictures = Array.from(body.querySelectorAll("img, canvas, svg"));
  for (const el of Array.from(body.querySelectorAll("div, a, section, main, span")).slice(0, MAX_BACKGROUND_CANDIDATES)) {
    if (win.getComputedStyle(el).backgroundImage !== "none") pictures.push(el);
  }
  if (win.getComputedStyle(body).backgroundImage !== "none") pictures.push(body);
  let largest = 0;
  for (const el of pictures) {
    const r = el.getBoundingClientRect();
    largest = Math.max(largest, Math.min(r.width, win.innerWidth) * Math.min(r.height, win.innerHeight));
  }
  return { textChars, fields, pictures: pictures.length, largest: largest / window_ };
}
// </visual-facts>

// The banner lives in a closed shadow root, in the browser's top layer (a popover), with its own
// styles marked important, so the page can neither restyle it, cover it nor find it by id. If the
// page removes or hides it, it is put back; a page that keeps doing so is reported to the service
// worker, which treats hiding the warning as a sign of phishing and shows the full warning page.
let banner = null; // { host, dismissed, restores }
const MAX_RESTORES = 5;

function buildBanner(result) {
  const host = document.createElement("phishdrift-banner");
  for (const [k, v] of Object.entries({
    all: "initial", display: "block", position: "fixed", inset: "0 0 auto 0", margin: "0", padding: "0",
    border: "0", background: "transparent", "z-index": "2147483647", opacity: "1", visibility: "visible",
    width: "100%", height: "auto", overflow: "visible", transform: "none", filter: "none", "clip-path": "none",
  })) {
    host.style.setProperty(k, v, "important");
  }
  const root = host.attachShadow({ mode: "closed" });
  const reasons = result.reasons.slice(0, 2);
  const style = document.createElement("style");
  style.textContent = `
    .bar { all: initial; display: flex; gap: 12px; align-items: center; padding: 10px 16px;
      background: #fef3c7; color: #451a03; border-bottom: 2px solid #d97706;
      font: 14px/1.4 system-ui, sans-serif; box-sizing: border-box; width: 100%; }
    .bar strong { font-weight: 600; }
    .bar ul { margin: 2px 0 0; padding-left: 18px; }
    .bar div { flex: 1; }
    button { all: initial; cursor: pointer; padding: 4px 10px; border: 1px solid #92400e;
      border-radius: 4px; color: #451a03; font: 13px system-ui, sans-serif; }`;
  const bar = document.createElement("div");
  bar.className = "bar";
  bar.setAttribute("role", "alert");
  const text = document.createElement("div");
  const head = document.createElement("strong");
  head.textContent = "PhishDrift: this page looks suspicious. Be careful with passwords and payments.";
  text.append(head);
  if (reasons.length) {
    const list = document.createElement("ul");
    for (const r of reasons) {
      const li = document.createElement("li");
      li.textContent = r;
      list.append(li);
    }
    text.append(list);
  }
  const dismiss = document.createElement("button");
  dismiss.textContent = "Dismiss";
  dismiss.addEventListener("click", () => {
    if (banner) banner.dismissed = true;
    host.remove();
  });
  bar.append(text, dismiss);
  root.append(style, bar);
  return host;
}

function placeBanner() {
  const { host } = banner;
  if (!host.isConnected) document.documentElement.append(host);
  try {
    host.setAttribute("popover", "manual");
    if (!host.matches(":popover-open")) host.showPopover();
  } catch {
    // no popover support: the fixed position and z-index still apply
  }
}

function showBanner(result) {
  if (banner) return;
  const state = { host: buildBanner(result), dismissed: false, restores: 0 };
  banner = state;
  placeBanner();
  const restore = () => {
    if (state !== banner || state.dismissed || state.restores >= MAX_RESTORES) return;
    const open = (() => {
      try {
        return state.host.matches(":popover-open");
      } catch {
        return true;
      }
    })();
    if (state.host.isConnected && open) return;
    state.restores += 1;
    placeBanner();
    if (state.restores >= MAX_RESTORES) chrome.runtime.sendMessage({ type: "tamper", url: location.href }).catch(() => {});
  };
  new MutationObserver(restore).observe(document.documentElement, { childList: true });
  state.host.addEventListener("toggle", () => setTimeout(restore, 0));
}

// A banner from an earlier verdict (the address before the page was read, an earlier in-page
// route) is taken down when the page's own check comes back safe. Not a page action, so it is never
// counted as tampering.
function hideBanner() {
  if (!banner) return;
  banner.dismissed = true;
  banner.host.remove();
  banner = null;
}

// The page's HTML for the page model, scored in the service worker on this device; it is never
// sent anywhere else. Capped so a huge page cannot stall the check.
const MAX_HTML_CHARS = 5_000_000;

function pageHtml(doc) {
  const doctype = doc.doctype ? new XMLSerializer().serializeToString(doc.doctype) : "";
  // shadow-root content is appended so the page model sees forms drawn inside web components
  const shadows = shadowRoots(doc)
    .map((r) => `<div data-phishdrift-shadow>${r.innerHTML}</div>`)
    .join("");
  const html = doc.documentElement.outerHTML;
  const end = html.lastIndexOf("</body>");
  const joined = end < 0 ? html + shadows : html.slice(0, end) + shadows + html.slice(end);
  return (doctype + joined).slice(0, MAX_HTML_CHARS);
}

const isTop = typeof window === "undefined" || window === window.top;
let raisesSeen = 0; // later warnings (frame, in-page address, backend) pushed to this page
let pageAnswered = false; // the page check has answered at least once
const asksCredentials = (facts) => facts.passwordFields + facts.credentialFields > 0;

async function run() {
  const facts = collectPageFacts(document, location.href);
  // Frames report only when they ask for credentials (ad and widget frames cost nothing).
  if (!isTop && !asksCredentials(facts)) return facts;
  if (isTop) {
    try {
      facts.visual = visualFacts(document, window);
    } catch {
      facts.visual = null; // the picture-only rule is skipped
    }
  }
  let html = null;
  try {
    html = pageHtml(document);
  } catch {
    html = null; // the page model is skipped; the address verdict stands
  }
  const message = { type: isTop ? "page" : "frame", url: location.href, origin: self.origin, facts, html };
  const sentAt = raisesSeen;
  const result = await chrome.runtime.sendMessage(message);
  if (isTop && result && !result.error) {
    pageAnswered = true;
    if (result.verdict === 1) showBanner(result);
    // the final verdict for this page is safe, unless a later warning (from a frame, say) came in
    // meanwhile; the address verdict from commit time does not count (the page check replaces it)
    else if (result.verdict === 0 && raisesSeen === sentAt) hideBanner();
  }
  return facts;
}

// The page is checked again (a few times at most, once it has been quiet for a moment) when a new
// password or other credential field appears (forms drawn by script or after a click), and when the
// service worker sees an in-page address change (single-page apps).
const MAX_RECHECKS = 5;
const RECHECK_DELAY_MS = 750;
let rechecks = 0;
let recheckTimer = null;

function scheduleRecheck() {
  if (recheckTimer || rechecks >= MAX_RECHECKS) return;
  recheckTimer = setTimeout(async () => {
    recheckTimer = null;
    rechecks += 1;
    await run().catch(() => {});
  }, RECHECK_DELAY_MS);
}

function watchForLateForms(seen) {
  let fields = seen.passwordFields + seen.credentialFields;
  let timer = null;
  const observer = new MutationObserver(() => {
    if (timer) return;
    timer = setTimeout(() => {
      timer = null;
      const now = collectPageFacts(document, location.href);
      const count = now.passwordFields + now.credentialFields;
      if (count <= fields) return;
      fields = count;
      if (rechecks >= MAX_RECHECKS) observer.disconnect();
      scheduleRecheck();
    }, RECHECK_DELAY_MS);
  });
  observer.observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ["type"] });
}

if (typeof chrome !== "undefined" && chrome.runtime?.id) {
  if (isTop) {
    // verdicts the service worker reached on its own (redirect, in-page address change, a frame, a
    // late backend answer), and requests to check the page again after an in-page address change
    chrome.runtime.onMessage.addListener((msg) => {
      if (msg?.type === "phishdrift-verdict") {
        const commit = msg.kind === "commit";
        if (commit && pageAnswered) return; // stale: the page check has already answered
        if (!commit && msg.result?.verdict >= 1) raisesSeen += 1;
        if (msg.result?.verdict === 1) showBanner(msg.result);
      }
      if (msg?.type === "phishdrift-recheck") scheduleRecheck();
    });
  }
  run()
    .then(watchForLateForms)
    .catch(() => {}); // fail open: a failed check never affects the page
}
