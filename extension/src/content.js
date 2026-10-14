// Content script (classic script, no imports). When the page has loaded it hands the page's HTML
// and its password forms to the service worker, which scores the page on this device, gets the
// final verdict back, and shows a banner for "suspicious". Nothing leaves the device from here:
// the page model runs in the service worker and the backend only ever sees a domain name.

function collectPageFacts(doc, base) {
  const forms = [];
  for (const form of Array.from(doc.forms ?? [])) {
    const hasPassword = Boolean(form.querySelector('input[type="password"]'));
    let action = null;
    try {
      action = new URL(form.getAttribute("action") || "", base).href;
    } catch {
      action = null;
    }
    forms.push({ hasPassword, action });
  }
  return {
    passwordFields: doc.querySelectorAll('input[type="password"]').length,
    forms,
  };
}

function showBanner(result) {
  if (document.getElementById("phishdrift-banner-host")) return;
  const host = document.createElement("div");
  host.id = "phishdrift-banner-host";
  const root = host.attachShadow({ mode: "closed" });
  const reasons = result.reasons.slice(0, 2);
  const style = document.createElement("style");
  style.textContent = `
    .bar { all: initial; position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
      display: flex; gap: 12px; align-items: center; padding: 10px 16px;
      background: #fef3c7; color: #451a03; border-bottom: 2px solid #d97706;
      font: 14px/1.4 system-ui, sans-serif; box-sizing: border-box; }
    .bar strong { font-weight: 600; }
    .bar ul { margin: 2px 0 0; padding-left: 18px; }
    .bar div { flex: 1; }
    button { all: initial; cursor: pointer; padding: 4px 10px; border: 1px solid #92400e;
      border-radius: 4px; color: #451a03; font: 13px system-ui, sans-serif; }`;
  const bar = document.createElement("div");
  bar.className = "bar";
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
  dismiss.addEventListener("click", () => host.remove());
  bar.append(text, dismiss);
  root.append(style, bar);
  document.documentElement.append(host);
}

// The page's HTML for the page model, scored in the service worker on this device; it is never
// sent anywhere else. Capped so a huge page cannot stall the check.
const MAX_HTML_CHARS = 5_000_000;

function pageHtml(doc) {
  const doctype = doc.doctype ? new XMLSerializer().serializeToString(doc.doctype) : "";
  return (doctype + doc.documentElement.outerHTML).slice(0, MAX_HTML_CHARS);
}

async function run() {
  const facts = collectPageFacts(document, location.href);
  let html = null;
  try {
    html = pageHtml(document);
  } catch {
    html = null; // the page model is skipped; the address verdict stands
  }
  const result = await chrome.runtime.sendMessage({ type: "page", url: location.href, facts, html });
  if (result && !result.error && result.verdict === 1) showBanner(result);
}

if (typeof chrome !== "undefined" && chrome.runtime?.id) {
  run().catch(() => {}); // fail open: a failed check never affects the page
}
