// Content script (classic script, no imports). When the page has loaded it reports which forms
// ask for a password and where they send it, gets the final verdict from the service worker, and
// shows a banner for "suspicious". Nothing leaves the device from here: the service worker
// compares the form targets locally and the backend only ever sees a domain name.

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

async function run() {
  const facts = collectPageFacts(document, location.href);
  const result = await chrome.runtime.sendMessage({ type: "page", url: location.href, facts });
  if (result && !result.error && result.verdict === 1) showBanner(result);
}

if (typeof chrome !== "undefined" && chrome.runtime?.id) {
  run().catch(() => {}); // fail open: a failed check never affects the page
}
