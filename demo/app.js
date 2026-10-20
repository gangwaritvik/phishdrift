// Demo page: loads the extension's address layers (check.js) and shows the verdict for a typed URL.

import { checkUrl, loadChecker } from "./check.js";

const root = new URL("../", import.meta.url);
const $ = (id) => document.getElementById(id);

const EXAMPLES = [
  ["Normal site", "https://en.wikipedia.org/wiki/Phishing"],
  ["Popular site the model alone flags", "https://web.whatsapp.com/"],
  ["Look-alike", "https://paypa1.com/signin"],
  ["Look-alike letters (punycode)", "https://www.xn--pple-43d.com/"],
  ["Brand + lure word", "https://sbi-kyc-update.com/login"],
  ["Phishing style", "http://secure-login-verify-account.xyz/wp-admin/office365/index.php"],
];

async function read(path) {
  const res = await fetch(new URL(path, root));
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`);
  return res.json();
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  for (const c of children) node.append(c);
  return node;
}

function list(title, items) {
  if (!items?.length) return [];
  return [el("h2", {}, title), el("ul", {}, ...items.map((t) => el("li", {}, t)))];
}

const LAYER_TEXT = {
  allowlist: "Decided by the allowlist (a widely used site).",
  blocklist: "Decided by the blocklist.",
  "url-model": "Decided by the address model.",
  lookalike: "Raised by the brand look-alike rules.",
  shortener: "Link shortener: judged by where it leads.",
  none: "Not checked.",
};

function meter(prob, thresholds) {
  const pct = (x) => `${(100 * x).toFixed(1)}%`;
  const m = el("div", { class: "meter", role: "img", "aria-label": `score ${prob.toFixed(3)}` });
  m.append(el("div", { class: "tick", style: `left:${pct(thresholds.suspicious)}`, title: "suspicious threshold (FPR 1%)" }));
  m.append(el("div", { class: "tick", style: `left:${pct(thresholds.dangerous)}`, title: "dangerous threshold (FPR 0.1%)" }));
  m.append(el("div", { class: "dot", style: `left:${pct(prob)}` }));
  return m;
}

function render(r, info) {
  const card = el("div", { class: `card ${r.verdict}` });
  card.append(el("div", { class: "verdict" }, el("span", { class: "pill" }, r.label ?? r.verdict)));
  card.append(el("p", { class: "url" }, r.url));
  if (r.layer) card.append(el("p", { class: "muted" }, LAYER_TEXT[r.layer] ?? r.layer));
  card.append(...list("Why", r.reasons));
  card.append(...list("Notes", r.notes));

  const m = r.modelAlone;
  if (m) {
    const skipped = r.layer !== "url-model" && r.layer !== "lookalike";
    card.append(el("h2", {}, skipped ? "Address model score (not used for this verdict)" : "Address model score"));
    card.append(meter(m.prob, info.thresholds));
    card.append(
      el("div", { class: "scale" }, el("span", {}, "0"), el("span", {}, `score ${m.prob.toFixed(3)}, model alone: ${m.verdict}`), el("span", {}, "1")),
    );
    card.append(
      el("p", { class: "muted" },
        `Suspicious at ${info.thresholds.suspicious.toFixed(3)} (1% false alarms on held-out legitimate URLs), ` +
        `dangerous at ${info.thresholds.dangerous.toFixed(3)} (0.1%). Calibrated phishing probability ${(100 * m.calibrated).toFixed(1)}%.`),
    );
    if (m.reasons.length) {
      const d = el("details", {}, el("summary", {}, "What pushed the score up"));
      d.append(el("ul", {}, ...m.reasons.map((t) => el("li", {}, t))));
      card.append(d);
    }
  }
  $("out").replaceChildren(card);
}

async function main() {
  let checker;
  try {
    checker = await loadChecker({ base: new URL("../extension/src/", import.meta.url), read });
  } catch (err) {
    $("info").replaceChildren(el("span", { class: "err" }, `Could not load the model: ${err.message}. Start the page with "python -m demo" from the repository folder.`));
    return;
  }
  const i = checker.info;
  $("info").textContent =
    `Allowlist: ${i.allowlist ?? "none"} (${i.allowDomains.toLocaleString()} domains). ` +
    (i.blocklist ? `Blocklist: ${i.blocklist} (${i.blockDomains.toLocaleString()} domains, ${i.blockUrls.toLocaleString()} URLs). ` : "Blocklist: none on this machine (build it with python -m backend build-lists). ") +
    (i.modelCreated ? `Model exported ${i.modelCreated}.` : "");

  const run = async (text) => {
    if (!text.trim()) return;
    $("go").disabled = true;
    try {
      render(await checkUrl(checker, text), i);
    } catch (err) {
      $("out").replaceChildren(el("div", { class: "card err" }, `Check failed: ${err.message}`));
    } finally {
      $("go").disabled = false;
    }
  };
  $("form").addEventListener("submit", (e) => {
    e.preventDefault();
    run($("url").value);
  });
  for (const [label, url] of EXAMPLES) {
    const b = el("button", { type: "button", title: url }, label);
    b.addEventListener("click", () => {
      $("url").value = url;
      run(url);
    });
    $("examples").append(b);
  }
  $("go").disabled = false;
  $("url").focus();
  const q = new URLSearchParams(location.search).get("url");
  if (q) {
    $("url").value = q;
    run(q);
  }
}

main();
