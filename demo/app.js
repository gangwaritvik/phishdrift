// Demo page: loads the extension's address layers (check.js) and plays a typed URL through them,
// layer by layer, ending in a verdict.

import { checkUrl, loadChecker } from "./check.js";

const root = new URL("../", import.meta.url);
const $ = (id) => document.getElementById(id);
const reduce = matchMedia("(prefers-reduced-motion: reduce)");
const sleep = (ms) => new Promise((r) => setTimeout(r, reduce.matches ? 0 : ms));

const EXAMPLES = [
  ["Normal site", "https://en.wikipedia.org/wiki/Phishing"],
  ["Popular site the model alone flags", "https://web.whatsapp.com/"],
  ["Look-alike", "https://paypa1.com/signin"],
  ["Look-alike letters (punycode)", "https://www.xn--pple-43d.com/"],
  ["Brand + lure word", "https://sbi-kyc-update.com/login"],
  ["Phishing style", "http://secure-login-verify-account.xyz/wp-admin/office365/index.php"],
];

const ICON = {
  allowlist: '<path d="M4 7h10M4 12h7M4 17h10"/><path d="m16 15 2.5 2.5L22 12"/>',
  blocklist: '<circle cx="12" cy="12" r="8.5"/><path d="m6 6 12 12"/>',
  model: '<path d="M3 17c2-8 4-8 6-2s4 6 6-4 3-7 6-1"/>',
  lookalike: '<circle cx="9" cy="12" r="5.5"/><circle cx="15" cy="12" r="5.5"/>',
  combine: '<path d="M5 5v4c0 3 2 4 4 5l3 1.5M19 5v4c0 3-2 4-4 5l-3 1.5M12 15.5V20"/>',
  page: '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c3 3 3 14 0 17M12 3.5c-3 3-3 14 0 17"/>',
};
const BADGE = {
  clear: '<path d="m5 12 4.5 4.5L19 7"/>', safe: '<path d="m5 12 4.5 4.5L19 7"/>', warn: '<path d="M12 6v8M12 18v.5"/>',
  bad: '<path d="m6 6 12 12M18 6 6 18"/>', skip: '<path d="M6 12h12"/>', na: '<path d="M6 12h12"/>',
};
const svg = (inner, cls = "") =>
  `<svg class="${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${inner}</svg>`;

const STATIONS = [
  ["allowlist", "Allowlist", "Widely used sites skip the rest."],
  ["blocklist", "Blocklist", "Addresses already reported as phishing."],
  ["model", "Address model", "Machine-learned look of the address."],
  ["lookalike", "Look-alike rules", "Imitations of well-known brands."],
  ["combine", "Combiner", "Merges the layers into one verdict."],
  ["page", "Page and domain checks", "Login forms, domain age and certificate."],
];
const TONE_COLOR = { clear: "var(--safe)", safe: "var(--safe)", warn: "var(--warn)", bad: "var(--bad)", skip: "var(--idle)", na: "var(--idle)" };
const VERDICT_TEXT = {
  safe: ["Looks safe", "Nothing in the address raised a flag."],
  suspicious: ["Suspicious", "Be careful. This address has traits common to phishing."],
  dangerous: ["Dangerous", "Harmful. This address is very likely phishing."],
};

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  for (const c of children) node.append(c);
  return node;
}

// --- pipeline -------------------------------------------------------------------------------

const rows = {};
function buildPipeline() {
  for (const [id, title, sub] of STATIONS) {
    const li = el("li", { class: "stn", "data-id": id });
    li.innerHTML =
      `<div class="node">${svg(ICON[id])}<span class="badge"></span></div>` +
      `<div class="body"><div class="head"><b>${title}</b><span class="tag"></span></div>` +
      `<p class="sub">${sub}</p><p class="detail">&nbsp;</p></div>`;
    $("pipe").append(li);
    rows[id] = {
      li,
      node: li.querySelector(".node"),
      badge: li.querySelector(".badge"),
      tag: li.querySelector(".tag"),
      detail: li.querySelector(".detail"),
    };
  }
}

function resetPipeline() {
  for (const r of Object.values(rows)) {
    r.li.className = "stn";
    r.badge.innerHTML = "";
    r.tag.textContent = "";
    r.detail.innerHTML = "&nbsp;";
  }
  $("packet").style.opacity = "0";
  const fill = $("fill");
  fill.style.transition = "none";
  fill.style.transform = "scaleY(0)";
  $("pipewrap").style.removeProperty("--packet");
  void fill.offsetHeight;
  fill.style.transition = "";
}

function centreOf(id) {
  const n = rows[id].node;
  return n.offsetTop + n.offsetHeight / 2;
}

function movePacket(id, animate = true) {
  const p = $("packet");
  const y = centreOf(id) - 8;
  if (!animate) p.style.transition = "none";
  p.style.transform = `translateY(${y}px)`;
  p.style.opacity = "1";
  const fill = $("fill");
  if (!animate) fill.style.transition = "none";
  fill.style.transform = `scaleY(${Math.max(0, (y + 8) / $("pipewrap").offsetHeight)})`;
  if (!animate) {
    void p.offsetHeight;
    p.style.transition = "";
    fill.style.transition = "";
  }
}

function hostMarkup(url) {
  try {
    const u = new URL(url);
    const i = url.indexOf(u.host);
    if (i > 0) {
      const esc = (t) => t.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);
      return `${esc(url.slice(0, i))}<span class="host">${esc(u.host)}</span>${esc(url.slice(i + u.host.length))}`;
    }
  } catch {
    // fall through to plain text
  }
  return null;
}

// Scrolls the page smoothly when an element is (partly) off screen, so the run stays in view.
function ensureVisible(node) {
  const box = node.getBoundingClientRect();
  const margin = 24;
  if (box.bottom > innerHeight - margin) scrollBy({ top: box.bottom - innerHeight + margin, behavior: reduce.matches ? "auto" : "smooth" });
  else if (box.top < margin) scrollBy({ top: box.top - margin, behavior: reduce.matches ? "auto" : "smooth" });
}

// --- verdict --------------------------------------------------------------------------------

function setVerdictIdle(word = "Ready", sub = "Run a check to see the verdict here.") {
  const v = $("verdict");
  v.className = "panel verdict v-idle";
  $("vword").textContent = word;
  $("vsub").textContent = sub;
  $("reasons").replaceChildren();
  $("extra").replaceChildren();
}

function countUp(node, to, ms) {
  if (reduce.matches || ms <= 0) {
    node.textContent = to.toFixed(3);
    return;
  }
  const t0 = performance.now();
  const step = (now) => {
    const k = Math.min(1, (now - t0) / ms);
    node.textContent = (to * (1 - (1 - k) ** 3)).toFixed(3);
    if (k < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function showVerdict(r, run) {
  const v = $("verdict");
  const short = r.layer === "shortener";
  const [word, sub] = short ? ["Short link", "The extension follows the link and judges the page it leads to."] : VERDICT_TEXT[r.verdict];
  v.className = `panel verdict v-${short ? "idle" : r.verdict} has-score`;
  if (r.verdict === "dangerous" && !reduce.matches) {
    void v.offsetWidth;
    v.classList.add("shake");
  }
  $("vword").textContent = word;
  $("vsub").textContent = sub;
  const list = $("reasons");
  list.replaceChildren(
    ...r.reasons.map((t, i) => {
      const li = el("li", { style: `animation-delay:${reduce.matches ? 0 : 350 + i * 130}ms` }, t);
      return li;
    }),
  );
  const m = r.modelAlone;
  const info = r.thresholds;
  if (m) {
    const used = r.layer === "url-model" || r.layer === "lookalike";
    $("mlabel").textContent = used ? "Address model score" : "Address model score (not used here)";
    $("meter").style.setProperty(
      "--zones",
      `linear-gradient(90deg, var(--safe-soft) 0 ${info.suspicious * 100}%, var(--warn-soft) ${info.suspicious * 100}% ${info.dangerous * 100}%, var(--bad-soft) ${info.dangerous * 100}% 100%)`,
    );
    $("t1").style.left = `${info.suspicious * 100}%`;
    $("t2").style.left = `${info.dangerous * 100}%`;
    $("mnote").textContent = `Dashed lines: warns from ${info.suspicious.toFixed(3)} (1% false alarms on held-out legitimate URLs), dangerous from ${info.dangerous.toFixed(3)} (0.1%).`;
    requestAnimationFrame(() => {
      $("mdot").style.left = `${m.prob * 100}%`;
      $("mfill").style.transform = `scaleX(${m.prob})`;
    });
    countUp($("mnum"), m.prob, 1000);
    if (m.reasons.length && !used) {
      $("extra").replaceChildren(
        el("details", { class: "detailsbox" }, el("summary", {}, "What the model alone would say"), el("ul", {}, ...m.reasons.map((t) => el("li", {}, t)))),
      );
    } else {
      $("extra").replaceChildren();
    }
  } else {
    v.classList.remove("has-score");
  }
  void run;
}

// --- one run --------------------------------------------------------------------------------

let runId = 0;

async function play(r) {
  const id = ++runId;
  const live = () => id === runId;
  const addr = $("addr");
  resetPipeline();
  $("mdot").style.left = "0%";
  $("mfill").style.transform = "scaleX(0)";
  $("mnum").textContent = "0.000";
  setVerdictIdle("Checking", "Following the address through each layer.");
  $("verdict").classList.remove("has-score");

  addr.innerHTML = hostMarkup(r.url) ?? "";
  if (!addr.innerHTML) addr.textContent = r.url;
  addr.classList.remove("scan");
  void addr.offsetWidth;
  addr.classList.add("scan");
  await sleep(550);
  if (!live()) return;

  if (r.verdict === "unscored") {
    addr.textContent = r.url;
    setVerdictIdle("Not a web address", r.notes[0]);
    return;
  }

  // Text is in place (invisible) before the packet arrives, so rows never change height mid-run.
  for (const t of r.trace) rows[t.id].detail.textContent = t.detail;
  movePacket(STATIONS[0][0], false);
  ensureVisible(addr);
  await sleep(150);
  for (const t of r.trace) {
    if (!live()) return;
    const row = rows[t.id];
    const quick = (t.tone === "skip" && t.id !== "allowlist" && t.id !== "blocklist") || t.tone === "na";
    movePacket(t.id);
    ensureVisible(row.li);
    await sleep(quick ? 230 : 400);
    if (!live()) return;
    row.li.classList.add("on");
    await sleep(quick ? 50 : 180);
    if (!live()) return;
    row.li.classList.remove("on");
    row.li.classList.add("done", `t-${t.tone}`);
    row.badge.innerHTML = svg(BADGE[t.tone], "");
    row.tag.textContent = t.label;
    if (t.tone !== "skip" && t.tone !== "na") $("pipewrap").style.setProperty("--packet", TONE_COLOR[t.tone]);
    await sleep(quick ? 30 : 260);
  }
  if (!live()) return;
  const tone = { safe: "var(--safe)", suspicious: "var(--warn)", dangerous: "var(--bad)" }[r.verdict];
  $("pipewrap").style.setProperty("--packet", r.layer === "shortener" ? "var(--idle)" : tone);
  $("packet").style.opacity = "0";
  showVerdict(r, id);
  ensureVisible($("verdict"));
}

async function main() {
  buildPipeline();
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
    try {
      await play(await checkUrl(checker, text));
    } catch (err) {
      $("addr").replaceChildren(el("span", { class: "err" }, `Check failed: ${err.message}`));
    }
  };
  $("form").addEventListener("submit", (e) => {
    e.preventDefault();
    run($("url").value);
  });
  for (const [label, url] of EXAMPLES) {
    const b = el("button", { type: "button", class: "chip", title: url }, label);
    b.addEventListener("click", () => {
      $("url").value = url;
      run(url);
    });
    $("examples").append(b);
  }
  $("go").disabled = false;
  addEventListener("resize", () => {
    const done = STATIONS.map(([id]) => id).filter((id) => rows[id].li.classList.contains("done"));
    if (done.length) movePacket(done[done.length - 1], false);
  });
  const q = new URLSearchParams(location.search).get("url");
  const start = q ?? EXAMPLES[2][1];
  $("url").value = start;
  $("url").focus();
  run(start);
}

async function read(path) {
  const res = await fetch(new URL(path, root));
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`);
  return res.json();
}

main();
