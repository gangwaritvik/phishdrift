// Demo page: loads the extension's address layers (check.js) and shows the verdict for a typed
// address as one animated screen (demo/evidence.js supplies what each layer looked at).
// Five themes; the switch ("lens") ripples the new theme out from the swatch you pick.

import { buildLens, setTheme, startTheme } from "../extension/src/theme.js";
import { checkUrl, loadChecker } from "./check.js";

const root = new URL("../", import.meta.url);
const $ = (id) => document.getElementById(id);
const reduce = matchMedia("(prefers-reduced-motion: reduce)");

const EXAMPLES = [
  ["Normal site", "https://en.wikipedia.org/wiki/Phishing"],
  ["Popular site the model alone flags", "https://web.whatsapp.com/"],
  ["Phishing style", "http://secure-login-verify-account.xyz/wp-admin/office365/index.php"],
  ["Look-alike", "https://secure-login.paypa1.com/signin/verify-account"],
];
const WORD = { safe: "Looks safe", suspicious: "Suspicious", dangerous: "Dangerous" };
const SUB = {
  safe: "Nothing in the address raised a flag.",
  suspicious: "Be careful. This address has traits common to phishing.",
  dangerous: "This address is very likely phishing. Don’t type a password or card number here.",
};
const NODE = { allowlist: "Allowlist", blocklist: "Blocklist", model: "Address model", llm: "AI brand check", combine: "Combiner" };
const ICON = {
  ok: '<path d="m5 12 5 5 9-10"/>',
  bang: '<path d="M12 6v8M12 18v.5"/>',
  x: '<path d="m6 6 12 12M18 6 6 18"/>',
  dash: '<path d="M6 12h12"/>',
  warn: '<path d="M12 3 2 20h20z"/><path d="M12 10v4M12 17.5v.1"/>',
};
const svg = (inner, w = 16, sw = 3) => `<svg width="${w}" height="${w}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="${sw}" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${inner}</svg>`;
const esc = (t) => String(t).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);

// --- theme lens (extension/src/theme.js) ----------------------------------------------------

const saveTheme = (id) => {
  try {
    localStorage.setItem("phishdrift-theme", id);
  } catch {
    // storage can be blocked; the theme still changes
  }
};
function startLens() {
  let saved = null;
  try {
    saved = localStorage.getItem("phishdrift-theme");
  } catch {
    // no storage
  }
  buildLens($("lens"), saveTheme);
  setTheme(startTheme(new URLSearchParams(location.search).get("theme"), saved), null);
}

// --- result screen --------------------------------------------------------------------------

function anatomy(r) {
  let u;
  try {
    u = new URL(r.url);
  } catch {
    return esc(r.url);
  }
  const host = u.hostname;
  const dom = r.evidence?.allowlist?.domain && host.endsWith(r.evidence.allowlist.domain) ? r.evidence.allowlist.domain : host;
  const sub = host.slice(0, host.length - dom.length);
  const user = u.username ? `${u.username}${u.password ? ":" + u.password : ""}@` : "";
  const rest = `${u.port ? ":" + u.port : ""}${u.pathname === "/" && !u.search && !u.hash ? "" : u.pathname}${u.search}${u.hash}`;
  return `<span class="dim">${esc(u.protocol)}//</span>${esc(user)}${esc(sub)}<span class="own">${esc(dom)}</span>${esc(rest)}`;
}

// Only clues that push toward phishing: they have plain-English sentences; the rest are raw feature names.
function clueCards(m) {
  if (!m?.used) return [];
  const up = m.items.filter((i) => i.delta > 0).slice(0, 4);
  return up.map((i) => ({ text: i.label, share: i.delta / up[0].delta }));
}

function render(r) {
  const verdict = ["safe", "suspicious", "dangerous"].includes(r.verdict) ? r.verdict : null;
  document.body.dataset.verdict = verdict ?? "safe";
  const out = $("out");
  if (!verdict) {
    out.innerHTML = `<section class="card xray"><span class="eyebrow">${esc(r.label ?? "Not a web address")}</span><p class="say" style="animation:none;margin:12px 0 0">${esc((r.notes ?? [])[0] ?? "Type a web address such as https://example.com/login.")}</p></section>`;
    return;
  }
  const m = r.evidence?.model;
  const score = m?.used ? m.prob : r.modelAlone?.prob ?? null;
  const t = r.thresholds;
  const word = [...WORD[verdict]].map((c, i) => `<span style="--k:${i}">${esc(c)}</span>`).join("");
  const relay = r.trace
    .filter((n) => NODE[n.id])
    .map((n, k) => {
      const kind = { safe: "ok", clear: "ok", warn: "bang", bad: "x" }[n.tone] ?? "dash";
      return `<div class="node ${esc(n.tone)}" style="--k:${k}" title="${esc(n.detail)}"><i>${svg(ICON[kind])}</i><b>${NODE[n.id]}</b><span>${esc(n.label)}</span></div>`;
    })
    .join("");
  const clues = clueCards(m);
  const strength = (s) => (s > 0.66 ? "strong" : s > 0.33 ? "medium" : "small");
  const dial = score === null ? "" : (() => {
    const tick = (p) => {
      const a = ((135 + 270 * p) * Math.PI) / 180;
      return `<line class="tick" x1="${100 + 94 * Math.cos(a)}" y1="${100 + 94 * Math.sin(a)}" x2="${100 + 110 * Math.cos(a)}" y2="${100 + 110 * Math.sin(a)}" stroke-width="2.5" stroke-linecap="round"/>`;
    };
    return `<div><div class="dial"><svg viewBox="-10 -10 220 220" role="img" aria-label="Address-model score ${score.toFixed(3)} of 1">
      <circle class="track" cx="100" cy="100" r="86" fill="none" stroke-width="14" stroke-linecap="round" stroke-dasharray="405.26 540.35" transform="rotate(135 100 100)"/>
      <circle class="arc" id="arc" cx="100" cy="100" r="86" fill="none" stroke-width="14" stroke-linecap="round" stroke-dasharray="405.26 540.35" stroke-dashoffset="405.26" transform="rotate(135 100 100)"/>
      ${tick(t.suspicious)}${tick(t.dangerous)}</svg>
      <div class="dc"><span class="num" id="num">0.000</span><span class="eyebrow">${m?.used ? "risk score" : "model alone, not used"}</span></div></div>
      <div class="dlab"><span>suspicious ${t.suspicious.toFixed(3)}</span><span>dangerous ${t.dangerous.toFixed(3)}</span></div></div>`;
  })();
  const notes = [...(r.notes ?? [])];
  const page = r.trace.find((n) => n.id === "page");
  if (page) notes.push(page.detail);
  out.innerHTML = `
  <section class="card xray">
    <div class="xhead"><span class="eyebrow">The address, x-rayed</span><span style="font-size:14px;color:var(--mute)">Highlighted: the part that says who owns the site</span></div>
    <div class="url${r.url.length > 70 ? " long" : ""}"><span class="beam" aria-hidden="true"></span>${anatomy(r)}</div>
    <div class="legend"><span class="lchip"><span class="sw"></span>Owner: ${esc(r.domain ?? "unknown")}</span></div>
    <div class="relay"><span class="rfill" aria-hidden="true"></span>${relay}</div>
  </section>
  <section class="card stage${score === null ? " nodial" : ""}">
    ${dial}
    <div class="vt"><div class="eyebrow">Verdict</div>
      <h1 class="word" aria-label="${WORD[verdict]}">${word}</h1>
      <p class="say">${esc(verdict === "safe" && r.layer === "allowlist" ? "A widely used site on the allowlist, so the address model is not consulted." : SUB[verdict])}</p>
      ${r.reasons.length ? `<ul class="says">${r.reasons.slice(0, 3).map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}
      <div class="acts"><button type="button" class="btn" id="again">Check another link</button><button type="button" class="btn ghost" id="copy">Copy a report</button></div></div>
  </section>
  ${tierCards(r)}
  ${clues.length ? `<section class="clues" aria-label="Biggest clues">${clues.map((c, k) => `<article class="card clue" style="--k:${k}"><div class="ck"><span class="ic">${svg(ICON.warn, 20, 2.2)}</span><span class="eyebrow">Points to phishing</span></div><h3>${esc(c.text)}</h3><div class="push"><span class="b"><i style="width:${Math.round(c.share * 100)}%"></i></span>${strength(c.share)}</div></article>`).join("")}</section>` : ""}
  ${notes.length ? `<div class="notes">${notes.map((n) => `<p>${esc(n)}</p>`).join("")}</div>` : ""}
  <div class="meta"><span>Model ${esc(model?.modelCreated?.slice?.(0, 10) ?? "")} · thresholds ${t.suspicious.toFixed(3)} / ${t.dangerous.toFixed(3)}</span><span>The AI check, when on, is sent the host name only, never the full link.</span></div>`;
  $("again").addEventListener("click", () => {
    $("url").focus();
    $("url").select();
  });
  $("copy").addEventListener("click", async (e) => {
    const text = `PhishDrift: ${WORD[verdict]}\n${r.url}\n${r.reasons.join("\n")}`;
    try {
      await navigator.clipboard.writeText(text);
      e.target.textContent = "Copied";
    } catch {
      e.target.textContent = "Copy not allowed here";
    }
  });
  if (score !== null) animateDial(score, t, Boolean(m?.used));
}

const FETCH_WHY = {
  timeout: "the site took too long to answer",
  not_html: "the address does not return a web page (a file or an image, for example)",
  not_public_address: "the address leads to a private network, which is never fetched",
  port_not_allowed: "only the standard web ports are fetched",
  too_many_redirects: "the address redirects too many times",
  bad_redirect: "the address redirects to something that is not a web address",
  unsupported_encoding: "the site sends its page in a format this check can't read",
  ENOTFOUND: "the site name does not exist",
  ECONNREFUSED: "the site refused the connection",
  ECONNRESET: "the site dropped the connection",
};
const NOT_CHECKED = {
  ip_or_empty: "An IP address has no registration to look up.",
  local_name: "A private network name has no registration to look up.",
  no_public_suffix: "This name has no public registration to look up.",
  shortener: "A link shortener says nothing about where it leads.",
  hosting_platform: "This is a shared hosting platform, so its registration says nothing about one site on it.",
  no_model: "The domain check has no model on this server.",
  failed: "The lookup of the registry, DNS or certificate failed or timed out.",
};
const toneOf = (v) => ({ safe: "safe", suspicious: "warn", dangerous: "bad" })[v] ?? "skip";
const score3 = (x) => (typeof x === "number" ? x.toFixed(3) : "n/a");
const cuts = (t) => (t ? `suspicious from ${score3(t.suspicious)}${t.dangerous != null ? `, dangerous from ${score3(t.dangerous)}` : ""}` : "");

// One card per tier: what it scored, against which cut-offs, or why it did not run.
function tierCards(r) {
  const t = r.tiers;
  if (!t) return "";
  const card = (k, name, what, head, tone, lines) =>
    `<article class="card tier" style="--k:${k}"><div class="eyebrow">${name} · ${what}</div><h3 class="tv ${tone}">${esc(head)}</h3>${lines.filter(Boolean).map((l) => `<p>${esc(l)}</p>`).join("")}</article>`;
  const A = t.a.state === "scored"
    ? card(0, "Tier A", "Address", WORD[t.a.verdict], toneOf(t.a.verdict), [`Score ${score3(t.a.prob)}.`, cuts(t.a.thresholds)])
    : card(0, "Tier A", "Address", "Not scored", "skip", ["A list or rule decided before the address model was needed."]);
  const b = t.b;
  const B = {
    off: () => card(1, "Tier B", "Page", "Not available", "skip", ["Reading a page needs the hosted page fetch, which this server does not have. The extension reads the page itself."]),
    skipped: () => card(1, "Tier B", "Page", "Not run", "skip", ["A list or rule had already decided, so the page was not fetched."]),
    unreachable: () => card(1, "Tier B", "Page", "No answer", "skip", ["The page fetch did not answer, so only tier A counts."]),
    unavailable: () => card(1, "Tier B", "Page", "Page not read", "skip", [`The page could not be fetched: ${b.error === "http_status" ? `the site answered with an error (HTTP ${b.status})` : FETCH_WHY[b.error] ?? b.error}.`, "Only tier A counts."]),
    unreadable: () => card(1, "Tier B", "Page", "Page empty", "skip", ["The page came back empty or with too little readable text. It may be built by scripts, may show this check a blank page, or may be a bare login box.", "Only tier A counts."]),
    scored: () => card(1, "Tier B", "Page", WORD[b.verdict], toneOf(b.verdict), [`Page score ${score3(b.prob)} (page model ${score3(b.probPage)}).`, cuts(b.thresholds), b.verdict !== "safe" && b.reasons[0], b.truncated ? "Only the first part of a very large page was read." : ""]),
  }[b.state]();
  const c = t.c;
  const age = c.facts?.domain_age_days;
  const C = {
    off: () => card(2, "Tier C", "Domain", "Not available", "skip", ["The domain check is not on this server."]),
    skipped: () => card(2, "Tier C", "Domain", "Not run", "skip", ["A list or rule had already decided."]),
    unreachable: () => card(2, "Tier C", "Domain", "No answer", "skip", ["The domain check did not answer."]),
    not_checked: () => card(2, "Tier C", "Domain", "Not checked", "skip", [NOT_CHECKED[c.reason] ?? c.reason, c.detail]),
    scored: () => card(2, "Tier C", "Domain", WORD[c.verdict], toneOf(c.verdict), [`Score ${score3(c.prob)}.`, cuts(c.thresholds), c.verdict !== "safe" && c.reasons[0] ? c.reasons[0] : typeof age === "number" ? `Registered about ${age} days ago.` : "Registration age could not be read."]),
  }[c.state]();
  return `<section class="tiers" aria-label="Score of each tier">${A}${B}${C}</section>`;
}

let model = null; // set once the checker loads (for the model date in the footer)
let frame = 0;
// Fills the dial and counts the score up (starts when the CSS animation reaches it).
function animateDial(score, t, used) {
  cancelAnimationFrame(frame);
  const arc = $("arc");
  const num = $("num");
  const paint = (v) => {
    num.textContent = v.toFixed(3);
    arc.style.strokeDashoffset = String(405.26 * (1 - v));
    arc.style.stroke = !used ? "var(--mute)" : v >= t.dangerous ? "var(--bad)" : v >= t.suspicious ? "var(--warn)" : "var(--safe)";
  };
  if (reduce.matches) return paint(score);
  const t0 = performance.now() + 1400;
  const step = (now) => {
    const k = Math.min(Math.max((now - t0) / 1500, 0), 1);
    paint(score * (1 - (1 - k) ** 3));
    if (k < 1) frame = requestAnimationFrame(step);
  };
  frame = requestAnimationFrame(step);
}

async function main() {
  startLens();
  let checker;
  try {
    checker = await loadChecker({ base: new URL("../extension/src/", import.meta.url), read });
    model = { modelCreated: checker.info.modelCreated };
    // the demo server forwards the host name to the local backend (python -m demo --backend URL)
    checker.askLlm = async (host) => {
      try {
        const res = await fetch("/api/llm-check", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain: host }) });
        return res.ok ? await res.json() : null;
      } catch {
        return null;
      }
    };
    // the hosted site fetches a page for the page model (tier B) and runs the domain check (tier C);
    // on a server without those functions the answer is a 404 and the tier says it is not available
    checker.fetchPage = async (url) => {
      try {
        const res = await fetch("/api/fetch-page", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url }) });
        return res.ok ? await res.json() : null;
      } catch {
        return null;
      }
    };
    checker.askTierC = async (domain) => {
      try {
        const res = await fetch("/api/domain-check", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain }) });
        return res.ok ? await res.json() : null;
      } catch {
        return null;
      }
    };
    // the hosted site follows short links (netlify/functions/expand.mjs); without it nothing is followed
    checker.expand = async (url) => {
      try {
        const res = await fetch("/api/expand", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url }) });
        return res.ok ? await res.json() : { complete: false, error: res.status === 404 ? "not available on this server" : `HTTP ${res.status}` };
      } catch {
        return { complete: false, error: "link check not reachable" };
      }
    };
  } catch (err) {
    $("out").innerHTML = `<p class="err">Could not load the model: ${esc(err.message)}. Start the page with "python -m demo" from the repository folder.</p>`;
    return;
  } finally {
    $("loader").classList.add("gone");
  }
  const go = async (text) => {
    if (!text.trim()) return;
    try {
      render(await checkUrl(checker, text));
    } catch (err) {
      $("out").innerHTML = `<p class="err">Check failed: ${esc(err.message)}</p>`;
      throw err;
    }
  };
  $("form").addEventListener("submit", (e) => {
    e.preventDefault();
    go($("url").value);
  });
  $("replay").addEventListener("click", () => go($("url").value));
  for (const [label, url] of EXAMPLES) {
    const b = Object.assign(document.createElement("button"), { type: "button", className: "chip", title: url, textContent: label });
    b.addEventListener("click", () => {
      $("url").value = url;
      go(url);
    });
    $("examples").append(b);
  }
  $("go").disabled = false;
  const start = new URLSearchParams(location.search).get("url") ?? EXAMPLES[3][1];
  $("url").value = start;
  go(start);
}

// Loading screen: one row per file with the bytes received so far. A compressed response's
// Content-Length is not the size of the decoded body, so a total is shown only for uncompressed ones.
const loads = new Map();
const mb = (n) => (n / 1e6).toFixed(1);
function showLoad(path, state, got = 0, total = 0) {
  let row = loads.get(path);
  if (!row) {
    row = document.createElement("li");
    row.append(Object.assign(document.createElement("code"), { textContent: path }), document.createElement("span"));
    loads.set(path, row);
    $("lfiles").append(row);
  }
  row.classList.toggle("done", state === "done");
  if (state === "done") got = total = row.total || 1;
  Object.assign(row, { got, total });
  row.lastChild.textContent = state;
  if (state === null) {
    row.remove();
    loads.delete(path);
  }
  const rows = [...loads.values()];
  // by bytes when every size is known, else by files finished
  const sum = (f) => rows.reduce((n, r) => n + f(r), 0);
  const share = rows.every((r) => r.total) ? sum((r) => r.got) / sum((r) => r.total) : sum((r) => r.classList.contains("done")) / Math.max(rows.length, 1);
  $("lbar").style.width = `${100 * share}%`;
}
async function body(path, res) {
  const total = res.headers.get("content-encoding") ? 0 : Number(res.headers.get("content-length")) || 0;
  if (!res.body) return res.json();
  const reader = res.body.getReader();
  const chunks = [];
  for (let got = 0; ; ) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    got += value.length;
    showLoad(path, total ? `${mb(got)} of ${mb(total)} MB` : `${mb(got)} MB`, Math.min(got, total), total);
  }
  return JSON.parse(await new Blob(chunks).text());
}

// One retry: a phone on a weak connection can drop the big model and list downloads. The error
// names the file, so "Load failed" (Safari's wording for any network error) says which one.
async function read(path) {
  for (let attempt = 1; ; attempt++) {
    try {
      showLoad(path, attempt === 1 ? "starting" : "retrying");
      const res = await fetch(new URL(path, root));
      if (res.status === 404) {
        showLoad(path, null); // optional file (lists built on the PC), not on every site
        return null;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await body(path, res);
      showLoad(path, "done");
      return json;
    } catch (err) {
      if (attempt === 2) {
        showLoad(path, "failed");
        throw new Error(`${path}: ${err.message}`);
      }
    }
  }
}

main();
