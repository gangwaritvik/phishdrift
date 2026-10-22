// Demo page: loads the extension's address layers (check.js) and plays one scene per layer for the
// typed address, each showing what that layer looked at (demo/evidence.js), ending in the verdict.

import { checkUrl, loadChecker } from "./check.js";

const root = new URL("../", import.meta.url);
const $ = (id) => document.getElementById(id);
const reduce = matchMedia("(prefers-reduced-motion: reduce)");

const EXAMPLES = [
  ["Normal site", "https://en.wikipedia.org/wiki/Phishing"],
  ["Popular site the model alone flags", "https://web.whatsapp.com/"],
  ["Phishing style", "http://secure-login-verify-account.xyz/wp-admin/office365/index.php"],
];

const svg = (inner) =>
  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${inner}</svg>`;
const I = {
  allow: '<path d="M4 7h10M4 12h7M4 17h10"/><path d="m16 15 2.5 2.5L22 12"/>',
  block: '<circle cx="12" cy="12" r="8.5"/><path d="m6 6 12 12"/>',
  model: '<path d="M3 17c2-8 4-8 6-2s4 6 6-4 3-7 6-1"/>',
  llm: '<circle cx="9" cy="12" r="5.5"/><circle cx="15" cy="12" r="5.5"/>',
  combine: '<path d="M5 5v4c0 3 2 4 4 5l3 1.5M19 5v4c0 3-2 4-4 5l-3 1.5M12 15.5V20"/>',
  verdict: '<path d="M12 3 5 6v6c0 4.5 3 7.5 7 9 4-1.5 7-4.5 7-9V6l-7-3Z"/>',
  ok: '<path d="m5 12 4.5 4.5L19 7"/>',
  bang: '<path d="M12 6v8M12 18v.5"/>',
  x: '<path d="m6 6 12 12M18 6 6 18"/>',
  dash: '<path d="M6 12h12"/>',
};
const STEPS = [
  ["allow", "Allowlist"],
  ["block", "Blocklist"],
  ["model", "Address model"],
  ["llm", "LLM check"],
  ["combine", "Combiner"],
  ["verdict", "Verdict"],
];
const TRACE_ID = { allow: "allowlist", block: "blocklist", model: "model", llm: "llm", combine: "combine" };
const WORD = { safe: "Looks safe", suspicious: "Suspicious", dangerous: "Dangerous" };
const TONE = { safe: "safe", suspicious: "warn", dangerous: "bad" };
const SUB = {
  safe: "Nothing in the address raised a flag.",
  suspicious: "Be careful. This address has traits common to phishing.",
  dangerous: "This address is very likely phishing.",
};

const esc = (t) => String(t).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
const num = (n) => Number(n).toLocaleString("en-US");
const sign = (v) => `${v >= 0 ? "+" : "−"}${Math.abs(v).toFixed(2)}`;

// --- timing ---------------------------------------------------------------------------------

const CANCEL = Symbol("cancel");
let token = 0;
let fast = false;
const pending = new Set();

function sleepRaw(ms) {
  if (fast) return Promise.resolve();
  return new Promise((resolve) => {
    const release = () => {
      clearTimeout(timer);
      pending.delete(release);
      resolve();
    };
    const timer = setTimeout(release, reduce.matches ? ms * 0.3 : ms);
    pending.add(release);
  });
}
const releaseAll = () => [...pending].forEach((release) => release());
const waiter = (tok) => async (ms) => {
  await sleepRaw(ms);
  if (tok !== token) throw CANCEL;
};
const show = (...els) => els.flat().forEach((e) => e?.classList.add("show"));

function countUp(node, to, ms, fmt = num) {
  if (fast || reduce.matches) {
    node.textContent = fmt(to);
    return;
  }
  const t0 = performance.now();
  const step = (now) => {
    const k = Math.min(1, (now - t0) / ms);
    node.textContent = fmt(Math.round(to * (1 - (1 - k) ** 3)));
    if (k < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

// --- scenes ---------------------------------------------------------------------------------
// Each scene is { html, play(root, w) }. All text comes from the evidence object, so it describes
// this address and nothing else.

const head = (n, name, title, lead) =>
  `<p class="kicker">Layer ${n} of 5 · ${name}</p><h2>${title}</h2>`;
const chip = (tone, icon, text) => `<div class="result rv t-${tone}">${svg(I[icon])}<span>${text}</span></div>`;
const skipScene = (n, name, title, why) => ({
  html: `<p class="kicker">Layer ${n} of 5 · ${name}</p><h2>${title}</h2>${chip("skip", "dash", "Not needed here")}<p class="note rv">${esc(why)}</p>`,
  play: async (el, w) => {
    show(el.querySelector(".result"));
    await w(500);
    show(el.querySelector(".note"));
    await w(900);
  },
});

function allowScene(r) {
  const e = r.evidence.allowlist;
  const parts = e.sub ? `<span class="seg">${esc(e.sub)}.</span>` : "";
  const dom = `<span class="seg dom">${esc(e.label ? `${e.label}.${e.suffix}` : e.domain)}</span>`;
  const verdict = e.shared
    ? chip("skip", "dash", e.shared === "shortener" ? "Link shortener: never trusted on its own" : "Shared hosting: the allowlist does not apply")
    : e.found
      ? chip("safe", "ok", `Found: ${esc(e.domain)} is on the allowlist`)
      : chip("na", "dash", "Not on the allowlist, so the check goes on");
  return {
    html:
      head(1, "Allowlist", "Is this a well-known site?", `Looking up <b>${esc(e.domain)}</b> among ${num(e.size)} widely used sites.`) +
      `<div class="urlparts rv">${parts}${dom}</div>` +
      `<div class="lookup"><div class="hashline rv">Fingerprint (SHA-256, first ${e.bytes} bytes): <span class="hash" data-hash></span></div>` +
      `<div class="scan rv"><span class="count">0 / ${num(e.size)}</span></div></div>${verdict}` +
      (e.shared === "zone" ? `<p class="note rv">${esc(e.domain)} is an open hosting zone: anyone can publish there, so being on the list proves nothing about this page.</p>` : "") +
      (e.shared === "platform" ? `<p class="note rv">${esc(e.domain)} is a shared hosting platform. Only the full address is matched against the blocklist.</p>` : ""),
    play: async (el, w) => {
      const [lead, urlparts, cap, hashline, scan, result, note] = ["h2 + .lead", ".urlparts", ".cap", ".hashline", ".scan", ".result", ".note"].map((s) => el.querySelector(s));
      show(lead);
      await w(450);
      show(urlparts);
      await w(500);
      show(cap);
      await w(500);
      show(hashline);
      const out = el.querySelector("[data-hash]");
      const hash = e.hash ?? "";
      for (let i = 2; i <= hash.length; i += 2) {
        out.textContent = hash.slice(0, i);
        await w(28);
      }
      show(scan);
      scan.classList.add("run");
      countUp(scan.querySelector(".count"), e.size, 1000, (n) => `${num(n)} / ${num(e.size)}`);
      await w(1150);
      show(result, note);
      await w(900);
    },
  };
}

function blockScene(r) {
  const e = r.evidence.blocklist;
  const rows = [];
  if (e.domain) rows.push({ tag: "Domain", key: e.domain, hash: e.domainHash, hit: e.domainHit });
  const seen = new Set(rows.map((x) => x.key));
  for (const k of e.keys) if (!seen.has(k.key)) rows.push({ tag: "Address", ...k });
  const shown = rows.slice(0, 8);
  const more = rows.length - shown.length;
  const anyHit = rows.some((x) => x.hit);
  const result = !e.loaded
    ? chip("na", "dash", "No blocklist on this machine, so nothing could match")
    : anyHit
      ? chip("bad", "x", e.blocked === "url" ? "Match: this exact address is a known phishing URL" : "Match: this domain is a known phishing domain")
      : chip("clear", "ok", `None of the ${rows.length} fingerprints is on the list`);
  return {
    html:
      head(2, "Blocklist", "Has this address already been reported?", e.loaded ? `Checking ${rows.length} fingerprints of this address against ${num(e.domains)} blocked domains and ${num(e.urls)} blocked addresses.` : `The extension would check these ${rows.length} fingerprints of this address against reported phishing sites.`) +
      `<ul class="keys">${shown.map((x) => `<li class="keyrow rv" data-hit="${x.hit ? 1 : 0}"><span class="tag">${x.tag}</span><span class="k">${esc(x.key)}</span><span class="h">${esc((x.hash ?? "").slice(0, 8))}…</span><span class="st">${svg(I.ok)}</span></li>`).join("")}` +
      (more > 0 ? `<li class="keyrow rv"><span class="tag"></span><span class="k">and ${more} more variants of the same address</span><span class="h"></span><span class="st">${svg(I.ok)}</span></li>` : "") +
      `</ul>${result}` +
      "",
    play: async (el, w) => {
      show(el.querySelector(".lead"));
      await w(350);
      for (const row of el.querySelectorAll(".keyrow")) {
        show(row);
        row.classList.add("checking");
        await w(e.loaded ? 260 : 150);
        row.classList.remove("checking");
        row.classList.add(!e.loaded ? "off" : row.dataset.hit === "1" ? "hit" : "ok");
        await w(90);
      }
      show(el.querySelector(".result"), el.querySelector(".note"));
      await w(900);
    },
  };
}

const LO = -6;
const HI = 10;
const at = (x) => Math.min(1, Math.max(0, (x - LO) / (HI - LO)));
const pct = (x) => `${(at(x) * 100).toFixed(2)}%`;

function modelScene(r) {
  const e = r.evidence.model;
  if (!e) return skipScene(3, "Address model", "How phishing-like does the address look?", "The address is too long to score here.");
  if (!e.used) {
    const why = r.evidence.allowlist.found ? "The allowlist already recognised this domain." : r.evidence.blocklist.blocked ? "The blocklist already decided." : "Short links are judged where they lead.";
    return skipScene(3, "Address model", "How phishing-like does the address look?", `${why} For comparison, the model on its own would score this address ${e.prob.toFixed(3)} (${e.prob >= e.thresholds.dangerous ? "dangerous" : e.prob >= e.thresholds.suspicious ? "suspicious" : "safe"}), which is why the allowlist matters.`);
  }
  const lt = e.logitThresholds;
  const rowsData = [{ label: "Average address (starting point)", delta: e.base, start: true }, ...e.items];
  if (Math.abs(e.other) >= 0.05) rowsData.push({ label: "All other, smaller clues", delta: e.other });
  const verdictTone = e.prob >= e.thresholds.dangerous ? "bad" : e.prob >= e.thresholds.suspicious ? "warn" : "clear";
  const verdictWord = verdictTone === "bad" ? "dangerous" : verdictTone === "warn" ? "suspicious" : "safe";
  return {
    html:
      head(3, "Address model", "How phishing-like does the address look?", "Every address starts from an average score. Each clue in the address then pushes it toward phishing (right) or toward safe (left).") +
      `<div class="gauge rv" style="--zones:linear-gradient(90deg,var(--safe-soft) 0 ${pct(lt.suspicious)},var(--warn-soft) ${pct(lt.suspicious)} ${pct(lt.dangerous)},var(--bad-soft) ${pct(lt.dangerous)} 100%);--p0:${pct(e.base)}">` +
      `<div class="tk" style="left:${pct(lt.suspicious)}"><span>warns</span></div><div class="tk" style="left:${pct(lt.dangerous)}"><span>dangerous</span></div>` +
      `<div class="val" style="left:${pct(e.base)}">${e.base.toFixed(2)}</div><div class="mk"></div></div>` +
      `<ul class="clues">${rowsData.map((x) => `<li class="clue rv"><span class="delta ${x.start ? "flat" : x.delta > 0 ? "up" : "down"}">${x.start ? e.base.toFixed(2) : sign(x.delta)}</span><span>${esc(x.label)}</span></li>`).join("")}` +
      `<li class="clue total rv"><span class="delta flat">${e.raw.toFixed(2)}</span><span>Total score, which is a ${(e.prob * 100).toFixed(1)}% phishing score of ${e.prob.toFixed(3)}</span></li></ul>` +
      chip(verdictTone, verdictTone === "clear" ? "ok" : verdictTone === "warn" ? "bang" : "x", `Score ${e.prob.toFixed(3)}: the model says ${verdictWord} (warns from ${e.thresholds.suspicious.toFixed(3)}, dangerous from ${e.thresholds.dangerous.toFixed(3)})`),
    play: async (el, w) => {
      show(el.querySelector(".lead"));
      await w(450);
      const gauge = el.querySelector(".gauge");
      show(gauge);
      await w(600);
      const mk = gauge.querySelector(".mk");
      const val = gauge.querySelector(".val");
      const rows = [...el.querySelectorAll(".clue:not(.total)")];
      let cum = 0;
      for (const [i, row] of rows.entries()) {
        show(row);
        cum += rowsData[i].delta;
        mk.style.left = pct(cum);
        val.style.left = pct(cum);
        val.textContent = cum.toFixed(2);
        await w(i === 0 ? 650 : 750);
      }
      show(el.querySelector(".total"));
      await w(450);
      show(el.querySelector(".result"));
      await w(900);
    },
  };
}

// The LLM brand check: what was sent, what the model answered, and what code made of it.
function llmScene(r) {
  const e = r.evidence.llm;
  const title = "Does the address pretend to be a known brand?";
  if (e.state === "off") return skipScene(4, "LLM check", title, "In the extension, borderline addresses are sent (host name only) to the backend, which asks a language model which brand the address imitates. Code then checks that brand against the real domain. This page was not given a backend, so it does not run this step.");
  if (e.state === "skipped") return skipScene(4, "LLM check", title, "An earlier layer already decided, or the address has no host name, so nothing is sent to the model.");
  if (e.state === "unreachable") return skipScene(4, "LLM check", title, "The local backend did not answer. Start it (python -m uvicorn backend.app:create_app --factory --port 8000) and check again.");
  if (e.error) return skipScene(4, "LLM check", title, e.error === "disabled" ? "The backend has no GEMINI_API_KEY, so the AI check is off there." : `The backend gave no opinion (${e.error}), so this step changes nothing.`);
  const sent = `<div class="tstep rv">Sent to the backend: <b>${esc(e.host)}</b> (the host name only, no path and no page).</div>`;
  const said = e.brand
    ? `<div class="tstep rv">The model says this imitates <b>${esc(e.brand)}</b>, whose own site is <b>${esc(e.brand_domain ?? "unknown")}</b> (confidence ${Number(e.confidence).toFixed(2)}).</div>`
    : `<div class="tstep rv">The model found no brand being imitated.</div>`;
  const result = e.raise
    ? chip("warn", "bang", `Code agrees: ${esc(e.host)} is not ${esc(e.brand_domain)}. The verdict goes up one step.`)
    : chip("clear", "ok", e.brand ? "Not raised: the site is the brand's own, or the model was not confident enough" : "Nothing to raise");
  return {
    html: head(4, "LLM check", title, "A language model names the brand it thinks the address imitates. Our own code, not the model, decides whether that is a real imitation.") + sent + said + result + (e.reason ? `<p class="note rv">The model's words: ${esc(e.reason)}</p>` : ""),
    play: async (el, w) => {
      show(el.querySelector(".lead"));
      await w(450);
      for (const row of el.querySelectorAll(".tstep")) {
        show(row);
        await w(700);
      }
      show(el.querySelector(".result"), el.querySelector(".note"));
      await w(1000);
    },
  };
}

function combineScene(r) {
  const e = r.evidence.combine;
  const names = ["Safe", "Suspicious", "Dangerous"];
  const verdict = e.end;
  return {
    html:
      head(5, "Combiner", "What do the layers add up to?", "The combiner starts from the strongest evidence and can only raise a verdict, never lower one.") +
      `<div class="ladder rv">${names.map((n, i) => `<div class="rung r${i}"><i>${svg(i === 0 ? I.ok : i === 1 ? I.bang : I.x)}</i>${n}</div>`).join("")}<div class="token" style="--tp:${16.6 + e.steps[0].to * 33.4}%"></div></div>` +
      e.steps.map((s) => `<div class="tstep rv">${esc(s.text)}</div>`).join("") +
      chip(TONE[r.verdict], verdict === 0 ? "ok" : verdict === 1 ? "bang" : "x", `Result: ${names[verdict].toLowerCase()}`),
    play: async (el, w) => {
      show(el.querySelector(".lead"));
      await w(450);
      show(el.querySelector(".ladder"));
      const token = el.querySelector(".token");
      const rungs = [...el.querySelectorAll(".rung")];
      await w(500);
      for (const [i, row] of [...el.querySelectorAll(".tstep")].entries()) {
        show(row);
        token.style.setProperty("--tp", `${16.6 + e.steps[i].to * 33.4}%`);
        rungs.forEach((x) => x.classList.remove("lit"));
        await w(550);
        rungs[e.steps[i].to].classList.add("lit");
        await w(700);
      }
      show(el.querySelector(".result"));
      await w(800);
    },
  };
}

function verdictScene(r) {
  const short = r.layer === "shortener";
  const cls = short ? "" : `v-${r.verdict}`;
  const reasons = r.reasons.length ? r.reasons : r.layer === "allowlist" ? [`${r.domain} is a widely used site on the allowlist.`] : ["No layer raised a concern about this address."];
  const model = r.evidence.model;
  const compare = model && !model.used ? [`For comparison, the address model alone would score this ${model.prob.toFixed(3)}. The allowlist is what keeps it safe.`] : [];
  return {
    cls,
    html:
      `<p class="kicker">Result</p><div class="vgrid ${cls}"><svg class="shield rv" viewBox="0 0 64 64" aria-hidden="true"><path class="bodyfill" d="M32 5 11 13v16c0 14 9 24 21 28 12-4 21-14 21-28V13L32 5Z"/><path d="M32 5 11 13v16c0 14 9 24 21 28 12-4 21-14 21-28V13L32 5Z"/><path class="mark m-safe" d="m22 33 7 7 14-15"/><path class="mark m-warn" d="M32 22v13M32 42v.5"/><path class="mark m-bad" d="m24 24 16 16M40 24 24 40"/></svg>` +
      `<div><p class="vword rv">${short ? "Short link" : WORD[r.verdict]}</p><p class="vsub rv">${short ? "The extension follows the link and judges the page it leads to." : SUB[r.verdict]}</p>` +
      `<ul class="reasons">${[...reasons, ...compare, ...r.notes.filter((n) => !short || !n.includes("shortener"))].map((t) => `<li class="rv">${esc(t)}</li>`).join("")}</ul></div></div>`,
    play: async (el, w) => {
      show(el.querySelector(".shield"));
      await w(500);
      show(el.querySelector(".vword"));
      await w(250);
      show(el.querySelector(".vsub"));
      await w(250);
      for (const li of el.querySelectorAll(".reasons li")) {
        show(li);
        await w(220);
      }
    },
  };
}

const BUILD = [allowScene, blockScene, modelScene, llmScene, combineScene, verdictScene];

// --- stage ----------------------------------------------------------------------------------

let current = null; // the result being shown
let scenes = [];
let stepEls = [];

function buildSteps() {
  const ol = $("steps");
  for (const [i, [id, name]] of STEPS.entries()) {
    const li = document.createElement("li");
    li.innerHTML = `<button type="button" class="step" data-i="${i}" aria-label="${name}"><span class="dot">${svg(I[id])}</span><b>${name}</b><small></small></button>`;
    ol.append(li);
  }
  // steps are direct grid children so the rail lines up with them
  stepEls = [...ol.querySelectorAll(".step")];
  for (const li of [...ol.querySelectorAll("li")]) {
    li.style.display = "contents";
  }
  stepEls.forEach((b) => b.addEventListener("click", () => b.classList.contains("done") && jump(Number(b.dataset.i))));
}

function setStep(i, state) {
  stepEls.forEach((b, k) => b.classList.toggle("on", state === "on" && k === i));
  $("prog").style.width = `calc((100% - (100% / 6)) * ${Math.max(0, i) / 5})`;
}

function labelStep(i) {
  const r = current;
  const b = stepEls[i];
  let tone;
  let text;
  if (i === 5) {
    tone = r.layer === "shortener" ? "skip" : TONE[r.verdict];
    text = r.layer === "shortener" ? "short link" : WORD[r.verdict].toLowerCase();
  } else {
    const t = r.trace.find((x) => x.id === TRACE_ID[STEPS[i][0]]);
    tone = t.tone;
    text = t.label;
    if (i === 2 && r.evidence.model?.used) text = r.evidence.model.prob.toFixed(3);
  }
  b.className = `step done t-${tone}`;
  b.querySelector(".dot").innerHTML = svg(tone === "clear" || tone === "safe" ? I.ok : tone === "warn" ? I.bang : tone === "bad" ? I.x : tone === "skip" || tone === "na" ? I.dash : I[STEPS[i][0]]);
  b.querySelector("small").textContent = text;
}

function resetSteps() {
  stepEls.forEach((b, i) => {
    b.className = "step";
    b.querySelector(".dot").innerHTML = svg(I[STEPS[i][0]]);
    b.querySelector("small").textContent = "";
  });
  setStep(0, "idle");
}

function addressMarkup(url) {
  try {
    const u = new URL(url);
    const i = url.indexOf(u.host);
    if (i > 0) return `${esc(url.slice(0, i))}<span class="host">${esc(u.host)}</span>${esc(url.slice(i + u.host.length))}`;
  } catch {
    // plain text below
  }
  return esc(url);
}

function setVerdictClass(cls) {
  const st = $("stage");
  st.classList.remove("v-safe", "v-suspicious", "v-dangerous");
  if (cls) st.classList.add(cls);
}

function showScene(i) {
  scenes.forEach((s, k) => s.classList.toggle("cur", k === i));
}

async function playScene(i, w) {
  const built = BUILD[i](current);
  scenes[i].innerHTML = built.html;
  showScene(i);
  if (i < 5) setVerdictClass(null);
  await built.play(scenes[i], w);
  if (i === 5) setVerdictClass(built.cls);
}

async function run(r) {
  const tok = ++token;
  releaseAll();
  fast = false;
  $("stage").classList.remove("fast");
  const w = waiter(tok);
  current = r;
  $("addr").innerHTML = addressMarkup(r.url);
  resetSteps();
  setVerdictClass(null);
  $("skip").disabled = false;
  $("replay").disabled = true;
  scenes = [];
  $("scenes").replaceChildren();

  if (r.verdict === "unscored") {
    const s = document.createElement("section");
    s.className = "scene cur";
    s.innerHTML = `<p class="kicker">Not checked</p><h2>That is not a web address</h2><p class="lead">${esc(r.notes[0] ?? "")}</p>`;
    $("scenes").append(s);
    $("skip").disabled = true;
    return;
  }
  // every scene is built once up front so the stage keeps the height of the tallest one
  for (let i = 0; i < BUILD.length; i++) {
    const s = document.createElement("section");
    s.className = "scene";
    s.innerHTML = BUILD[i](r).html;
    $("scenes").append(s);
    scenes.push(s);
  }
  $("stage").scrollIntoView({ behavior: reduce.matches ? "auto" : "smooth", block: "nearest" });
  try {
    await w(250);
    for (let i = 0; i < BUILD.length; i++) {
      setStep(i, "on");
      await playScene(i, w);
      labelStep(i);
      setStep(i + 1 > 5 ? 5 : i + 1, "idle");
      if (i < BUILD.length - 1) await w(350);
    }
    setStep(5, "idle");
    stepEls[5].classList.remove("on");
    $("stage").classList.remove("fast");
    fast = false;
    $("skip").disabled = true;
    $("replay").disabled = false;
  } catch (err) {
    if (err !== CANCEL) throw err;
  }
}

// Play one finished layer again (a step was clicked).
async function jump(i) {
  const tok = ++token;
  releaseAll();
  fast = false;
  $("stage").classList.remove("fast");
  $("skip").disabled = true;
  setStep(i, "on");
  try {
    await playScene(i, waiter(tok));
    stepEls[i].classList.remove("on");
  } catch (err) {
    if (err !== CANCEL) throw err;
  }
}

function skipToVerdict() {
  fast = true;
  $("stage").classList.add("fast");
  releaseAll();
}

async function main() {
  buildSteps();
  resetSteps();
  let checker;
  try {
    checker = await loadChecker({ base: new URL("../extension/src/", import.meta.url), read });
    // the demo server forwards the host name to the local backend (python -m demo --backend URL)
    checker.askLlm = async (host) => {
      try {
        const res = await fetch("/api/llm-check", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain: host }) });
        return res.ok ? await res.json() : null;
      } catch {
        return null;
      }
    };
  } catch (err) {
    $("info").replaceChildren(Object.assign(document.createElement("span"), { className: "err", textContent: `Could not load the model: ${err.message}. Start the page with "python -m demo" from the repository folder.` }));
    return;
  }
  const go = async (text) => {
    if (!text.trim()) return;
    try {
      await run(await checkUrl(checker, text));
    } catch (err) {
      $("addr").textContent = `Check failed: ${err.message}`;
      throw err;
    }
  };
  $("form").addEventListener("submit", (e) => {
    e.preventDefault();
    go($("url").value);
  });
  $("skip").addEventListener("click", skipToVerdict);
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
  const q = new URLSearchParams(location.search).get("url");
  const start = q ?? EXAMPLES[2][1];
  $("url").value = start;
  go(start);
}

async function read(path) {
  const res = await fetch(new URL(path, root));
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`);
  return res.json();
}

main();
