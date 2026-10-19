// Verdicts of the extension's page path for a list of (url, html file) pairs, without a browser:
// js/src/page.js scorePage with the shipped bundles (js/data/tier_a_hybrid.json + tier_b_page.json),
// exactly what extension/src/background.js pageCheck runs on the HTML the content script sends
// (capped at the content script's MAX_HTML_CHARS). The backend domain checks and the password-form
// rule (used only when the page model cannot read the page) are not applied.
//
//   node js/bench/page_verdicts.mjs PAIRS.json|PAIRS.csv [--base DIR] [--allowlist ALLOWLIST.json]
//
// PAIRS: a JSON array of {url, file} or a CSV with a header holding `url` and `file` columns. Relative
// files resolve against --base (default: the folder of PAIRS). With --allowlist (needs
// `node extension/build.mjs` first) each row also says whether the extension's allowlist would have
// skipped the page model for that address. Prints a JSON array on stdout, one row per pair:
// {url, file, htmlChars, hasHtml, probAddress, probPage, blended, verdict, allowlisted?} or {url, file, error}.

import { readFileSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { loadHybrid } from "../src/hybrid.js";
import { loadPage, scorePage } from "../src/page.js";

const MAX_HTML_CHARS = 5_000_000; // extension/src/content.js
const NAMES = ["safe", "suspicious", "dangerous"];

export function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') {
        field += '"';
        i++;
      } else if (c === '"') quoted = false;
      else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ",") {
      row.push(field);
      field = "";
    } else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(field);
      field = "";
      if (row.length > 1 || row[0] !== "") rows.push(row);
      row = [];
    } else field += c;
  }
  if (field !== "" || row.length) {
    row.push(field);
    rows.push(row);
  }
  const [head, ...body] = rows;
  return body.map((r) => Object.fromEntries(head.map((h, j) => [h, r[j] ?? ""])));
}

function readPairs(path) {
  const text = readFileSync(path, "utf8");
  return path.toLowerCase().endsWith(".csv") ? parseCsv(text) : JSON.parse(text);
}

async function main(argv) {
  const args = [...argv];
  const opt = (name) => {
    const i = args.indexOf(name);
    if (i < 0) return null;
    const [, value] = args.splice(i, 2);
    return value;
  };
  const base = opt("--base");
  const allowFile = opt("--allowlist");
  const [pairsFile] = args;
  if (!pairsFile) throw new Error("usage: page_verdicts.mjs PAIRS.json|PAIRS.csv [--base DIR] [--allowlist FILE]");
  const baseDir = base ?? dirname(resolve(pairsFile));

  const root = new URL("../../", import.meta.url);
  const read = (path) => JSON.parse(readFileSync(new URL(path, root), "utf8"));
  const address = loadHybrid(read("js/data/tier_a_hybrid.json"), read("js/data/psl_icann.json"));
  const page = loadPage(read("js/data/tier_b_page.json"));

  let lists = null;
  if (allowFile) {
    // extension/src imports ./lib/psl.js, which only exists in the assembled extension/dist.
    const { ListSet } = await import("../../extension/dist/lists.js").catch(() => {
      throw new Error("extension/dist is missing: run node extension/build.mjs first");
    });
    lists = new ListSet(
      { allowlist: JSON.parse(readFileSync(allowFile, "utf8")) },
      { platforms: address.lists.platforms, psl: address.lists.psl },
    );
  }

  const rows = [];
  for (const { url, file } of readPairs(pairsFile)) {
    const row = { url, file };
    try {
      const html = readFileSync(isAbsolute(file) ? file : resolve(baseDir, file), "utf8").slice(0, MAX_HTML_CHARS);
      const r = scorePage(address, page, url, html);
      Object.assign(row, {
        htmlChars: html.length,
        hasHtml: r.hasHtml,
        probAddress: r.probAddress,
        probPage: r.probPage,
        blended: r.blended,
        verdict: NAMES[r.verdict],
      });
      if (lists) row.allowlisted = Boolean((await lists.check(url)).allow);
    } catch (err) {
      row.error = String(err?.message ?? err);
    }
    rows.push(row);
  }
  process.stdout.write(JSON.stringify(rows));
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main(process.argv.slice(2));
}
