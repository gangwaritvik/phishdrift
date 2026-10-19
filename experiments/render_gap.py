"""Train/serve gap of the page model: raw server HTML against the rendered DOM (red-team gap 5).

``python -m experiments.render_gap --pages PAGES --cache DIR [--dist extension/dist] [--sample N]``

The page model was trained, and its false alarms measured, on raw HTML, but the extension scores
the live DOM after scripts ran (``extension/src/content.js`` ``pageHtml``). This renders each
natural legitimate page's stored HTML offline in headless Chromium (``js/bench/render_pages.mjs``:
the stored HTML is served at the page's real address, every other request is aborted, so inline
scripts run but external scripts, styles and frames do not), serialises the DOM as ``pageHtml``
does and reads the content script's page facts from it. Both versions then go through
``js/bench/page_verdicts.mjs`` (allowlist, URL model, page model and combiner; no backend, no
blocklist), with and without the bundled allowlist (four runs in parallel).

Raw side: stored HTML, facts from the bench's tag scan (as in ``page_fixes_fpr``). Rendered side:
rendered DOM, facts from the DOM (as the extension reads them). Only pages that rendered are
compared. A lower bound on the real gap: external scripts did not run here.

The rendered HTML is cached in ``--cache`` (``raw.jsonl``, ``rendered.jsonl``; resumable); keep it
out of the repository and ``data/``. Writes ``reports/render_gap.md`` and
``reports/tables/render_gap.csv``.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import numpy as np
import pandas as pd

from experiments.page_fixes_fpr import load_pages, run
from phishdrift.domains import registered_domain

ROOT = Path(__file__).resolve().parents[1]
RENDER = ROOT / "js" / "bench" / "render_pages.mjs"
SEED = 0
VERDICT = {0: "safe", 1: "suspicious", 2: "dangerous"}


def sample_pages(pages: pd.DataFrame, n: int | None, seed: int = SEED) -> pd.DataFrame:
    """All pages, or a fixed-seed sample of ``n`` of them (in the input order)."""
    if n is None or n >= len(pages):
        return pages.reset_index(drop=True)
    return pages.sample(n, random_state=seed).sort_index().reset_index(drop=True)


def read_jsonl(path: Path) -> pd.DataFrame:
    with path.open(encoding="utf-8") as f:
        rows = [json.loads(line) for line in f if line.strip()]
    return pd.DataFrame(rows)


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def compare(raw: pd.DataFrame, ren: pd.DataFrame) -> pd.DataFrame:
    """One row per URL scored on both sides: verdicts, blended page scores, readability."""
    cols = ["url", "verdict", "layer", "page", "probPage", "hasHtml", "creds", "short"]
    m = raw[cols].merge(ren[cols], on="url", suffixes=("_raw", "_ren"), validate="one_to_one")
    for side in ("raw", "ren"):
        m[f"page_{side}"] = pd.to_numeric(m[f"page_{side}"], errors="coerce")
        m[f"creds_{side}"] = m[f"creds_{side}"].fillna(False).astype(bool)
    m["delta"] = m["page_ren"] - m["page_raw"]
    m["change"] = np.sign(m["verdict_ren"] - m["verdict_raw"]).astype(int)
    return m


def rates(m: pd.DataFrame) -> list[dict]:
    """Warned (verdict >= 1) and dangerous counts on each side, over all pages and over pages the
    page model reads on both sides."""
    both = m["hasHtml_raw"] & m["hasHtml_ren"]
    out = []
    for subset, d in (("all rendered pages", m), ("page model reads both", m[both])):
        for side, name in (("raw", "raw HTML"), ("ren", "rendered DOM")):
            n = len(d)
            warned = int((d[f"verdict_{side}"] >= 1).sum())
            dangerous = int((d[f"verdict_{side}"] >= 2).sum())
            out.append(
                {
                    "subset": subset,
                    "side": name,
                    "pages": n,
                    "warned": warned,
                    "warned_pct": 100 * warned / n if n else float("nan"),
                    "dangerous": dangerous,
                    "dangerous_pct": 100 * dangerous / n if n else float("nan"),
                }
            )
    return out


def transitions(m: pd.DataFrame) -> dict[str, int]:
    """Counts of verdict changes raw -> rendered, e.g. ``{"safe->suspicious": 3}``."""
    d = m[m["verdict_raw"] != m["verdict_ren"]]
    keys = [
        f"{VERDICT[a]}->{VERDICT[b]}"
        for a, b in zip(d["verdict_raw"], d["verdict_ren"], strict=True)
    ]
    return dict(sorted(pd.Series(keys, dtype=object).value_counts().items()))


def top_changes(m: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """The ``n`` pages with the largest absolute change in the blended page score, by domain."""
    d = m[m["delta"].notna()].copy()
    d["abs_delta"] = d["delta"].abs()
    d = d.sort_values(["abs_delta", "url"], ascending=[False, True]).head(n)
    d["domain"] = [registered_domain(u) for u in d["url"]]
    return d


def render(pages_jsonl: Path, out: Path, workers: int, settle_ms: int, timeout_ms: int) -> None:
    cmd = ["node", str(RENDER), str(pages_jsonl), str(out), "--workers", str(workers)]
    cmd += ["--settle-ms", str(settle_ms), "--timeout-ms", str(timeout_ms)]
    subprocess.run(cmd, check=True, timeout=6 * 3600)


def _pct(x: float) -> str:
    return f"{x:.2f}%"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pages", type=Path, required=True, help="parquet file or dir (url, html)")
    ap.add_argument("--cache", type=Path, required=True, help="scratch dir for rendered HTML")
    ap.add_argument("--dist", type=Path, default=ROOT / "extension" / "dist")
    ap.add_argument(
        "--sample", type=int, default=None, help="fixed-seed sample size (all if unset)"
    )
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--settle-ms", type=int, default=1500)
    ap.add_argument("--timeout-ms", type=int, default=15000)
    ap.add_argument("--reports", type=Path, default=ROOT / "reports")
    a = ap.parse_args()

    pages = sample_pages(load_pages(a.pages), a.sample, a.seed)
    a.cache.mkdir(parents=True, exist_ok=True)
    raw_jl = a.cache / "raw.jsonl"
    pairs = list(zip(pages["url"], pages["html"], strict=True))
    write_jsonl(raw_jl, [{"url": u, "html": h} for u, h in pairs])
    ren_out = a.cache / "rendered.jsonl"
    render(raw_jl, ren_out, a.workers, a.settle_ms, a.timeout_ms)

    rendered = read_jsonl(ren_out)
    rendered = rendered[rendered["url"].isin(set(pages["url"]))].drop_duplicates("url", keep="last")
    ok = rendered[rendered["ok"]]
    failed = rendered[~rendered["ok"]]
    ren_jl = a.cache / "rendered_ok.jsonl"
    write_jsonl(
        ren_jl,
        [
            {"url": u, "html": h, "facts": f}
            for u, h, f in zip(ok["url"], ok["html"], ok["facts"], strict=True)
        ],
    )
    raw_ok_jl = a.cache / "raw_ok.jsonl"
    keep = set(ok["url"])
    write_jsonl(
        raw_ok_jl,
        [{"url": u, "html": h} for u, h in pairs if u in keep],
    )

    jobs = {
        (side, allow): (raw_ok_jl if side == "raw" else ren_jl, allow)
        for side in ("raw", "ren")
        for allow in (True, False)
    }
    with ThreadPoolExecutor(len(jobs)) as ex:
        futs = {k: ex.submit(run, a.dist, jl, False, allow) for k, (jl, allow) in jobs.items()}
        res = {k: f.result() for k, f in futs.items()}

    cmp = {allow: compare(res[("raw", allow)], res[("ren", allow)]) for allow in (True, False)}

    # per-page table
    parts = []
    for allow, m in cmp.items():
        t = m.copy()
        t.insert(0, "allowlist", "on" if allow else "off")
        parts.append(t)
    fail_rows = pd.DataFrame({"url": failed["url"], "render_error": failed["error"]})
    table = pd.concat(parts, ignore_index=True)
    table["render_ok"] = True
    table = pd.concat([table, fail_rows.assign(render_ok=False)], ignore_index=True)
    (a.reports / "tables").mkdir(parents=True, exist_ok=True)
    table.to_csv(a.reports / "tables" / "render_gap.csv", index=False)

    raw_len = pages.set_index("url")["html"].str.len()
    ren_len = ok.set_index("url")["html"].str.len()
    len_ratio = ren_len / raw_len.reindex(ren_len.index)
    ratio = len_ratio.median()
    grew = int((len_ratio > 1.1).sum())
    shrank = int((len_ratio < 0.9).sum())
    err_kinds = failed["error"].str.extract(r"^([^:]+)")[0].value_counts()

    off = cmp[False]
    sampled = "" if a.sample is None else f", sample of {a.sample} with seed {a.seed}"
    lines = [
        "# Raw HTML against the rendered DOM: the page path's verdicts (red-team gap 5)",
        "",
        "**Offline approximation, a lower bound.** The stored raw HTML of each page was rendered",
        "in headless Chromium with every network request other than the page itself aborted:",
        "inline scripts ran; external scripts, styles, frames and XHR did not. Real pages that",
        "build their content with external scripts (most single-page apps) change much more when",
        "rendered live, so the real gap is likely larger than this. The real measurement needs",
        "live rendering on Ritvik's PC (sandboxed browser).",
        "",
        f"Pages: {len(pages):,} naturally browsed legitimate pages with stored HTML "
        f"(`{a.pages.name}`{sampled}).",
        f"Rendered OK: {len(ok):,}; failed: {len(failed):,}"
        + (" (" + ", ".join(f"{k}: {v}" for k, v in err_kinds.items()) + ")" if len(failed) else "")
        + f". Median render time {ok['ms'].median() / 1000:.1f} s; settle {a.settle_ms} ms after "
        f"load, hard limit {a.timeout_ms / 1000:.0f} s per page. Median rendered/raw HTML length "
        f"{ratio:.2f} (more than 10% longer: {grew}, more than 10% shorter: {shrank}).",
        "",
        "Verdicts from `js/bench/page_verdicts.mjs` (allowlist, URL model, page model, combiner as",
        "in the service worker; no backend, no blocklist). Raw side: stored HTML, page facts from",
        "the bench's tag scan. Rendered side: DOM serialised as `content.js` `pageHtml` does",
        "(shadow roots appended; closed roots captured by wrapping `attachShadow`), page facts",
        "read from the DOM as `collectPageFacts` does. Only pages that rendered are compared.",
        "",
        "## False alarms",
        "",
        "| allowlist | subset | side | pages | warned | % | dangerous | % |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for allow in (True, False):
        for r in rates(cmp[allow]):
            lines.append(
                f"| {'on' if allow else 'off'} | {r['subset']} | {r['side']} | {r['pages']:,} "
                f"| {r['warned']} | {_pct(r['warned_pct'])} | {r['dangerous']} "
                f"| {_pct(r['dangerous_pct'])} |"
            )
    lines += [
        "",
        "## Verdict changes (raw -> rendered)",
        "",
        "| allowlist | raised | lowered | transitions |",
        "|---|---|---|---|",
    ]
    for allow in (True, False):
        m = cmp[allow]
        tr = ", ".join(f"{k} {v}" for k, v in transitions(m).items()) or "none"
        lines.append(
            f"| {'on' if allow else 'off'} | {int((m['change'] > 0).sum())} "
            f"| {int((m['change'] < 0).sum())} | {tr} |"
        )
    both = off["hasHtml_raw"] & off["hasHtml_ren"]
    d_all = off["delta"].abs()
    d_both = off.loc[both, "delta"].abs()
    lines += [
        "",
        "## Page model input (allowlist off, every page scored)",
        "",
        f"- Page model reads the page: raw {int(off['hasHtml_raw'].sum()):,}, rendered "
        f"{int(off['hasHtml_ren'].sum()):,}; readable only raw "
        f"{int((off['hasHtml_raw'] & ~off['hasHtml_ren']).sum())}, only rendered "
        f"{int((~off['hasHtml_raw'] & off['hasHtml_ren']).sum())}.",
        f"- Asks for credentials (password, one-time-code, card or PIN field): raw "
        f"{int(off['creds_raw'].sum())}, rendered {int(off['creds_ren'].sum())}; changed on "
        f"{int((off['creds_raw'] != off['creds_ren']).sum())} pages.",
        f"- Blended page score, median absolute change: {d_all.median():.4f} over all "
        f"{len(off):,} pages (95th percentile {d_all.quantile(0.95):.4f}, max {d_all.max():.4f}); "
        f"{d_both.median():.4f} over the {int(both.sum()):,} pages the page model reads on both "
        f"sides. Changed by more than 0.05 on {int((d_all > 0.05).sum())} pages.",
        "",
        "## Largest changes in the blended page score (allowlist off)",
        "",
        "| domain | raw score | rendered score | change | verdict raw -> rendered "
        "| page model reads raw / rendered |",
        "|---|---|---|---|---|---|",
    ]
    for r in top_changes(off).itertuples():
        lines.append(
            f"| {r.domain} | {r.page_raw:.3f} | {r.page_ren:.3f} | {r.delta:+.3f} "
            f"| {VERDICT[r.verdict_raw]} -> {VERDICT[r.verdict_ren]} "
            f"| {'yes' if r.hasHtml_raw else 'no'} / {'yes' if r.hasHtml_ren else 'no'} |"
        )
    lines += [
        "",
        "Not measured here: live rendering with external scripts, other extensions' injected",
        "nodes (password managers, ad blockers), and the recall effect on phishing pages (no",
        "phishing HTML in this set).",
        "",
    ]
    (a.reports / "render_gap.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
