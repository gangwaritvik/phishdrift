"""Train/serve gap of the page model: raw server HTML vs the rendered DOM on legitimate pages.

``python -m experiments.render_gap --index data/raw/ood_render/render_index.csv [--no-allowlist]``

The page model (tier B) was trained on raw HTML (dataset-saved pages and plain HTTP fetches); the
extension scores the rendered DOM. ``python -m collector render-ood`` renders a sample of the
naturally browsed legitimate pages that have stored raw HTML; this script scores both forms of every
successfully rendered page with the shipped page path (``js/bench/render_verdicts.mjs``:
js/src/page.js ``scorePage`` with the bundles the extension ships) and compares the false
alarms. Every page is legitimate, so every warning is a false alarm.

Writes ``reports/render_gap.md``, ``reports/tables/render_gap.csv`` (one row per HTML form) and
``reports/tables/render_gap_pages.csv`` (one row per page).
"""

from __future__ import annotations

import argparse
import json
import math
import subprocess
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd
from phishdrift.domains import registered_domain

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "js" / "bench" / "render_verdicts.mjs"
ALLOWLIST = ROOT / "extension" / "data" / "allowlist.json"
FORMS = ("raw", "rendered")
WARN = ("suspicious", "dangerous")
MAX_FLIPS_LISTED = 60

MEASURED = " ".join(
    [
        "What is measured: the page model was trained on raw server HTML (dataset-saved pages",
        "and the crawler's plain HTTP fetches) while the extension scores the rendered DOM",
        "(`outerHTML` after the page's scripts ran). The same naturally browsed legitimate pages",
        "are scored both ways with the shipped page path (`js/src/page.js` `scorePage`: address",
        "model + page model, `agree` rule, the bundles in `js/data/`). Every page is legitimate,",
        "so every warning is a false alarm.",
    ]
)
HOW_RENDERED = " ".join(
    [
        "How the rendered form was made: `python -m collector render-ood` loaded each URL afresh",
        "in the locally installed Chrome/Edge (`--headless=new --dump-dom`, a new empty profile",
        "per page). Pages therefore render without the user's extensions, cookies or sign-ins",
        "(no logged-in views; consent banners as for a first-time visitor) and with a headless",
        "browser's user agent. The raw HTML was fetched earlier by the crawler, so content",
        "changes between the two fetches are part of the difference. The address is the sampled",
        "URL in both forms (redirects are not followed into the address). The backend domain",
        "checks and the password-form rule are not applied; the allowlist rows show what a user",
        "meets with the allowlist on.",
    ]
)


def sample_pages(pages: pd.DataFrame, n: int | None, seed: int = 0) -> pd.DataFrame:
    """All pages, or a fixed-seed sample of ``n`` of them (in the input order)."""
    if n is None or n >= len(pages):
        return pages.reset_index(drop=True)
    return pages.sample(n, random_state=seed).sort_index().reset_index(drop=True)


def compare(raw: pd.DataFrame, ren: pd.DataFrame) -> pd.DataFrame:
    """One row per URL scored on both sides: verdicts, page scores and readability."""
    cols = ["url", "verdict", "layer", "page", "probPage", "hasHtml", "creds", "short"]
    m = raw[cols].merge(ren[cols], on="url", suffixes=("_raw", "_ren"), validate="one_to_one")
    for side in ("raw", "ren"):
        m[f"page_{side}"] = pd.to_numeric(m[f"page_{side}"], errors="coerce")
        m[f"creds_{side}"] = m[f"creds_{side}"].fillna(False).astype(bool)
    m["delta"] = m["page_ren"] - m["page_raw"]
    m["change"] = np.sign(m["verdict_ren"] - m["verdict_raw"]).astype(int)
    return m


def rates(m: pd.DataFrame) -> list[dict]:
    """Warned and dangerous counts on each side, over all pages and the readable subset."""
    both = m["hasHtml_raw"] & m["hasHtml_ren"]
    out: list[dict] = []
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
    names = {0: "safe", 1: "suspicious", 2: "dangerous"}
    d = m[m["verdict_raw"] != m["verdict_ren"]]
    keys = [f"{names[a]}->{names[b]}" for a, b in zip(d["verdict_raw"], d["verdict_ren"], strict=True)]
    return pd.Series(keys).value_counts().sort_index().to_dict()


def top_changes(m: pd.DataFrame, n: int = 15) -> pd.DataFrame:
    """Largest absolute blended-page changes, with domain and verdict context."""
    d = m.copy()
    d["domain"] = d["url"].map(registered_domain)
    d["abs_delta"] = d["delta"].abs()
    cols = [
        "domain",
        "url",
        "verdict_raw",
        "verdict_ren",
        "page_raw",
        "page_ren",
        "delta",
        "abs_delta",
        "hasHtml_raw",
        "hasHtml_ren",
    ]
    return d.sort_values("abs_delta", ascending=False).head(n).reset_index(drop=True)[cols]


def load_index(index: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    """All index rows, and the pages with both a raw and a rendered file (status ok)."""
    d = pd.read_csv(index, dtype=str, keep_default_na=False)
    ok = d[(d["status"] == "ok") & (d["raw_file"] != "") & (d["rendered_file"] != "")]
    return d, ok.drop_duplicates("url").reset_index(drop=True)


def run_node(pairs: pd.DataFrame, base: Path, allowlist: Path | None) -> pd.DataFrame:
    """Score (url, file) pairs with the bench; files are relative to ``base``."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "pairs.json"
        path.write_text(json.dumps(pairs[["url", "file"]].to_dict("records")), encoding="utf-8")
        cmd = ["node", str(BENCH), str(path), "--base", str(base)]
        if allowlist is not None:
            cmd += ["--allowlist", str(allowlist)]
        out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", check=True)
    return pd.DataFrame(json.loads(out.stdout))


def score(ok: pd.DataFrame, base: Path, allowlist: Path | None) -> pd.DataFrame:
    """One row per page with ``raw_*`` and ``rendered_*`` columns from the bench."""
    if allowlist is not None:
        subprocess.run(
            ["node", str(ROOT / "extension" / "build.mjs")], check=True, capture_output=True
        )
    out = ok[["id", "url", "domain"]].copy()
    for form in FORMS:
        res = run_node(ok.assign(file=ok[f"{form}_file"]), base, allowlist)
        if "error" in res and res["error"].notna().any():
            bad = res[res["error"].notna()]
            raise RuntimeError(
                f"{form}: {len(bad)} pages failed in the bench, e.g. {bad.iloc[0].to_dict()}"
            )
        if "allowlisted" in res and "allowlisted" not in out:
            out["allowlisted"] = res["allowlisted"].astype(bool).to_numpy()
        for col in ("htmlChars", "hasHtml", "probAddress", "probPage", "blended", "verdict"):
            out[f"{form}_{col}"] = res[col].to_numpy()
    for form in FORMS:
        out[f"{form}_hasHtml"] = out[f"{form}_hasHtml"].astype(bool)
        out[f"{form}_warned"] = out[f"{form}_verdict"].isin(WARN)
        out[f"{form}_dangerous"] = out[f"{form}_verdict"] == "dangerous"
    return out


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value for b and c discordant pairs."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2**n
    return min(1.0, 2 * tail)


def summarise(pages: pd.DataFrame) -> list[dict]:
    rows = []
    sets = {"all pages (allowlist off)": pages}
    if "allowlisted" in pages:
        sets["pages not on the allowlist"] = pages[~pages["allowlisted"]]
    for name, d in sets.items():
        for form in FORMS:
            rows.append(
                {
                    "set": name,
                    "html": form,
                    "pages": len(d),
                    "sites": d["domain"].nunique(),
                    "usable_html": int(d[f"{form}_hasHtml"].sum()),
                    "warned": int(d[f"{form}_warned"].sum()),
                    "dangerous": int(d[f"{form}_dangerous"].sum()),
                    "warned_rate": d[f"{form}_warned"].mean() if len(d) else float("nan"),
                    "dangerous_rate": d[f"{form}_dangerous"].mean() if len(d) else float("nan"),
                    "median_blended": d[f"{form}_blended"].median(),
                }
            )
    return rows


def paired(d: pd.DataFrame, col: str) -> dict:
    r, n = d[f"raw_{col}"], d[f"rendered_{col}"]
    return {
        "both": int((r & n).sum()),
        "only_raw": int((r & ~n).sum()),
        "only_rendered": int((~r & n).sum()),
        "neither": int((~r & ~n).sum()),
    }


def _pct(a: int, b: int) -> str:
    return f"{a} / {b} ({100 * a / b:.1f}%)" if b else f"{a} / 0 (n/a)"


def render(index: pd.DataFrame, pages: pd.DataFrame, rows: list[dict], allowlist_used: bool) -> str:
    status = index["status"].value_counts()
    n, sites = len(pages), pages["domain"].nunique() if len(pages) else 0
    lines = [
        "# Page model on raw HTML vs the rendered DOM (natural legitimate pages)",
        "",
        "Generated by `python -m experiments.render_gap`. Do not edit by hand.",
        "",
        MEASURED,
        "",
        HOW_RENDERED,
        "",
        f"Sample: {len(index):,} pages; render status: "
        + ", ".join(f"{k} {v:,}" for k, v in status.items())
        + f". Compared: {n:,} pages from {sites:,} sites with both forms.",
        "",
        "| set | HTML | pages | sites | usable HTML | warned (suspicious or worse) | dangerous |"
        " median blended score |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| {r['set']} | {r['html']} | {r['pages']:,} | {r['sites']:,} "
            f"| {_pct(r['usable_html'], r['pages'])} | {_pct(r['warned'], r['pages'])} "
            f"| {_pct(r['dangerous'], r['pages'])} | {r['median_blended']:.4f} |"
        )
    if not n:
        return "\n".join(lines + ["", "No page has both forms: nothing to compare.", ""])
    lines += ["", "## Paired (same page, all pages, allowlist off)", ""]
    lines += [
        "| outcome | both forms | only raw | only rendered | neither | exact McNemar p |",
        "|---|---|---|---|---|---|",
    ]
    for col, label in (
        ("warned", "warned"),
        ("dangerous", "dangerous"),
        ("hasHtml", "usable HTML"),
    ):
        p = paired(pages, col)
        lines.append(
            f"| {label} | {p['both']} | {p['only_raw']} | {p['only_rendered']} | {p['neither']} "
            f"| {mcnemar_exact(p['only_raw'], p['only_rendered']):.3g} |"
        )
    diff = (pages["rendered_blended"] - pages["raw_blended"]).abs()
    lines += [
        "",
        f"Median |blended score difference| (rendered - raw): {diff.median():.4f} "
        f"(90th percentile {diff.quantile(0.9):.4f}, max {diff.max():.4f}).",
        "",
    ]
    flips = pages[pages["raw_verdict"] != pages["rendered_verdict"]]
    lines += [f"## Pages whose verdict changes ({len(flips)})", ""]
    if len(flips):
        lines += [
            "| domain | URL | raw verdict | rendered verdict | raw blended | rendered blended "
            "| usable HTML raw / rendered |" + (" allowlisted |" if allowlist_used else ""),
            "|---|---|---|---|---|---|---|" + ("---|" if allowlist_used else ""),
        ]
        for r in flips.head(MAX_FLIPS_LISTED).itertuples(index=False):
            url = r.url if len(r.url) <= 90 else r.url[:87] + "..."
            row = (
                f"| {r.domain} | {url} | {r.raw_verdict} | {r.rendered_verdict} "
                f"| {r.raw_blended:.4f} | {r.rendered_blended:.4f} "
                f"| {bool(r.raw_hasHtml)} / {bool(r.rendered_hasHtml)} |"
            )
            if allowlist_used:
                row += f" {bool(r.allowlisted)} |"
            lines.append(row)
        if len(flips) > MAX_FLIPS_LISTED:
            lines.append(
                f"\n{len(flips) - MAX_FLIPS_LISTED} more in `tables/render_gap_pages.csv`."
            )
    lines.append("")
    return "\n".join(lines)


def run(index_path: Path, reports: Path, allowlist: Path | None) -> Path:
    index, ok = load_index(index_path)
    base = index_path.resolve().parent
    pages = score(ok, base, allowlist) if len(ok) else pd.DataFrame(columns=["url", "domain"])
    rows = summarise(pages) if len(pages) else []
    tables = reports / "tables"
    tables.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(tables / "render_gap.csv", index=False)
    pages.to_csv(tables / "render_gap_pages.csv", index=False)
    out = reports / "render_gap.md"
    out.write_text(render(index, pages, rows, allowlist is not None), encoding="utf-8")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="experiments.render_gap")
    ap.add_argument("--index", type=Path, required=True, help="render_index.csv of render-ood")
    ap.add_argument("--reports", type=Path, default=Path("reports"))
    ap.add_argument("--allowlist", type=Path, default=ALLOWLIST)
    ap.add_argument("--no-allowlist", action="store_true", help="skip the allowlist rows")
    a = ap.parse_args(argv)
    allowlist = None if a.no_allowlist or not a.allowlist.exists() else a.allowlist
    print(run(a.index, a.reports, allowlist))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
