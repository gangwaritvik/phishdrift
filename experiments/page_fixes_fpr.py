"""False alarms of the extension's page path on natural legitimate pages, before and after a change.

``python -m experiments.page_fixes_fpr --pages data/raw/ood_html/pages --old-dist DIR``
(``--new-dist`` defaults to ``extension/dist``)

Runs ``js/bench/page_verdicts.mjs`` (the service worker's allowlist, URL model, page model and
combiner on stored HTML; no backend, no blocklist) over the out-of-distribution legitimate pages
with HTML, once with an older assembled extension (``--old-dist``, e.g. a worktree of the
previous commit after ``node extension/build.mjs``; run with ``--old``, the pipeline before
2026-10-15) and once with the current one, each with and without the bundled allowlist (four runs
in parallel). Page facts (password and credential fields, form actions) are read from the stored
HTML, not a live DOM.
Writes ``reports/page_fixes_fpr.md`` and ``reports/tables/page_fixes_fpr.csv``.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "js" / "bench" / "page_verdicts.mjs"


def load_pages(path: Path) -> pd.DataFrame:
    files = sorted(path.glob("*.parquet")) if path.is_dir() else [path]
    d = pd.concat([pd.read_parquet(f, columns=["url", "html"]) for f in files], ignore_index=True)
    return d[d["html"].notna()].drop_duplicates("url").reset_index(drop=True)


def run(dist: Path, pages: Path, old: bool, allow: bool) -> pd.DataFrame:
    cmd = ["node", str(BENCH), str(dist), str(pages)]
    cmd += ["--old"] if old else []
    cmd += [] if allow else ["--no-allowlist"]
    out = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=3600).stdout
    return pd.DataFrame(json.loads(out)["rows"])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pages", type=Path, required=True)
    ap.add_argument("--old-dist", type=Path, required=True)
    ap.add_argument("--new-dist", type=Path, default=ROOT / "extension" / "dist")
    ap.add_argument("--reports", type=Path, default=ROOT / "reports")
    a = ap.parse_args()

    pages = load_pages(a.pages)
    with tempfile.TemporaryDirectory() as tmp:
        jl = Path(tmp) / "pages.jsonl"
        with jl.open("w", encoding="utf-8") as f:
            for u, h in zip(pages["url"], pages["html"], strict=True):
                f.write(json.dumps({"url": u, "html": h}) + "\n")
        jobs = {
            (side, allow): (a.old_dist if side == "before" else a.new_dist, side == "before", allow)
            for side in ("before", "after")
            for allow in (True, False)
        }
        with ThreadPoolExecutor(len(jobs)) as ex:
            futs = {k: ex.submit(run, d, jl, old, allow) for k, (d, old, allow) in jobs.items()}
            res = {k: f.result() for k, f in futs.items()}

    usable = res[("before", True)]["hasHtml"].to_numpy()  # page model could read it (training rule)
    rows = []
    for allow in (True, False):
        for subset, mask in (("all pages", None), ("pages the page model reads", usable)):
            for side in ("before", "after"):
                d = res[(side, allow)]
                d = d if mask is None else d[mask]
                rows.append(
                    {
                        "allowlist": "on" if allow else "off",
                        "subset": subset,
                        "side": side,
                        "pages": len(d),
                        "warned": int((d["verdict"] >= 1).sum()),
                        "dangerous": int((d["verdict"] >= 2).sum()),
                    }
                )
    t = pd.DataFrame(rows)
    t["warned_pct"] = 100 * t["warned"] / t["pages"]
    t["dangerous_pct"] = 100 * t["dangerous"] / t["pages"]
    (a.reports / "tables").mkdir(parents=True, exist_ok=True)
    t.to_csv(a.reports / "tables" / "page_fixes_fpr.csv", index=False)

    changed = []
    for allow in (True, False):
        b, n = res[("before", allow)], res[("after", allow)]
        diff = b["verdict"] != n["verdict"]
        for (_, x), (_, y) in zip(b[diff].iterrows(), n[diff].iterrows(), strict=True):
            side = "on" if allow else "off"
            changed.append(
                f"| {side} | `{x['url'][:80]}` | {x['verdict']} -> {y['verdict']} "
                f"| {y['layer']} | {bool(y['creds'])} | {bool(y['short'])} |"
            )

    lines = [
        "# Page-check fixes: false alarms on natural legitimate pages",
        "",
        f"{len(pages):,} naturally browsed legitimate pages with stored HTML "
        f"({int(usable.sum()):,} the page model can read under the training rule).",
        "Verdicts from `js/bench/page_verdicts.mjs`: allowlist, URL model, page model and combiner",
        "as in the service worker; no backend, no blocklist; page facts read from the stored HTML",
        "(not a live DOM). Before = the pipeline before 2026-10-15 (the page model may lower any",
        "suspicious address); after = the page model may lower a verdict only on pages with no",
        "password, one-time-code, card or PIN field, and bare login forms are read by the page",
        "model.",
        "",
        "| allowlist | subset | side | pages | warned | % | dangerous | % |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in t.itertuples():
        lines.append(
            f"| {r.allowlist} | {r.subset} | {r.side} | {r.pages:,} | {r.warned} "
            f"| {r.warned_pct:.2f}% | {r.dangerous} | {r.dangerous_pct:.2f}% |"
        )
    lines += [
        "",
        "Pages whose verdict changed (0 safe, 1 suspicious, 2 dangerous):",
        "",
        "| allowlist | url | verdict | layer after | asks credentials | short page |",
        "|---|---|---|---|---|---|",
        *changed,
        "",
        "Not measured here: the recall effect on phishing pages (no phishing HTML in this set).",
        "",
    ]
    (a.reports / "page_fixes_fpr.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
