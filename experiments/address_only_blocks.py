"""Full blocks from the address model alone: before and after the 2026-10-20 rule.

``python -m experiments.address_only_blocks --old-dist DIR [--new-dist extension/dist]
[--pages data/raw/ood_html/pages] [--processed data/processed]``

The rule: a "dangerous" verdict that rests on the address model alone opens the warning page only
when the page asks for a credential (password, one-time code, card, CVV or UPI PIN field) or the
page model on its own also says dangerous; otherwise the page gets the banner (suspicious). It never
lowers a page below suspicious, so the share of pages warned cannot change; only full blocks move.

Measured on (every run in parallel):
- naturally browsed legitimate pages with stored HTML (``js/bench/page_verdicts.mjs``, the
  service worker's allowlist, URL model, page model and combiner; with and without the bundled
  allowlist);
- the newest time slice and split 0's test side, rows with page features
  (``js/bench/block_rows.mjs``: address model, page model on the stored tier B features,
  combiner; no allowlist, blocklist, backend or brand rules). Split 0 is the split the shipped page
  model was trained on, so its test side and the time slice are both unseen by it.

Writes ``reports/address_only_blocks.md`` and ``reports/tables/address_only_blocks.csv``.
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
BENCH = ROOT / "js" / "bench"
SPLIT = "split_0"  # the shipped page model's split (js/data/tier_b_page.json "split")


def _node(args: list[str]) -> pd.DataFrame:
    out = subprocess.run(
        ["node", *args], check=True, capture_output=True, text=True, timeout=3600
    ).stdout
    return pd.DataFrame(json.loads(out)["rows"])


def write_pages(src: Path, dst: Path) -> int:
    files = sorted(src.glob("*.parquet")) if src.is_dir() else [src]
    d = pd.concat([pd.read_parquet(f, columns=["url", "html"]) for f in files], ignore_index=True)
    d = d[d["html"].notna()].drop_duplicates("url")
    with dst.open("w", encoding="utf-8") as f:
        for u, h in zip(d["url"], d["html"], strict=True):
            f.write(json.dumps({"url": u, "html": h}) + "\n")
    return len(d)


def write_rows(processed: Path, part: str, dst: Path) -> None:
    """Rows with page features of the time slice (``part="time_slice"``) or split 0's test side."""
    if part == "time_slice":
        b = pd.read_parquet(processed / "features_b_time_slice.parquet")
        meta = pd.read_parquet(
            processed / "meta_time_slice.parquet", columns=["uid", "url", "label", "source"]
        )
        d = b.merge(meta, on="uid")
    else:
        b = pd.read_parquet(processed / "features_b.parquet")
        meta = pd.read_parquet(
            processed / "meta_pool.parquet", columns=["uid", "url", "label", "source"]
        )
        splits = pd.read_parquet(processed / "splits.parquet", columns=["uid", SPLIT])
        d = b.merge(meta, on="uid").merge(splits, on="uid")
        d = d[d[SPLIT] == "test"]
    cols = [c for c in b.columns if c != "uid"]
    feats = d[cols].astype(float)
    with dst.open("w", encoding="utf-8") as f:
        for i, (url, label, source) in enumerate(
            zip(d["url"], d["label"], d["source"], strict=True)
        ):
            row = feats.iloc[i]
            page = {c: (None if pd.isna(v) else float(v)) for c, v in row.items()}
            f.write(
                json.dumps({"url": url, "label": int(label), "source": source, "b": page}) + "\n"
            )


def summarise(res: dict[tuple[str, str], pd.DataFrame]) -> pd.DataFrame:
    """One row per (set, class, side): rows, warned (suspicious or dangerous) and blocked."""
    out = []
    for (name, side), d in res.items():
        groups = (
            [("legitimate", d)]
            if "label" not in d
            else [("phishing", d[d["label"] == 1]), ("legitimate", d[d["label"] == 0])]
        )
        for cls, g in groups:
            out.append(
                {
                    "set": name,
                    "class": cls,
                    "side": side,
                    "rows": len(g),
                    "domains": g["url"].map(lambda u: u.split("/")[2] if "//" in u else u).nunique()
                    if "url" in g
                    else None,
                    "warned": int((g["verdict"] >= 1).sum()),
                    "blocked": int((g["verdict"] >= 2).sum()),
                }
            )
    t = pd.DataFrame(out)
    t["order"] = t["side"].map({"before": 0, "after": 1})
    t = t.sort_values(["set", "class", "order"], kind="stable").drop(columns="order")
    t = t.reset_index(drop=True)
    t["warned_pct"] = 100 * t["warned"] / t["rows"]
    t["blocked_pct"] = 100 * t["blocked"] / t["rows"]
    return t


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--old-dist", type=Path, required=True)
    ap.add_argument("--new-dist", type=Path, default=ROOT / "extension" / "dist")
    ap.add_argument("--pages", type=Path, default=ROOT / "data" / "raw" / "ood_html" / "pages")
    ap.add_argument("--processed", type=Path, default=ROOT / "data" / "processed")
    ap.add_argument("--reports", type=Path, default=ROOT / "reports")
    a = ap.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        n_pages = write_pages(a.pages, tmp / "natural.jsonl")
        write_rows(a.processed, "time_slice", tmp / "time_slice.jsonl")
        write_rows(a.processed, "test", tmp / "test.jsonl")
        dists = {"before": a.old_dist, "after": a.new_dist}
        jobs = {}
        for side, dist in dists.items():
            jobs[("natural, allowlist on", side)] = [
                str(BENCH / "page_verdicts.mjs"),
                str(dist),
                str(tmp / "natural.jsonl"),
            ]
            jobs[("natural, allowlist off", side)] = [
                *jobs[("natural, allowlist on", side)],
                "--no-allowlist",
            ]
            jobs[("time slice", side)] = [
                str(BENCH / "block_rows.mjs"),
                str(dist),
                str(tmp / "time_slice.jsonl"),
            ]
            jobs[(f"{SPLIT} test", side)] = [
                str(BENCH / "block_rows.mjs"),
                str(dist),
                str(tmp / "test.jsonl"),
            ]
        with ThreadPoolExecutor(len(jobs)) as ex:
            futs = {k: ex.submit(_node, v) for k, v in jobs.items()}
            res = {k: f.result() for k, f in futs.items()}

    t = summarise(res)
    (a.reports / "tables").mkdir(parents=True, exist_ok=True)
    t.to_csv(a.reports / "tables" / "address_only_blocks.csv", index=False)

    intro = (
        "Rule (2026-10-20): a dangerous verdict resting on the address model "
        "alone opens the warning "
        "page only if the page asks for a password, one-time code, card, CVV "
        "or UPI PIN, or the page "
        "model on its own also says dangerous; otherwise the page gets the banner. Pages are never "
        "lowered below suspicious, so the warned share cannot change. Before = the build given as "
        "`--old-dist`.\n\n"
        f"Natural legitimate pages: {n_pages:,} pages with stored HTML "
        "(`js/bench/page_verdicts.mjs`). "
        "Time slice and split 0 test: rows with page features "
        "(`js/bench/block_rows.mjs`; credential "
        "fields read from the stored page features; no allowlist, blocklist, "
        "backend or brand rules)."
    )
    lines = [
        "# Full blocks from the address model alone",
        "",
        intro,
        "",
        "| set | class | side | rows | warned | % | blocked | % |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in t.itertuples():
        lines.append(
            f"| {r.set} | {r._2} | {r.side} | {r.rows:,} | {r.warned:,} | {r.warned_pct:.2f}% "
            f"| {r.blocked:,} | {r.blocked_pct:.2f}% |"
        )
    lines += [
        "",
        "Not measured here: the redirect-hop part of the change (no warning page before commit), "
        "covered by the browser smoke test (`extension/e2e/smoke.mjs`, step 4c); phishing pages "
        "that add their credential form after load are rechecked by the content script and are "
        "not modelled.",
    ]
    (a.reports / "address_only_blocks.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
