"""Data card for the pooled corpus, written to reports/ (markdown + CSV tables).

URL counts and registrable-domain counts are always reported side by side (report §12.1).
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from data_pipeline.corpus import POOL, CorpusStats, depth_table
from data_pipeline.split import CAL, TEST, TRAIN


def _dates(d: pd.Series) -> tuple[str, str]:
    d = d.dropna()
    return ("n/a", "n/a") if d.empty else (d.min().date().isoformat(), d.max().date().isoformat())


def part_summary(df: pd.DataFrame) -> dict:
    start, end = _dates(df["date"])
    return {
        "urls": len(df),
        "domains": df["domain"].nunique(),
        "phishing": int((df["label"] == 1).sum()),
        "benign": int((df["label"] == 0).sum()),
        "phishing_pct": round(100 * df["label"].mean(), 2) if len(df) else 0.0,
        "with_html": int(df["has_html"].sum()),
        "depth0_pct": round(100 * (df["depth"] == 0).mean(), 2) if len(df) else 0.0,
        "date_min": start,
        "date_max": end,
    }


def sources_table(meta: pd.DataFrame, corpus: pd.DataFrame, load_stats: dict) -> pd.DataFrame:
    rows = []
    for (source, part), g in corpus.groupby(["source", "part"]):
        rows.append({"source": source, "part": part, **part_summary(g)})
    out = pd.DataFrame(rows)
    loaded = meta.groupby("source").size().rename("rows_loaded")
    unparsable = pd.Series(
        {s: v.get("rows_unparsable_url", 0) for s, v in load_stats.items()}, name="unparsable"
    )
    return out.join(loaded, on="source").join(unparsable, on="source")


def removals_table(stats: CorpusStats) -> pd.DataFrame:
    return pd.DataFrame(stats.removed).fillna(0).astype(int).rename_axis("source")


def splits_summary(pool: pd.DataFrame, splits: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for col in splits.columns:
        for side in (TRAIN, CAL, TEST):
            part = pool.loc[splits[col].to_numpy() == side]
            rows.append(
                {
                    "split": col,
                    "side": side,
                    "urls": len(part),
                    "domains": part["domain"].nunique(),
                    "phishing_pct": round(100 * part["label"].mean(), 2) if len(part) else 0.0,
                    "benign": int((part["label"] == 0).sum()),
                }
            )
    return pd.DataFrame(rows)


def crawl_table(attempts: pd.DataFrame | None) -> pd.DataFrame:
    """Crawler outcomes per seed set: domains tried, outcome counts, pages kept."""
    if attempts is None or not len(attempts):
        return pd.DataFrame()
    t = pd.crosstab(attempts["seed_source"], attempts["status"])
    t.insert(0, "domains_tried", t.sum(axis=1))
    t["pages"] = attempts.groupby("seed_source")["pages"].sum()
    ok = t.get("ok", 0)
    t["success_pct"] = (100 * ok / t["domains_tried"]).round(1)
    return t


def build_card(
    meta: pd.DataFrame,
    corpus: pd.DataFrame,
    splits: pd.DataFrame,
    stats: CorpusStats,
    load_stats: dict,
    cfg: dict,
    crawl_attempts: pd.DataFrame | None = None,
) -> dict:
    pool = corpus.loc[corpus["part"] == POOL]
    top = cfg["corpus"]["depth"]["top_bucket"]
    return {
        "sources": sources_table(meta, corpus, load_stats),
        "removals": removals_table(stats),
        "parts": pd.DataFrame([{"part": p, **part_summary(g)} for p, g in corpus.groupby("part")]),
        "depth_pool": depth_table(pool, top),
        "depth_by_source": pd.concat(
            {s: depth_table(g, top) for s, g in corpus.groupby("source")}, names=["source"]
        ),
        "splits": splits_summary(pool, splits),
        "crawl": crawl_table(crawl_attempts),
        "depth_check": stats.depth_check,
        "shared_phishing_domains": stats.shared_phishing_domains,
        "rows_in": stats.rows_in,
        "licenses": {s: c.get("license", "") for s, c in cfg["sources"].items()},
        "homepage_only": [s for s, c in cfg["sources"].items() if c.get("homepage_only_benign")],
        "holdouts": cfg["holdouts"],
    }


def _md(df: pd.DataFrame) -> str:
    df = df.reset_index() if not isinstance(df.index, pd.RangeIndex) else df
    cols = [str(c) for c in df.columns]
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for row in df.itertuples(index=False):
        lines.append(
            "| " + " | ".join(f"{v:,}" if isinstance(v, int) else str(v) for v in row) + " |"
        )
    return "\n".join(lines)


def render_markdown(card: dict) -> str:
    check = card["depth_check"]
    status = (
        "PASSED"
        if check["passed"]
        else "FAILED: " + ", ".join(f"bucket {b} {v:.1%}" for b, v in check["bad_buckets"].items())
    )
    split_stats = (
        card["splits"]
        .groupby("side")[["urls", "domains", "phishing_pct", "benign"]]
        .agg(["median", "min", "max"])
    )
    split_stats.columns = [f"{a}_{b}" for a, b in split_stats.columns]
    return "\n".join(
        [
            "# Data card",
            "",
            "Generated by `python -m data_pipeline build`. Do not edit by hand.",
            "Labels: 1 = phishing, 0 = benign. "
            "`domains` = registrable domains (public-suffix-only).",
            "Holdouts (never trained or calibrated on): held-out source "
            f"`{card['holdouts']['heldout_source']}`, newest time slice, evaluation-only sources "
            f"{card['holdouts'].get('eval_only_sources')}.",
            "",
            f"Rows loaded: {card['rows_in']:,}. Domains in more than one phishing source "
            f"(removed from all sources): {card['shared_phishing_domains']:,}.",
            f"Sources whose benign class is homepage-only (never used as the only benign source): "
            f"{', '.join(card['homepage_only']) or 'none'}.",
            "",
            "## Corpus parts",
            "",
            _md(card["parts"]),
            "",
            "## Sources by part",
            "",
            _md(card["sources"]),
            "",
            "## Rows removed per step and source",
            "",
            _md(card["removals"]),
            "",
            f"## Depth check on the training pool: {status}",
            "",
            f"A bucket fails if more than {check['fail_share']:.0%} of its rows are one class.",
            "",
            _md(card["depth_pool"]),
            "",
            "## Depth by source (all parts)",
            "",
            _md(card["depth_by_source"]),
            "",
            "## 10 domain-grouped splits of the pool (median, min, max)",
            "",
            _md(split_stats),
            "",
            "## Benign inner-page crawl (all runs so far)",
            "",
            _md(card["crawl"]) if len(card["crawl"]) else "No crawl runs yet.",
            "",
            "## Licenses",
            "",
            *[f"- {s}: {lic}" for s, lic in card["licenses"].items()],
            "",
        ]
    )


def write_card(card: dict, reports_dir: Path) -> Path:
    reports_dir = Path(reports_dir)
    tables = reports_dir / "tables"
    tables.mkdir(parents=True, exist_ok=True)
    card["sources"].to_csv(tables / "data_card_sources.csv", index=False)
    card["removals"].to_csv(tables / "data_card_removals.csv")
    card["parts"].to_csv(tables / "data_card_parts.csv", index=False)
    card["depth_pool"].to_csv(tables / "depth_pool.csv")
    card["depth_by_source"].to_csv(tables / "depth_by_source.csv")
    card["splits"].to_csv(tables / "splits_summary.csv", index=False)
    if len(card["crawl"]):
        card["crawl"].to_csv(tables / "crawl_success.csv")
    md = reports_dir / "data_card.md"
    md.write_text(render_markdown(card), encoding="utf-8")
    return md
