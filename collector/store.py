"""Collector storage.

Layout:
  data/raw/feeds/YYYY-MM-DD/<feed>.parquet       what each training feed returned that day
  data/raw/blocklists/YYYY-MM-DD/<feed>.parquet  blocklist-only feeds (URLhaus); never training data
  data/raw/crawl/YYYY-MM-DD/<seed_source>.parquet benign inner pages from the crawler
  data/raw/crawl/attempts.parquet                every seed domain tried and its outcome
  data/interim/feeds_first_seen.parquet          one row per normalized feed URL

The first-seen index is the dedup point for feed URLs: a URL seen again later keeps its
original ``first_seen`` and only gains new sources.
"""

from __future__ import annotations

import os
from datetime import date, datetime
from pathlib import Path

import pandas as pd

from phishdrift.domains import normalize_url

INDEX_COLUMNS = [
    "url_norm",
    "url",
    "label",
    "threat",
    "sources",
    "first_seen",
    "last_seen",
    "feed_time",
    "target",
    "label_conflict",
]


def write_daily(df: pd.DataFrame, raw_dir: Path, day: date, source: str) -> Path:
    out = Path(raw_dir) / day.isoformat() / f"{source}.parquet"
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out, index=False)
    return out


CRAWL_COLUMNS = ["url", "html", "seed_source", "seed_domain", "crawled_at"]


def write_crawl(df: pd.DataFrame, crawl_dir: Path, day: date, seed_source: str) -> Path:
    out = Path(crawl_dir) / day.isoformat() / f"{seed_source}.parquet"
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():  # a second run on the same day appends
        df = pd.concat([pd.read_parquet(out), df], ignore_index=True)
    df[CRAWL_COLUMNS].to_parquet(out, index=False)
    return out


ATTEMPT_COLUMNS = ["seed_source", "seed_domain", "status", "pages", "attempted_at"]


def load_attempts(crawl_dir: Path) -> pd.DataFrame:
    """Every seed domain the crawler has tried, with its outcome."""
    path = Path(crawl_dir) / "attempts.parquet"
    if not path.exists():
        return pd.DataFrame(columns=ATTEMPT_COLUMNS)
    return pd.read_parquet(path)


def append_attempts(df: pd.DataFrame, crawl_dir: Path) -> Path:
    path = Path(crawl_dir) / "attempts.parquet"
    path.parent.mkdir(parents=True, exist_ok=True)
    if not len(df):
        return path
    old = load_attempts(crawl_dir)
    merged = pd.concat([p for p in (old, df[ATTEMPT_COLUMNS]) if len(p)], ignore_index=True)
    merged["attempted_at"] = pd.to_datetime(merged["attempted_at"], utc=True)
    tmp = path.with_suffix(".tmp.parquet")
    merged.to_parquet(tmp, index=False)
    os.replace(tmp, path)
    return path


def load_crawl(crawl_dir: Path) -> pd.DataFrame:
    """All crawled pages, one row per normalized URL (earliest crawl kept)."""
    files = sorted(Path(crawl_dir).glob("*/*.parquet"))
    if not files:
        return pd.DataFrame(columns=CRAWL_COLUMNS)
    df = pd.concat([pd.read_parquet(f) for f in files], ignore_index=True)
    df["crawled_at"] = pd.to_datetime(df["crawled_at"], utc=True)
    df = df.assign(_k=df["url"].map(normalize_url)).sort_values("crawled_at", kind="stable")
    return df.drop_duplicates("_k").drop(columns="_k").reset_index(drop=True)


def empty_index() -> pd.DataFrame:
    return pd.DataFrame(columns=INDEX_COLUMNS).astype(
        {
            "label": "int8",
            "label_conflict": bool,
            "first_seen": "datetime64[ns, UTC]",
            "last_seen": "datetime64[ns, UTC]",
            "feed_time": "datetime64[ns, UTC]",
        }
    )


def load_index(index_path: Path) -> pd.DataFrame:
    if Path(index_path).exists():
        return pd.read_parquet(index_path)
    return empty_index()


def _join_sources(values) -> str:
    return ",".join(sorted({s for v in values for s in str(v).split(",") if s}))


def update_index(
    index: pd.DataFrame, batch: pd.DataFrame, seen_at: datetime
) -> tuple[pd.DataFrame, int]:
    """Merge one run's rows (FEED_COLUMNS) into the index. Returns (index, n_new_urls)."""
    seen_at = (
        pd.Timestamp(seen_at).tz_convert("UTC")
        if pd.Timestamp(seen_at).tzinfo
        else (pd.Timestamp(seen_at).tz_localize("UTC"))
    )
    b = batch.copy()
    b["url_norm"] = b["url"].map(normalize_url)
    b = (
        b.groupby("url_norm", sort=False)
        .agg(
            url=("url", "first"),
            label=("label", "max"),
            label_min=("label", "min"),
            threat=("threat", "first"),
            sources=("source", _join_sources),
            feed_time=("feed_time", "min"),
            target=("target", "first"),
        )
        .reset_index()
    )
    b["first_seen"] = seen_at
    b["last_seen"] = seen_at
    b["label_conflict"] = b["label"] != b.pop("label_min")

    existing = index.set_index("url_norm")
    is_new = ~b["url_norm"].isin(existing.index)
    new_rows = b.loc[is_new, INDEX_COLUMNS]

    old = b.loc[~is_new].set_index("url_norm")
    if len(old):
        cur = existing.loc[old.index]
        existing.loc[old.index, "last_seen"] = seen_at
        existing.loc[old.index, "sources"] = [
            _join_sources([a, c]) for a, c in zip(cur["sources"], old["sources"], strict=True)
        ]
        conflict = (cur["label"].astype(int) != old["label"].astype(int)) | old["label_conflict"]
        existing.loc[old.index, "label_conflict"] = cur["label_conflict"].astype(bool) | conflict
        existing.loc[old.index, "label"] = (
            pd.concat([cur["label"], old["label"]], axis=1).max(axis=1).astype("int8")
        )

    parts = [p for p in (existing.reset_index()[INDEX_COLUMNS], new_rows) if len(p)]
    merged = pd.concat(parts, ignore_index=True) if parts else empty_index()
    merged["label"] = merged["label"].astype("int8")
    merged["label_conflict"] = merged["label_conflict"].astype(bool)
    return merged, int(is_new.sum())


def save_index(index: pd.DataFrame, index_path: Path) -> None:
    index_path = Path(index_path)
    index_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = index_path.with_suffix(".tmp.parquet")
    index.to_parquet(tmp, index=False)
    os.replace(tmp, index_path)
