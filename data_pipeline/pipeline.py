"""interim/<source>.parquet (all sources) -> pooled corpus -> data/processed/ + data card.

Outputs in data/processed/:
  pool.parquet, heldout_source.parquet, time_slice.parquet, eval_only.parquet
      schema columns + origin, domain_u2, uid, has_html, weight
  splits.parquet   uid + split_0..split_9 (train / cal / test) for the pool
  manifest.json    configs, counts and removal stats
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from data_pipeline.corpus import POOL, build_corpus, enforce_depth
from data_pipeline.datacard import build_card, write_card
from data_pipeline.split import grouped_splits
from phishdrift.schema import BOOKKEEPING, COLUMNS

log = logging.getLogger(__name__)

META_COLUMNS = [c for c in COLUMNS if c != "html"] + [
    *BOOKKEEPING,
    "row_id",
    "html_simhash",
    "has_html",
]
OUTPUT_COLUMNS = [*COLUMNS, *BOOKKEEPING, "uid", "has_html", "weight"]


def load_meta(interim: dict[str, Path]) -> pd.DataFrame:
    """Metadata of every source (no HTML), with a corpus-wide ``uid``."""
    parts = []
    for name, path in interim.items():
        df = pq.read_table(path, columns=META_COLUMNS).to_pandas()
        parts.append(df.assign(uid=name + ":" + df["row_id"].astype(str)))
    return pd.concat(parts, ignore_index=True)


def write_parts(interim: dict[str, Path], corpus: pd.DataFrame, out_dir: Path) -> dict[str, int]:
    """Stream every source (with HTML) into one parquet file per corpus part."""
    out_dir.mkdir(parents=True, exist_ok=True)
    for old in out_dir.glob("*.parquet"):
        old.unlink()
    lookup = corpus.set_index("uid")[["part", "weight"]]
    writers: dict[str, pq.ParquetWriter] = {}
    counts: dict[str, int] = {}
    try:
        for name, path in interim.items():
            for batch in pq.ParquetFile(path).iter_batches(batch_size=20_000):
                chunk = batch.to_pandas()
                chunk["uid"] = name + ":" + chunk["row_id"].astype(str)
                chunk = chunk.join(lookup, on="uid", how="inner")
                for part, rows in chunk.groupby("part"):
                    table = pa.Table.from_pandas(rows[OUTPUT_COLUMNS], preserve_index=False)
                    if part not in writers:
                        writers[part] = pq.ParquetWriter(out_dir / f"{part}.parquet", table.schema)
                    writers[part].write_table(table.cast(writers[part].schema))
                    counts[part] = counts.get(part, 0) + len(rows)
    finally:
        for w in writers.values():
            w.close()
    return counts


def build(
    interim: dict[str, Path],
    cfg: dict,
    split_cfg: dict,
    load_stats: dict,
    crawl_attempts: pd.DataFrame | None = None,
) -> dict:
    meta = load_meta(interim)
    log.info("pooled metadata: %d rows from %d sources", len(meta), len(interim))
    corpus, stats = build_corpus(meta, cfg)

    pool = corpus.loc[corpus["part"] == POOL]
    splits = grouped_splits(
        pool,
        split_cfg["n_splits"],
        split_cfg["test_fraction"],
        split_cfg["cal_fraction"],
        split_cfg["seed"],
    )

    reports_dir = Path(cfg["paths"]["reports_dir"])
    card = build_card(meta, corpus, splits, stats, load_stats, cfg, crawl_attempts)
    write_card(card, reports_dir)
    enforce_depth(stats.depth_check)  # after the reports, so a failure can be inspected

    out_dir = Path(cfg["paths"]["processed_dir"])
    counts = write_parts(interim, corpus, out_dir)
    splits.assign(uid=pool["uid"].to_numpy()).to_parquet(out_dir / "splits.parquet", index=False)
    manifest = {
        "sources": list(interim),
        "counts": counts,
        "removed": stats.removed,
        "shared_phishing_domains": stats.shared_phishing_domains,
        "corpus_config": cfg["corpus"],
        "holdouts": cfg["holdouts"],
        "split_config": split_cfg,
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, default=str))
    return card
