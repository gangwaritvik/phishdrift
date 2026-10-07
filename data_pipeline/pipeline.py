"""interim parquet -> dedup -> random + time splits -> data/processed/ + data card."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from data_pipeline.datacard import dataset_card
from data_pipeline.dedup import deduplicate
from data_pipeline.split import (
    TEST,
    TRAIN,
    assert_domain_disjoint,
    random_domain_split,
    resolve_cutoff,
    time_split,
)
from phishdrift.schema import COLUMNS

log = logging.getLogger(__name__)

OUTPUT_COLUMNS = [*COLUMNS, "row_id"]
META_COLUMNS = ["url", "domain", "label", "date", "source", "row_id", "html_simhash", "has_html"]


def make_splits(df: pd.DataFrame, split_cfg: dict) -> tuple[dict[str, pd.Series], dict]:
    """Random (always) and time (when the dataset has dates) splits, leakage-checked."""
    info: dict = {"notes": []}
    splits = {
        "random": random_domain_split(
            df, split_cfg["random_split"]["test_fraction"], split_cfg["seed"]
        )
    }
    if df["date"].notna().sum() > 0:
        tcfg = split_cfg["time_split"]
        cutoff = resolve_cutoff(df, tcfg["cutoff"], tcfg["cutoff_quantile"])
        splits["time"] = time_split(df, cutoff, tcfg["drop_test_domains_seen_in_train"])
        info["time_cutoff"] = cutoff.isoformat()
    else:
        info["notes"].append("no per-row dates, so only the random domain split is produced")
    for name, s in splits.items():
        assert_domain_disjoint(df, s)
        if (s == TEST).sum() == 0 or (s == TRAIN).sum() == 0:
            info["notes"].append(f"{name} split has an empty train or test side")
    return splits, info


def write_splits(
    interim: Path, out_dir: Path, splits: dict[str, pd.Series], row_ids: pd.Series
) -> dict:
    """Stream the interim file (with HTML) into <out_dir>/<split>/<train|test>.parquet."""
    lookup = {name: pd.Series(s.to_numpy(), index=row_ids.to_numpy()) for name, s in splits.items()}
    writers: dict[tuple[str, str], pq.ParquetWriter] = {}
    counts: dict[str, dict[str, int]] = {n: {TRAIN: 0, TEST: 0} for n in splits}
    try:
        for batch in pq.ParquetFile(interim).iter_batches(
            batch_size=20_000, columns=OUTPUT_COLUMNS
        ):
            chunk = batch.to_pandas()
            for name, lk in lookup.items():
                part = lk.reindex(chunk["row_id"].to_numpy()).to_numpy()
                for side in (TRAIN, TEST):
                    rows = chunk.loc[part == side]
                    if rows.empty:
                        continue
                    key = (name, side)
                    table = pa.Table.from_pandas(rows, preserve_index=False).cast(batch.schema)
                    if key not in writers:
                        path = out_dir / name / f"{side}.parquet"
                        path.parent.mkdir(parents=True, exist_ok=True)
                        writers[key] = pq.ParquetWriter(path, batch.schema)
                    writers[key].write_table(table)
                    counts[name][side] += len(rows)
    finally:
        for w in writers.values():
            w.close()
    return counts


def build_dataset(
    name: str, interim: Path, cfg: dict, split_cfg: dict, load_stats: dict | None
) -> dict:
    df = pq.read_table(interim, columns=META_COLUMNS).to_pandas()
    log.info("%s: %d rows loaded", name, len(df))
    df, dstats = deduplicate(df, cfg["dedup"])
    log.info("%s: %s", name, dstats.as_dict())
    splits, info = make_splits(df, split_cfg)

    out_dir = Path(cfg["paths"]["processed_dir"]) / name
    for old in out_dir.glob("*/*.parquet"):
        old.unlink()
    counts = write_splits(interim, out_dir, splits, df["row_id"])
    manifest = {
        "dataset": name,
        "seed": split_cfg["seed"],
        "split_config": split_cfg,
        "time_cutoff": info.get("time_cutoff"),
        "counts": counts,
        "dedup": dstats.as_dict(),
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, default=str))
    return dataset_card(
        name,
        cfg.get(name, {}),
        df,
        splits,
        {
            "load": load_stats or {"rows_loaded": dstats.n_in, "rows_unparsable_url": 0},
            "dedup": dstats.as_dict(),
            **info,
        },
    )
