"""Stage a processed folder for ``experiments.char_cnn_a`` from a URL sample, without the PC's data.

python -m experiments.char_cnn_stage --populations FILE [--natural FILE] --out DIR

``FILE`` is a parquet of URLs sampled from the pooled corpus (columns uid, url, domain, label,
depth; the uid prefix names the source), e.g. the sample staged for the prior-study run. The
held-out source (config ``holdouts.heldout_source``) becomes ``heldout_source``, every other
source is the pool, with per-source class weights (``corpus.source_weights``) and one
domain-grouped split. Pool domains that also occur in the held-out source (or in the natural
pages) are dropped, so the hard leakage checks hold. There is no time slice (a sample has no
dates), no HTML, and fewer rows than the PC's pool; the report must say so.
``--natural`` (a CSV with url, domain and ok columns) adds the naturally browsed legitimate pages
as an evaluation-only ``natural`` part (benign, so only its false-alarm rate is defined).
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

import pandas as pd

from data_pipeline.corpus import source_weights
from data_pipeline.split import grouped_splits
from features.extract import extract
from features.fit import Fitted
from features.lists import load_lists
from features.registry import NAMES
from phishdrift.config import load_config

log = logging.getLogger("char_cnn_stage")


def _write(out: Path, name: str, meta: pd.DataFrame, lists) -> None:
    meta.to_parquet(out / f"meta_{name}.parquet", index=False)
    feats = pd.DataFrame(
        [extract(u, lists=lists, fitted=Fitted()) for u in meta["url"]], columns=list(NAMES)
    ).astype("float32")
    feats.insert(0, "uid", meta["uid"].to_numpy())
    feats.to_parquet(
        out / ("features_a.parquet" if name == "pool" else f"features_a_{name}.parquet")
    )
    log.info("%s: %d rows", name, len(meta))


def stage(populations: Path, natural: Path | None, out: Path) -> dict:
    ds, corp, sp = load_config("datasets"), load_config("datasets")["corpus"], load_config("splits")
    held = ds["holdouts"]["heldout_source"]
    out.mkdir(parents=True, exist_ok=True)
    lists = load_lists()
    # the sample lists a URL once per part (A and B): keep each uid once
    df = pd.read_parquet(populations)[["uid", "url", "domain", "label", "depth"]]
    df = df.drop_duplicates("uid")
    df["source"] = df["uid"].str.split(":").str[0]
    df["label"] = df["label"].astype(int)
    held_df = df[df["source"] == held].reset_index(drop=True)
    pool = df[df["source"] != held]
    shared = set(pool["domain"]) & set(held_df["domain"])
    pool = pool[~pool["domain"].isin(shared)].reset_index(drop=True)
    pool["weight"] = source_weights(pool, corp["max_source_share"]).to_numpy()
    held_df["weight"] = 1.0
    parts = {"pool": pool, "heldout_source": held_df}
    dropped = {
        "pool_rows_sharing_a_domain_with_heldout": int(df["source"].ne(held).sum() - len(pool))
    }
    if natural is not None:
        nat = pd.read_csv(natural)
        nat = nat[nat["ok"].astype(str).str.lower() == "true"].drop_duplicates("url")
        nat = nat[~nat["domain"].isin(set(pool["domain"]) | set(held_df["domain"]))]
        nat = nat.assign(uid="natural:" + nat["url"], label=0, source="natural", weight=1.0)
        nat["depth"] = (
            nat["url"].str.replace(r"^[a-z]+://[^/]+", "", regex=True).str.count(r"/[^/]")
        )
        parts["natural"] = nat[["uid", "url", "domain", "label", "source", "depth", "weight"]]
        parts["natural"] = parts["natural"].reset_index(drop=True)
    for name, meta in parts.items():
        _write(out, name, meta, lists)
    splits = grouped_splits(
        pool, sp["n_splits"], sp["test_fraction"], sp["cal_fraction"], sp["seed"]
    )
    splits.assign(uid=pool["uid"].to_numpy()).to_parquet(out / "splits.parquet", index=False)
    return {"rows": {k: len(v) for k, v in parts.items()}} | dropped


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="experiments.char_cnn_stage")
    ap.add_argument("--populations", type=Path, required=True)
    ap.add_argument("--natural", type=Path, default=None)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s: %(message)s")
    print(stage(a.populations, a.natural, a.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
