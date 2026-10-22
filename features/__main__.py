"""Feature engine commands.

python -m features dictionary           # regenerate docs/FEATURE_DICTIONARY.md
python -m features lists [names...]     # collect word lists from the internet (needs network)
python -m features fit                  # fit bigram and TLD numbers on the training folds
python -m features build [--split NAME]  # tier A features for one processed part (default pool)
python -m features build --tier B [--split NAME] [--workers N]
                                         # tier B (HTML) features, resumable shards, then
                                         # data/processed/features_b[_NAME].parquet
python -m features build --tier C [--info-dir DIR] [--out FILE]
                                         # tier C (domain/DNS/TLS) features of the first-seen
                                         # captures -> data/processed/features_c.parquet
python -m features export-js            # js/data/ (public-suffix rules, lists, fitted numbers) and
                                         # js/src/pydata.js (entity tables, Python Unicode sets)
python -m features parity               # tests/fixtures/url_parity.json and html_parity.json
                                         # (Python-JS parity cases)
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from features import dictionary
from features.extract import extract
from features.fit import fit, load_fitted, write_fitted
from features.lists import load_lists
from features.registry import NAMES
from phishdrift.config import load_config, resolve

log = logging.getLogger("features")
BATCH = 20_000


def _paths() -> tuple[Path, Path]:
    processed = resolve(load_config("datasets")["paths"]["processed_dir"])
    return processed, processed / "features_a.parquet"


def output_path(base: Path, split: str) -> Path:
    """features_a.parquet for the pool, features_a_<split>.parquet for any other part."""
    return base if split == "pool" else base.with_name(f"{base.stem}_{split}{base.suffix}")


def _url_batches(path: Path, columns: list[str]):
    yield from pq.ParquetFile(path).iter_batches(batch_size=BATCH, columns=columns)


def build(split: str = "pool") -> Path:
    """Tier A features for every row of a processed part, streamed (URLs only, no HTML)."""
    processed, base = _paths()
    out_path = output_path(base, split)
    src = processed / f"{split}.parquet"
    lists, fitted = load_lists(), load_fitted()
    schema = pa.schema([("uid", pa.string())] + [(n, pa.float32()) for n in NAMES])
    tmp = out_path.with_suffix(".tmp.parquet")
    n = 0
    with pq.ParquetWriter(tmp, schema, compression="zstd") as writer:
        for batch in _url_batches(src, ["uid", "url"]):
            df = batch.to_pandas()
            feats = [extract(u, lists=lists, fitted=fitted) for u in df["url"]]
            table = pd.DataFrame(feats, columns=list(NAMES)).astype("float32")
            table.insert(0, "uid", df["uid"].to_numpy())
            writer.write_table(pa.Table.from_pandas(table, schema=schema, preserve_index=False))
            n += len(df)
            log.info("%d rows", n)
    tmp.replace(out_path)
    return out_path


def fit_command(split_index: int = 0) -> Path:
    """Fit on the train side of one split only (cal and test rows are never used)."""
    processed, _ = _paths()
    pool = pq.read_table(processed / "pool.parquet", columns=["uid", "url", "label"]).to_pandas()
    splits = pq.read_table(processed / "splits.parquet").to_pandas()
    train_uids = set(splits.loc[splits[f"split_{split_index}"] == "train", "uid"])
    train = pool[pool["uid"].isin(train_uids)]
    data = fit(train["url"].tolist(), train["label"].astype(int).tolist(), load_lists().platforms)
    return write_fitted(data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="features")
    parser.add_argument(
        "command",
        choices=[
            "dictionary",
            "lists",
            "fit",
            "build",
            "export-js",
            "parity",
        ],
    )
    parser.add_argument("names", nargs="*")
    parser.add_argument("--split", default="pool", help="part to build features for (build only)")
    parser.add_argument(
        "--tier", choices=["A", "B", "C"], default="A", help="feature tier to build (build only)"
    )
    parser.add_argument(
        "--info-dir",
        type=Path,
        default=None,
        help="tier C: first-seen capture JSONL directory (default paths.domain_info_dir)",
    )
    parser.add_argument(
        "--out", type=Path, default=None, help="tier C: output parquet (default features_c)"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="worker processes for tier B (default: CPUs - 1, at most 4)",
    )
    args, rest = parser.parse_known_args(argv)
    if rest:
        parser.error(f"unrecognized arguments: {' '.join(rest)}")
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    if args.command == "dictionary":
        print(dictionary.write())
    elif args.command == "lists":
        from features import scrape

        print(scrape.run(args.names or None))
    elif args.command == "export-js":
        from features import html_parity, js_export

        print(*js_export.export_js(), html_parity.export_pydata(), sep="\n")
    elif args.command == "parity":
        from features import html_parity, js_export

        print(
            js_export.write_parity(),
            html_parity.write_parity_b(),
            sep="\n",
        )
    elif args.command == "fit":
        print(fit_command())
    elif args.tier == "C":
        from features import build_c

        out, counts = build_c.build_c(args.info_dir, args.out)
        print(counts.to_string())
        print(out)
    elif args.tier == "B":
        from features import build_b

        try:
            out = build_b.build_b(args.split, workers=args.workers)
        except KeyboardInterrupt:
            return 130  # build_b already said how to resume
        print(out if out is not None else f"no HTML in {args.split}: tier B not built")
    else:
        print(build(args.split))
    return 0


if __name__ == "__main__":
    sys.exit(main())
