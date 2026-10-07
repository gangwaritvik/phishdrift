"""Load each dataset into the common schema and write it to data/interim/<name>.parquet.

The interim file holds the schema columns plus helper columns used by the pipeline:
``row_id`` (stable row number), ``html_simhash`` (for near-dup detection; null when a
page has no or too little HTML) and ``has_html``. Big datasets are converted in chunks
so HTML never has to fit in memory at once.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Iterator
from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from collector.store import load_index
from data_pipeline.dedup import html_simhash
from phishdrift.config import load_config, resolve
from phishdrift.schema import COLUMNS, drop_unparsable, to_schema, validate

log = logging.getLogger(__name__)

INTERIM_COLUMNS = [*COLUMNS, "row_id", "html_simhash", "has_html"]
PHISHING_STRINGS = {"1", "phish", "phishing", "malicious", "bad", "true"}
BENIGN_STRINGS = {"0", "benign", "legitimate", "legit", "good", "false"}

INTERIM_SCHEMA = pa.schema(
    [
        ("url", pa.string()),
        ("domain", pa.string()),
        ("label", pa.int8()),
        ("date", pa.timestamp("ns", tz="UTC")),
        ("source", pa.string()),
        ("html", pa.large_string()),
        ("row_id", pa.int64()),
        ("html_simhash", pa.int64()),
        ("has_html", pa.bool_()),
    ]
)


def to_binary_label(values: pd.Series) -> pd.Series:
    """Map common label encodings to 1 = phishing, 0 = benign; fail on anything else."""
    as_str = values.astype(str).str.strip().str.lower()
    out = pd.Series(pd.NA, index=values.index, dtype="Int8")
    out[as_str.isin(PHISHING_STRINGS)] = 1
    out[as_str.isin(BENIGN_STRINGS)] = 0
    unknown = sorted(as_str[out.isna()].unique())
    if unknown:
        raise ValueError(f"unrecognized label values: {unknown[:10]}")
    return out.astype("int8")


def write_interim(chunks: Iterable[pd.DataFrame], out_path: Path, dedup_cfg: dict) -> dict:
    """Validate, add helper columns and stream chunks to ``out_path``. Returns load stats."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_suffix(".tmp.parquet")
    n_rows = n_unparsable = 0
    with pq.ParquetWriter(tmp, INTERIM_SCHEMA) as writer:
        for chunk in chunks:
            chunk, dropped = drop_unparsable(validate(chunk))
            n_unparsable += dropped
            chunk = chunk.assign(
                row_id=range(n_rows, n_rows + len(chunk)),
                html_simhash=pd.array(
                    [html_simhash(h, dedup_cfg) for h in chunk["html"]], dtype="Int64"
                ),
                has_html=chunk["html"].map(lambda h: bool(h)),
            )
            table = pa.Table.from_pandas(
                chunk[INTERIM_COLUMNS], schema=INTERIM_SCHEMA, preserve_index=False
            )
            writer.write_table(table)
            n_rows += len(chunk)
            log.info("%s: %d rows written", out_path.name, n_rows)
    tmp.replace(out_path)
    return {"rows_loaded": n_rows + n_unparsable, "rows_unparsable_url": n_unparsable}


# --- PhreshPhish (Hugging Face) ------------------------------------------------------


def iter_phreshphish(cfg: dict, chunk_rows: int) -> Iterator[pd.DataFrame]:
    from datasets import load_dataset  # optional dependency: pip install -e ".[datasets]"

    cols = cfg["columns"]
    for split in cfg["splits"]:
        ds = load_dataset(cfg["hf_id"], split=split, revision=cfg["revision"])
        missing = [c for c in cols.values() if c and c not in ds.column_names]
        if missing:
            raise KeyError(
                f"PhreshPhish split {split!r} has no columns {missing}; it has {ds.column_names}. "
                "Fix phreshphish.columns in configs/datasets.yaml."
            )
        for batch in ds.iter(batch_size=chunk_rows):
            b = pd.DataFrame({k: batch[v] for k, v in cols.items() if v})
            yield to_schema(
                b["url"],
                to_binary_label(b["label"]),
                "phreshphish",
                dates=b.get("date"),
                html=b.get("html"),
            )


# --- PhiUSIIL (UCI 967) ------------------------------------------------------------


def phiusiil_frame(raw: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    """Convert the raw PhiUSIIL table. Its label is 1 = legitimate, so it is flipped."""
    cols = cfg["columns"]
    label = (raw[cols["label"]].astype(int) == int(cfg["phishing_label_value"])).astype("int8")
    return to_schema(raw[cols["url"]], label, "phiusiil")  # no dates, no HTML in the UCI release


def iter_phiusiil(cfg: dict, chunk_rows: int) -> Iterator[pd.DataFrame]:
    from ucimlrepo import fetch_ucirepo  # optional dependency

    raw = fetch_ucirepo(id=cfg["uci_id"]).data.original
    df = phiusiil_frame(raw, cfg)
    for start in range(0, len(df), chunk_rows):
        yield df.iloc[start : start + chunk_rows].reset_index(drop=True)


# --- Live feeds (collector output) -------------------------------------------------


def live_frame(index: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    """Collector first-seen index -> schema. Drops label conflicts and excluded threats."""
    keep = (index["threat"].isin([*cfg["include_threats"], "benign"])) & ~index["label_conflict"]
    idx = index.loc[keep]
    # source = the first feed that reported it (sorted name order for ties).
    source = idx["sources"].str.split(",").str[0]
    return to_schema(idx["url"], idx["label"], source, dates=idx["first_seen"])


def iter_live(cfg: dict, chunk_rows: int) -> Iterator[pd.DataFrame]:
    collector_cfg = load_config("collector")
    index_path = resolve(collector_cfg["paths"]["index_path"])
    if not index_path.exists():
        raise FileNotFoundError(f"{index_path} not found; run `python -m collector run` first")
    df = live_frame(load_index(index_path), cfg)
    for start in range(0, len(df), chunk_rows):
        yield df.iloc[start : start + chunk_rows].reset_index(drop=True)


LOADERS = {"phreshphish": iter_phreshphish, "phiusiil": iter_phiusiil, "live": iter_live}


def load_dataset_to_interim(name: str, cfg: dict) -> tuple[Path, dict]:
    out = resolve(cfg["paths"]["interim_dir"]) / f"{name}.parquet"
    stats = write_interim(LOADERS[name](cfg[name], cfg["chunk_rows"]), out, cfg["dedup"])
    return out, stats


def inspect(name: str, cfg: dict, n: int = 3) -> str:
    """Show raw column names and a few rows, to check the column mapping in the config."""
    if name == "phreshphish":
        from datasets import load_dataset

        c = cfg[name]
        ds = load_dataset(c["hf_id"], split=c["splits"][0], revision=c["revision"])
        rows = ds.select(range(min(n, len(ds)))).to_pandas()
    elif name == "phiusiil":
        from ucimlrepo import fetch_ucirepo

        rows = fetch_ucirepo(id=cfg[name]["uci_id"]).data.original.head(n)
    else:
        raise ValueError(f"inspect supports phreshphish and phiusiil, not {name!r}")
    rows = rows.map(lambda v: (v[:80] + "...") if isinstance(v, str) and len(v) > 80 else v)
    return f"columns: {list(rows.columns)}\n{rows.T.to_string()}"
