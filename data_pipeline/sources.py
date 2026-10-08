"""Source loaders: every source -> unified schema -> data/interim/<source>.parquet.

Only URL, label, date and HTML are read from any source. Precomputed feature columns
(PhiUSIIL's URLSimilarityIndex etc.) are never loaded into the schema.

Loader kinds (``kind`` in configs/datasets.yaml):
  huggingface  PhreshPhish (``datasets`` package)
  uci          PhiUSIIL (``ucimlrepo``); only the URL and label columns are kept
  table        local CSV / Parquet / JSONL files with a column map (Phish360, URL-Phish,
               PhishStorm, natural legitimate pages)
  folders      one folder per site with a URL file and an HTML file (Phishpedia)
  phishblitz   Phish-Blitz output: <root>/info.csv + downloaded page folders
  live         collector feeds (first-seen index)

Pages from the benign inner-page crawler are appended to the source whose domains seeded
them (``origin = "crawl"``): PhiUSIIL-seeded pages belong to ``phiusiil``, Tranco-seeded
pages to ``live``. That keeps registrable domains inside one source.

The interim file holds the schema plus helper columns: ``row_id``, ``html_simhash``,
``has_html``. Big sources are converted in chunks so HTML never has to fit in memory.
"""

from __future__ import annotations

import glob
import logging
from collections.abc import Iterable, Iterator
from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from collector.store import load_crawl, load_index
from data_pipeline.dedup import html_simhash
from phishdrift.config import load_config, resolve
from phishdrift.schema import BOOKKEEPING, COLUMNS, drop_unparsable, to_schema, validate

log = logging.getLogger(__name__)

INTERIM_COLUMNS = [*COLUMNS, *BOOKKEEPING, "row_id", "html_simhash", "has_html"]
PHISHING_STRINGS = {"1", "phish", "phishing", "malicious", "bad", "true", "1.0"}
BENIGN_STRINGS = {"0", "benign", "legitimate", "legit", "good", "false", "0.0"}

INTERIM_SCHEMA = pa.schema(
    [
        ("url", pa.string()),
        ("domain", pa.string()),
        ("label", pa.int8()),
        ("date", pa.timestamp("ns", tz="UTC")),
        ("source", pa.string()),
        ("html", pa.large_string()),
        ("depth", pa.int16()),
        ("origin", pa.string()),
        ("domain_u2", pa.string()),
        ("row_id", pa.int64()),
        ("html_simhash", pa.int64()),
        ("has_html", pa.bool_()),
    ]
)


def to_binary_label(values: pd.Series, phishing_values: Iterable | None = None) -> pd.Series:
    """Map label encodings to 1 = phishing, 0 = benign; fail on anything unrecognised.

    With ``phishing_values`` given, exactly those values (compared as lowercase strings)
    mean phishing and everything else must be a known benign value or another listed value.
    """
    as_str = values.astype(str).str.strip().str.lower()
    phish = {str(v).lower() for v in phishing_values} if phishing_values else PHISHING_STRINGS
    out = pd.Series(pd.NA, index=values.index, dtype="Int8")
    out[as_str.isin(phish)] = 1
    out[out.isna() & as_str.isin(BENIGN_STRINGS - phish)] = 0
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
            chunk, dropped = drop_unparsable(chunk)
            validate(chunk)
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


def _chunked(df: pd.DataFrame, chunk_rows: int) -> Iterator[pd.DataFrame]:
    for start in range(0, len(df), chunk_rows):
        yield df.iloc[start : start + chunk_rows].reset_index(drop=True)


def _labels(raw: pd.DataFrame, cfg: dict) -> pd.Series:
    if "label" in cfg:  # one-class source
        return pd.Series([int(cfg["label"])] * len(raw), dtype="int8")
    return to_binary_label(raw[cfg["columns"]["label"]], cfg.get("phishing_values"))


def _col(raw: pd.DataFrame, cfg: dict, name: str) -> pd.Series | None:
    col = (cfg.get("columns") or {}).get(name)
    return raw[col] if col else None


def frame_from_table(raw: pd.DataFrame, name: str, cfg: dict) -> pd.DataFrame:
    """Raw table -> schema using the source's column map. Unmapped columns are ignored."""
    raw = raw[raw[cfg["columns"]["url"]].notna()].reset_index(drop=True)
    return to_schema(
        raw[cfg["columns"]["url"]],
        _labels(raw, cfg),
        name,
        dates=_col(raw, cfg, "date"),
        html=_col(raw, cfg, "html"),
        origin=cfg.get("origin", ""),
    )


# --- huggingface (PhreshPhish) ---------------------------------------------------------


def _hf_files(cfg: dict, split: str) -> list[str]:
    """Parquet files of one split in the dataset repo, e.g. data/train-000.parquet."""
    from huggingface_hub import HfApi

    files = HfApi().list_repo_files(cfg["hf_id"], repo_type="dataset", revision=cfg["revision"])
    return sorted(f for f in files if f.startswith(f"data/{split}-") and f.endswith(".parquet"))


def _trim_html(values, limit: int | None) -> list:
    return [v[:limit] if isinstance(v, str) else v for v in values] if limit else list(values)


def iter_huggingface(name: str, cfg: dict, chunk_rows: int) -> Iterator[pd.DataFrame]:
    """Streams the dataset one parquet file at a time and deletes each file after reading it, so
    peak disk use is one file (about 0.5 GB), not the whole dataset (about 25 GB). Only the mapped
    columns are read; the html column is cut to `html_max_chars` characters when that is set
    (feature definitions that need the full page must treat truncated HTML as a known limit)."""
    import shutil
    import tempfile

    cols = cfg["columns"]
    want = [c for c in cols.values() if c]
    html_col = cols.get("html")
    limit = cfg.get("html_max_chars")
    tmp_root = Path(tempfile.mkdtemp(prefix="phishdrift_hf_", dir=cfg.get("download_dir")))
    manifest: dict[str, int] = {}
    try:
        for split, origin in cfg["splits"].items():
            files = _hf_files(cfg, split)
            if not files:
                raise RuntimeError(f"{name}: no parquet files found for split {split!r}")
            for i, fname in enumerate(files, 1):
                path = _download_with_retry(cfg, fname, tmp_root)
                pf = pq.ParquetFile(path)
                missing = [c for c in want if c not in pf.schema_arrow.names]
                if missing:
                    raise KeyError(
                        f"{name} file {fname} has no columns {missing}; it has "
                        f"{pf.schema_arrow.names}. Fix sources.{name}.columns in "
                        "configs/datasets.yaml."
                    )
                expected, seen = pf.metadata.num_rows, 0
                for batch in pf.iter_batches(batch_size=min(chunk_rows, 2000), columns=want):
                    raw = batch.to_pandas()
                    seen += len(raw)
                    if html_col:
                        raw[html_col] = _trim_html(raw[html_col], limit)
                    yield frame_from_table(raw, name, {**cfg, "origin": origin})
                if seen != expected:
                    raise RuntimeError(f"{name} {fname}: read {seen} of {expected} rows")
                manifest[fname] = expected
                log.info("%s %s [%d/%d]: %d rows read", name, split, i, len(files), expected)
                del pf
                Path(path).unlink(missing_ok=True)
        log.info("%s: %d files, %d rows read in total", name, len(manifest), sum(manifest.values()))
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


def _download_with_retry(cfg: dict, fname: str, dest: Path, attempts: int = 4) -> str:
    """hf_hub_download with exponential backoff; a file that still fails stops the build
    instead of silently leaving a hole in the corpus."""
    import time

    from huggingface_hub import hf_hub_download

    for attempt in range(1, attempts + 1):
        try:
            return hf_hub_download(
                cfg["hf_id"],
                fname,
                repo_type="dataset",
                revision=cfg["revision"],
                local_dir=dest,
            )
        except Exception as exc:  # network errors, disk full, rate limits
            if attempt == attempts:
                raise
            wait = 2**attempt
            log.warning("download of %s failed (%s); retry %d in %ds", fname, exc, attempt, wait)
            time.sleep(wait)
    raise AssertionError("unreachable")


# --- uci (PhiUSIIL) ------------------------------------------------------------------


def phiusiil_frame(raw: pd.DataFrame, name: str, cfg: dict) -> pd.DataFrame:
    """PhiUSIIL's label is 1 = legitimate, 0 = phishing, so it is recoded. Only the URL
    and label columns are read; every precomputed feature column is ignored."""
    cols = cfg["columns"]
    label = (raw[cols["label"]].astype(int) == int(cfg["phishing_label_value"])).astype("int8")
    return to_schema(raw[cols["url"]], label, name, origin="original")


def iter_uci(name: str, cfg: dict, chunk_rows: int) -> Iterator[pd.DataFrame]:
    from ucimlrepo import fetch_ucirepo  # optional dependency

    raw = fetch_ucirepo(id=cfg["uci_id"]).data.original[list(cfg["columns"].values())]
    yield from _chunked(phiusiil_frame(raw, name, cfg), chunk_rows)


# --- table (local files) -------------------------------------------------------------


def read_table(path: str, read_options: dict | None = None) -> pd.DataFrame:
    opts = read_options or {}
    suffix = Path(path).suffix.lower()
    if suffix == ".parquet":
        return pd.read_parquet(path)
    if suffix in (".jsonl", ".json"):
        return pd.read_json(path, lines=suffix == ".jsonl", **opts)
    if suffix in (".csv", ".txt", ".tsv"):
        return pd.read_csv(path, dtype=str, sep="\t" if suffix == ".tsv" else ",", **opts)
    raise ValueError(f"unsupported table format: {path}")


def _paths(pattern: str) -> list[str]:
    paths = sorted(glob.glob(str(resolve(pattern))))
    if not paths:
        raise FileNotFoundError(f"no files match {pattern}; download the source first")
    return paths


def iter_table(name: str, cfg: dict, chunk_rows: int) -> Iterator[pd.DataFrame]:
    for path in _paths(cfg["path"]):
        raw = read_table(path, cfg.get("read_options"))
        yield from _chunked(frame_from_table(raw, name, cfg), chunk_rows)


# --- folders (Phishpedia) ------------------------------------------------------------


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def read_site_folder(folder: Path, url_file: str, html_file: str) -> tuple[str, str | None] | None:
    """(url, html) from one site folder; None when there is no usable URL."""
    text = _read_text(folder / url_file)
    if not text:
        return None
    url = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
    if not url:
        return None
    return url, _read_text(folder / html_file)


def iter_folders(name: str, cfg: dict, chunk_rows: int) -> Iterator[pd.DataFrame]:
    folders = [Path(p) for p in _paths(cfg["path"]) if Path(p).is_dir()]
    for start in range(0, len(folders), chunk_rows):
        rows = [
            r
            for f in folders[start : start + chunk_rows]
            if (r := read_site_folder(f, cfg["url_file"], cfg["html_file"]))
        ]
        if rows:
            raw = pd.DataFrame(rows, columns=["url", "html"])
            yield to_schema(
                raw["url"], pd.Series([int(cfg["label"])] * len(raw)), name, html=raw["html"]
            )


# --- phishblitz ----------------------------------------------------------------------


def _find_html(root: Path, folder: str, subdirs: list[str]) -> str | None:
    for sub in subdirs:
        base = root / sub / folder
        if not base.exists():
            continue
        candidates = (
            [base] if base.is_file() else [base / "index.html", *sorted(base.rglob("*.html"))]
        )
        for c in candidates:
            if c.is_file():
                return _read_text(c)
    return None


def iter_phishblitz(name: str, cfg: dict, chunk_rows: int) -> Iterator[pd.DataFrame]:
    for label, root in cfg["roots"].items():
        root = resolve(root)
        info = pd.read_csv(root / cfg["info_csv"], dtype=str)
        cols = cfg["columns"]
        info = info[info[cols["url"]].notna()].reset_index(drop=True)
        for chunk in _chunked(info, chunk_rows):
            html = [
                _find_html(root, str(f), cfg["page_dirs"]) if isinstance(f, str) else None
                for f in chunk[cols["html_folder"]]
            ]
            yield to_schema(
                chunk[cols["url"]], pd.Series([int(label)] * len(chunk)), name, html=pd.Series(html)
            )


# --- live (collector) ----------------------------------------------------------------


def live_frame(index: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    """First-seen index -> schema. Only training feeds; label conflicts dropped."""
    from_training_feed = (
        index["sources"].str.split(",").map(lambda s: any(x in cfg["training_feeds"] for x in s))
    )
    idx = index.loc[from_training_feed & ~index["label_conflict"].astype(bool)]
    origin = idx["sources"].str.split(",").str[0]
    return to_schema(idx["url"], idx["label"], "live", dates=idx["first_seen"], origin=origin)


def crawl_frame(crawl: pd.DataFrame, name: str) -> pd.DataFrame:
    """Benign inner pages crawled from ``name``'s seed domains."""
    part = crawl.loc[crawl["seed_source"] == name]
    return to_schema(
        part["url"],
        pd.Series([0] * len(part)),
        name,
        dates=part["crawled_at"],
        html=part["html"],
        origin="crawl",
    )


def iter_live(name: str, cfg: dict, chunk_rows: int) -> Iterator[pd.DataFrame]:
    index_path = resolve(load_config("collector")["paths"]["index_path"])
    if not index_path.exists():
        raise FileNotFoundError(f"{index_path} not found; run `python -m collector run` first")
    yield from _chunked(live_frame(load_index(index_path), cfg), chunk_rows)


LOADERS = {
    "huggingface": iter_huggingface,
    "uci": iter_uci,
    "table": iter_table,
    "folders": iter_folders,
    "phishblitz": iter_phishblitz,
    "live": iter_live,
}


def iter_source(name: str, cfg: dict, chunk_rows: int) -> Iterator[pd.DataFrame]:
    """All rows of one source, plus crawler pages seeded from it (if any)."""
    yield from LOADERS[cfg["kind"]](name, cfg, chunk_rows)
    crawl_dir = resolve(load_config("collector")["paths"]["crawl_dir"])
    crawl = load_crawl(crawl_dir)
    if len(crawl):
        part = crawl_frame(crawl, name)
        if len(part):
            log.info("%s: +%d crawled inner pages", name, len(part))
            yield from _chunked(part, chunk_rows)


def load_source_to_interim(name: str, cfg: dict) -> tuple[Path, dict]:
    out = resolve(cfg["paths"]["interim_dir"]) / f"{name}.parquet"
    chunks = iter_source(name, cfg["sources"][name], cfg["chunk_rows"])
    return out, write_interim(chunks, out, cfg["dedup"])


def inspect(name: str, cfg: dict, n: int = 3) -> str:
    """Raw column names and a few rows, to check the column map in the config."""
    scfg = cfg["sources"][name]
    kind = scfg["kind"]
    if kind == "huggingface":
        import shutil
        import tempfile

        import pyarrow.parquet as pq
        from huggingface_hub import hf_hub_download

        split = next(iter(scfg["splits"]))
        fname = _hf_files(scfg, split)[0]
        tmp_root = Path(tempfile.mkdtemp(prefix="phishdrift_hf_", dir=scfg.get("download_dir")))
        try:
            path = hf_hub_download(
                scfg["hf_id"],
                fname,
                repo_type="dataset",
                revision=scfg["revision"],
                local_dir=tmp_root,
            )
            pf = pq.ParquetFile(path)
            rows = next(pf.iter_batches(batch_size=n)).to_pandas()
            del pf
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)
    elif kind == "uci":
        from ucimlrepo import fetch_ucirepo

        rows = fetch_ucirepo(id=scfg["uci_id"]).data.original.head(n)
    elif kind == "table":
        rows = read_table(_paths(scfg["path"])[0], scfg.get("read_options")).head(n)
    elif kind == "phishblitz":
        root = resolve(next(iter(scfg["roots"].values())))
        rows = pd.read_csv(root / scfg["info_csv"], dtype=str).head(n)
    else:
        raise ValueError(f"inspect does not support kind {kind!r}")
    rows = rows.map(lambda v: (v[:80] + "...") if isinstance(v, str) and len(v) > 80 else v)
    return f"columns: {list(rows.columns)}\n{rows.T.to_string()}"
