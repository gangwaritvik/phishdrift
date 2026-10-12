"""Tier B build: HTML features for one processed part, in resumable shards.

``python -m features build --tier B [--split NAME] [--workers N]``

Reads ``data/processed/<split>.parquet`` (columns ``uid``, ``url``, ``html`` only, a few hundred
rows at a time, never the whole file), computes ``features.html_features`` for every row, and
writes ``data/interim/features_b/<split>/shard_NNNNN.parquet``: one shard per run of row groups
(about ``SHARD_ROWS`` rows), written atomically and skipped on a rerun. When every shard exists they
are joined into ``data/processed/features_b[_<split>].parquet`` (``uid`` + tier B columns, float32,
only the rows whose HTML was usable).

Safe to stop with Ctrl+C at any time: rerun the same command and it continues at the first missing
shard. If the input file changed since the shards were written, the run stops and says so (delete
the shard folder to start over). A part with no HTML at all (for example the held-out source)
is skipped without writing anything.
"""

from __future__ import annotations

import json
import os
import time
from collections import Counter, deque
from collections.abc import Callable, Iterator
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from features.html_features import analyze
from features.lists import load_lists
from features.registry import NAMES_B
from phishdrift.config import load_config, resolve

SHARD_ROWS = 5_000  # rows per shard (whole row groups, so a shard can be skipped without reading)
BATCH_ROWS = 200  # rows read from the parquet file at a time
CHUNK_ROWS = 25  # rows handed to a worker at a time
MAX_DEFAULT_WORKERS = 4
STATUSES = ("ok", "short", "junk", "empty", "no_url", "timeout", "failed")

SCHEMA = pa.schema([("uid", pa.string())] + [(n, pa.float32()) for n in NAMES_B])

Row = tuple[str, str | None, str | None]  # uid, url, html


def default_workers() -> int:
    return max(1, min(MAX_DEFAULT_WORKERS, (os.cpu_count() or 2) - 1))


def output_path(processed: Path, split: str) -> Path:
    """features_b.parquet for the pool, features_b_<split>.parquet for any other part."""
    return processed / ("features_b.parquet" if split == "pool" else f"features_b_{split}.parquet")


def shard_dir(interim: Path, split: str) -> Path:
    return interim / "features_b" / split


def shard_plan(pf: pq.ParquetFile, shard_rows: int = SHARD_ROWS) -> list[list[int]]:
    """Row-group indices of each shard, from the file metadata only (no data is read)."""
    meta = pf.metadata
    shards: list[list[int]] = []
    current: list[int] = []
    rows = 0
    for i in range(meta.num_row_groups):
        current.append(i)
        rows += meta.row_group(i).num_rows
        if rows >= shard_rows:
            shards.append(current)
            current, rows = [], 0
    if current:
        shards.append(current)
    return shards


def fingerprint(path: Path, pf: pq.ParquetFile, shard_rows: int) -> dict:
    meta = pf.metadata
    return {
        "file_bytes": path.stat().st_size,
        "num_rows": meta.num_rows,
        "num_row_groups": meta.num_row_groups,
        "shard_rows": shard_rows,
        "names_b": list(NAMES_B),
    }


def part_has_html(pf: pq.ParquetFile, batch_rows: int = BATCH_ROWS) -> bool:
    """True if any row has HTML. Uses the column statistics; scans only if they are missing."""
    if "html" not in pf.schema_arrow.names:
        return False
    meta = pf.metadata
    column = meta.schema.names.index("html")
    unknown = False
    for i in range(meta.num_row_groups):
        group = meta.row_group(i)
        stats = group.column(column).statistics
        if stats is None or not stats.has_null_count:
            unknown = True
        elif stats.null_count < group.num_rows:
            return True
    if not unknown:
        return False
    for batch in pf.iter_batches(batch_size=batch_rows, columns=["html"]):
        if any(isinstance(h, str) and h for h in batch.column(0).to_pylist()):
            return True
    return False


def process_rows(rows: list[Row]) -> list[tuple[str, dict[str, float] | None, str]]:
    """Tier B features of some rows (runs in a worker process; uses the cached word lists)."""
    lists = load_lists()
    out = []
    for uid, url, html in rows:
        values, status = analyze(url or "", html, lists=lists)
        out.append((uid, values, status))
    return out


def _chunks(rows: list[Row]) -> Iterator[list[Row]]:
    for i in range(0, len(rows), CHUNK_ROWS):
        yield rows[i : i + CHUNK_ROWS]


def _with_meta(meta: dict) -> pa.Schema:
    return SCHEMA.with_metadata({k: json.dumps(v) for k, v in meta.items()})


def _write_shard(path: Path, uids: list[str], values: list[dict[str, float]], meta: dict) -> None:
    columns: dict[str, pa.Array] = {"uid": pa.array(uids, pa.string())}
    for name in NAMES_B:
        columns[name] = pa.array([v[name] for v in values], pa.float32())
    table = pa.table(
        columns, schema=SCHEMA.with_metadata({k: json.dumps(v) for k, v in meta.items()})
    )
    tmp = path.with_name(path.name + ".tmp")
    pq.write_table(table, tmp, compression="zstd")
    os.replace(tmp, path)


def _read_meta(path: Path) -> dict | None:
    """Row and status counts stored in a finished shard; None if the shard is unreadable."""
    try:
        raw = pq.read_schema(path).metadata or {}
        meta = {
            k.decode(): json.loads(v) for k, v in raw.items() if k.decode() in ("rows_in", "status")
        }
        return meta if "rows_in" in meta and "status" in meta else None
    except Exception:
        return None


def _concat(shards: list[Path], out: Path, meta: dict) -> None:
    tmp = out.with_name(out.name + ".tmp")
    with pq.ParquetWriter(tmp, _with_meta(meta), compression="zstd") as writer:
        for shard in shards:
            writer.write_table(pq.read_table(shard).cast(SCHEMA))
    os.replace(tmp, out)


def _clock(seconds: float) -> str:
    s = int(seconds)
    return f"{s // 3600:02d}:{s % 3600 // 60:02d}:{s % 60:02d}"


def build_b(
    split: str = "pool",
    *,
    processed_dir: Path | None = None,
    interim_dir: Path | None = None,
    workers: int | None = None,
    shard_rows: int = SHARD_ROWS,
    batch_rows: int = BATCH_ROWS,
    progress: Callable[[str], None] = lambda s: print(s, flush=True),
) -> Path | None:
    """Build tier B for one part; returns the output file, or None if the part has no HTML."""
    paths = load_config("datasets")["paths"]
    processed = Path(processed_dir) if processed_dir else resolve(paths["processed_dir"])
    interim = Path(interim_dir) if interim_dir else resolve(paths["interim_dir"])
    workers = workers or default_workers()
    src = processed / f"{split}.parquet"
    if not src.exists():
        raise FileNotFoundError(f"{src} is missing: run the milestone 1 build first")
    pf = pq.ParquetFile(src)
    if not part_has_html(pf, batch_rows):
        progress(f"[{split}] no HTML in {src.name}: skipped, nothing written")
        return None

    plan = shard_plan(pf, shard_rows)
    total_rows = pf.metadata.num_rows
    folder = shard_dir(interim, split)
    folder.mkdir(parents=True, exist_ok=True)
    for stale in folder.glob("*.tmp"):
        stale.unlink()
    finger = fingerprint(src, pf, shard_rows)
    plan_file = folder / "plan.json"
    if plan_file.exists():
        if json.loads(plan_file.read_text(encoding="utf-8")) != finger:
            raise RuntimeError(
                f"{src.name} or the feature list changed since the shards in {folder} were "
                f"written: delete that folder to start over"
            )
    else:
        plan_file.write_text(json.dumps(finger), encoding="utf-8")

    started = time.monotonic()
    totals: Counter = Counter()
    rows_done = 0
    rows_run = 0  # rows computed in this run (skipped shards excluded), for the time estimate
    interrupted = False
    shard_files: list[Path] = []
    executor = ProcessPoolExecutor(workers) if workers > 1 else None
    progress(
        f"[{split}] {total_rows:,} rows in {len(plan)} shards, {workers} worker(s); "
        f"shards in {folder}"
    )
    try:
        for index, row_groups in enumerate(plan):
            path = folder / f"shard_{index:05d}.parquet"
            shard_files.append(path)
            meta = _read_meta(path) if path.exists() else None
            if meta is not None:
                totals.update(meta["status"])
                rows_done += meta["rows_in"]
                progress(
                    f"[{split}] shard {index + 1}/{len(plan)} already done (skipped); "
                    f"rows {rows_done:,}/{total_rows:,}"
                )
                continue
            uids, values, status = _run_shard(pf, row_groups, batch_rows, executor)
            rows_in = sum(status.values())
            _write_shard(path, uids, values, {"rows_in": rows_in, "status": dict(status)})
            totals.update(status)
            rows_done += rows_in
            rows_run += rows_in
            progress(
                _shard_line(split, index, len(plan), rows_done, total_rows, totals)
                + _timing(time.monotonic() - started, rows_run, total_rows - rows_done)
            )
    except KeyboardInterrupt:
        interrupted = True
        progress(
            f"[{split}] interrupted: finished shards are kept; rerun the same command to resume"
        )
        raise
    finally:
        if executor is not None:
            executor.shutdown(wait=not interrupted, cancel_futures=True)

    out = output_path(processed, split)
    out.parent.mkdir(parents=True, exist_ok=True)
    _concat(shard_files, out, {"rows_in": rows_done, "status": dict(totals)})
    usable = totals["ok"]
    progress(
        f"[{split}] done: {usable:,} of {rows_done:,} rows have usable HTML "
        f"({100 * usable / max(rows_done, 1):.1f}%) -> {out} ({out.stat().st_size / 1e6:.1f} MB)"
    )
    return out


def _run_shard(
    pf: pq.ParquetFile, row_groups: list[int], batch_rows: int, executor: ProcessPoolExecutor | None
) -> tuple[list[str], list[dict[str, float]], Counter]:
    """Features of every row in the given row groups; only rows with usable HTML are returned."""
    uids: list[str] = []
    values: list[dict[str, float]] = []
    status: Counter = Counter()

    def collect(results) -> None:
        for uid, row_values, row_status in results:
            status[row_status] += 1
            if row_values is not None:
                uids.append(uid)
                values.append(row_values)

    pending: deque = deque()
    for batch in pf.iter_batches(
        batch_size=batch_rows, row_groups=row_groups, columns=["uid", "url", "html"]
    ):
        rows: list[Row] = list(
            zip(
                batch.column("uid").to_pylist(),
                batch.column("url").to_pylist(),
                batch.column("html").to_pylist(),
                strict=True,
            )
        )
        if executor is None:
            collect(process_rows(rows))
            continue
        # Submit this batch before collecting the previous one, so reading overlaps computing.
        pending.append([executor.submit(process_rows, chunk) for chunk in _chunks(rows)])
        if len(pending) > 1:
            for future in pending.popleft():
                collect(future.result())
    while pending:
        for future in pending.popleft():
            collect(future.result())
    return uids, values, status


def _shard_line(
    split: str, index: int, n_shards: int, rows_done: int, total_rows: int, totals: Counter
) -> str:
    usable = totals["ok"]
    other = " ".join(f"{k} {totals[k]:,}" for k in STATUSES[1:] if totals[k])
    return (
        f"[{split}] shard {index + 1}/{n_shards} written: rows {rows_done:,}/{total_rows:,} "
        f"usable {usable:,} ({100 * usable / max(rows_done, 1):.1f}%)"
        f"{' | ' + other if other else ''}"
    )


def _timing(elapsed: float, rows_run: int, rows_left: int) -> str:
    eta = elapsed * rows_left / rows_run if rows_run else 0.0
    return f" | elapsed {_clock(elapsed)}, about {_clock(eta)} left"
